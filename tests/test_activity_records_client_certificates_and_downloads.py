"""Activity answers "who revoked Anna's certificate" and "who pulled the key".

Found by the #1511 perception audit (P24): after revoking a client certificate
and downloading a server ZIP that holds the private key, /api/activity had the
same count as before, and the page's Revoked and Downloaded filters said "No
activity matches". The audit helpers for create, revoke, renew and download
existed in modules/core/audit.py and nothing called them.

docs/compliance.md promises that every certificate-lifecycle action is recorded
with its actor, and that lifecycle coverage includes create, renew and revoke.
Here that is held for client certificates, and every certificate download,
server or client, with or without the key, is one entry that says who took
what and whether it carried a private key. One entry per request: a ZIP of
four files is one download.

The real application, on the real audit log, through the real routes.
"""
import secrets
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

CHECKOUT = Path(__file__).resolve().parent.parent
DOMAIN = 'payments.example.com'


@pytest.fixture
def instance(tmp_path, monkeypatch):
    """The real app, anchored in tmp_path, as the API Bearer Token (admin)."""
    from modules.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    for name in ('templates', 'static'):
        (root.parent / name).symlink_to(CHECKOUT / name, target_is_directory=True)
    monkeypatch.setattr('modules.factory.__file__', str(root / 'factory.py'))
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    app, container = create_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    certificate = Path(container.cert_dir) / DOMAIN
    certificate.mkdir(parents=True)
    for name in ('cert.pem', 'chain.pem', 'fullchain.pem'):
        (certificate / name).write_text('-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n')
    (certificate / 'privkey.pem').write_text('-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n')
    return client


def _entries(client, **query):
    answer = client.get('/api/activity', query_string=dict(query, limit=500))
    assert answer.status_code == 200, answer.get_data(as_text=True)
    return answer.get_json()['entries']


def _client_certificate(client, name='laptop-anna'):
    answer = client.post('/api/client-certs/create', json={'common_name': name})
    assert answer.status_code == 201, answer.get_data(as_text=True)
    return answer.get_json()['identifier']


def test_creating_revoking_and_renewing_a_client_certificate_each_leave_an_entry_naming_it(instance):
    identifier = _client_certificate(instance)
    renewed = instance.post(f'/api/client-certs/{identifier}/renew')
    assert renewed.status_code == 201, renewed.get_data(as_text=True)
    revoked = instance.post(f'/api/client-certs/{identifier}/revoke', json={'reason': 'keyCompromise'})
    assert revoked.status_code == 200, revoked.get_data(as_text=True)

    mine = [e for e in _entries(instance, resource_type='client_certificate')
            if e['resource_id'] == identifier]
    by_operation = {e['operation']: e for e in mine}
    assert set(by_operation) >= {'create', 'renew', 'revoke'}, (
        f'a client certificate was created, renewed and revoked and Activity recorded {sorted(by_operation)}')
    for operation in ('create', 'renew', 'revoke'):
        entry = by_operation[operation]
        assert entry['status'] == 'success', entry
        assert entry['details'].get('common_name') == 'laptop-anna', entry
        # Who: the API Bearer Token, attributed as such, not "system".
        assert entry['actor']['kind'] == 'api_token', entry
    assert by_operation['revoke']['details'].get('reason') == 'keyCompromise'
    # A renewal is a new certificate with its own identifier: the entry names it.
    assert by_operation['renew']['details'].get('new_identifier') == renewed.get_json()['identifier']
    # Exactly one entry per action.
    assert sorted(e['operation'] for e in mine) == ['create', 'renew', 'revoke'], mine


def test_a_renewal_that_is_refused_is_recorded_as_a_failure(instance):
    """A lifecycle attempt that fails is evidence too: a revoked certificate
    cannot be renewed, and the attempt says so instead of vanishing."""
    identifier = _client_certificate(instance)
    assert instance.post(f'/api/client-certs/{identifier}/revoke', json={}).status_code == 200
    refused = instance.post(f'/api/client-certs/{identifier}/renew')
    assert refused.status_code == 400

    renewals = [e for e in _entries(instance, operation='renew', resource_type='client_certificate')
                if e['resource_id'] == identifier]
    assert len(renewals) == 1, renewals
    assert renewals[0]['status'] == 'failure'
    assert 'revoked' in (renewals[0]['error'] or '').lower(), renewals[0]


def test_a_batch_records_each_client_certificate_it_creates(instance):
    answer = instance.post('/api/client-certs/batch', json={
        'headers': ['common_name'], 'rows': [['batch-one'], ['batch-two']]})
    assert answer.status_code == 201, answer.get_data(as_text=True)
    made = {c['identifier'] for c in answer.get_json()['certificates']}
    assert len(made) == 2
    created = {e['resource_id'] for e in _entries(instance, operation='create', resource_type='client_certificate')}
    assert made <= created, f'created {sorted(made)}, recorded {sorted(created)}'


def test_a_batch_row_with_no_name_is_recorded_by_its_row(instance):
    answer = instance.post('/api/client-certs/batch', json={
        'headers': ['common_name'], 'rows': [['batch-ok'], ['']]})
    assert answer.status_code == 201, answer.get_data(as_text=True)
    assert answer.get_json()['failed'] == 1
    failed = [e for e in _entries(instance, operation='create', resource_type='client_certificate')
              if e['status'] == 'failure']
    assert [e['resource_id'] for e in failed] == ['batch row 3'], failed


def test_a_batch_row_that_cannot_be_read_is_recorded_by_its_row(instance):
    """A row whose cell is not text throws inside the loop; the batch answers
    "Certificate creation failed" for it, and the log says so too."""
    answer = instance.post('/api/client-certs/batch', json={
        'headers': ['common_name'], 'rows': [['batch-fine'], [5]]})
    assert answer.status_code == 201, answer.get_data(as_text=True)
    assert answer.get_json()['errors'] == [{'row': 3, 'error': 'Certificate creation failed'}]
    failed = [e for e in _entries(instance, operation='create', resource_type='client_certificate')
              if e['status'] == 'failure']
    assert [(e['resource_id'], e['error']) for e in failed] == [
        ('batch row 3', 'Certificate creation failed')], failed


def _chain_lines(instance):
    """The audit hash chain's lines, as bytes."""
    import modules.factory as factory
    data_dir = Path(factory.__file__).resolve().parent.parent.parent
    return [line for path in data_dir.rglob('certificate_audit.chain.jsonl')
            for line in path.read_bytes().splitlines()]


def test_a_refused_name_cannot_grow_the_permanent_chain(instance):
    """A refused batch row wrote the request's name whole, twice, into the
    hash chain: a 20,000-character name made a 40,561-byte line that no one
    can take back out. (A single create refuses a name over 64 characters
    before it reaches a certificate, and writes nothing.)"""
    single = instance.post('/api/client-certs/create', json={'common_name': 'x' * 20000})
    assert single.status_code == 400
    instance.post('/api/client-certs/batch', json={'headers': ['common_name'], 'rows': [['x' * 20000]]})
    failed = [e for e in _entries(instance, operation='create', resource_type='client_certificate')
              if e['status'] == 'failure']
    assert len(failed) == 1, failed
    assert len(failed[0]['resource_id']) <= 250, len(failed[0]['resource_id'])
    assert len(failed[0]['details']['common_name']) <= 250
    assert '20000 characters' in failed[0]['details']['common_name'], 'the cut is not marked'
    assert max(len(line) for line in _chain_lines(instance)) < 2000


def test_a_refused_name_with_a_line_break_is_kept_on_one_line(instance):
    instance.post('/api/client-certs/create', json={'common_name': 'evil\nname\x1b[31m'})
    entries = [e for e in _entries(instance, operation='create', resource_type='client_certificate')
               if e['status'] == 'failure']
    assert len(entries) == 1, entries
    name = entries[0]['details']['common_name']
    assert '\n' not in name and '\x1b' not in name, repr(name)
    assert name == 'evil\\nname\\x1b[31m', repr(name)


@pytest.mark.parametrize('body', [
    {'headers': ['common_name'], 'rows': 'xyz'},
    {'headers': ['common_name'], 'rows': 9},
    {'headers': ['common_name'], 'rows': [{'common_name': 'a'}]},
    {'headers': 'common_name', 'rows': [['a']]},
])
def test_a_batch_that_is_not_a_table_is_refused_and_creates_nothing(instance, body):
    """"rows": "xyz" created three certificates, x, y and z; "rows": 9 was a
    500. The batch is a list of header names and a list of rows of cells."""
    answer = instance.post('/api/client-certs/batch', json=body)
    assert answer.status_code == 400, answer.get_data(as_text=True)
    assert instance.get('/api/client-certs').get_json()['total'] == 0


@pytest.mark.parametrize('reason, refused', [
    ('x' * 201, 'longer than 200'),
    ('first line\nsecond line', 'one line'),
    (42, 'must be text'),
])
def test_a_revocation_reason_that_cannot_be_kept_is_refused(instance, reason, refused):
    """The reason goes into the certificate's record and into the hash chain,
    which nothing takes back out."""
    identifier = _client_certificate(instance)
    answer = instance.post(f'/api/client-certs/{identifier}/revoke', json={'reason': reason})
    assert answer.status_code == 400, answer.get_data(as_text=True)
    assert refused in answer.get_json()['error'], answer.get_json()
    assert instance.get(f'/api/client-certs/{identifier}').get_json()['revoked'] is False
    assert not _entries(instance, operation='revoke', resource_type='client_certificate')


def test_a_revocation_reason_of_200_characters_is_kept(instance):
    """CONTROL: the limit is a limit, not a refusal of every reason."""
    identifier = _client_certificate(instance)
    answer = instance.post(f'/api/client-certs/{identifier}/revoke', json={'reason': 'y' * 200})
    assert answer.status_code == 200, answer.get_data(as_text=True)
    revokes = _entries(instance, operation='revoke', resource_type='client_certificate')
    assert revokes[0]['details']['reason'] == 'y' * 200


@pytest.mark.parametrize('file_type, carries_key', [
    ('crt', False), ('csr', False), ('key', True),
])
def test_every_client_certificate_download_says_whether_it_carried_the_key(instance, file_type, carries_key):
    identifier = _client_certificate(instance)
    answer = instance.get(f'/api/client-certs/{identifier}/download/{file_type}')
    assert answer.status_code == 200, answer.get_data(as_text=True)

    downloads = [e for e in _entries(instance, operation='download', resource_type='client_certificate')
                 if e['resource_id'] == identifier]
    assert len(downloads) == 1, downloads
    assert downloads[0]['status'] == 'success'
    assert downloads[0]['details']['key_included'] is carries_key, downloads[0]
    assert downloads[0]['details']['file_type'] == file_type
    assert downloads[0]['details'].get('common_name') == 'laptop-anna', downloads[0]
    assert downloads[0]['actor']['kind'] == 'api_token'


@pytest.mark.parametrize('suffix, query, carries_key', [
    ('', {}, True),                                   # the default ZIP, four files
    ('', {'include_private': '0'}, False),            # the public ZIP
    ('', {'format': 'json'}, True),
    ('', {'file': 'fullchain.pem'}, False),
    ('', {'file': 'privkey.pem'}, True),
    ('', {'file': 'combined.pem'}, True),
    ('/fullchain', {}, False),
    ('/privkey', {}, True),
])
def test_every_server_certificate_download_is_one_entry_saying_whether_it_carried_the_key(
        instance, suffix, query, carries_key):
    answer = instance.get(f'/api/certificates/{DOMAIN}/download{suffix}', query_string=query)
    assert answer.status_code == 200, answer.get_data(as_text=True)

    downloads = [e for e in _entries(instance, operation='download', resource_id=DOMAIN)
                 if e['status'] == 'success']
    assert len(downloads) == 1, f'one request, {len(downloads)} entries: {downloads}'
    assert downloads[0]['resource_type'] == 'certificate'
    assert downloads[0]['details']['key_included'] is carries_key, downloads[0]
    assert downloads[0]['actor']['kind'] == 'api_token'


def test_a_refused_download_is_not_recorded_as_a_download(instance):
    """CONTROL: an answer that did not hand the files over is not a download."""
    answer = instance.get(f'/api/certificates/{DOMAIN}/download', query_string={'file': 'nope.pem'})
    assert answer.status_code == 400
    assert not [e for e in _entries(instance, operation='download') if e['status'] == 'success']


def test_a_batch_download_is_one_entry_naming_the_certificates_in_it(instance):
    answer = instance.post('/api/web/certificates/download/batch',
                           json={'domains': [DOMAIN, 'missing.example.com']},
                           headers={'Origin': 'http://localhost'})
    assert answer.status_code == 200, answer.get_data(as_text=True)
    batches = _entries(instance, operation='batch_download')
    assert len(batches) == 1, batches
    assert batches[0]['status'] == 'success'
    assert batches[0]['details']['domains'] == [DOMAIN], batches[0]
    assert batches[0]['details']['key_included'] is False
