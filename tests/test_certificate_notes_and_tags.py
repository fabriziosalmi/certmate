"""Notes and tags on a server certificate (#1043).

Two optional fields an operator attaches to a certificate after it exists. The
request asked for them to be editable, returned, kept across renewal and Edit &
Reissue, in backups, in the audit log, and readable by a deploy hook. Each of
those is a separate way for the feature to be half there, so each has its own
test, and they run against a real instance (a real certificate on disk, real
HTTP routes, the real metadata writer) rather than against mocks that would
agree with whatever the code did.
"""

import datetime
import json
import secrets
import zipfile
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core import cert_labels
from modules.core.cert_labels import (
    MAX_NOTES_LENGTH, MAX_TAGS, MAX_TAG_LENGTH, normalize_notes, normalize_tags,
    tags_from_metadata,
)

pytestmark = [pytest.mark.unit]

DOMAIN = 'example.com'


# --------------------------------------------------------------------------
# The rules themselves
# --------------------------------------------------------------------------

def test_tags_are_lower_cased_deduplicated_and_keep_their_order():
    assert normalize_tags(['Prod', 'customer-x', 'PROD', ' load-balancer ']) == [
        'prod', 'customer-x', 'load-balancer']


@pytest.mark.parametrize('tag', ['env:prod', 'team/network', 'v1.2_a-b', 'a', 'x' * MAX_TAG_LENGTH])
def test_tags_a_person_would_write_are_accepted(tag):
    assert normalize_tags([tag]) == [tag]


@pytest.mark.parametrize('tag', [
    '', '   ', '-rf', '/etc', '.hidden', ':x', 'with space', 'semi;colon', "quo'te", 'dollar$',
    'new\nline', 'ünï', 'x' * (MAX_TAG_LENGTH + 1)])
def test_a_tag_that_could_not_be_pasted_into_a_shell_unquoted_is_refused(tag):
    with pytest.raises(ValueError):
        normalize_tags([tag])


@pytest.mark.parametrize('bad', ['prod', None, 5, {'a': 1}, [1], [['x']], ['ok', None]])
def test_tags_must_be_a_list_of_strings(bad):
    with pytest.raises(ValueError):
        normalize_tags(bad)


def test_at_most_twenty_tags():
    assert len(normalize_tags([f't{i}' for i in range(MAX_TAGS)])) == MAX_TAGS
    with pytest.raises(ValueError):
        normalize_tags([f't{i}' for i in range(MAX_TAGS + 1)])


def test_a_duplicate_does_not_count_against_the_limit():
    assert normalize_tags(['a', 'A'] * 30) == ['a']


def test_notes_are_trimmed_bounded_and_free_of_control_characters():
    assert normalize_notes('  order 4711\nowner: net team\t ') == 'order 4711\nowner: net team'
    assert normalize_notes('   ') == ''
    assert len(normalize_notes('n' * MAX_NOTES_LENGTH)) == MAX_NOTES_LENGTH
    for bad in ('n' * (MAX_NOTES_LENGTH + 1), 'bell\x07', 'nul\x00', 'esc\x1b[31m', 'del\x7f', 5, None):
        with pytest.raises(ValueError):
            normalize_notes(bad)


def test_the_read_side_skips_what_the_write_side_would_have_refused():
    """metadata.json can be edited by hand or restored from another version."""
    stored = {'tags': ['ok', 'Bad Tag', '-x', 5, None, 'OK', 'fine:2'] + [f't{i}' for i in range(40)]}
    tags = tags_from_metadata(stored)
    assert tags[:3] == ['ok', 'fine:2', 't0']
    assert len(tags) == MAX_TAGS
    for garbage in (None, {}, {'tags': 'prod'}, {'tags': {'a': 1}}, {'tags': None}):
        assert tags_from_metadata(garbage) == []


def test_there_is_one_definition_of_a_tag():
    """The writer and the hook reader must agree on the charset."""
    assert cert_labels._TAG_RE.pattern == r'[a-z0-9][a-z0-9._:/-]*'
    assert normalize_tags(['a.b_c:d/e-f']) == tags_from_metadata({'tags': ['a.b_c:d/e-f']})


# --------------------------------------------------------------------------
# A real instance
# --------------------------------------------------------------------------

@pytest.fixture
def instance(tmp_path, monkeypatch):
    for var, sub in (('CERTMATE_CERT_DIR', 'certificates'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(var, str(tmp_path / sub))
    # urlsafe, not hex: a random 64-hex token is refused by validate_api_token about 0.17% of the time
    # (a 3-character run that happens to occur three times), which fails a fixture at random.
    token = secrets.token_urlsafe(48)
    monkeypatch.setenv('API_BEARER_TOKEN', token)

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=60))
            .sign(key, hashes.SHA256()))
    cert_dir = tmp_path / 'certificates' / DOMAIN
    cert_dir.mkdir()
    (cert_dir / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (cert_dir / 'privkey.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    (cert_dir / 'metadata.json').write_text(json.dumps(
        {'domain': DOMAIN, 'dns_provider': 'cloudflare', 'deployment_port': 8443}))

    from modules.factory import create_app
    app, container = create_app()
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}

    class Instance:
        pass

    i = Instance()
    i.app, i.container, i.client, i.headers, i.cert_dir = app, container, client, headers, cert_dir
    i.patch = lambda body, domain=DOMAIN: client.patch(
        f'/api/certificates/{domain}', data=json.dumps(body), headers=headers)
    i.detail = lambda: client.get(f'/api/certificates/{DOMAIN}', headers=headers).get_json()
    i.listing = lambda: next(c for c in client.get('/api/certificates', headers=headers).get_json()
                             if c['domain'] == DOMAIN)
    i.stored = lambda: json.loads((cert_dir / 'metadata.json').read_text())
    return i


def test_a_certificate_with_no_labels_says_so(instance):
    for answer in (instance.detail(), instance.listing()):
        assert answer['notes'] is None
        assert answer['tags'] == []


def test_notes_and_tags_are_set_returned_and_listed(instance):
    response = instance.patch({'notes': 'order 4711, installed on lb-2 by hand',
                               'tags': ['Production', 'customer-x', 'load-balancer']})

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body['notes'] == 'order 4711, installed on lb-2 by hand'
    assert body['tags'] == ['production', 'customer-x', 'load-balancer']
    for answer in (instance.detail(), instance.listing()):
        assert answer['notes'] == 'order 4711, installed on lb-2 by hand'
        assert answer['tags'] == ['production', 'customer-x', 'load-balancer']
    assert instance.stored()['tags'] == ['production', 'customer-x', 'load-balancer']


def test_a_key_that_is_not_sent_is_left_alone(instance):
    instance.patch({'notes': 'keep me', 'tags': ['a', 'b']})

    assert instance.patch({'tags': ['c']}).status_code == 200
    assert instance.stored()['notes'] == 'keep me'
    assert instance.patch({'notes': 'changed'}).status_code == 200
    assert instance.stored()['tags'] == ['c']
    # And the probe config the certificate already had is untouched by both.
    assert instance.stored()['deployment_port'] == 8443


@pytest.mark.parametrize('clear', [{'notes': None}, {'notes': ''}, {'notes': '   '}])
def test_a_note_is_cleared_by_null_or_empty(instance, clear):
    instance.patch({'notes': 'something', 'tags': ['a']})
    assert instance.patch(clear).status_code == 200
    assert 'notes' not in instance.stored()
    assert instance.stored()['tags'] == ['a']


@pytest.mark.parametrize('clear', [{'tags': None}, {'tags': []}])
def test_tags_are_cleared_by_null_or_an_empty_list(instance, clear):
    instance.patch({'notes': 'n', 'tags': ['a']})
    assert instance.patch(clear).status_code == 200
    assert 'tags' not in instance.stored()
    assert instance.stored()['notes'] == 'n'


@pytest.mark.parametrize('body', [
    {'tags': 'production'}, {'tags': ['has space']}, {'tags': ['-x']},
    {'tags': [f't{i}' for i in range(MAX_TAGS + 1)]},
    {'notes': 'n' * (MAX_NOTES_LENGTH + 1)}, {'notes': 'bell\x07'}, {'notes': 5},
])
def test_a_refused_value_changes_nothing(instance, body):
    instance.patch({'notes': 'before', 'tags': ['before']})
    before = instance.stored()

    response = instance.patch(body)

    assert response.status_code == 400, response.get_json()
    assert 'error' in response.get_json()
    assert instance.stored() == before


def test_a_refused_tag_does_not_half_apply_the_note_sent_with_it(instance):
    before = instance.stored()
    assert instance.patch({'notes': 'would be kept', 'tags': ['bad tag']}).status_code == 400
    assert instance.stored() == before


def test_a_patch_with_nothing_to_change_still_says_what_it_accepts(instance):
    response = instance.patch({})
    assert response.status_code == 400
    assert 'notes' in response.get_json()['error'] and 'tags' in response.get_json()['error']


def test_labels_do_not_leak_into_a_certificate_that_was_not_named(instance):
    other = instance.cert_dir.parent / 'other.example.org'
    other.mkdir()
    instance.patch({'tags': ['mine']})
    assert not (other / 'metadata.json').exists()


# --------------------------------------------------------------------------
# What it must not do
# --------------------------------------------------------------------------

def test_editing_labels_does_not_rewrite_settings_or_take_a_backup(instance):
    """Every settings save takes a backup and counts against retention."""
    settings = instance.container.managers['settings']
    settings.update = MagicMock(wraps=settings.update)

    assert instance.patch({'notes': 'x', 'tags': ['a']}).status_code == 200
    assert instance.patch({'deployment_port': 9443}).status_code == 200
    settings.update.assert_not_called()

    # The control: a change that has a settings entry to mirror still writes it,
    # so the assertion above is about the labels and not about a dead spy.
    instance.container.managers['cert_service'].update_config(DOMAIN, {'dns_provider': 'cloudflare'})
    assert settings.update.called


def test_a_change_is_audited_with_the_tags_but_not_the_note(instance):
    audit = instance.container.managers['audit']
    calls = []
    audit.log_operation = lambda **kw: calls.append(kw)
    instance.patch({'tags': ['a']})
    calls.clear()

    secret_note = 'ticket INC-99 for the customer we may not name'
    assert instance.patch({'tags': ['a', 'b'], 'notes': secret_note}).status_code == 200

    entry = next(c for c in calls if c.get('operation') == 'update_labels')
    assert entry['resource_type'] == 'certificate' and entry['resource_id'] == DOMAIN
    assert entry['status'] == 'success'
    assert entry['details']['fields'] == ['notes', 'tags']
    assert entry['details']['tags_before'] == ['a'] and entry['details']['tags_after'] == ['a', 'b']
    assert entry['details']['notes_set'] is True
    assert entry['details']['notes_length'] == len(secret_note)
    assert secret_note not in repr(entry)
    assert entry.get('user') is not None or entry.get('ip_address') is not None


def test_a_probe_only_change_is_not_a_label_change_in_the_audit_log(instance):
    audit = instance.container.managers['audit']
    calls = []
    audit.log_operation = lambda **kw: calls.append(kw)
    assert instance.patch({'deployment_port': 9443}).status_code == 200
    assert not [c for c in calls if c.get('operation') == 'update_labels']


# --------------------------------------------------------------------------
# Where they must survive
# --------------------------------------------------------------------------

def test_labels_survive_edit_and_reissue(instance):
    instance.patch({'notes': 'hand installed on lb-2', 'tags': ['loadbalancer', 'prod']})
    manager = instance.container.managers['certificates']

    merged = manager._merge_reissue_metadata(DOMAIN, {
        'domain': DOMAIN, 'dns_provider': 'cloudflare', 'san_domains': ['www.example.com'],
        'created_at': '2026-09-30T00:00:00'})

    assert merged['notes'] == 'hand installed on lb-2'
    assert merged['tags'] == ['loadbalancer', 'prod']
    assert merged['san_domains'] == ['www.example.com']


def test_labels_survive_a_renewal(instance):
    instance.patch({'notes': 'hand installed on lb-2', 'tags': ['loadbalancer']})
    manager = instance.container.managers['certificates']
    live = instance.cert_dir / 'live' / DOMAIN
    live.mkdir(parents=True)
    for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
        (live / name).write_bytes((instance.cert_dir / 'cert.pem').read_bytes()
                                  if name != 'privkey.pem' else
                                  (instance.cert_dir / 'privkey.pem').read_bytes())

    # What the renewal carries across certbot is the metadata it loaded first.
    manager._publish_renewed_certificate(DOMAIN, instance.cert_dir, manager._load_metadata(DOMAIN))

    stored = instance.stored()
    assert stored['notes'] == 'hand installed on lb-2'
    assert stored['tags'] == ['loadbalancer']
    assert stored['renewed_at']


def test_labels_are_in_the_backup_and_come_back_from_it(instance):
    instance.patch({'notes': 'survives a restore', 'tags': ['dr-test']})
    file_ops = instance.container.managers['file_ops']

    filename = file_ops.create_unified_backup(
        instance.container.managers['settings'].load_settings(), 'test', include_secrets=True)
    assert filename
    archive_path = file_ops.backup_dir / 'unified' / filename
    with zipfile.ZipFile(archive_path) as archive:
        member = next(n for n in archive.namelist() if n.endswith(f'{DOMAIN}/metadata.json'))
        assert json.loads(archive.read(member))['tags'] == ['dr-test']

    # Lose them, then get them back the way a disaster recovery would.
    assert instance.patch({'notes': None, 'tags': None}).status_code == 200
    assert 'tags' not in instance.stored()
    assert file_ops.restore_unified_backup(archive_path) is True
    assert instance.stored()['tags'] == ['dr-test']
    assert instance.stored()['notes'] == 'survives a restore'


# --------------------------------------------------------------------------
# Deploy hooks
# --------------------------------------------------------------------------

def _deployer(instance):
    from modules.core.deployer import DeployManager
    from modules.core.shell import MockShellExecutor
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0, stdout='')
    manager = DeployManager(
        settings_manager=instance.container.managers['settings'], shell_executor=shell,
        audit_logger=MagicMock(), event_bus=MagicMock(),
        cert_dir=instance.cert_dir.parent, data_dir=str(instance.cert_dir.parent.parent / 'data'))
    return manager, shell


def _hook_env(instance, monkeypatch=None):
    manager, shell = _deployer(instance)
    hook = {'id': 'h', 'name': 'probe', 'command': 'true', 'enabled': True,
            'timeout': 10, 'on_events': ['renewed']}
    manager._run_hook(hook, DOMAIN, 'renewed')
    return shell.envs_executed[-1]


def test_a_hook_sees_the_tags_comma_separated(instance):
    instance.patch({'tags': ['loadbalancer', 'env:prod']})
    assert _hook_env(instance)['CERTMATE_TAGS'] == 'loadbalancer,env:prod'


def test_the_variable_is_always_set_so_a_hook_can_rely_on_it(instance):
    assert _hook_env(instance)['CERTMATE_TAGS'] == ''


def test_a_stale_value_in_certmates_own_environment_never_reaches_a_hook(instance, monkeypatch):
    monkeypatch.setenv('CERTMATE_TAGS', 'inherited-from-the-container')
    assert _hook_env(instance)['CERTMATE_TAGS'] == ''


def test_a_bad_tag_in_a_hand_edited_file_is_dropped_not_fatal(instance):
    metadata = instance.stored()
    metadata['tags'] = ['good', 'x; rm -rf /', '$(id)', 'also-good']
    (instance.cert_dir / 'metadata.json').write_text(json.dumps(metadata))
    assert _hook_env(instance)['CERTMATE_TAGS'] == 'good,also-good'


def test_unreadable_metadata_means_no_tags_and_the_hook_still_runs(instance):
    (instance.cert_dir / 'metadata.json').write_text('{not json')
    assert _hook_env(instance)['CERTMATE_TAGS'] == ''
