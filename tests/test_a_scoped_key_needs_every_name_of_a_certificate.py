"""A scoped key acts on a certificate only when its scope covers every name in it.

A certificate is one object however many names it carries: one key serves all
of them, and renewing, reissuing, deploying or deleting it does so for all of
them. So every operation on a certificate that already exists requires the
caller's scope to cover each name the certificate covers, the same rule
creation applies to the names it is asked for.

The names are read from both places they can be recorded, and each place has
a certificate here that only it describes:

* `mixed`     names the other tenant in its metadata and in the certificate;
* `bare`      only in the certificate, as for one adopted or restored without
              `san_domains`;
* `torn`      only in the metadata, as for a lineage whose certificate is gone
              and that renewal would reissue from the recorded names;
* `gone`      is `mixed` without its private key, for the reissue-keyless sweep.

`lost` is `gone` with both names in scope: the sweep has to see it, or not
seeing `gone` would prove nothing.

`clean` covers two names, both in scope, and is the control: everything
refused for the others is allowed for it, so a refusal here is the rule and
not the route being broken.
"""
import json
import os
import secrets
import time

import pytest

from tests.contract_world import Certbot, certbot_standing_in, sealed, warm_up, write_certificate
from tests.restricted_keys import stored_as_admin_with_domains, the_downgrade_lifted

pytestmark = [pytest.mark.unit]

SCOPE = ['*.team.example']
OTHER = 'other.example'
CLEAN = 'ok.team.example'
MIXED = 'app.team.example'
BARE = 'bare.team.example'
TORN = 'torn.team.example'
GONE = 'gone.team.example'
LOST = 'lost.team.example'
REFUSED = (MIXED, BARE, TORN, GONE)


def _metadata(domain, sans):
    return json.dumps({'domain': domain, 'san_domains': list(sans),
                       'dns_provider': 'cloudflare', 'challenge_type': 'dns-01',
                       'email': 'ops@team.example', 'staging': True,
                       'account_id': 'default', 'ca_provider': 'letsencrypt_staging'})


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('every-name')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'),
                         ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'),
                         ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        app, container = create_app()

        certs = tmp / 'certs'
        sans = {CLEAN: ['www.team.example'], MIXED: [f'app.{OTHER}'],
                BARE: [f'bare.{OTHER}'], TORN: [f'torn.{OTHER}'], GONE: [f'gone.{OTHER}'],
                LOST: ['www.lost.team.example']}
        for name, extra in sans.items():
            write_certificate(certs / name, name, extra)
            if name != BARE:
                (certs / name / 'metadata.json').write_text(_metadata(name, extra), encoding='utf-8')
        # `torn` keeps its record and loses its certificate: what renewal reissues from.
        (certs / TORN / 'cert.pem').write_bytes(b'')
        for name in (GONE, LOST):
            # What a share-safe restore leaves: certificate generations, no key anywhere.
            (certs / name / 'privkey.pem').unlink()
            archive = certs / name / 'archive' / name
            archive.mkdir(parents=True)
            (archive / 'cert1.pem').write_bytes((certs / name / 'cert.pem').read_bytes())
        settings = container.managers['settings']
        current = settings.load_settings()
        current['email'] = 'ops@team.example'
        current['domains'] = [{'domain': d, 'dns_provider': 'cloudflare'} for d in sans]
        settings.save_settings(current)

        auth = container.managers['auth']
        ok, key = auth.create_api_key('tenant', role='operator', allowed_domains=SCOPE)
        assert ok, key
        # Deleting and deploying take the admin role. A key stored as admin with
        # `allowed_domains` acts as an operator and never reaches them; with
        # that lifted, the scope check those two routes have is what answers.
        legacy = stored_as_admin_with_domains(container, 'tenant-admin', SCOPE)
        _LIMITER.append(container.managers.get('rate_limiter'))
        # Sealed from the network: after an issuance the application asks the CA
        # for its renewal window, and a test about scope should not wait on, or
        # depend on, a CA answering.
        warm_up()
        with certbot_standing_in(Certbot()) as certbot, the_downgrade_lifted(), sealed():
            yield app.test_client(), {'Authorization': f"Bearer {key['token']}"}, \
                {'Authorization': f'Bearer {token}'}, certbot, certs, \
                {'Authorization': f"Bearer {legacy['token']}"}


_LIMITER = []


@pytest.fixture(autouse=True)
def _a_minute_of_its_own(instance):
    """The API answers 429 after 100 requests a minute from one address, and this
    module makes more than that. A test that met the limit would report a 429
    where it expects a 403, which says nothing about scope. Each test starts
    with the count at zero; the limit itself has tests of its own."""
    for limiter in _LIMITER:
        if limiter is not None:
            limiter.requests.clear()


def _refused(response, domain):
    assert response.status_code == 403, (domain, response.status_code, response.get_data(as_text=True))
    body = response.get_json()
    assert body['code'] == 'DOMAIN_OUT_OF_SCOPE'
    # The refusal names what the caller sent, not the other tenant's name.
    assert OTHER not in response.get_data(as_text=True)


@pytest.mark.parametrize('domain', REFUSED)
def test_the_certificate_is_not_readable(instance, domain):
    client, tenant, _admin, _certbot, _certs, _legacy = instance
    _refused(client.get(f'/api/certificates/{domain}', headers=tenant), domain)
    _refused(client.get(f'/api/certificates/{domain}/deployment-status', headers=tenant), domain)


@pytest.mark.parametrize('path', ['download', 'download/privkey', 'download/fullchain'])
@pytest.mark.parametrize('domain', (MIXED, BARE))
def test_its_key_and_chain_are_not_downloadable(instance, domain, path):
    client, tenant, _admin, _certbot, _certs, _legacy = instance
    _refused(client.get(f'/api/certificates/{domain}/{path}', headers=tenant), domain)


@pytest.mark.parametrize('domain', REFUSED)
def test_it_is_not_changed_renewed_reissued_deployed_or_deleted(instance, domain):
    client, tenant, _admin, certbot, certs, legacy_admin = instance
    before = len(certbot.commands)
    _refused(client.patch(f'/api/certificates/{domain}', headers=tenant,
                          json={'dns_provider': 'route53'}), domain)
    _refused(client.put(f'/api/certificates/{domain}/auto-renew', headers=tenant,
                        json={'enabled': False}), domain)
    _refused(client.post(f'/api/certificates/{domain}/renew', headers=tenant, json={}), domain)
    _refused(client.post(f'/api/web/certificates/{domain}/renew', headers=tenant, json={}), domain)
    # Naming only in-scope SANs must not let a reissue drop the other tenant's.
    _refused(client.post(f'/api/certificates/{domain}/reissue', headers=tenant,
                         json={'san_domains': []}), domain)
    _refused(client.post(f'/api/certificates/{domain}/deploy', headers=legacy_admin), domain)
    _refused(client.delete(f'/api/certificates/{domain}', headers=legacy_admin), domain)
    assert (certs / domain).is_dir(), 'a refused delete removed the certificate'
    assert len(certbot.commands) == before, 'certbot ran for a refused certificate'


def test_it_is_not_listed(instance):
    client, tenant, admin, _certbot, _certs, _legacy = instance
    listed = {c['domain'] for c in client.get('/api/certificates', headers=tenant).get_json()}
    assert CLEAN in listed
    assert not listed & set(REFUSED)
    everything = {c['domain'] for c in client.get('/api/certificates', headers=admin).get_json()}
    assert set(REFUSED) <= everything


def test_it_is_left_out_of_a_batch_download(instance):
    import io
    import zipfile
    client, tenant, _admin, _certbot, _certs, _legacy = instance
    response = client.post('/api/web/certificates/download/batch', headers=tenant,
                           json={'domains': [CLEAN, MIXED, BARE]})
    assert response.status_code == 200, response.get_data(as_text=True)
    names = zipfile.ZipFile(io.BytesIO(response.data)).namelist()
    assert names == [f'{CLEAN}.crt']


def test_its_browser_report_is_not_recorded(instance):
    client, tenant, _admin, _certbot, _certs, _legacy = instance
    response = client.post('/api/certificates/deployment-status/browser', headers=tenant,
                           json={'reports': [{'domain': MIXED, 'reachable': True},
                                             {'domain': CLEAN, 'reachable': True}]})
    body = response.get_json()
    assert [s['domain'] for s in body['skipped']] == [MIXED]
    assert body['updated'] == [CLEAN]


def test_the_keyless_sweep_does_not_see_it(instance):
    client, tenant, _admin, certbot, _certs, _legacy = instance
    before = len(certbot.commands)
    response = client.post('/api/certificates/reissue-keyless', headers=tenant, json={})
    body = response.get_json()
    seen = json.dumps(body)
    assert LOST in seen, body
    assert GONE not in seen, body
    # The reissue `lost` was queued for runs on a worker thread. It has to end
    # while the stand-in is in place: after the fixture closes, the next
    # certbot is the real one, and it reaches the real CA.
    for job in body['queued']:
        deadline = time.monotonic() + 30
        while client.get(job['status_url'], headers=tenant).get_json()['status'] not in (
                'succeeded', 'failed'):
            assert time.monotonic() < deadline, f"job {job['job_id']} never finished"
            # Not faster: each poll is a request, and they count (see above).
            time.sleep(0.25)
    assert len(certbot.commands) > before, 'the queued reissue never reached the stand-in'


def test_the_certificate_with_every_name_in_scope_is_the_callers(instance):
    """The control: the same requests succeed for `clean`, so the refusals above
    are the rule and not routes that refuse everything."""
    client, tenant, _admin, certbot, _certs, legacy_admin = instance
    assert client.get(f'/api/certificates/{CLEAN}', headers=tenant).status_code == 200
    assert client.post(f'/api/certificates/{CLEAN}/deploy', headers=legacy_admin).status_code == 200
    privkey = client.get(f'/api/certificates/{CLEAN}/download/privkey', headers=tenant)
    assert privkey.status_code == 200 and b'PRIVATE KEY' in privkey.data
    assert client.put(f'/api/certificates/{CLEAN}/auto-renew', headers=tenant,
                      json={'enabled': True}).status_code == 200
    before = len(certbot.commands)
    renewed = client.post(f'/api/certificates/{CLEAN}/renew', headers=tenant, json={})
    assert renewed.status_code != 403, renewed.get_data(as_text=True)
    assert len(certbot.commands) > before, 'the in-scope renewal never reached certbot'


def test_an_unrestricted_caller_is_unaffected(instance):
    client, _tenant, admin, _certbot, _certs, _legacy = instance
    privkey = client.get(f'/api/certificates/{MIXED}/download/privkey', headers=admin)
    assert privkey.status_code == 200 and b'PRIVATE KEY' in privkey.data


class _Backend:
    """A storage backend holding one certificate, or failing to answer."""

    def __init__(self, cert_files=None, metadata=None, error=None):
        self.answer = (cert_files, metadata or {}) if cert_files else None
        self.error = error

    def retrieve_certificate(self, domain):
        if self.error:
            raise self.error
        return self.answer


def _manager(tmp_path, backend=None):
    from unittest import mock

    from modules.core.certificates import CertificateManager
    return CertificateManager(tmp_path, mock.MagicMock(), mock.MagicMock(),
                              storage_manager=backend)


def test_a_certificate_only_the_backend_holds_is_read_there(tmp_path):
    """No local copy is the one case the storage backend is the only record."""
    from tests.tls_support import make_cert, pem
    leaf, _key = make_cert(MIXED, san_dns=[MIXED, f'app.{OTHER}'])
    backend = _Backend({'cert.pem': pem(leaf)}, {'san_domains': [f'api.{OTHER}']})
    assert _manager(tmp_path, backend).names_covered(MIXED) == [
        MIXED, f'api.{OTHER}', f'app.{OTHER}']


def test_a_local_certificate_is_not_second_guessed_by_the_backend(tmp_path):
    write_certificate(tmp_path / CLEAN, CLEAN)
    backend = _Backend(error=AssertionError('the backend was asked'))
    assert _manager(tmp_path, backend).names_covered(CLEAN) == [CLEAN]


def test_a_backend_that_cannot_answer_refuses_rather_than_narrows(tmp_path):
    """Fewer names than the certificate has is the answer this exists to stop,
    so a backend failure propagates and the request fails closed."""
    backend = _Backend(error=ConnectionError('vault unreachable'))
    with pytest.raises(ConnectionError):
        _manager(tmp_path, backend).names_covered(MIXED)


@pytest.mark.parametrize('domain', [None, '', '../escape', 'a/b'])
def test_a_name_that_is_not_a_directory_is_just_itself(tmp_path, domain):
    assert _manager(tmp_path).names_covered(domain) == [domain]


def test_a_reissue_answers_the_same_whether_or_not_the_certificate_exists(instance):
    """Scope is checked before the certificate is looked for, so the refusal
    does not say which names outside the scope have a certificate."""
    client, tenant, admin, _certbot, _certs, _legacy = instance
    absent = client.post('/api/certificates/absent.other.example/reissue', headers=tenant, json={})
    assert absent.status_code == 403, absent.get_json()
    assert absent.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE'
    # CONTROL: an unrestricted caller is told there is nothing to reissue.
    assert client.post('/api/certificates/absent.other.example/reissue',
                       headers=admin, json={}).status_code == 404
    # CONTROL: inside its scope the key is told the same.
    assert client.post('/api/certificates/absent.team.example/reissue',
                       headers=tenant, json={}).status_code == 404
