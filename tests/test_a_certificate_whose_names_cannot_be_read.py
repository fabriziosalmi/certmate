"""A scoped key is refused a certificate whose names cannot be read.

The scope rule needs the names a certificate covers. They come from the
certificate and from the `san_domains` CertMate records. When the copy it
serves is missing or torn, certbot's lineage still has the certificate:
`live/<name>/cert.pem`, then the newest generation in `archive/<name>/`. When
neither a certificate nor a record names anything, the scope cannot be
confirmed, and a scoped key is refused rather than checked against the one
name the request carries.
"""
import json
import os
import secrets

import pytest

from tests.contract_world import write_certificate

pytestmark = [pytest.mark.unit]

SCOPE = ['*.team.example']
OTHER = 'other.example'
LIVE = 'live.team.example'          # served copy torn, live/ names the other tenant
ARCHIVED = 'archived.team.example'  # only archive/, newest generation names the other tenant
BLANK = 'blank.team.example'        # nothing readable, no record
RECORDED = 'recorded.team.example'  # nothing readable, a record that lists no other name
FINE = 'fine.team.example'          # served copy torn, live/ names only the scope


def _torn(directory):
    (directory / 'cert.pem').write_bytes(b'-----BEGIN CERTIFICATE-----\ntorn')


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('unknown-names')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        app, container = create_app()
        certs = tmp / 'certs'

        write_certificate(certs / LIVE, LIVE)
        write_certificate(certs / LIVE / 'live' / LIVE, LIVE, [f'live.{OTHER}'])
        _torn(certs / LIVE)

        write_certificate(certs / FINE, FINE)
        write_certificate(certs / FINE / 'live' / FINE, FINE, ['www.fine.team.example'])
        _torn(certs / FINE)

        # Generations 2 and 10: read as text, "cert2" sorts after "cert10" and
        # the older, in-scope generation would be taken for the newest.
        write_certificate(certs / ARCHIVED, ARCHIVED)
        (certs / ARCHIVED / 'cert.pem').unlink()
        archive = certs / ARCHIVED / 'archive' / ARCHIVED
        write_certificate(archive / 'g2', ARCHIVED)
        write_certificate(archive / 'g10', ARCHIVED, [f'archived.{OTHER}'])
        (archive / 'cert2.pem').write_bytes((archive / 'g2' / 'cert.pem').read_bytes())
        (archive / 'cert10.pem').write_bytes((archive / 'g10' / 'cert.pem').read_bytes())

        write_certificate(certs / BLANK, BLANK)
        _torn(certs / BLANK)

        write_certificate(certs / RECORDED, RECORDED)
        _torn(certs / RECORDED)
        (certs / RECORDED / 'metadata.json').write_text(
            json.dumps({'domain': RECORDED, 'san_domains': []}), encoding='utf-8')

        ok, key = container.managers['auth'].create_api_key(
            'tenant', role='operator', allowed_domains=SCOPE)
        assert ok, key
        yield (app.test_client(), {'Authorization': f"Bearer {key['token']}"},
               {'Authorization': f'Bearer {token}'}, container)


def _status(instance, domain, headers=None):
    client, tenant, _admin, _container = instance
    return client.get(f'/api/certificates/{domain}/download/fullchain',
                      headers=headers or tenant).status_code


@pytest.mark.parametrize('domain', [LIVE, ARCHIVED, BLANK])
def test_the_scoped_key_is_refused(instance, domain):
    assert _status(instance, domain) == 403


@pytest.mark.parametrize('domain', [FINE, RECORDED])
def test_names_that_can_be_read_and_are_in_scope_are_allowed(instance, domain):
    """CONTROL: the lineage and the record are read, not just refused."""
    assert _status(instance, domain) != 403


def test_an_unrestricted_caller_is_not_affected(instance):
    _client, _tenant, admin, _container = instance
    assert _status(instance, BLANK, headers=admin) != 403


def test_none_of_them_is_listed_for_the_scoped_key(instance):
    client, tenant, _admin, _container = instance
    listed = {c['domain'] for c in client.get('/api/certificates', headers=tenant).get_json()}
    assert not listed & {LIVE, ARCHIVED, BLANK}
    assert {FINE, RECORDED} <= listed


def test_the_names_come_from_where_they_survive(instance):
    from modules.core.certificates import CertificateNamesUnknown
    certificates = instance[3].managers['certificates']
    assert certificates.names_covered(LIVE) == [LIVE, f'live.{OTHER}']
    assert certificates.names_covered(ARCHIVED) == [ARCHIVED, f'archived.{OTHER}']
    assert certificates.names_covered(RECORDED) == [RECORDED]
    assert certificates.names_covered('absent.team.example') == ['absent.team.example']
    with pytest.raises(CertificateNamesUnknown):
        certificates.names_covered(BLANK)


def test_an_empty_directory_is_not_a_certificate(instance):
    """What a first issuance has before certbot answers, and what a failed
    create can leave: nothing to protect, so just the name."""
    container = instance[3]
    certificates = container.managers['certificates']
    (certificates.cert_dir / 'empty.team.example').mkdir()
    assert certificates.names_covered('empty.team.example') == ['empty.team.example']
    assert _status(instance, 'empty.team.example') != 403


def test_the_key_that_is_creating_a_certificate_can_follow_it(tmp_path):
    """While certbot runs, the directory exists and holds no certificate yet.
    The scoped key that asked for it reads its progress; it is not refused as
    a certificate whose names cannot be read."""
    import threading
    import time

    from tests.contract_world import Certbot, certbot_standing_in

    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp_path / sub).mkdir()
            patch.setenv(var, str(tmp_path / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        app, container = create_app()
        settings = container.managers['settings']
        current = settings.load_settings()
        current['email'] = 'ops@team.example'
        settings.save_settings(current)
        assert container.managers['dns'].add_account('default', 'cloudflare', {'api_token': 'w' * 24})
        ok, key = container.managers['auth'].create_api_key(
            'tenant', role='operator', allowed_domains=SCOPE)
        assert ok, key
        headers = {'Authorization': f"Bearer {key['token']}"}
        name = 'new.team.example'
        certbot = Certbot()
        with certbot_standing_in(certbot):
            gate = certbot.hold_next()
            created = {}
            issuing = threading.Thread(target=lambda: created.update(response=app.test_client().post(
                '/api/certificates/create', headers=headers,
                json={'domain': name, 'dns_provider': 'cloudflare'})))
            issuing.start()
            try:
                deadline = time.monotonic() + 20
                while not certbot.commands:
                    assert time.monotonic() < deadline, 'the issuance never reached certbot'
                    time.sleep(0.02)
                client = app.test_client()
                assert (tmp_path / 'certs' / name).is_dir(), 'the premise: the directory is there'
                detail = client.get(f'/api/certificates/{name}', headers=headers)
                listed = client.get('/api/certificates', headers=headers).get_json()
                status = client.get(f'/api/certificates/{name}/deployment-status', headers=headers)
            finally:
                gate.set()
                issuing.join(30)
        assert detail.status_code == 200, detail.get_json()
        assert status.status_code != 403
        assert name in {c['domain'] for c in listed}
        assert created['response'].status_code == 201, created['response'].get_json()
