"""A certificate can be named apart from its domain (#854, step 4: #1149).

Until now a certificate's name was its domain, so one domain could hold one
certificate. `POST /api/certificates/create` takes an optional `name` since API
contract 2.61: the certificate is for `domain` and is named `name`, so a second
certificate for the same domain, from another CA, has a name of its own. The
name is what every later request takes; the domain is recorded as the
certificate's `host`, which issuance, scope, the deployment check and the
answers have read since #1360, #1363 and #1364.

A name has the shape of a DNS name, the shape every route and backup already
accept. It may not be an IP certificate's (`ip-<dashed>`), may not start with
`*.` unless it is the wildcard it is for, and an IP certificate is named by its
address, not by a name given to it.
"""

import json
import os
import secrets
import time
from pathlib import Path

import pytest

import tests.contract_world as world

pytestmark = [pytest.mark.unit]

HOST = 'example.com'
NAME = 'internal.example.com'


def _option(cmd, flag):
    return cmd[cmd.index(flag) + 1] if flag in cmd else None


class _Certbot(world.Certbot):
    """The stand-in, writing a certificate for what the CA was asked for (`-d`),
    under the lineage named by --cert-name."""

    def _write_lineage(self, cmd):
        config_dir, name = _option(cmd, '--config-dir'), _option(cmd, '--cert-name')
        names = [cmd[i + 1] for i, word in enumerate(cmd[:-1]) if word == '-d']
        if not (config_dir and name and names):
            return super()._write_lineage(cmd)
        world.write_certificate(Path(config_dir) / 'live' / name, names[0], names[1:], self._ca)

    def runs(self, word):
        return [list(map(str, cmd)) for cmd in self.commands if word in map(str, cmd)]


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('named-apart')
    token = secrets.token_urlsafe(32)
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs'),
                         ('ACME_CHALLENGES_DIR', 'challenges')):
            (tmp / sub).mkdir()
            patch.setenv(var, str(tmp / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', token)
        os.environ['API_BEARER_TOKEN'] = token
        from modules.factory import create_app
        _app, container = create_app()
        certbot = _Certbot()
        with world.certbot_standing_in(certbot):
            settings = container.managers['settings']
            current = settings.load_settings()
            current['email'] = world.EMAIL
            settings.save_settings(current)
            client = _app.test_client()
            client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
            yield client, container, certbot, Path(tmp / 'certs')


def _create(client, **body):
    return client.post('/api/certificates/create',
                       json={'challenge_type': 'http-01', 'ca_provider': 'letsencrypt', **body})


def _issued(instance, domain, name=None):
    """The certificate, created here unless it exists: every test makes its own
    state, since xdist runs the tests of one module on different workers."""
    client, _container, _certbot, certs = instance
    if not (certs / (name or domain) / 'cert.pem').exists():
        body = {'domain': domain, **({'name': name} if name else {})}
        response = _create(client, **body)
        assert response.status_code == 201, response.get_json()


def _registered(container):
    return [entry['domain'] for entry in container.managers['settings'].load_settings()['domains']]


def test_two_certificates_for_one_domain_each_under_its_own_name(instance):
    client, container, certbot, certs = instance
    _issued(instance, HOST)
    if (certs / NAME).exists():
        assert client.delete(f'/api/certificates/{NAME}').status_code == 200

    response = _create(client, domain=HOST, name=NAME)

    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert (body['domain'], body['host']) == (NAME, HOST)
    issued = certbot.runs('certonly')[-1]
    assert (_option(issued, '--cert-name'), _option(issued, '-d')) == (NAME, HOST)
    metadata = json.loads((certs / NAME / 'metadata.json').read_text(encoding='utf-8'))
    assert (metadata['domain'], metadata['host']) == (NAME, HOST)
    assert {HOST, NAME} <= set(_registered(container))
    listed = {c['domain']: c['host'] for c in client.get('/api/certificates').get_json()}
    assert (listed[HOST], listed[NAME]) == (HOST, HOST)


def test_a_certificate_named_apart_is_renewed_and_deleted_by_its_name(instance):
    client, container, certbot, certs = instance
    _issued(instance, HOST)
    _issued(instance, HOST, NAME)

    renewed = client.post(f'/api/certificates/{NAME}/renew', json={'force': True})
    assert renewed.status_code == 200, renewed.get_json()
    assert _option(certbot.runs('renew')[-1], '--cert-name') == NAME

    assert client.delete(f'/api/certificates/{NAME}').status_code == 200
    assert not (certs / NAME).exists()
    assert (certs / HOST / 'cert.pem').exists()
    assert NAME not in _registered(container) and HOST in _registered(container)


def test_a_name_equal_to_the_domain_is_no_name_at_all(instance):
    client, _container, _certbot, certs = instance
    if (certs / 'plain.example.com').exists():
        assert client.delete('/api/certificates/plain.example.com').status_code == 200
    response = _create(client, domain='plain.example.com', name='plain.example.com')
    assert response.status_code == 201, response.get_json()
    metadata = json.loads((certs / 'plain.example.com' / 'metadata.json').read_text(encoding='utf-8'))
    assert 'host' not in metadata


def test_an_empty_name_is_no_name_at_all(instance):
    client, _container, _certbot, certs = instance
    if (certs / 'blank.example.com').exists():
        assert client.delete('/api/certificates/blank.example.com').status_code == 200
    response = _create(client, domain='blank.example.com', name='  ')
    assert response.status_code == 201, response.get_json()
    assert response.get_json()['domain'] == 'blank.example.com'


def test_a_name_already_taken_is_refused(instance):
    client, _container, _certbot, _certs = instance
    _issued(instance, 'other.example.net', 'taken.example.com')
    assert _create(client, domain='another.example.net', name='taken.example.com').status_code == 409


@pytest.mark.parametrize('domain,name,reason', [
    (HOST, '../etc', 'Invalid name'),
    (HOST, 'two words', 'Invalid name'),
    (HOST, 'ip-1-2-3-4', 'Invalid name'),   # no dot: never a DNS-shaped name
    (HOST, '*.example.com', 'wildcard'),
    (HOST, 7, "not of type 'string'"),   # the request model refuses it first
    ('1.1.1.1', NAME, 'named by its address'),
])
def test_a_name_that_cannot_be_given_is_refused_before_anything_is_issued(instance, domain, name, reason):
    client, _container, certbot, _certs = instance
    before = len(certbot.commands)

    response = _create(client, domain=domain, name=name)

    assert response.status_code == 400, response.get_json()
    assert reason in json.dumps(response.get_json())
    assert len(certbot.commands) == before


@pytest.mark.parametrize('domain', [HOST, '*.example.com'])
def test_a_name_equal_to_the_domain_is_no_name_even_for_a_wildcard(domain):
    from modules.core.cert_service import _name_apart
    assert _name_apart(domain.upper(), domain, None) is None


def test_the_service_refuses_a_name_that_is_not_a_string_on_its_own():
    from modules.core.cert_service import _name_apart
    with pytest.raises(ValueError, match='a name is a string'):
        _name_apart(7, HOST, None)


def _key(container, *scope):
    ok, key = container.managers['auth'].create_api_key(
        f'tenant-{secrets.token_hex(4)}', role='operator', allowed_domains=list(scope))
    assert ok, key
    return {'Authorization': f"Bearer {key['token']}"}


def test_a_key_restricted_to_domains_names_a_certificate_only_within_them(instance):
    client, container, certbot, _certs = instance
    headers = _key(container, 'tenant.example.org')
    before = len(certbot.commands)

    response = client.post('/api/certificates/create', headers=headers, json={
        'domain': 'tenant.example.org', 'name': 'victim.example.net',
        'challenge_type': 'http-01', 'ca_provider': 'letsencrypt'})

    assert response.status_code == 403, response.get_json()
    assert len(certbot.commands) == before


def test_a_key_names_a_certificate_within_its_scope_and_then_renews_it(instance):
    client, container, _certbot, _certs = instance
    headers = _key(container, 'tenant.example.org', '*.tenant.example.org')
    name = f'n{secrets.token_hex(3)}.tenant.example.org'

    created = client.post('/api/certificates/create', headers=headers, json={
        'domain': 'tenant.example.org', 'name': name,
        'challenge_type': 'http-01', 'ca_provider': 'letsencrypt'})
    assert created.status_code == 201, created.get_json()

    renewed = client.post(f'/api/certificates/{name}/renew', headers=headers, json={'force': True})
    assert renewed.status_code == 200, renewed.get_json()


def _finished(client, job_id):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        job = client.get(f'/api/certificates/jobs/{job_id}').get_json()
        if job['status'] in ('succeeded', 'failed'):
            return job
        time.sleep(0.05)
    raise AssertionError(f'job {job_id} did not finish')


def test_an_asynchronous_create_takes_the_name_too(instance):
    client, _container, certbot, certs = instance
    name = f'n{secrets.token_hex(3)}.example.com'

    response = _create(client, domain=HOST, name=name, **{'async': True})

    assert response.status_code == 202, response.get_json()
    assert _finished(client, response.get_json()['job_id'])['status'] == 'succeeded'
    issued = certbot.runs('certonly')[-1]
    assert (_option(issued, '--cert-name'), _option(issued, '-d')) == (name, HOST)
    metadata = json.loads((certs / name / 'metadata.json').read_text(encoding='utf-8'))
    assert metadata['host'] == HOST


def test_a_name_held_by_an_external_certificate_is_refused_before_an_asynchronous_create_is_accepted(instance):
    client, _container, certbot, certs = instance
    name = f'x{secrets.token_hex(3)}.example.com'
    (certs / name).mkdir()
    (certs / name / 'metadata.json').write_text(json.dumps({'domain': name, 'external': True}))
    before = len(certbot.commands)

    response = _create(client, domain=HOST, name=name, **{'async': True})

    assert response.status_code == 409, response.get_json()
    assert response.get_json()['code'] == 'EXTERNAL_CERTIFICATE'
    assert len(certbot.commands) == before


def test_a_key_is_given_no_certificate_named_outside_its_scope_by_any_route(instance):
    """An admin names a certificate outside a key's scope, for a host inside it:
    the batch download judges the name as the single download does."""
    import io
    import zipfile
    client, container, _certbot, _certs = instance
    host = f'h{secrets.token_hex(3)}.tenant.example.org'
    name = f'ops-{secrets.token_hex(3)}.example.net'
    _issued(instance, host, name)
    headers = _key(container, host)

    assert client.get(f'/api/certificates/{name}/download', headers=headers).status_code == 403
    batch = client.post('/api/web/certificates/download/batch', headers=headers,
                        json={'domains': [name]})
    assert batch.status_code == 200
    assert zipfile.ZipFile(io.BytesIO(batch.data)).namelist() == []
