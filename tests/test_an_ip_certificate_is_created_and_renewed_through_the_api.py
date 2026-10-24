"""An IP-address certificate is created, listed, renewed, reissued and deleted through the API (#1130).

#1336 taught issuance to ask Let's Encrypt for an address; the API could not
ask it to. Measured on main before this change, through the application:
POST /api/certificates/create answered 400 for an address (validate_domain read
its last octet as a TLD), and a certificate issued below the API was listed
under its derived name only, with every route about it (detail, download,
renew, reissue, auto-renew, deploy, delete) answering 400. These tests drive the
application with certbot stood in for, so every argument it would have been
given is on record.
"""
import contextlib
import datetime
import ipaddress
import json
import secrets
import time
from pathlib import Path
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.utils import ip_for_cert_name
from tests import contract_world as world
from tests.tls_support import key_pem, make_cert, pem

pytestmark = [pytest.mark.unit]

# Each test makes what it reads: the suite runs on four xdist workers, which
# share no state and run a module's tests in no fixed order. An address is
# created by one test only where the test is about its creation.
ADDRESS = '1.1.1.1'
NAME = 'ip-1-1-1-1'


def _option(cmd, flag):
    return cmd[cmd.index(flag) + 1] if flag in cmd else None


class _Certbot(world.Certbot):
    """The stand-in, writing what Let's Encrypt issues for an address: a
    certificate whose only SAN is that IP, for an issuance (--ip-address) and
    for a renewal of the lineage (which names no identifier: certbot reads it
    from the renewal conf)."""

    def _write_lineage(self, cmd):
        config_dir, name = _option(cmd, '--config-dir'), _option(cmd, '--cert-name')
        address = _option(cmd, '--ip-address') or ip_for_cert_name(name)
        if not (config_dir and address):
            return super()._write_lineage(cmd)
        leaf, key = make_cert(address, san_ip=[address], issuer=self._ca[0], issuer_key=self._ca[1])
        live = Path(config_dir) / 'live' / name
        live.mkdir(parents=True, exist_ok=True)
        for filename, content in {'cert.pem': pem(leaf), 'chain.pem': pem(self._ca[0]),
                                  'fullchain.pem': pem(leaf) + pem(self._ca[0]),
                                  'privkey.pem': key_pem(key)}.items():
            (live / filename).write_bytes(content)

    def runs(self, word):
        return [list(map(str, cmd)) for cmd in self.commands if word in map(str, cmd)]


@pytest.fixture(scope='module')
def instance(tmp_path_factory):
    tmp = tmp_path_factory.mktemp('ip-certificates')
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
        from modules.factory import create_app
        app, container = create_app()
        certbot = _Certbot()
        with world.certbot_standing_in(certbot):
            settings = container.managers['settings']
            current = settings.load_settings()
            current['email'] = world.EMAIL
            # Every other certificate here is DNS-01: an address must not inherit it.
            current['challenge_type'] = 'dns-01'
            settings.save_settings(current)
            client = app.test_client()
            client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
            yield client, container, certbot, Path(tmp / 'certs')


def _registered(container):
    return [entry['domain'] for entry in container.managers['settings'].load_settings()['domains']]


def _issued(instance, address):
    """The certificate for *address*, created through the API unless it exists."""
    client, _container, _certbot, certs = instance
    name = 'ip-' + address.replace('.', '-')
    if not (certs / name / 'cert.pem').exists():
        response = client.post('/api/certificates/create', json={'domain': address})
        assert response.status_code == 201, response.get_json()
    return name


# --- created through the API ----------------------------------------------------

def test_an_address_is_created_under_its_derived_name(instance):
    client, container, certbot, certs = instance
    response = client.post('/api/certificates/create', json={'domain': '1.0.0.1'})
    assert response.status_code == 201, response.get_json()
    body = response.get_json()
    assert body['domain'] == 'ip-1-0-0-1'
    assert body['ip_address'] == '1.0.0.1'

    issued = certbot.runs('certonly')[-1]
    assert _option(issued, '--ip-address') == '1.0.0.1'
    assert '-d' not in issued
    assert _option(issued, '--cert-name') == 'ip-1-0-0-1'
    assert _option(issued, '--required-profile') == 'shortlived'
    assert '--webroot' in issued
    # Registered under the name the sweep walks, so it is renewed like any other.
    assert 'ip-1-0-0-1' in _registered(container)
    metadata = json.loads((certs / 'ip-1-0-0-1' / 'metadata.json').read_text(encoding='utf-8'))
    assert metadata['challenge_type'] == 'http-01'
    assert metadata['acme_profile'] == 'shortlived'


def test_the_list_and_the_detail_show_the_address(instance):
    client, *_ = instance
    _issued(instance, ADDRESS)
    listed = [c for c in client.get('/api/certificates').get_json() if c['domain'] == NAME]
    assert len(listed) == 1
    assert listed[0]['ip_address'] == ADDRESS
    assert listed[0]['exists'] is True
    detail = client.get(f'/api/certificates/{NAME}')
    assert detail.status_code == 200, detail.get_json()
    assert detail.get_json()['ip_address'] == ADDRESS


def test_a_domain_certificate_says_it_has_no_address(instance):
    client, *_ = instance
    response = client.post('/api/certificates/create',
                           json={'domain': 'www.example.test', 'challenge_type': 'http-01'})
    assert response.status_code == 201, response.get_json()
    assert response.get_json()['ip_address'] is None
    listed = [c for c in client.get('/api/certificates').get_json() if c['domain'] == 'www.example.test']
    assert listed[0]['ip_address'] is None


@pytest.mark.parametrize('path', [f'/api/certificates/{NAME}/download',
                                  f'/api/certificates/{NAME}/download/cert',
                                  f'/api/certificates/{NAME}/deployment-status'])
def test_its_routes_answer_by_its_name(instance, path):
    client, *_ = instance
    _issued(instance, ADDRESS)
    response = client.get(path)
    assert response.status_code == 200, response.get_data()[:200]


def test_it_is_renewed_by_its_name(instance):
    client, _container, certbot, certs = instance
    _issued(instance, ADDRESS)
    before = (certs / NAME / 'cert.pem').read_bytes()
    response = client.post(f'/api/certificates/{NAME}/renew', json={'force': True})
    assert response.status_code == 200, response.get_json()
    renewed = certbot.runs('renew')[-1]
    assert _option(renewed, '--cert-name') == NAME
    assert (certs / NAME / 'cert.pem').read_bytes() != before


# --- refused before anything is issued -----------------------------------------------

@pytest.mark.parametrize('body, reason', [
    ({'challenge_type': 'dns-01'}, 'HTTP-01 only'),
    ({'san_domains': ['example.test']}, 'single address'),
    ({'domain_alias': 'validation.example.test'}, 'DNS alias'),
    ({'acme_profile': 'classic'}, "'shortlived' profile only"),
    ({'ca_provider': 'zerossl'}, "Let's Encrypt only"),
    ({'async': True, 'challenge_type': 'dns-01'}, 'HTTP-01 only'),
])
def test_a_request_let_s_encrypt_would_refuse_is_refused_here(instance, body, reason):
    """Before certbot, and before an asynchronous create would answer 202 and
    then fail in its job."""
    client, container, certbot, certs = instance
    ran = len(certbot.commands)
    response = client.post('/api/certificates/create', json={'domain': '9.9.9.9', **body})
    assert response.status_code == 400, response.get_json()
    assert reason in response.get_json()['error']
    assert len(certbot.commands) == ran
    assert not (certs / 'ip-9-9-9-9').exists()
    assert 'ip-9-9-9-9' not in _registered(container)


@pytest.mark.parametrize('address', ['10.0.0.1', '192.0.2.1', '100.64.0.1', '2001:db8::1'])
def test_an_address_let_s_encrypt_cannot_reach_is_refused(instance, address):
    client, _container, certbot, _certs = instance
    ran = len(certbot.commands)
    response = client.post('/api/certificates/create', json={'domain': address})
    assert response.status_code == 400
    assert 'Invalid IP address' in response.get_json()['error']
    assert len(certbot.commands) == ran


def test_a_key_restricted_to_domains_cannot_create_one(instance):
    client, container, certbot, _certs = instance
    ok, key = container.managers['auth'].create_api_key(
        'tenant', role='operator', allowed_domains=['*.example.test'])
    assert ok, key
    ran = len(certbot.commands)
    response = client.post('/api/certificates/create', json={'domain': '9.9.9.9'},
                           headers={'Authorization': f"Bearer {key['token']}"})
    assert response.status_code == 403
    assert len(certbot.commands) == ran


# --- asynchronously, and from the dashboard's own route ---------------------------------

def _finished(client, job_id):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        job = client.get(f'/api/certificates/jobs/{job_id}').get_json()
        if job['status'] in ('succeeded', 'failed'):
            return job
        time.sleep(0.05)
    raise AssertionError(f'job {job_id} did not finish')


def test_an_asynchronous_create_names_the_job_for_the_certificate(instance):
    client, container, certbot, _certs = instance
    response = client.post('/api/certificates/create',
                           json={'domain': '149.112.112.112', 'async': True})
    assert response.status_code == 202, response.get_json()
    assert response.get_json()['domain'] == 'ip-149-112-112-112'
    job = _finished(client, response.get_json()['job_id'])
    assert job['status'] == 'succeeded', job
    assert job['domain'] == 'ip-149-112-112-112'
    assert any(_option(cmd, '--ip-address') == '149.112.112.112' for cmd in certbot.runs('certonly'))
    assert 'ip-149-112-112-112' in _registered(container)


def test_the_dashboard_route_creates_one_too(instance):
    client, container, certbot, _certs = instance
    response = client.post('/api/web/certificates/create', json={'domain': '8.8.4.4'})
    assert response.status_code == 200, response.get_json()
    assert response.get_json()['domain'] == 'ip-8-8-4-4'
    assert response.get_json()['ip_address'] == '8.8.4.4'
    assert _option(certbot.runs('certonly')[-1], '--ip-address') == '8.8.4.4'
    assert 'ip-8-8-4-4' in _registered(container)


# --- reissued with its address, never as a DNS name ------------------------------------

def test_a_reissue_asks_for_the_address(instance):
    """Measured on main: a reissue from metadata built `-d ip-<dashed>`, a DNS
    name that does not exist, so the CA could only refuse it."""
    client, _container, certbot, _certs = instance
    _issued(instance, ADDRESS)
    response = client.post(f'/api/certificates/{NAME}/reissue', json={})
    assert response.status_code == 200, response.get_json()
    reissued = certbot.runs('certonly')[-1]
    assert _option(reissued, '--ip-address') == ADDRESS
    assert '-d' not in reissued
    assert _option(reissued, '--cert-name') == NAME


def test_a_reissue_from_metadata_asks_for_the_address(instance):
    """The sweep's own reissue (auto_reissue_keyless), which does not pass
    through the route."""
    _client, container, certbot, _certs = instance
    _issued(instance, ADDRESS)
    container.managers['certificates']._reissue_from_metadata(NAME)
    reissued = certbot.runs('certonly')[-1]
    assert _option(reissued, '--ip-address') == ADDRESS
    assert '-d' not in reissued


@pytest.mark.parametrize('asynchronous', [False, True], ids=['sync', 'async'])
def test_a_reissue_cannot_add_a_name(instance, asynchronous):
    """Asynchronously as well: refused before the 202, not in the job."""
    client, _container, certbot, _certs = instance
    _issued(instance, ADDRESS)
    ran = len(certbot.commands)
    response = client.post(f'/api/certificates/{NAME}/reissue',
                           json={'san_domains': ['example.test'], 'async': asynchronous})
    assert response.status_code == 400, response.get_json()
    assert 'single address' in response.get_json()['error']
    assert len(certbot.commands) == ran


# --- the renewal sweep ------------------------------------------------------------------

def _due_certificate(directory, address):
    """160 hours long with 10 left: due under any rule the sweep applies."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ip test CA')])
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(issuer)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(hours=150))
            .not_valid_after(now + datetime.timedelta(hours=10))
            .add_extension(x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(address))]), critical=True)
            .sign(key, hashes.SHA256()))
    (directory / 'cert.pem').write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    (directory / 'privkey.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))


@contextlib.contextmanager
def _no_ari(manager):
    # The CA's renewal window is not asked: nothing here may leave the process.
    with mock.patch.object(manager, '_refresh_renewal_info', lambda *a, **k: None):
        yield


def test_the_sweep_renews_it_as_a_registered_certificate(instance):
    _client, container, certbot, certs = instance
    manager = container.managers['certificates']
    name = _issued(instance, '8.8.8.8')
    _due_certificate(certs / name, '8.8.8.8')
    ran = len(certbot.runs('renew'))
    with _no_ari(manager):
        summary = manager.check_renewals()
    renewals = certbot.runs('renew')[ran:]
    # Only this one: every other certificate here is a day into thirty.
    assert [_option(cmd, '--cert-name') for cmd in renewals] == [name]
    assert '--force-renewal' in renewals[0]
    assert summary['renewed'] == 1
    # Through the registered path: neither unmanaged nor taken on from disk.
    assert summary['unmanaged'] == 0
    assert summary['reregistered'] == 0


# --- deleted by its name --------------------------------------------------------------------

def test_it_is_deleted_by_its_name(instance):
    client, container, _certbot, _certs = instance
    name = _issued(instance, '208.67.222.222')
    response = client.delete(f'/api/certificates/{name}')
    assert response.status_code == 200, response.get_json()
    assert name not in _registered(container)
    assert name not in [c['domain'] for c in client.get('/api/certificates').get_json()]


def test_the_stand_in_writes_what_the_ca_issues(tmp_path):
    """CONTROL: the stand-in's certificate carries the address as its only
    SAN, as Let's Encrypt's does, so the reads above were about that shape."""
    _Certbot().run(['certbot', 'certonly', '--config-dir', str(tmp_path),
                    '--cert-name', NAME, '--ip-address', ADDRESS])
    leaf = x509.load_pem_x509_certificate((tmp_path / 'live' / NAME / 'cert.pem').read_bytes())
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address(ADDRESS)]
    assert san.get_values_for_type(x509.DNSName) == []


def test_the_batch_takes_domains_only(instance):
    """docs/api.md says so: each name of a batch is a domain, and an address
    in one is refused for itself, before certbot."""
    client, container, certbot, certs = instance
    ran = len(certbot.commands)
    response = client.post('/api/web/certificates/batch',
                           json={'domains': ['9.9.9.9'], 'challenge_type': 'http-01'})
    assert response.status_code == 200, response.get_json()
    [result] = response.get_json()
    assert result['success'] is False
    assert len(certbot.commands) == ran
    assert not (certs / 'ip-9-9-9-9').exists()
    assert 'ip-9-9-9-9' not in _registered(container)
