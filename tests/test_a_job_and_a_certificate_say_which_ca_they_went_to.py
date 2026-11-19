"""A create or reissue job names the CA its request went to and what the CA's
answer says went wrong, and a certificate says whether CertMate renews it from
a staging directory.

UX perception audit, 2026-11-18 (P22): a newcomer's first certificate goes to
production Let's Encrypt, and when it fails nothing says that a test mode
exists. The dashboard now suggests "Test with staging first" when production
Let's Encrypt failed a validation or hit a rate limit, what staging helps with,
and at no other time. To tell which failures those are it needs facts the
answers did not carry:

* the CA a job's request went to (`ca_provider`): the one it named; when it
  named none, a create takes the instance default and a reissue the CA the
  certificate records, or the default when none is recorded. A keyless
  reissue is a reissue. Null for a renewal job;
* what the CA's answer says went wrong (`ca_failure`), on a failed job and on
  a certificate's last failed renewal, read from the whole error: validation,
  rate_limit, account, order, other, or null when the CA was not reached or
  it cannot be told. The texts below are certbot's and Let's Encrypt's
  wording for each case;
* `staging` on a certificate: before 2.12.0 Let's Encrypt staging was
  recorded as `ca_provider` "letsencrypt" with a staging flag, and such a
  lineage still renews from staging.
"""
import time
from unittest.mock import MagicMock

import pytest

from modules.core.cert_jobs import IssuanceExecutor
from tests.test_async_issuance import _build_app

pytestmark = [pytest.mark.unit]


def _finished(client, job_id, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f'/api/certificates/jobs/{job_id}').get_json()
        if job['status'] in ('succeeded', 'failed'):
            return job
        time.sleep(0.01)
    raise AssertionError(f'job {job_id} did not finish')


def _failing_create(tmp_path, settings, body):
    app, managers = _build_app(tmp_path, IssuanceExecutor(app=None))
    managers['settings'].load_settings.return_value = settings
    managers['certificates'].create_certificate.side_effect = RuntimeError('urn:ietf:params:acme:error:dns')
    client = app.test_client()
    answer = client.post('/api/certificates/create', json={**body, 'async': True})
    assert answer.status_code == 202, answer.data
    return _finished(client, answer.get_json()['job_id'])


SETTINGS = {'email': 'ops@example.com', 'dns_provider': 'cloudflare', 'challenge_type': 'dns-01'}


def test_a_create_that_names_no_ca_is_a_job_naming_the_default_it_went_to(tmp_path):
    job = _failing_create(tmp_path, SETTINGS, {'domain': 'x.example.com', 'dns_provider': 'cloudflare'})
    assert job['status'] == 'failed'
    # No default_ca in the settings: the request goes to production Let's Encrypt.
    assert job['ca_provider'] == 'letsencrypt'


def test_a_create_names_the_instance_default_when_one_is_set(tmp_path):
    job = _failing_create(tmp_path, {**SETTINGS, 'default_ca': 'letsencrypt_staging'},
                          {'domain': 'x.example.com', 'dns_provider': 'cloudflare'})
    assert job['ca_provider'] == 'letsencrypt_staging'


def test_a_create_that_names_a_ca_is_a_job_naming_that_ca(tmp_path):
    job = _failing_create(tmp_path, SETTINGS, {'domain': 'x.example.com', 'dns_provider': 'cloudflare',
                                               'ca_provider': 'letsencrypt_staging'})
    assert job['ca_provider'] == 'letsencrypt_staging'


def test_a_renewal_job_names_no_ca():
    """CONTROL: a renewal's CA is its certificate's, which the list says."""
    ex = IssuanceExecutor(app=None)
    job_id = ex.submit('renew', 'x.example.com', lambda: {'success': True})
    assert ex.get(job_id)['ca_provider'] is None


def _manager(tmp_path, metadata):
    """A manager holding one self-signed certificate with *metadata*."""
    import datetime
    import json

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    from modules.core.certificates import CertificateManager

    domain = 'x.example.com'
    cert_dir = tmp_path / 'certificates'
    folder = cert_dir / domain
    folder.mkdir(parents=True)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, domain)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=60))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(domain)]), critical=False)
            .sign(key, hashes.SHA256()))
    (folder / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (folder / 'privkey.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (folder / 'metadata.json').write_text(json.dumps(metadata))
    settings = MagicMock()
    settings.load_settings.return_value = {'domains': [{'domain': domain}]}
    return CertificateManager(cert_dir, settings, MagicMock(), MagicMock())


def _info(tmp_path, metadata):
    return _manager(tmp_path, metadata).get_certificate_info('x.example.com')


@pytest.mark.parametrize('metadata, staging', [
    ({'ca_provider': 'letsencrypt'}, False),
    ({'ca_provider': 'letsencrypt', 'staging': False}, False),
    # Before 2.12.0 a Let's Encrypt staging certificate was recorded this way.
    ({'ca_provider': 'letsencrypt', 'staging': True}, True),
    ({'ca_provider': 'letsencrypt_staging', 'staging': True}, True),
    ({'ca_provider': 'letsencrypt_staging'}, True),
    ({}, False),
])
def test_a_certificate_says_whether_it_came_from_a_staging_directory(tmp_path, metadata, staging):
    info = _info(tmp_path, metadata)
    assert info['exists'] is True
    assert info['staging'] is staging


# --- a reissue job: the CA the certificate records comes first -------------

def _reissue(tmp_path, metadata, default_ca='letsencrypt', body=None):
    """An async reissue of x.example.com that certbot refuses: the job."""
    from flask import Flask, request
    from flask_restx import Api, Namespace

    from modules.api.models import create_api_models
    from modules.api.resources import create_api_resources
    from modules.core.cert_service import CertificateService
    from modules.core.certificates import CertificateManager
    from tests.test_async_issuance import _passthrough_decorator

    settings = MagicMock()
    settings.load_settings.return_value = {'email': 'ops@example.com', 'dns_provider': 'cloudflare',
                                           'challenge_type': 'dns-01',
                                           **({'default_ca': default_ca} if default_ca else {})}
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=MagicMock(), storage_manager=None)
    (tmp_path / 'x.example.com').mkdir()
    (tmp_path / 'x.example.com' / 'cert.pem').write_bytes(b'original certificate')
    manager._load_metadata = lambda domain: {'dns_provider': 'cloudflare', 'challenge_type': 'dns-01',
                                             'san_domains': [], **metadata}
    manager.create_certificate = MagicMock(side_effect=RuntimeError('urn:ietf:params:acme:error:dns'))
    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth.user_can_access_domain.return_value = True
    managers = {'auth': auth, 'settings': settings, 'certificates': manager,
                'file_ops': MagicMock(cert_dir=tmp_path), 'cache': MagicMock(), 'dns': MagicMock(),
                'audit': None, 'cert_executor': IssuanceExecutor(app=None),
                'cert_service': CertificateService(manager, settings, MagicMock())}
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    resources = create_api_resources(api, create_api_models(api), managers)
    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['CertificateReissue'], '/<string:domain>/reissue')
    ns.add_resource(resources['CertificateJob'], '/jobs/<string:job_id>')

    @app.before_request
    def _attach_user():
        request.current_user = {'username': 'op', 'role': 'operator', 'allowed_domains': None}

    client = app.test_client()
    accepted = client.post('/api/certificates/x.example.com/reissue', json={'async': True, **(body or {})})
    assert accepted.status_code == 202, accepted.get_json()
    return _finished(client, accepted.get_json()['job_id'])


def test_a_reissue_that_names_no_ca_is_a_job_naming_the_ca_the_certificate_records(tmp_path):
    job = _reissue(tmp_path, {'ca_provider': 'letsencrypt_staging'}, default_ca='letsencrypt')
    assert job['status'] == 'failed'
    assert job['ca_provider'] == 'letsencrypt_staging'


def test_a_reissue_of_a_certificate_with_no_recorded_ca_names_the_default(tmp_path):
    job = _reissue(tmp_path, {}, default_ca='zerossl')
    assert job['ca_provider'] == 'zerossl'


def test_a_reissue_that_names_a_ca_is_a_job_naming_that_ca(tmp_path):
    job = _reissue(tmp_path, {'ca_provider': 'letsencrypt_staging'}, body={'ca_provider': 'letsencrypt'})
    assert job['ca_provider'] == 'letsencrypt'


# --- a keyless reissue is a reissue job too --------------------------------

def test_a_keyless_reissue_job_names_the_ca_its_reissue_goes_to():
    from tests.test_reissue_everything_that_lost_its_key import _client

    service = MagicMock()
    service.keyless_domains.return_value = ['k.example.com']
    service.prepare_reissue.return_value = {'domain': 'k.example.com', 'ca_provider': 'zerossl'}
    service.issue_reissue.side_effect = RuntimeError('urn:ietf:params:acme:error:dns')
    executor = IssuanceExecutor(app=None)
    try:
        body = _client(service, executor).post('/api/certificates/reissue-keyless', json={}).get_json()
        job_id = body['queued'][0]['job_id']
        deadline = time.time() + 5
        while executor.get(job_id)['status'] not in ('succeeded', 'failed') and time.time() < deadline:
            time.sleep(0.01)
        assert executor.get(job_id)['ca_provider'] == 'zerossl'
    finally:
        executor.shutdown()


# --- what the CA's answer says went wrong -----------------------------------

CLASSIFIED = [
    ('Certificate creation failed: Some challenges have failed.\nDetail: DNS problem: NXDOMAIN looking up TXT '
     'for _acme-challenge.x.example.com - check that a DNS record exists for this domain', 'validation'),
    ('Invalid response from http://x.example.com/.well-known/acme-challenge/abc: 404', 'validation'),
    ('Error creating new order :: too many failed authorizations (5) for "x.example.com" in the last 1h0m0s, '
     'retry after 2026-11-19 10:00:00 UTC', 'rate_limit'),
    ('urn:ietf:params:acme:error:rateLimited :: too many certificates (5) already issued for this exact set '
     'of identifiers in the last 168h0m0s', 'rate_limit'),
    # Staging refuses the same address: not a case for staging.
    ('Unable to register an account with ACME server. Error returned by the ACME server: '
     'urn:ietf:params:acme:error:invalidContact :: Error validating contact(s) :: contact email has '
     'forbidden domain "example.com"', 'account'),
    # Refusals of the order itself, at new-order and at finalize, with no URN in the text.
    ('An unexpected error occurred:\nError creating new order :: Cannot issue for "x.example.com": The ACME '
     'server refuses to issue a certificate for this domain name, because it is forbidden by policy', 'order'),
    ('An unexpected error occurred:\nError finalizing order :: Rechecking CAA for "x.example.com" and 1 more '
     'identifiers failed. Refer to sub-problems for more information', 'order'),
    ('An unexpected error occurred:\nurn:ietf:params:acme:error:serverInternal :: The server experienced an '
     'internal error :: Error retrieving account', 'other'),
    # Never reached the CA.
    ('Renewal failed: No certificate found with name x.example.com (expected '
     '/etc/letsencrypt/renewal/x.example.com.conf).', None),
    ('Certificate for x.example.com already exists. Use renew to replace it, or reissue to change it.', None),
    ("requests.exceptions.ConnectionError: HTTPSConnectionPool(host='acme-v02.api.letsencrypt.org', "
     "port=443): Max retries exceeded with url: /directory (Caused by NewConnectionError(...))", None),
    ('Error determining zone_id: 9109 Invalid access token. Please confirm that you have supplied valid '
     'Cloudflare API credentials.', None),
    ('', None),
]


@pytest.mark.parametrize('error, kind', CLASSIFIED)
def test_a_failure_is_classified_by_what_the_ca_answered(error, kind):
    from modules.core.failure_hints import ca_failure
    assert ca_failure(error) == kind


VALIDATION = CLASSIFIED[0][0]
NO_LINEAGE = CLASSIFIED[8][0]
ACCOUNT = CLASSIFIED[4][0]


@pytest.mark.parametrize('error, kind', [(VALIDATION, 'validation'), (ACCOUNT, 'account'), (NO_LINEAGE, None)])
def test_a_failed_job_says_what_the_ca_answered(error, kind):
    ex = IssuanceExecutor(app=None)

    def fail():
        raise RuntimeError(error)
    job_id = ex.submit('create', 'x.example.com', fail, ca_provider='letsencrypt')
    deadline = time.time() + 5
    while ex.get(job_id)['status'] != 'failed' and time.time() < deadline:
        time.sleep(0.01)
    assert ex.get(job_id)['ca_failure'] == kind


@pytest.mark.parametrize('error, kind', [(VALIDATION, 'validation'), (NO_LINEAGE, None)])
def test_a_failed_renewal_on_the_certificate_says_what_the_ca_answered(tmp_path, error, kind):
    manager = _manager(tmp_path, {'ca_provider': 'letsencrypt'})
    manager.record_renewal_failure('x.example.com', RuntimeError(error))
    attempt = manager.get_certificate_info('x.example.com', use_cache=False)['last_renewal_attempt']
    assert attempt['outcome'] == 'failed'
    assert attempt['ca_failure'] == kind


def test_a_long_error_is_classified_from_all_of_it_not_from_what_is_kept(tmp_path):
    """The record keeps 2000 characters; the cause can come after them."""
    error = 'certbot output line\n' * 120 + VALIDATION
    assert len(error) > 2100 and 'challenges have failed' not in error[:2000].lower()
    manager = _manager(tmp_path, {'ca_provider': 'letsencrypt'})
    manager.record_renewal_failure('x.example.com', RuntimeError(error))
    attempt = manager.get_certificate_info('x.example.com', use_cache=False)['last_renewal_attempt']
    assert len(attempt['error']) == 2000
    assert attempt['ca_failure'] == 'validation'
