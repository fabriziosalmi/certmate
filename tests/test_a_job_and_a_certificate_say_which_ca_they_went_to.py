"""A create or reissue job names the CA its request went to, and a certificate
says whether it came from a staging directory.

UX perception audit, 2026-11-18 (P22): a newcomer's first certificate goes to
production Let's Encrypt, and when it fails nothing says that a test mode
exists. The dashboard now suggests "Test with staging first" on a failed
certificate whose CA is production Let's Encrypt, and on no other. To tell
which ones those are it needs two facts the answers did not carry:

* a create that names no CA takes the instance's default, which the page
  cannot see from the job: the job now carries `ca_provider`, the CA the
  request resolved to (null for a renewal, whose certificate names its CA);
* a certificate issued before 2.12.0 from Let's Encrypt staging is recorded
  as `ca_provider` "letsencrypt" with a `staging` flag, and renews from
  staging: the certificate answer now carries `staging`.
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


def _info(tmp_path, metadata):
    """The certificate answer for one self-signed certificate with *metadata*."""
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
    manager = CertificateManager(cert_dir, settings, MagicMock(), MagicMock())
    return manager.get_certificate_info(domain)


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
