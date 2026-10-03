"""ACME profiles end to end, on Let's Encrypt staging (#395).

Real certbot, real CA, Cloudflare DNS-01. What only a real CA and a real certbot can say:

* the certificate a profile asks for is that kind of certificate (`tlsserver`: 45 days and no
  Common Name; `shortlived`: 160 hours);
* certbot writes the profile into the lineage's renewal configuration, and CertMate softens it
  from required to preferred: read off the file certbot wrote, not off a fixture of it;
* a renewal of a `tlsserver` certificate comes back as a `tlsserver` certificate;
* a profile the CA does not offer is refused at issuance (required), and nothing is issued.

Requires CLOUDFLARE_API_TOKEN and CERTMATE_TEST_DOMAIN, like the other files of the real-
certificate gate. Issuance is pinned to staging and the issuer is read off the leaf.
"""
import os
import secrets
import uuid
from datetime import timedelta

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from tests.e2e_support import TEST_EMAIL, assert_staging_issuer

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

BASE_DOMAIN = os.environ.get('CERTMATE_TEST_DOMAIN', 'gpfree.org')
RUN = uuid.uuid4().hex[:8]
TLSSERVER = f'profile-tls-{RUN}.{BASE_DOMAIN}'
SHORTLIVED = f'profile-short-{RUN}.{BASE_DOMAIN}'
REFUSED = f'profile-none-{RUN}.{BASE_DOMAIN}'
ACCOUNT_ID = 'profiles-e2e'


@pytest.fixture(scope='module')
def instance(tmp_path_factory, cloudflare_token):
    """A real CertMate, in this process, pinned to Let's Encrypt staging."""
    tmp = tmp_path_factory.mktemp('profiles-e2e')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp / sub))
        patch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(32))
        from modules.factory import create_app
        _, container = create_app()
        managers = container.managers
        settings_manager = managers['settings']
        settings = settings_manager.load_settings()
        settings.update({
            'email': TEST_EMAIL,
            'default_ca': 'letsencrypt_staging',
            # Non-empty on purpose: an EMPTY staging entry aliases back to production.
            'ca_providers': {'letsencrypt': {'email': TEST_EMAIL},
                             'letsencrypt_staging': {'email': TEST_EMAIL}},
            'dns_provider': 'cloudflare',
            'domains': [{'domain': d, 'dns_provider': 'cloudflare', 'account_id': ACCOUNT_ID,
                         'auto_renew': True} for d in (TLSSERVER, SHORTLIVED)],
        })
        assert settings_manager.save_settings(settings, 'profiles-e2e') is not False
        managers['dns'].add_account(ACCOUNT_ID, 'cloudflare', {'api_token': cloudflare_token})
        yield managers['certificates']


def _issue(manager, domain, profile):
    return manager.create_certificate(domain, TEST_EMAIL, 'cloudflare', account_id=ACCOUNT_ID,
                                      ca_provider='letsencrypt_staging', acme_profile=profile)


def _leaf(manager, domain):
    pem = (manager.cert_dir / domain / 'cert.pem').read_bytes()
    return pem, x509.load_pem_x509_certificate(pem)


def _lifetime(cert):
    return cert.not_valid_after_utc - cert.not_valid_before_utc


def _renewal_conf(manager, domain):
    return (manager.cert_dir / domain / 'renewal' / f'{domain}.conf').read_text()


def test_01_a_tlsserver_certificate_is_one(instance):
    assert _issue(instance, TLSSERVER, 'tlsserver')
    pem, cert = _leaf(instance, TLSSERVER)
    assert_staging_issuer(pem.decode())
    assert abs(_lifetime(cert) - timedelta(days=45)) < timedelta(days=1), _lifetime(cert)
    assert not cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME), cert.subject
    assert instance._load_metadata(TLSSERVER)['acme_profile'] == 'tlsserver'
    print('tlsserver lifetime:', _lifetime(cert))


def test_02_certbot_wrote_the_profile_and_it_was_softened(instance):
    conf = _renewal_conf(instance, TLSSERVER)
    assert 'preferred_profile = tlsserver' in conf, conf
    assert 'required_profile' not in conf, conf


def test_03_the_renewal_keeps_the_profile(instance):
    _pem, before = _leaf(instance, TLSSERVER)
    result = instance.renew_certificate(TLSSERVER, force=True)
    assert result and result.get('renewed') is not False, result
    _pem, after = _leaf(instance, TLSSERVER)
    assert after.serial_number != before.serial_number
    assert abs(_lifetime(after) - timedelta(days=45)) < timedelta(days=1), _lifetime(after)
    assert 'acme_profile_withdrawn_at' not in instance._load_metadata(TLSSERVER)
    assert 'required_profile' not in _renewal_conf(instance, TLSSERVER)


def test_04_a_shortlived_certificate_lives_160_hours(instance):
    assert _issue(instance, SHORTLIVED, 'shortlived')
    _pem, cert = _leaf(instance, SHORTLIVED)
    assert abs(_lifetime(cert) - timedelta(hours=160)) < timedelta(hours=2), _lifetime(cert)
    info = instance.get_certificate_info(SHORTLIVED, use_cache=False)
    assert info['acme_profile'] == 'shortlived'
    assert info['needs_renewal'] is False        # a third of it is not gone: half under 10 days
    print('shortlived lifetime:', _lifetime(cert), 'renews_at:', info['renews_at'])


def test_05_a_profile_the_ca_does_not_offer_is_refused(instance):
    """Required at issuance: the CA refuses the order, and nothing is issued as something else."""
    with pytest.raises(RuntimeError):
        _issue(instance, REFUSED, 'no-such-profile')
    assert not (instance.cert_dir / REFUSED / 'cert.pem').exists()
