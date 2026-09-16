"""#830: on the default installation, CertMate could not tell whether a
certificate had a private key.

#608 closed "a certificate with no private key is reported as healthy, and the
scheduler leaves it alone". It closed it against the filesystem branch of
`get_certificate_info`, which is the branch no real deployment takes:
`create_container` always builds a StorageManager, StorageManager defaults to
`local_filesystem`, and the storage branch is entered whenever one exists. So
the fix landed on a path that only unit tests reach, and the path every
installation takes kept answering `private_key_state: 'unknown'` for every
certificate, which `needs_renewal` treats as "nothing to see".

Every test here therefore goes through a real StorageManager with the real
local backend, the way the application does. A test that builds a
CertificateManager with `storage_manager=None` cannot fail on this defect, and
that is precisely how it survived five releases.
"""
import datetime
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager
from modules.core.storage_backends import StorageManager

pytestmark = [pytest.mark.unit]

DOMAIN = 'abc.local'


def _pair(days_valid=90):
    """A real certificate and the real key that signed it."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=days_valid))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.TraditionalOpenSSL,
                              serialization.NoEncryption()))


@pytest.fixture
def instance(tmp_path):
    """A CertificateManager wired the way create_container wires it."""
    cert_dir = tmp_path / 'certificates'
    settings = MagicMock()
    settings.load_settings.return_value = {
        'certificate_storage': {'backend': 'local_filesystem',
                                'cert_dir': str(cert_dir)},
    }
    settings.get_domain_dns_provider.return_value = 'cloudflare'
    storage = StorageManager(settings)
    manager = CertificateManager(cert_dir, settings, MagicMock(),
                                 storage_manager=storage)
    return manager, storage, cert_dir


def _store(storage, cert_pem, key_pem=None, metadata=None):
    files = {'cert.pem': cert_pem, 'chain.pem': cert_pem,
             'fullchain.pem': cert_pem}
    if key_pem is not None:
        files['privkey.pem'] = key_pem
    assert storage.get_backend().store_certificate(DOMAIN, files, metadata or {})


def test_a_key_on_disk_is_seen(instance):
    """The whole defect in one assertion: the key is right there."""
    manager, storage, cert_dir = instance
    cert_pem, key_pem = _pair()
    _store(storage, cert_pem, key_pem)

    info = manager.get_certificate_info(DOMAIN, use_cache=False)

    assert info['private_key_state'] == 'present', (
        "the default backend read privkey.pem off the disk and then threw it "
        "away before anyone could be told about it"
    )
    assert info['private_key_present'] is True
    assert info['usable'] is True


def test_a_certificate_with_no_key_is_not_healthy(instance):
    """#608, on the path the application actually takes."""
    manager, storage, cert_dir = instance
    cert_pem, key_pem = _pair()
    _store(storage, cert_pem, key_pem)
    (cert_dir / DOMAIN / 'privkey.pem').unlink()

    info = manager.get_certificate_info(DOMAIN, use_cache=False)

    assert info['private_key_state'] == 'missing'
    assert info['private_key_present'] is False
    assert info['usable'] is False
    assert info['needs_renewal'] is True, (
        "a certificate that cannot complete a handshake was reported as "
        "needing nothing, which is the sentence #608 was closed for"
    )


def test_a_key_from_another_certificate_is_caught(instance):
    """cert.pem from one issuance beside privkey.pem from another."""
    manager, storage, cert_dir = instance
    cert_pem, _ = _pair()
    _, other_key = _pair()
    _store(storage, cert_pem, other_key)

    info = manager.get_certificate_info(DOMAIN, use_cache=False)

    assert info['private_key_state'] == 'mismatched'
    assert info['usable'] is False
    assert info['needs_renewal'] is True


def test_a_csr_only_certificate_is_not_reported_as_broken(instance):
    """#599: the key was never ours, so its absence is the feature."""
    manager, storage, cert_dir = instance
    cert_pem, _ = _pair()
    _store(storage, cert_pem, metadata={'key_management': 'external'})

    info = manager.get_certificate_info(DOMAIN, use_cache=False)

    assert info['private_key_state'] == 'external'
    assert info['needs_renewal'] is False, (
        "a CSR-only certificate reissued every sweep burns CA rate limit for "
        "a problem that does not exist"
    )


def test_a_backend_that_does_not_answer_about_keys_still_says_unknown(instance):
    """The reason the storage branch answered 'unknown' in the first place.

    Azure Key Vault and S3 override retrieve_certificate_info with a genuinely
    cheap path that never fetches key material. For those, absence is not
    evidence: reading it as 'missing' would mark every certificate as needing
    renewal, which is the regression #608's fix was avoiding. They must keep
    answering 'unknown', and must not be dragged into needs_renewal by it.
    """
    manager, storage, cert_dir = instance
    cert_pem, key_pem = _pair()
    _store(storage, cert_pem, key_pem)

    backend = storage.get_backend()
    original = backend.retrieve_certificate_info

    def cert_only(domain):
        files, metadata = original(domain)
        return {'cert.pem': files['cert.pem']}, metadata

    backend.retrieve_certificate_info = cert_only
    backend.info_includes_private_key = False

    info = manager.get_certificate_info(DOMAIN, use_cache=False)

    assert info['private_key_state'] == 'unknown'
    assert info['private_key_present'] is None
    assert info['usable'] is None
    assert info['needs_renewal'] is False
