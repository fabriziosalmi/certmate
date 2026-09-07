"""A certificate with no usable private key must not report as healthy (#608).

`get_certificate_info` decided a certificate existed from `cert.pem` alone. A
directory holding a valid certificate and no key therefore came back as

    exists True   days_left 74   needs_renewal False

and the renewal sweep left it alone for another six weeks — for an instance
that cannot complete a TLS handshake for that name at all.

The state is not hypothetical. It is exactly what restoring a **share-safe**
backup produces, because those deliberately carry no key material: the restore
writes back cert.pem, chain.pem and fullchain.pem and nothing else. An operator
verifying a recovery the obvious way — the API lists my certificates with sane
expiries — is told the node is fine.

The mismatch case is the same question asked once more: cert.pem from one
issuance beside privkey.pem from another cannot handshake either.

One thing this must NOT do, and the reason half this file exists: the
storage-backed listing path fetches `cert.pem` alone **on purpose**, to avoid
pulling private keys out of a secrets backend for a dashboard. Reading that
absence as a missing key would mark every storage-backed certificate as needing
renewal. Absent-because-nobody-looked is reported as `unknown`, not `missing`.
"""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]


def _self_signed(days_left=74):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'example.com')])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_left))
            .sign(key, hashes.SHA256()))
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


@pytest.fixture
def manager(tmp_path):
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    file_ops = FileOperations(*dirs)
    settings = SettingsManager(file_ops, dirs[1] / 'settings.json')
    return CertificateManager(
        cert_dir=dirs[0], settings_manager=settings, dns_manager=MagicMock(),
        shell_executor=MagicMock())


def _plant(manager, domain, cert_pem, key_pem=None):
    directory = manager.cert_dir / domain
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'cert.pem').write_bytes(cert_pem)
    if key_pem is not None:
        (directory / 'privkey.pem').write_bytes(key_pem)
    return directory


# ---------------------------------------------------------------------------
# The state a restored share-safe backup leaves behind
# ---------------------------------------------------------------------------

def test_a_certificate_with_no_key_is_not_reported_healthy(manager):
    cert_pem, _key = _self_signed(days_left=74)
    _plant(manager, 'example.com', cert_pem)

    info = manager.get_certificate_info('example.com')

    assert info['private_key_present'] is False
    assert info['usable'] is False
    assert info['needs_renewal'] is True, (
        'a certificate that cannot serve TLS was left for the scheduler to '
        'ignore until an expiry that does not matter'
    )
    assert info['days_left'] > 30, (
        'this test is only meaningful while the expiry is far away — '
        'otherwise needs_renewal would be True for the ordinary reason'
    )


def test_a_complete_certificate_is_still_healthy(manager):
    """CONTROL: the point is not to mark everything as broken."""
    cert_pem, key_pem = _self_signed(days_left=74)
    _plant(manager, 'good.example.com', cert_pem, key_pem)

    info = manager.get_certificate_info('good.example.com')

    assert info['private_key_present'] is True
    assert info['usable'] is True
    assert info['needs_renewal'] is False


def test_a_key_from_a_different_issuance_is_not_usable(manager):
    """cert.pem from one issuance beside privkey.pem from another cannot
    complete a handshake — the split-bundle state a partial publish leaves."""
    cert_pem, _own_key = _self_signed()
    _other_cert, foreign_key = _self_signed()
    _plant(manager, 'split.example.com', cert_pem, foreign_key)

    info = manager.get_certificate_info('split.example.com')

    assert info['private_key_state'] == 'mismatched'
    assert info['usable'] is False
    assert info['needs_renewal'] is True


def test_an_unreadable_key_is_not_treated_as_a_good_one(manager):
    cert_pem, _key = _self_signed()
    _plant(manager, 'broken.example.com', cert_pem, b'not a private key')

    info = manager.get_certificate_info('broken.example.com')

    assert info['usable'] is False
    assert info['needs_renewal'] is True


# ---------------------------------------------------------------------------
# The false positive this must not create
# ---------------------------------------------------------------------------

def test_the_storage_listing_path_does_not_invent_a_missing_key(tmp_path):
    """`retrieve_certificate_info` returns cert.pem alone BY DESIGN — its whole
    purpose is to avoid fetching private keys out of a secrets backend for a
    listing view. Treating that as a missing key would mark every
    storage-backed certificate as needing renewal.
    """
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    file_ops = FileOperations(*dirs)
    settings = SettingsManager(file_ops, dirs[1] / 'settings.json')

    cert_pem, _key = _self_signed(days_left=60)
    storage = MagicMock()
    storage.retrieve_certificate_info.return_value = (
        {'cert.pem': cert_pem}, {'domain': 'example.com', 'dns_provider': 'azure'})

    manager = CertificateManager(
        cert_dir=dirs[0], settings_manager=settings, dns_manager=MagicMock(),
        storage_manager=storage, shell_executor=MagicMock())

    info = manager.get_certificate_info('example.com')

    assert info['private_key_state'] == 'unknown'
    assert info['private_key_present'] is None, (
        'the listing path reported a definite answer about a key it never '
        'asked for'
    )
    assert info['needs_renewal'] is False, (
        'every storage-backed certificate was marked for renewal because the '
        'lightweight listing bundle does not carry a private key'
    )


def test_a_storage_bundle_that_does_carry_a_key_says_so(tmp_path):
    """CONTROL: when the key IS in the bundle, the answer is definite."""
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    file_ops = FileOperations(*dirs)
    settings = SettingsManager(file_ops, dirs[1] / 'settings.json')

    cert_pem, key_pem = _self_signed(days_left=60)
    storage = MagicMock()
    storage.retrieve_certificate_info.return_value = (
        {'cert.pem': cert_pem, 'privkey.pem': key_pem}, {'domain': 'example.com'})

    manager = CertificateManager(
        cert_dir=dirs[0], settings_manager=settings, dns_manager=MagicMock(),
        storage_manager=storage, shell_executor=MagicMock())

    info = manager.get_certificate_info('example.com')

    assert info['private_key_state'] == 'present'
    assert info['private_key_present'] is True


# ---------------------------------------------------------------------------
# The helper on its own
# ---------------------------------------------------------------------------

def test_the_key_state_helper_answers_without_a_certificate(manager):
    """Callers that only want to know whether a key file is there should not
    have to load and parse the certificate."""
    cert_pem, key_pem = _self_signed()
    _plant(manager, 'a.example.com', cert_pem, key_pem)
    _plant(manager, 'b.example.com', cert_pem)

    assert manager.private_key_state('a.example.com') == 'present'
    assert manager.private_key_state('b.example.com') == 'missing'
