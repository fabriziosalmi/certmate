"""Unit tests for the Windows .pfx (PKCS#12) export (issue #230)."""
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from modules.core.certificates import CertificateManager
from modules.core.storage_backends import _build_pfx

pytestmark = [pytest.mark.unit]


def _self_signed():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def test_build_pfx_with_password_is_loadable_and_rejects_wrong_password():
    cert_pem, key_pem = _self_signed()
    blob = _build_pfx(cert_pem, None, key_pem, password=b's3cr3t-pw')
    key, cert, _chain = pkcs12.load_key_and_certificates(blob, b's3cr3t-pw')
    assert key is not None and cert is not None
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(blob, b'wrong-pw')


def test_build_pfx_without_password_is_unencrypted():
    cert_pem, key_pem = _self_signed()
    blob = _build_pfx(cert_pem, None, key_pem)  # default: NoEncryption (Azure path)
    key, cert, _chain = pkcs12.load_key_and_certificates(blob, None)
    assert key is not None and cert is not None


def _manager(tmp_path, password):
    sm = MagicMock()
    sm.load_settings.return_value = {'pfx_password': password}
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=sm,
        dns_manager=MagicMock(), storage_manager=None, ca_manager=None,
    )


def _seed_domain(tmp_path, domain='example.com'):
    cert_pem, key_pem = _self_signed()
    d = tmp_path / domain
    d.mkdir()
    (d / 'cert.pem').write_bytes(cert_pem)
    (d / 'privkey.pem').write_bytes(key_pem)
    return d


def test_write_pfx_creates_encrypted_bundle_when_password_set(tmp_path):
    d = _seed_domain(tmp_path)
    _manager(tmp_path, 'win-pw-123')._write_pfx('example.com')

    pfx = d / 'cert.pfx'
    assert pfx.exists()
    # Private-key material must be owner-only.
    assert (pfx.stat().st_mode & 0o777) == 0o600
    key, cert, _chain = pkcs12.load_key_and_certificates(pfx.read_bytes(), b'win-pw-123')
    assert key is not None and cert is not None


def test_write_pfx_removes_stale_bundle_when_password_unset(tmp_path):
    d = _seed_domain(tmp_path)
    (d / 'cert.pfx').write_bytes(b'stale')
    _manager(tmp_path, '')._write_pfx('example.com')
    assert not (d / 'cert.pfx').exists()


def test_write_pfx_noop_when_pems_missing(tmp_path):
    (tmp_path / 'example.com').mkdir()
    # No cert.pem/privkey.pem present; must not raise or create a bundle.
    _manager(tmp_path, 'win-pw-123')._write_pfx('example.com')
    assert not (tmp_path / 'example.com' / 'cert.pfx').exists()
