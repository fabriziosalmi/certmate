"""Certificate list lookups should use lightweight cached storage metadata."""

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
from modules.core.storage_backends import LocalFileSystemBackend


pytestmark = [pytest.mark.unit]


def _make_cert_pem(not_after: datetime) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(not_after)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def cert_manager(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for directory in (cert_dir, data_dir, backup_dir, logs_dir):
        directory.mkdir()

    file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
    settings_manager = SettingsManager(file_ops, data_dir / "settings.json")
    storage = MagicMock()
    storage.retrieve_certificate_info.return_value = (
        {"cert.pem": _make_cert_pem(datetime.now(timezone.utc) + timedelta(days=60))},
        {"domain": "example.com", "dns_provider": "azure"},
    )

    return CertificateManager(
        cert_dir=cert_dir,
        settings_manager=settings_manager,
        dns_manager=MagicMock(),
        storage_manager=storage,
        shell_executor=MagicMock(),
    )


def test_storage_certificate_info_uses_lightweight_backend_method(cert_manager):
    info = cert_manager.get_certificate_info("example.com")

    assert info["exists"] is True
    assert info["dns_provider"] == "azure"
    cert_manager.storage_manager.retrieve_certificate_info.assert_called_once_with("example.com")
    cert_manager.storage_manager.retrieve_certificate.assert_not_called()


def test_storage_certificate_info_is_cached_per_domain(cert_manager):
    first = cert_manager.get_certificate_info("example.com")
    second = cert_manager.get_certificate_info("example.com")

    assert first == second
    cert_manager.storage_manager.retrieve_certificate_info.assert_called_once_with("example.com")
    cert_manager.storage_manager.retrieve_certificate.assert_not_called()


def test_storage_certificate_info_cache_varies_by_renewal_threshold(cert_manager):
    low_threshold = {"renewal_threshold_days": 30}
    high_threshold = {"renewal_threshold_days": 90}

    first = cert_manager.get_certificate_info("example.com", settings=low_threshold)
    second = cert_manager.get_certificate_info("example.com", settings=high_threshold)

    assert first["needs_renewal"] is False
    assert second["needs_renewal"] is True
    assert cert_manager.storage_manager.retrieve_certificate_info.call_count == 2
    cert_manager.storage_manager.retrieve_certificate.assert_not_called()


def test_save_metadata_invalidates_cached_certificate_info(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for directory in (cert_dir, data_dir, backup_dir, logs_dir):
        directory.mkdir()

    file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
    settings_manager = SettingsManager(file_ops, data_dir / "settings.json")
    domain_dir = cert_dir / "example.com"
    domain_dir.mkdir()
    (domain_dir / "cert.pem").write_bytes(
        _make_cert_pem(datetime.now(timezone.utc) + timedelta(days=60))
    )
    (domain_dir / "metadata.json").write_text('{"dns_provider": "cloudflare"}')

    manager = CertificateManager(
        cert_dir=cert_dir,
        settings_manager=settings_manager,
        dns_manager=MagicMock(),
        storage_manager=LocalFileSystemBackend(cert_dir),
        shell_executor=MagicMock(),
    )

    first = manager.get_certificate_info("example.com")
    assert first["dns_provider"] == "cloudflare"

    assert manager._save_metadata("example.com", {"dns_provider": "route53"}) is True
    second = manager.get_certificate_info("example.com")

    assert second["dns_provider"] == "route53"
