"""Certificate expiry parsing must happen in-process via ``cryptography``.

Before this change, ``_parse_certificate_info`` wrote each certificate to a
temp file and spawned an ``openssl x509 -enddate`` subprocess. With ~30
certificates that is 30 process spawns + 30 temp files on every table load,
which under a CPU-throttled container makes the listing crawl. These tests
pin the behaviour: expiry is parsed in-process and NO ``openssl`` subprocess
is spawned.
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from modules.core.certificates import CertificateManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager


pytestmark = [pytest.mark.unit]


def _make_cert_pem(not_after: datetime) -> bytes:
    """Build a throwaway self-signed cert with a known notAfter."""
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
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()

    file_ops = FileOperations(
        cert_dir=cert_dir, data_dir=data_dir, backup_dir=backup_dir, logs_dir=logs_dir
    )
    settings_manager = SettingsManager(
        file_ops=file_ops, settings_file=data_dir / "settings.json"
    )

    # A shell executor that explodes if anyone tries to spawn openssl: the
    # parse path must be fully in-process now.
    shell = MagicMock()

    def _no_subprocess(cmd, *args, **kwargs):
        raise AssertionError(f"unexpected subprocess spawn during parse: {cmd!r}")

    shell.run.side_effect = _no_subprocess

    return CertificateManager(
        cert_dir=cert_dir,
        settings_manager=settings_manager,
        dns_manager=MagicMock(),
        shell_executor=shell,
    )


def _write_cert(cert_manager, domain, pem):
    cert_path = cert_manager.cert_dir / domain
    cert_path.mkdir(parents=True, exist_ok=True)
    (cert_path / "cert.pem").write_bytes(pem)


def test_expiry_parsed_in_process_without_openssl(cert_manager):
    not_after = datetime.now(timezone.utc) + timedelta(days=42)
    _write_cert(cert_manager, "example.com", _make_cert_pem(not_after))

    info = cert_manager.get_certificate_info("example.com")

    assert info["exists"] is True
    assert info["expiry_date"] is not None
    # Allow off-by-one on day boundary rounding.
    assert info["days_left"] in (41, 42)
    assert info["needs_renewal"] is False
    # The shell executor must never have been touched.
    cert_manager.shell_executor.run.assert_not_called()


def test_near_expiry_flags_needs_renewal(cert_manager):
    not_after = datetime.now(timezone.utc) + timedelta(days=5)
    _write_cert(cert_manager, "soon.example.com", _make_cert_pem(not_after))

    info = cert_manager.get_certificate_info("soon.example.com")

    assert info["exists"] is True
    assert info["days_left"] in (4, 5)
    assert info["needs_renewal"] is True
    cert_manager.shell_executor.run.assert_not_called()


def test_unparseable_cert_marks_exists_without_crashing(cert_manager):
    _write_cert(cert_manager, "garbage.example.com", b"not a real certificate")

    info = cert_manager.get_certificate_info("garbage.example.com")

    assert info["exists"] is True
    assert info["expiry_date"] is None
    assert info["needs_renewal"] is True
    cert_manager.shell_executor.run.assert_not_called()
