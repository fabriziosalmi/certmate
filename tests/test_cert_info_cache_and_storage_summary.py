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
from modules.core.utils import DeploymentStatusCache


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
    # Caching is ON here (use_cache defaults True), but the two calls carry
    # different renewal thresholds, which produce different cache keys, so
    # both still miss the cache and hit storage. This pins key-variance, not
    # the cache being disabled by passing settings.
    low_threshold = {"renewal_threshold_days": 30}
    high_threshold = {"renewal_threshold_days": 90}

    first = cert_manager.get_certificate_info("example.com", settings=low_threshold)
    second = cert_manager.get_certificate_info("example.com", settings=high_threshold)

    assert first["needs_renewal"] is False
    assert second["needs_renewal"] is True
    assert cert_manager.storage_manager.retrieve_certificate_info.call_count == 2
    cert_manager.storage_manager.retrieve_certificate.assert_not_called()


def test_listing_path_retains_cache_when_settings_threaded(cert_manager):
    """The regression guard: a listing-style call that threads settings=
    (use_cache defaults True) must STILL hit the cross-request cert-info
    cache. Two calls with the same settings => storage is queried ONCE,
    the second served from _certificate_info_cache.

    Before the fix, ``cache_enabled = settings is None`` meant passing
    settings silently disabled the cache, turning a cached re-list into N
    storage round-trips for Azure KV / AWS SM / Vault backends."""
    settings = {"renewal_threshold_days": 30}

    first = cert_manager.get_certificate_info("example.com", settings=settings)
    second = cert_manager.get_certificate_info("example.com", settings=settings)

    assert first == second
    cert_manager.storage_manager.retrieve_certificate_info.assert_called_once_with("example.com")
    cert_manager.storage_manager.retrieve_certificate.assert_not_called()


def test_use_cache_false_skips_cache_on_storage_path(cert_manager):
    """The check_renewals path: use_cache=False must bypass the cert-info
    cache entirely, so every call hits storage. Two calls => two storage
    round-trips and nothing is read back from _certificate_info_cache."""
    settings = {"renewal_threshold_days": 30}

    cert_manager.get_certificate_info("example.com", settings=settings, use_cache=False)
    cert_manager.get_certificate_info("example.com", settings=settings, use_cache=False)

    assert cert_manager.storage_manager.retrieve_certificate_info.call_count == 2
    cert_manager.storage_manager.retrieve_certificate.assert_not_called()
    # Nothing was written to the cache, so a later cached lookup misses.
    assert cert_manager._get_cached_certificate_info("example.com", settings) is None


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


def test_clear_prefix_removes_only_matching_entries():
    """clear_prefix must drop only keys starting with the prefix and
    return the number removed, leaving every other entry intact."""
    cache = DeploymentStatusCache(default_ttl=300)
    cache.set("a.com|x", {"v": 1})
    cache.set("b.com|y", {"v": 2})

    removed = cache.clear_prefix("a.com|")

    assert removed == 1
    assert cache.get("a.com|x") is None
    assert cache.get("b.com|y") == {"v": 2}


def test_clear_prefix_pipe_separator_isolates_prefix_overlap():
    """The "{domain}|" prefix (with the literal pipe) must not match a
    different domain that merely shares a leading string (e.g.
    example.com vs example.com.evil)."""
    cache = DeploymentStatusCache(default_ttl=300)
    cache.set("example.com|renewal_threshold_days=30|date=2026-05-28", {"v": 1})
    cache.set("example.com.evil|renewal_threshold_days=30|date=2026-05-28", {"v": 2})

    removed = cache.clear_prefix("example.com|")

    assert removed == 1
    assert cache.get("example.com|renewal_threshold_days=30|date=2026-05-28") is None
    assert cache.get("example.com.evil|renewal_threshold_days=30|date=2026-05-28") == {"v": 2}


def test_clear_prefix_returns_zero_when_no_match():
    cache = DeploymentStatusCache(default_ttl=300)
    cache.set("b.com|y", {"v": 2})

    assert cache.clear_prefix("a.com|") == 0
    assert cache.get("b.com|y") == {"v": 2}


def test_invalidate_cert_info_cache_is_scoped_per_domain(tmp_path):
    """A single-domain invalidation must clear only that domain's cached
    certificate-info entries — the previous global .clear() wiped every
    domain's entry on any mutation."""
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for directory in (cert_dir, data_dir, backup_dir, logs_dir):
        directory.mkdir()

    file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
    settings_manager = SettingsManager(file_ops, data_dir / "settings.json")

    manager = CertificateManager(
        cert_dir=cert_dir,
        settings_manager=settings_manager,
        dns_manager=MagicMock(),
        storage_manager=MagicMock(),
        shell_executor=MagicMock(),
    )

    # Prime the cert-info cache for two distinct domains.
    manager._set_cached_certificate_info("a.com", {"domain": "a.com", "exists": True})
    manager._set_cached_certificate_info("b.com", {"domain": "b.com", "exists": True})

    assert manager._get_cached_certificate_info("a.com") is not None
    assert manager._get_cached_certificate_info("b.com") is not None

    # Mutate only a.com.
    manager._invalidate_certificate_info_cache("a.com")

    # a.com's entry is gone; b.com's survives (global clear would wipe both).
    assert manager._get_cached_certificate_info("a.com") is None
    assert manager._get_cached_certificate_info("b.com") is not None
