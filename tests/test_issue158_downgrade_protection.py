import json
from unittest.mock import patch

import pytest

from modules import __version__
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager


pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_manager(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    (backup_dir / "unified").mkdir()
    file_ops = FileOperations(
        cert_dir=cert_dir,
        data_dir=data_dir,
        backup_dir=backup_dir,
        logs_dir=logs_dir,
    )
    return SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")


def test_load_settings_stamps_version_on_migrated_file(settings_manager, caplog):
    """If certmate_version is missing from an existing file, it is added and saved."""
    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "email": "admin@example.com",
                "domains": [],
                "auto_renew": True,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
                "api_bearer_token_hash": "hmac-sha256:abc123",
            }
        )
    )

    with caplog.at_level("INFO"):
        settings = settings_manager.load_settings()

    assert settings["certmate_version"] == __version__
    saved = json.loads(settings_manager.settings_file.read_text())
    assert saved["certmate_version"] == __version__
    assert "Settings migrated, saving updated format" in caplog.text


@patch("modules.core.settings._CERTMATE_VERSION", "2.4.7")
def test_load_settings_warns_on_downgrade(settings_manager, caplog):
    """If disk version > running version, an ERROR is logged."""
    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "certmate_version": "9.9.9",
                "email": "admin@example.com",
                "domains": [],
                "auto_renew": True,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
                "api_bearer_token_hash": "hmac-sha256:abc123",
            }
        )
    )

    with caplog.at_level("ERROR"):
        settings = settings_manager.load_settings()

    assert "DOWNGRADE DETECTED" in caplog.text
    assert "9.9.9" in caplog.text
    assert "2.4.7" in caplog.text
    # load_settings still returns usable data
    assert settings["email"] == "admin@example.com"


def test_load_settings_info_on_same_version(settings_manager, caplog):
    """If disk version < running version, log 'continuing normally' (upgrade path)."""
    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "certmate_version": "2.4.10",
                "email": "admin@example.com",
                "domains": [],
                "users": {"admin": {"password_hash": "x", "role": "admin"}},
                "auto_renew": True,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
                "api_bearer_token_hash": "hmac-sha256:abc123",
            }
        )
    )

    with caplog.at_level("INFO"):
        settings_manager.load_settings()

    assert "continuing normally" in caplog.text
    assert "DOWNGRADE DETECTED" not in caplog.text


def test_load_settings_logs_critical_when_users_missing_with_backups(
    settings_manager, caplog
):
    """When users is absent but a unified backup exists, log is CRITICAL and lists backups."""
    # Create a dummy unified backup
    dummy_backup = (
        settings_manager.file_ops.backup_dir / "unified" / "backup_20260512_test.zip"
    )
    dummy_backup.write_text("dummy")

    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "email": "admin@example.com",
                "domains": [],
                "auto_renew": True,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
                # users intentionally omitted
            }
        )
    )

    with caplog.at_level("ERROR"):
        settings_manager.load_settings()

    assert "CRITICAL: settings.json has no users" in caplog.text
    assert "backup_20260512_test.zip" in caplog.text
    assert "restore a backup before using the UI" in caplog.text


def test_load_settings_logs_critical_when_users_missing_no_backups(
    settings_manager, caplog
):
    """When users is absent and there are no backups, log still mentions CRITICAL."""
    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "email": "admin@example.com",
                "domains": [],
                "auto_renew": True,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
            }
        )
    )

    with caplog.at_level("ERROR"):
        settings_manager.load_settings()

    assert "CRITICAL: settings.json has no users" in caplog.text
    assert "no backups were found" in caplog.text


def test_load_settings_logs_warning_when_domains_missing_but_certs_exist(
    settings_manager, caplog
):
    """When domains is empty but certs exist on disk, log lists them."""
    cert_dir = settings_manager.file_ops.cert_dir
    domain_dir = cert_dir / "example.com"
    domain_dir.mkdir(parents=True)
    (domain_dir / "cert.pem").write_text("dummy cert")

    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "email": "admin@example.com",
                "domains": [],
                "users": {"admin": {"password_hash": "x", "role": "admin"}},
                "auto_renew": True,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
            }
        )
    )

    with caplog.at_level("WARNING"):
        settings_manager.load_settings()

    warnings = [r for r in caplog.records
                if r.getMessage().startswith("settings.json has no domains but certificates exist on disk")]
    assert len(warnings) == 1
    assert warnings[0].args == (["example.com"],)


def _no_users_records(caplog):
    return [r for r in caplog.records
            if 'settings.json has no users' in r.getMessage()]


def test_the_no_users_warning_is_said_once_not_at_every_load(settings_manager, caplog):
    """It lived inside load_settings, so it fired at every read of the file:
    five CRITICAL lines on the first boot of the released image, and one per
    settings load forever on an instance used only through an API token,
    which is a legitimate configuration with no users at all. An alarm that
    repeats on a healthy instance is one an operator learns to ignore."""
    settings_manager.settings_file.write_text(json.dumps({
        "email": "admin@example.com", "domains": [], "setup_completed": True}))

    with caplog.at_level("ERROR"):
        for _ in range(5):
            settings_manager.load_settings()

    assert len(_no_users_records(caplog)) == 1


def test_a_changed_situation_is_said_again(settings_manager, caplog):
    """CONTROL. Once per situation, not once forever: a backup appearing
    later is new information (there is now something to restore from) and
    the message that names it must still be written."""
    settings_manager.settings_file.write_text(json.dumps({
        "email": "admin@example.com", "domains": [], "setup_completed": True}))
    with caplog.at_level("ERROR"):
        settings_manager.load_settings()
        (settings_manager.file_ops.backup_dir / "unified"
         / "backup_20260929_later.zip").write_text("dummy")
        settings_manager.load_settings()

    messages = [r.getMessage() for r in _no_users_records(caplog)]
    assert len(messages) == 2
    assert 'backup_20260929_later.zip' in messages[1]
