import json

import pytest

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
    file_ops = FileOperations(
        cert_dir=cert_dir,
        data_dir=data_dir,
        backup_dir=backup_dir,
        logs_dir=logs_dir,
    )
    return SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")


def test_load_settings_keeps_completed_setup_when_cloudflare_env_overrides_legacy_config(
    settings_manager, monkeypatch, caplog
):
    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "email": "admin@example.com",
                "domains": [],
                "auto_renew": True,
                "renewal_threshold_days": 30,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
                "api_bearer_token_hash": "hmac-sha256:abc123",
                "dns_providers": {
                    "cloudflare": {
                        "api_token": "old-token",
                    },
                },
                "users": {
                    "admin": {
                        "password_hash": "hash",
                        "role": "admin",
                        "enabled": True,
                    },
                },
            }
        )
    )
    monkeypatch.setenv("CLOUDFLARE_TOKEN", "env-token")

    with caplog.at_level("ERROR"):
        settings = settings_manager.load_settings()

    assert settings["setup_completed"] is True
    assert settings["users"]["admin"]["role"] == "admin"
    assert (
        settings["dns_providers"]["cloudflare"]["accounts"]["default"]["api_token"]
        == "env-token"
    )
    assert "api_token" not in settings["dns_providers"]["cloudflare"]
    assert not any("Error loading settings" in rec.message for rec in caplog.records)


def test_load_settings_migrates_legacy_dns_provider_shape_on_disk(settings_manager):
    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "email": "admin@example.com",
                "domains": [],
                "auto_renew": True,
                "renewal_threshold_days": 30,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
                "api_bearer_token_hash": "hmac-sha256:abc123",
                "dns_providers": {
                    "cloudflare": {
                        "api_token": "old-token",
                    },
                },
            }
        )
    )

    settings = settings_manager.load_settings()
    saved = json.loads(settings_manager.settings_file.read_text())

    assert settings["setup_completed"] is True
    assert saved["dns_providers"]["cloudflare"]["accounts"]["default"]["api_token"] == "old-token"
    assert saved["default_accounts"]["cloudflare"] == "default"
