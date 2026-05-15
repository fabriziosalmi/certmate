"""
Regression test for issue #162: saving settings without re-sending
`api_bearer_token` must preserve the existing `api_bearer_token_hash`.

The UI bug reported in #162 was a client-side throw ("API Bearer Token
is required") that happened because post-2.4.8 settings.json only stores
the hashed token. The fix landed in static/js/settings.js, but this test
locks in the backend contract the UI fix relies on: a save that omits
`api_bearer_token` must not clobber the existing hash.
"""
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
    (backup_dir / "unified").mkdir()
    file_ops = FileOperations(
        cert_dir=cert_dir,
        data_dir=data_dir,
        backup_dir=backup_dir,
        logs_dir=logs_dir,
    )
    return SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")


def test_save_settings_without_bearer_field_preserves_hash(settings_manager):
    settings_manager.settings_file.write_text(
        json.dumps(
            {
                "email": "admin@example.com",
                "domains": [],
                "auto_renew": True,
                "setup_completed": True,
                "dns_provider": "cloudflare",
                "challenge_type": "dns-01",
                "api_bearer_token_hash": "hmac-sha256:abc123def456",
            }
        )
    )

    loaded = settings_manager.load_settings()
    assert loaded.get("api_bearer_token_hash") == "hmac-sha256:abc123def456"
    assert "api_bearer_token" not in loaded

    loaded.pop("api_bearer_token", None)
    loaded["default_ca"] = "letsencrypt"
    settings_manager.save_settings(loaded)

    on_disk = json.loads(settings_manager.settings_file.read_text())
    assert on_disk["api_bearer_token_hash"] == "hmac-sha256:abc123def456", (
        "Hash must be preserved across saves that omit the plaintext token field"
    )
    assert "api_bearer_token" not in on_disk
    assert on_disk["default_ca"] == "letsencrypt"
