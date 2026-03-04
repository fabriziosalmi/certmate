"""
Regression test for issue #76 — saving settings must not fail when the
masked api_bearer_token placeholder '********' is present.

These are fast unit tests that do NOT require Docker.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_env(tmp_path):
    """Create a minimal SettingsManager with a temp settings file,
    bypassing the compat layer so writes go to the temp directory."""
    from modules.core.file_operations import FileOperations
    from modules.core.settings import SettingsManager

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    cert_dir = tmp_path / "certificates"
    cert_dir.mkdir()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()

    file_ops = FileOperations(
        data_dir=data_dir,
        cert_dir=cert_dir,
        backup_dir=backup_dir,
        logs_dir=logs_dir,
    )
    settings_file = data_dir / "settings.json"
    mgr = SettingsManager(file_ops, settings_file)

    # Bypass the compat wrappers so we use our local file_ops directly
    mgr._safe_file_write_compat = file_ops.safe_file_write
    mgr._safe_file_read_compat = file_ops.safe_file_read
    mgr._settings_file_exists_compat = lambda: settings_file.exists()
    mgr._save_settings_compat = lambda s, r="auto": mgr.save_settings(s, r)

    return mgr, settings_file


def _seed(settings_file):
    """Write a valid baseline settings file and return the dict."""
    from modules.core.utils import generate_secure_token
    base = {
        "email": "user@example.com",
        "dns_provider": "cloudflare",
        "domains": [],
        "auto_renew": True,
        "api_bearer_token": generate_secure_token(),
        "setup_completed": True,
    }
    settings_file.write_text(json.dumps(base))
    return base


class TestMaskedTokenSave:
    """Issue #76: save_settings must handle masked api_bearer_token."""

    def test_save_with_masked_token_succeeds(self, settings_env):
        """Saving settings that contain '********' must not fail."""
        mgr, settings_file = settings_env
        initial = _seed(settings_file)

        updated = dict(initial)
        updated["api_bearer_token"] = "********"
        result = mgr.save_settings(updated, "test")
        assert result is True, "save_settings should succeed with masked token"

        saved = json.loads(settings_file.read_text())
        assert saved.get("api_bearer_token") != "********", \
            "Masked placeholder must not be persisted"

    def test_save_with_empty_token_succeeds(self, settings_env):
        """Saving settings with an empty api_bearer_token must not fail."""
        mgr, settings_file = settings_env
        _seed(settings_file)

        updated = json.loads(settings_file.read_text())
        updated["api_bearer_token"] = ""
        result = mgr.save_settings(updated, "test")
        assert result is True, "save_settings should succeed with empty token"

    def test_save_with_valid_token_still_validates(self, settings_env):
        """A real, valid token must still pass through validation."""
        mgr, settings_file = settings_env
        initial = _seed(settings_file)
        real_token = initial["api_bearer_token"]

        result = mgr.save_settings(dict(initial), "test")
        assert result is True

        saved = json.loads(settings_file.read_text())
        assert saved.get("api_bearer_token") == real_token

    def test_save_with_invalid_token_still_rejected(self, settings_env):
        """A truly invalid (short, non-masked) token must still be rejected."""
        mgr, settings_file = settings_env
        _seed(settings_file)

        bad_settings = json.loads(settings_file.read_text())
        bad_settings["api_bearer_token"] = "tooshort"
        result = mgr.save_settings(bad_settings, "test")
        assert result is False, "Short invalid tokens must still be rejected"
