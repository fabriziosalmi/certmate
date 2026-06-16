"""Regression: webhook secrets survive a GENERIC settings round-trip.

notifications is a _DEEP_MERGE_SETTINGS_KEYS subtree, but its secrets live in a
list-of-dicts (channels.webhooks). _deep_merge_dict replaces lists wholesale and
_strip_masked_values only walks dicts, so a GET (which masks the secret to
'********') followed by a POST of the whole settings blob through the GENERIC
/api/settings path persisted '********' over the real secret. The dedicated
/api/notifications/config route restored list secrets; the generic path did not.

atomic_update now restores masked list secrets generically for every deep-merge
key, so both paths behave the same.
"""
import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager, SECRET_MASK_SENTINEL as MASK

pytestmark = [pytest.mark.unit]


@pytest.fixture
def sm(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(cert_dir=cert_dir, data_dir=data_dir,
                              backup_dir=backup_dir, logs_dir=logs_dir)
    return SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")


def _seed(sm, secret="REAL-HMAC-SECRET", token="REAL-BOT-TOKEN"):
    assert sm.atomic_update({
        "notifications": {"channels": {"webhooks": [
            {"name": "wh", "type": "generic", "url": "https://h", "secret": secret},
            {"name": "tg", "type": "telegram", "url": "", "token": token, "chat_id": "1"},
        ]}}
    }) is True


def _webhooks_by_name(sm):
    whs = sm.load_settings()["notifications"]["channels"]["webhooks"]
    return {w["name"]: w for w in whs}


def test_masked_list_secret_not_clobbered_on_generic_roundtrip(sm):
    _seed(sm)
    # GET masks the secrets; the whole blob is POSTed back via the generic path.
    assert sm.atomic_update({
        "notifications": {"channels": {"webhooks": [
            {"name": "wh", "type": "generic", "url": "https://h", "secret": MASK},
            {"name": "tg", "type": "telegram", "url": "", "token": MASK, "chat_id": "1"},
        ]}}
    }) is True

    by_name = _webhooks_by_name(sm)
    assert by_name["wh"]["secret"] == "REAL-HMAC-SECRET"   # not '********'
    assert by_name["tg"]["token"] == "REAL-BOT-TOKEN"


def test_retyped_secret_still_overrides(sm):
    _seed(sm)
    assert sm.atomic_update({
        "notifications": {"channels": {"webhooks": [
            {"name": "wh", "type": "generic", "url": "https://h", "secret": "NEW-SECRET"},
            {"name": "tg", "type": "telegram", "url": "", "token": MASK, "chat_id": "1"},
        ]}}
    }) is True

    by_name = _webhooks_by_name(sm)
    assert by_name["wh"]["secret"] == "NEW-SECRET"
    assert by_name["tg"]["token"] == "REAL-BOT-TOKEN"
