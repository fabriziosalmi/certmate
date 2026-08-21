"""Can a backup actually bring this instance back?

Nobody had asked. There are tests for creating a backup, for listing them, for
masking secrets inside one, for the restore endpoint's authorization and for
its zip-bomb limits. There was no test that took a working instance, destroyed
it, restored it, and then tried to log in — so nothing noticed that the answer
was no.

Every AUTOMATIC backup is masked. `save_settings` calls
`create_unified_backup(settings, reason)` and `include_secrets` defaults to
False, which writes the mask sentinel in place of every credential. That
default is correct: a leaked backup must not also be a credential dump. What
was wrong is that every restore path treated those archives as authoritative:

  * `_try_restore_from_backup` installed the newest one as live settings when
    settings.json could not be parsed, producing an instance whose every
    password hash, bearer token, API key hash, OIDC client secret and DNS
    credential was the literal sentinel — and `setup_completed` was still True,
    so the setup wizard did not reopen. The operator was locked out, and the
    log said "Settings restored successfully from backup".
  * the pre-restore rollback archive was masked too, so the safety net under a
    manual restore could not recover a single credential.
  * and every successful login wrote one of these archives and then pruned to
    MAX_BACKUPS_PER_TYPE, so fifty logins evicted every older restore point.

Together: restore points created constantly by routine noise, evicting the real
ones, none of which could restore. This file is the round trip that makes that
combination impossible to reintroduce.
"""
from __future__ import annotations

import json
import zipfile

import pytest

from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.settings import (
    SECRET_MASK_SENTINEL,
    SettingsManager,
    SettingsUnreadableError,
)

pytestmark = [pytest.mark.unit]

PASSWORD = "correct horse battery staple"


@pytest.fixture
def instance(tmp_path):
    """A configured CertMate: an admin who can log in, and a DNS credential."""
    dirs = {name: tmp_path / name for name in
            ("certificates", "data", "backups", "logs")}
    for d in dirs.values():
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=dirs["certificates"], data_dir=dirs["data"],
        backup_dir=dirs["backups"], logs_dir=dirs["logs"],
    )
    settings_manager = SettingsManager(
        file_ops=file_ops, settings_file=dirs["data"] / "settings.json")
    auth = AuthManager(settings_manager)
    settings_manager.save_settings({
        'email': 'ops@example.com',
        'setup_completed': True,
        'local_auth_enabled': True,
        'dns_provider': 'cloudflare',
        'dns_providers': {'cloudflare': {'api_token': 'cf-real-token-value'}},
        'users': {'admin': {
            'password_hash': auth._hash_password(PASSWORD),
            'role': 'admin',
        }},
    })
    # Two things have to happen before a test can measure anything.
    # The first save writes no backup — save_settings only backs up a file
    # that already exists — and the first load runs the DNS multi-account
    # migration, which saves again and legitimately does write one. Both are
    # one-time events; get them out of the way so a test that counts backups
    # is counting what it thinks it is.
    settings_manager.load_settings()
    settings_manager.save_settings(settings_manager.load_settings())
    return type('Instance', (), {
        'settings': settings_manager, 'file_ops': file_ops,
        'auth': auth, 'data': dirs["data"], 'backups': dirs["backups"],
    })


def _unified(instance):
    return sorted((instance.backups / "unified").glob("backup_*"))


def _credential_survived(settings):
    """The token, wherever it ended up.

    `dns_providers` is rewritten into the multi-account shape by the migration
    that runs inside load_settings, so asserting on a fixed key path tests the
    migration rather than the round trip. What matters is that the real secret
    came back instead of the mask sentinel.
    """
    return 'cf-real-token-value' in json.dumps(settings)


def _can_log_in(instance):
    users = instance.settings.load_settings().get('users', {})
    record = users.get('admin') or {}
    return instance.auth._verify_password(PASSWORD, record.get('password_hash', ''))


# --------------------------------------------------------------------------
# The round trip itself
# --------------------------------------------------------------------------

def test_a_plaintext_backup_brings_the_instance_back(instance):
    """Configure, back up, destroy, restore, log in."""
    assert _can_log_in(instance), "fixture is wrong: the admin cannot log in"

    filename = instance.file_ops.create_unified_backup(
        instance.settings.load_settings(), "manual", include_secrets=True)
    assert filename, "the backup was not written"

    (instance.data / "settings.json").unlink()

    assert instance.file_ops.restore_unified_backup(
        str(instance.backups / "unified" / filename))

    assert _can_log_in(instance), (
        "restored, and the admin still cannot log in — the backup did not "
        "carry a usable password hash"
    )
    assert _credential_survived(instance.settings.load_settings()), (
        "the DNS credential did not survive the round trip, so every renewal "
        "after this restore would fail at the provider"
    )


def test_an_automatic_backup_cannot_bring_it_back_and_says_so(instance):
    """The masked archive must be refused, not installed as credentials."""
    # save_settings has already written masked archives for the fixture.
    automatic = _unified(instance)
    assert automatic, "expected save_settings to have left automatic backups"
    with zipfile.ZipFile(automatic[-1]) as zf:
        metadata = json.loads(zf.read("backup_metadata.json").decode("utf-8"))
        assert metadata["secrets_masked"] is True, (
            "this test is built on the assumption that automatic backups are "
            "masked; if that changed, the whole file needs rethinking"
        )

    # settings.json becomes unparseable — a hand-edit typo, a truncation.
    (instance.data / "settings.json").write_text("{ this is not json", encoding="utf-8")

    with pytest.raises(SettingsUnreadableError) as raised:
        instance.settings.load_settings(use_cache=False)

    assert "include_secrets" in str(raised.value), (
        "the error must tell the operator how to make a backup that would "
        "have worked, or it is just a crash"
    )
    # And it must NOT have destroyed the file a text editor could repair.
    assert (instance.data / "settings.json").read_text(encoding="utf-8") == "{ this is not json", (
        "the corrupt settings.json was overwritten — that was the operator's "
        "only copy of their real configuration"
    )


def test_a_masked_backup_is_never_installed_as_credentials(instance):
    """The specific outcome that locked operators out."""
    (instance.data / "settings.json").write_text("{ broken", encoding="utf-8")
    try:
        settings = instance.settings.load_settings(use_cache=False)
    except SettingsUnreadableError:
        return                      # refused outright: the correct outcome
    blob = json.dumps(settings)
    assert SECRET_MASK_SENTINEL not in blob, (
        "settings were restored from a masked backup, so every credential is "
        "now the literal mask sentinel and no login, token or renewal works"
    )


def test_a_plaintext_backup_is_preferred_over_a_newer_masked_one(instance):
    """Recency must not beat usability when picking a restore source."""
    instance.file_ops.create_unified_backup(
        instance.settings.load_settings(), "manual", include_secrets=True)
    # Now write a NEWER masked one, the way any settings save would.
    instance.settings.save_settings(instance.settings.load_settings())

    (instance.data / "settings.json").write_text("nonsense", encoding="utf-8")
    settings = instance.settings.load_settings(use_cache=False)

    assert _credential_survived(settings), (
        "the newest backup won even though it could not restore; the restore "
        "must pick the newest backup that CAN"
    )


# --------------------------------------------------------------------------
# Restore points must survive routine noise
# --------------------------------------------------------------------------

def test_logging_in_does_not_consume_restore_points(instance):
    """A login is not a configuration change and must not evict a backup."""
    before = len(_unified(instance))

    for _ in range(5):
        assert instance.auth.authenticate_user('admin', PASSWORD), (
            "the fixture user cannot authenticate; the rest of this test is "
            "meaningless"
        )

    after = len(_unified(instance))
    assert after == before, (
        f"{after - before} backup(s) were written by 5 logins. Retention is "
        f"MAX_BACKUPS_PER_TYPE, so login traffic alone evicts every restore "
        f"point an operator actually wanted."
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])


def test_an_empty_settings_file_still_boots_with_the_first_time_template(tmp_path):
    """The refusal to overwrite exists to protect content a text editor could
    repair. A zero-byte settings.json has nothing to lose: a fresh boot with
    the first-time template is the pre-existing behaviour and stays."""
    from modules.core.file_operations import FileOperations
    from modules.core.settings import SettingsManager
    dirs = [tmp_path / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir()
    settings_file = dirs[1] / "settings.json"
    settings_file.write_text("")
    sm = SettingsManager(file_ops=FileOperations(*dirs), settings_file=settings_file)
    settings = sm.load_settings()
    assert isinstance(settings, dict) and 'dns_providers' in settings
    assert settings_file.stat().st_size > 0


def test_a_corrupt_settings_file_with_no_usable_backup_refuses_to_boot(tmp_path):
    from modules.core.file_operations import FileOperations
    from modules.core.settings import SettingsManager, SettingsUnreadableError
    dirs = [tmp_path / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir()
    settings_file = dirs[1] / "settings.json"
    settings_file.write_text('{"users": {"admin": {"password_hash": "$2b$12$real"}, "domains": [')
    sm = SettingsManager(file_ops=FileOperations(*dirs), settings_file=settings_file)
    import pytest as _pytest
    with _pytest.raises(SettingsUnreadableError):
        sm.load_settings()
    assert 'password_hash' in settings_file.read_text(), "the operator's only copy must survive"
