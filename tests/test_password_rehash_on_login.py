"""Legacy password hashes must be upgraded on a successful login."""
import hashlib
import secrets

import pytest

from tests.test_auth_manager_coverage import _mk_settings_manager  # noqa: E402


def _mgr(initial):
    from modules.core.auth import AuthManager
    sm = _mk_settings_manager(initial)
    return AuthManager(sm), sm


def _legacy_prefixed(password):
    salt = secrets.token_hex(16)
    return f"sha256:{salt}:{hashlib.sha256((salt + password).encode()).hexdigest()}"


def _legacy_bare(password):
    salt = secrets.token_hex(16)
    return f"{salt}:{hashlib.sha256((salt + password).encode()).hexdigest()}"


@pytest.mark.parametrize("make_hash", [_legacy_prefixed, _legacy_bare],
                         ids=["sha256-prefixed", "bare-salt-hash"])
def test_legacy_hash_is_upgraded_on_successful_login(make_hash):
    settings = {"users": {"admin": {"password_hash": make_hash("pw"),
                                    "role": "admin", "enabled": True}}}
    mgr, _ = _mgr(settings)

    assert mgr.authenticate_user("admin", "pw") is not None

    stored = settings["users"]["admin"]["password_hash"]
    assert not stored.startswith("sha256:"), "still a legacy prefixed hash"
    assert stored.startswith(("$2", "scrypt:")), f"not upgraded: {stored[:20]}"
    # and the upgraded hash must still accept the same password
    assert mgr._verify_password("pw", stored) is True
    assert mgr._verify_password("wrong", stored) is False


def test_the_user_can_log_in_again_after_the_upgrade():
    settings = {"users": {"admin": {"password_hash": _legacy_prefixed("pw"),
                                    "role": "admin", "enabled": True}}}
    mgr, _ = _mgr(settings)
    assert mgr.authenticate_user("admin", "pw") is not None
    assert mgr.authenticate_user("admin", "pw") is not None
    assert mgr.authenticate_user("admin", "nope") is None


def test_a_modern_hash_is_left_alone():
    """No pointless rewrite: a bcrypt/scrypt hash must survive untouched."""
    from modules.core.auth import AuthManager
    settings = {"users": {}}
    mgr, _ = _mgr(settings)
    modern = mgr._hash_password("pw")
    settings["users"]["admin"] = {"password_hash": modern, "role": "admin",
                                  "enabled": True}
    assert mgr.authenticate_user("admin", "pw") is not None
    assert settings["users"]["admin"]["password_hash"] == modern


def test_a_failed_login_never_rewrites_anything():
    legacy = _legacy_prefixed("pw")
    settings = {"users": {"admin": {"password_hash": legacy, "role": "admin",
                                    "enabled": True}}}
    mgr, _ = _mgr(settings)
    assert mgr.authenticate_user("admin", "wrong") is None
    assert settings["users"]["admin"]["password_hash"] == legacy


def test_a_hashing_failure_does_not_lock_the_user_out(monkeypatch):
    """The credential was correct. A storage problem must not deny entry."""
    legacy = _legacy_prefixed("pw")
    settings = {"users": {"admin": {"password_hash": legacy, "role": "admin",
                                    "enabled": True}}}
    mgr, _ = _mgr(settings)
    monkeypatch.setattr(mgr, "_hash_password",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert mgr.authenticate_user("admin", "pw") is not None
    assert settings["users"]["admin"]["password_hash"] == legacy


def test_a_persist_failure_does_not_lock_the_user_out():
    legacy = _legacy_prefixed("pw")
    settings = {"users": {"admin": {"password_hash": legacy, "role": "admin",
                                    "enabled": True}}}
    mgr, sm = _mgr(settings)
    sm.update.side_effect = OSError("disk full")
    assert mgr.authenticate_user("admin", "pw") is not None


def test_a_user_deleted_during_the_login_is_not_resurrected():
    """The targeted mutation re-reads under the lock, so a racing delete wins."""
    settings = {"users": {"admin": {"password_hash": _legacy_prefixed("pw"),
                                    "role": "admin", "enabled": True}}}
    mgr, sm = _mgr(settings)

    def _update_after_delete(fn, label):
        settings["users"].pop("admin", None)   # concurrent delete lands first
        fn(settings)
        return True

    sm.update.side_effect = _update_after_delete
    assert mgr.authenticate_user("admin", "pw") is not None
    assert "admin" not in settings["users"], "deleted user was recreated"
