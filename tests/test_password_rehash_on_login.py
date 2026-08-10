"""Legacy password hashes must be upgraded on a successful login."""
import pytest

from tests.test_auth_manager_coverage import _mk_settings_manager  # noqa: E402

# Fixed fixtures, not values recomputed with hashlib at test time.
#
# Recomputing them would mean the test derives the expected hash with the same
# algorithm the implementation uses, so a shared mistake would cancel out and
# the test would still pass. These are literal captures of the two pre-bcrypt
# formats for the password "pw", which is what an old settings.json actually
# contains.
#
# It also keeps `hashlib.sha256(<a password>)` out of the repository, which
# CodeQL flags as py/weak-sensitive-data-hashing — correctly, and unhelpfully,
# since constructing a weak hash is the only way to prove one gets replaced.
PASSWORD = "pw"
LEGACY_PREFIXED = (
    "sha256:a1b2c3d4e5f60718293a4b5c6d7e8f90"
    ":6b21c4387f25c7448b4154058bda0dfdd0a9c1b483da47af907a0fb91024f712"
)
LEGACY_BARE = (
    "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
    ":88bd7522cfa5e38ef717b8dd51f6190ae895b11240bd28e45954434d88fe6575"
)


def _mgr(initial):
    from modules.core.auth import AuthManager
    sm = _mk_settings_manager(initial)
    return AuthManager(sm), sm


def _legacy_prefixed(password=PASSWORD):
    assert password == PASSWORD, "the fixture is captured for this password only"
    return LEGACY_PREFIXED


def _legacy_bare(password=PASSWORD):
    assert password == PASSWORD, "the fixture is captured for this password only"
    return LEGACY_BARE


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
