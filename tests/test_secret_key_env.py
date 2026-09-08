"""
Unit tests for _secret_key_from_env_or_generate() in factory.py.

Covers the three-step resolution order:
1. SECRET_KEY_FILE (mutually exclusive with SECRET_KEY; a read error or an
   empty file refuses to start rather than generating a key)
2. SECRET_KEY (skipped when SECRET_KEY_FILE is set)
3. Persisted generated key in data_dir/.secret_key
"""

import pytest

from modules.core.factory import (
    SecretKeyUnreadableError, _secret_key_from_env_or_generate,
)

pytestmark = [pytest.mark.unit]

GOOD_KEY = "a" * 32  # arbitrary non-empty, non-insecure string


# ---------------------------------------------------------------------------
# SECRET_KEY_FILE tests
# ---------------------------------------------------------------------------

def test_file_var_used_when_set_and_valid(monkeypatch, tmp_path):
    key_file = tmp_path / "secret.txt"
    key_file.write_text(GOOD_KEY)
    monkeypatch.setenv("SECRET_KEY_FILE", str(key_file))
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert _secret_key_from_env_or_generate(tmp_path) == GOOD_KEY


def test_file_var_takes_precedence_over_env_var(monkeypatch, tmp_path):
    key_file = tmp_path / "secret.txt"
    key_file.write_text(GOOD_KEY)
    monkeypatch.setenv("SECRET_KEY_FILE", str(key_file))
    monkeypatch.setenv("SECRET_KEY", "Z" * 32)  # also valid but must be ignored
    assert _secret_key_from_env_or_generate(tmp_path) == GOOD_KEY


def test_file_read_error_refuses_rather_than_consulting_secret_key(monkeypatch,
                                                                   tmp_path):
    """A file failure must not fall through to SECRET_KEY.

    This test used to assert that a fresh key was generated. The property it
    was protecting is the one asserted here — the two variables are mutually
    exclusive, and a broken file must not be silently answered by a variable
    the operator forgot was set. Generating was how that was achieved, not
    what was wanted: it signed out every user, did it again on every restart,
    and left sessions signed by a key nobody chose. Refusing to start keeps
    the mutual exclusivity and drops the silent rotation. See
    tests/test_secret_key_file_failures_fail_closed.py.
    """
    monkeypatch.setenv("SECRET_KEY_FILE", "/nonexistent/path/secret.txt")
    monkeypatch.setenv("SECRET_KEY", "Z" * 32)  # must never be consulted
    with pytest.raises(SecretKeyUnreadableError) as caught:
        _secret_key_from_env_or_generate(tmp_path)
    assert "Z" * 32 not in str(caught.value)
    assert "SECRET_KEY_FILE" in str(caught.value)


def test_file_empty_refuses_rather_than_consulting_secret_key(monkeypatch,
                                                              tmp_path):
    """Same contract for an empty file: a Kubernetes secret that exists but
    has not been populated reads as empty, not as missing."""
    key_file = tmp_path / "secret.txt"
    key_file.write_text("   \n")  # whitespace only → strips to empty
    monkeypatch.setenv("SECRET_KEY_FILE", str(key_file))
    monkeypatch.setenv("SECRET_KEY", "Z" * 32)  # must never be consulted
    with pytest.raises(SecretKeyUnreadableError) as caught:
        _secret_key_from_env_or_generate(tmp_path)
    assert "empty" in str(caught.value)


def test_file_strips_whitespace(monkeypatch, tmp_path):
    key_file = tmp_path / "secret.txt"
    key_file.write_text(f"  {GOOD_KEY}\n")
    monkeypatch.setenv("SECRET_KEY_FILE", str(key_file))
    monkeypatch.delenv("SECRET_KEY", raising=False)
    assert _secret_key_from_env_or_generate(tmp_path) == GOOD_KEY


def test_file_var_absent_falls_through_to_env_var(monkeypatch, tmp_path):
    monkeypatch.delenv("SECRET_KEY_FILE", raising=False)
    monkeypatch.setenv("SECRET_KEY", GOOD_KEY)
    assert _secret_key_from_env_or_generate(tmp_path) == GOOD_KEY


# ---------------------------------------------------------------------------
# SECRET_KEY env var tests
# ---------------------------------------------------------------------------

def test_env_var_insecure_default_ignored(monkeypatch, tmp_path, caplog):
    monkeypatch.delenv("SECRET_KEY_FILE", raising=False)
    monkeypatch.setenv("SECRET_KEY", "change-me")
    with caplog.at_level("WARNING"):
        key = _secret_key_from_env_or_generate(tmp_path)
    assert key != "change-me"
    assert any("insecure default" in rec.message for rec in caplog.records)


def test_env_var_missing_generates_and_persists(monkeypatch, tmp_path):
    monkeypatch.delenv("SECRET_KEY_FILE", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    key = _secret_key_from_env_or_generate(tmp_path)
    assert len(key) > 0
    assert (tmp_path / ".secret_key").exists()
    assert (tmp_path / ".secret_key").read_text().strip() == key


def test_persisted_key_reused_on_second_call(monkeypatch, tmp_path):
    """Simulates a restart — second call reads the persisted file."""
    monkeypatch.delenv("SECRET_KEY_FILE", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    key1 = _secret_key_from_env_or_generate(tmp_path)
    key2 = _secret_key_from_env_or_generate(tmp_path)
    assert key1 == key2, "Key must be stable across restarts via .secret_key file"
