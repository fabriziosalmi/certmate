"""Regression guards for AuthManager.is_setup_mode / operator-bearer-token
enforcement (2026-07-02 audit, P0-1).

A fresh, unconfigured install must stay in "setup mode" (unauthenticated
access → admin) so the operator can bootstrap. But the moment the operator
provides an API bearer token via API_BEARER_TOKEN(_FILE) — documented as
required on all endpoints — it must be enforced even when local auth is still
off. The auto-generated fallback token that settings.json always carries must
NOT trigger enforcement (the operator never sees it, so a fresh install would
be locked out)."""
from unittest.mock import MagicMock

import pytest

from modules.core.auth import AuthManager
from modules.core.utils import generate_secure_token

pytestmark = [pytest.mark.unit]


def _valid_token():
    # Guaranteed to pass validate_api_token by construction.
    return generate_secure_token(40)


def _auth(local_auth=False, users=None):
    sm = MagicMock()
    sm.load_settings.return_value = {
        'local_auth_enabled': local_auth,
        'users': users or {},
    }
    return AuthManager(sm)


def _clear_token_env(monkeypatch):
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    monkeypatch.delenv('API_BEARER_TOKEN_FILE', raising=False)


# --- _detect_operator_bearer_token ----------------------------------------

def test_detect_no_env_is_false(monkeypatch):
    _clear_token_env(monkeypatch)
    assert AuthManager._detect_operator_bearer_token() is False


def test_detect_valid_env_token_is_true(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv('API_BEARER_TOKEN', _valid_token())
    assert AuthManager._detect_operator_bearer_token() is True


def test_detect_invalid_env_token_is_false(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv('API_BEARER_TOKEN', 'short')  # < min length
    assert AuthManager._detect_operator_bearer_token() is False


def test_detect_empty_env_token_is_false(monkeypatch):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv('API_BEARER_TOKEN', '')
    assert AuthManager._detect_operator_bearer_token() is False


def test_detect_token_file_is_true(monkeypatch, tmp_path):
    _clear_token_env(monkeypatch)
    f = tmp_path / 'bearer.token'
    f.write_text(_valid_token() + '\n')
    monkeypatch.setenv('API_BEARER_TOKEN_FILE', str(f))
    assert AuthManager._detect_operator_bearer_token() is True


def test_detect_missing_token_file_is_false(monkeypatch, tmp_path):
    _clear_token_env(monkeypatch)
    monkeypatch.setenv('API_BEARER_TOKEN_FILE', str(tmp_path / 'does-not-exist'))
    assert AuthManager._detect_operator_bearer_token() is False


# --- is_setup_mode ----------------------------------------------------------

def test_setup_mode_true_on_fresh_install(monkeypatch):
    _clear_token_env(monkeypatch)
    assert _auth(local_auth=False, users={}).is_setup_mode() is True


def test_setup_mode_true_during_onboarding_before_first_user(monkeypatch):
    # Local auth flagged on but no user yet — bypass must persist so the first
    # admin can be created.
    _clear_token_env(monkeypatch)
    assert _auth(local_auth=True, users={}).is_setup_mode() is True


def test_setup_mode_false_when_local_auth_and_user_exist(monkeypatch):
    _clear_token_env(monkeypatch)
    a = _auth(local_auth=True, users={'admin': {'role': 'admin'}})
    assert a.is_setup_mode() is False


def test_operator_bearer_token_forces_enforcement(monkeypatch):
    """The fix: an operator-provided token disables the bypass even with local
    auth off and no users — so the token an API-only operator configured is
    actually required, instead of the instance being world-open."""
    _clear_token_env(monkeypatch)
    monkeypatch.setenv('API_BEARER_TOKEN', _valid_token())
    a = _auth(local_auth=False, users={})
    assert a.has_operator_bearer_token() is True
    assert a.is_setup_mode() is False


def test_generated_token_does_not_force_enforcement(monkeypatch):
    """A fresh install carries an auto-generated token in settings but has NO
    operator env var; it must stay in setup mode or onboarding breaks."""
    _clear_token_env(monkeypatch)
    a = _auth(local_auth=False, users={})
    assert a.has_operator_bearer_token() is False
    assert a.is_setup_mode() is True
