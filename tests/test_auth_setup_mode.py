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


def _auth(local_auth=False, users=None, oidc=None):
    sm = MagicMock()
    settings = {
        'local_auth_enabled': local_auth,
        'users': users or {},
    }
    if oidc is not None:
        settings['oidc'] = oidc
    sm.load_settings.return_value = settings
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


# --- OIDC-only deployments --------------------------------------------------

_FULL_OIDC = {
    'enabled': True,
    'issuer_url': 'https://idp.example.com',
    'client_id': 'certmate',
}


def test_setup_mode_false_when_oidc_fully_configured(monkeypatch):
    """The fix: an SSO-only deployment (OIDC enabled + issuer + client_id, no
    bearer token, local auth off) must NOT stay world-open. Before the fix
    is_setup_mode() ignored OIDC and returned True forever, serving every
    gated endpoint to anonymous callers as admin."""
    _clear_token_env(monkeypatch)
    a = _auth(local_auth=False, users={}, oidc=dict(_FULL_OIDC))
    assert a.is_setup_mode() is False


def test_setup_mode_false_oidc_even_after_jit_users(monkeypatch):
    """JIT-provisioned OIDC users never flip local_auth_enabled, so the
    local-auth branch stays False; OIDC being configured is what closes it."""
    _clear_token_env(monkeypatch)
    a = _auth(local_auth=False,
              users={'alice': {'role': 'admin', 'oidc_subject': 'sub-1'}},
              oidc=dict(_FULL_OIDC))
    assert a.is_setup_mode() is False


def test_setup_mode_true_when_oidc_enabled_but_incomplete(monkeypatch):
    """enabled=True but issuer/client_id blank is NOT a usable credential, so
    onboarding must still work (mirrors OIDCManager.is_enabled semantics) —
    the operator can still reach the box to finish configuring it."""
    _clear_token_env(monkeypatch)
    for partial in ({'enabled': True, 'issuer_url': '', 'client_id': 'certmate'},
                    {'enabled': True, 'issuer_url': 'https://idp', 'client_id': ''},
                    {'enabled': False, 'issuer_url': 'https://idp', 'client_id': 'certmate'}):
        a = _auth(local_auth=False, users={}, oidc=partial)
        assert a.is_setup_mode() is True, partial
