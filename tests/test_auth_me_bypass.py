"""
Test for the audit punch-list M2 item: /api/auth/me must report the
caller's role even when local auth is bypassed (no users yet, or
local_auth_enabled=False), so the dashboard UI can hide controls the
caller would 403 on.

Old behavior: returned 401 in the bypass case, so the UI couldn't tell
whether the caller was an admin (during onboarding) or a viewer that
needs to log in. Now returns 200 with auth_mode='bypass' during the
setup window.
"""

from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.web.auth_routes import register_auth_routes


pytestmark = [pytest.mark.unit]


def _passthrough_decorator(min_role):
    """Mimic auth_manager.require_role(...) — returns a decorator that
    leaves the wrapped view alone, so tests can hit /api/auth/me without
    a real session."""
    def deco(fn):
        return fn
    return deco


def _build_app(auth_manager_mock):
    app = Flask(__name__)
    app.secret_key = 'test'
    auth_manager_mock.require_role = MagicMock(side_effect=_passthrough_decorator)
    register_auth_routes(
        app,
        managers={},
        require_web_auth=lambda f: f,
        auth_manager=auth_manager_mock,
        _check_login_rate_limit=lambda *a, **kw: True,
        _record_login_attempt=lambda *a, **kw: None,
    )
    return app


def test_me_returns_admin_when_auth_disabled():
    auth_manager = MagicMock()
    auth_manager.is_local_auth_enabled.return_value = False
    auth_manager.has_any_users.return_value = False
    app = _build_app(auth_manager)
    client = app.test_client()

    r = client.get('/api/auth/me')
    assert r.status_code == 200
    body = r.get_json()
    assert body['user']['role'] == 'admin'
    assert body['auth_mode'] == 'bypass'


def test_me_returns_admin_when_no_users_yet():
    """Onboarding case: auth is technically enabled in settings but no
    user has been created — the UI is in admin mode until first user
    creation."""
    auth_manager = MagicMock()
    auth_manager.is_local_auth_enabled.return_value = True
    auth_manager.has_any_users.return_value = False
    app = _build_app(auth_manager)
    client = app.test_client()

    r = client.get('/api/auth/me')
    assert r.status_code == 200
    body = r.get_json()
    assert body['user']['role'] == 'admin'
    assert body['auth_mode'] == 'bypass'


def test_me_returns_401_when_authed_with_no_session():
    auth_manager = MagicMock()
    auth_manager.is_local_auth_enabled.return_value = True
    auth_manager.has_any_users.return_value = True
    auth_manager.validate_session.return_value = None
    app = _build_app(auth_manager)
    client = app.test_client()

    r = client.get('/api/auth/me')
    assert r.status_code == 401


def test_me_returns_session_user_when_authed():
    auth_manager = MagicMock()
    auth_manager.is_local_auth_enabled.return_value = True
    auth_manager.has_any_users.return_value = True
    auth_manager.validate_session.return_value = {
        'username': 'alice', 'role': 'operator'
    }
    app = _build_app(auth_manager)
    client = app.test_client()

    client.set_cookie('certmate_session', 'abc')
    r = client.get('/api/auth/me')
    assert r.status_code == 200
    body = r.get_json()
    assert body['user']['username'] == 'alice'
    assert body['user']['role'] == 'operator'
    assert body['auth_mode'] == 'session'
