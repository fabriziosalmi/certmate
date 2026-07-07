"""P1-4 (2026-07-02 audit): POST /api/keys passed role/allowed_domains straight
through with no clamp against the CALLER's own key. require_role('admin') gates
by role LEVEL only, so a scoped admin key could mint an unrestricted admin key
and escape its scope. The handler now forbids minting a key that exceeds the
creator's role or domain scope, and rejects domain-scoped admin keys (a false
containment, since admin bypasses domain scope on non-per-domain endpoints)."""
from unittest.mock import MagicMock

import pytest
from flask import Flask, request

from modules.core.auth import AuthManager
from modules.web.settings_routes import register_settings_routes

pytestmark = [pytest.mark.unit]


def _build_app(caller):
    sm = MagicMock()
    sm.load_settings.return_value = {}
    sm.update.return_value = True
    auth = AuthManager(sm)                       # real: domain_matches_scope + create_api_key
    auth.require_role = lambda role: (lambda fn: fn)   # passthrough the role gate
    app = Flask(__name__)
    app.config['TESTING'] = True
    register_settings_routes(app, {'audit': MagicMock()}, (lambda f: f), auth, sm, MagicMock())

    @app.before_request
    def _set_user():
        request.current_user = caller

    return app


def _post(caller, body):
    return _build_app(caller).test_client().post('/api/keys', json=body)


_SCOPED_OP = {'username': 'op', 'role': 'operator', 'allowed_domains': ['a.example.com']}
_ADMIN = {'username': 'root', 'role': 'admin', 'allowed_domains': None}


def test_scoped_caller_cannot_escalate_role():
    r = _post(_SCOPED_OP, {'name': 'esc', 'role': 'admin', 'allowed_domains': ['a.example.com']})
    assert r.status_code == 403
    assert 'role higher' in r.get_json()['error']


def test_scoped_caller_cannot_mint_unscoped_key():
    r = _post(_SCOPED_OP, {'name': 'wide', 'role': 'operator'})  # no allowed_domains
    assert r.status_code == 403
    assert 'unscoped' in r.get_json()['error']


def test_scoped_caller_cannot_grant_out_of_scope_domain():
    r = _post(_SCOPED_OP, {'name': 'other', 'role': 'operator', 'allowed_domains': ['b.example.com']})
    assert r.status_code == 403
    assert 'outside your own key scope' in r.get_json()['error']


def test_admin_key_cannot_be_domain_scoped():
    r = _post(_ADMIN, {'name': 'scoped-admin', 'role': 'admin', 'allowed_domains': ['a.example.com']})
    assert r.status_code == 400
    assert 'cannot be domain-scoped' in r.get_json()['error']


def test_unrestricted_admin_can_create_scoped_operator_key():
    r = _post(_ADMIN, {'name': 'scoped-op', 'role': 'operator', 'allowed_domains': ['a.example.com']})
    assert r.status_code == 201


def test_scoped_caller_can_mint_subset_within_wildcard():
    caller = {'username': 'op', 'role': 'operator', 'allowed_domains': ['*.example.com']}
    r = _post(caller, {'name': 'sub', 'role': 'operator', 'allowed_domains': ['foo.example.com']})
    assert r.status_code == 201


def test_scoped_caller_can_mint_equal_scope():
    r = _post(_SCOPED_OP, {'name': 'same', 'role': 'operator', 'allowed_domains': ['a.example.com']})
    assert r.status_code == 201
