"""Setup mode must be a door that only closes.

`is_setup_mode()` is not a mild state. `_authenticate_request` returns
`{'username': 'setup_user', 'role': 'admin'}` for a caller with no credential
at all, which is enough to read /api/settings, mint API keys, create admin
users, and download private keys — `resources.py` gates the private-key
download on the operator role, and setup_user is admin.

It exists so a fresh install can be bootstrapped, and it closes as soon as the
operator configures any credential. What nothing checked was the way back.

v2.21.4 added the OIDC branch to `is_setup_mode()` to CLOSE a real hole: an
SSO-only deployment has no bearer token and never gets `local_auth_enabled`
set, because OIDC JIT provisioning does not flip it, so such a box sat in setup
mode — world-open — forever. The fix was right. Its side effect was that
closure now depends on a checkbox: unchecking "Enable OIDC/SSO" in the settings
UI put the whole instance back into anonymous-admin, with no guard on the route
and no warning next to the toggle (the "Authentication is disabled" banner
lives on the separate Users tab).

`delete_user` already refuses to remove the last admin, so that third way in is
closed. These tests pin the other two, and the two shapes that must keep
working: a fresh install still has to be configurable, and an instance with
another credential must still be free to turn SSO off.
"""
from __future__ import annotations

import pytest
from flask import Flask

from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.oidc import OIDCManager
from modules.core.settings import SettingsManager
from modules.web.auth_routes import register_auth_routes
from modules.web.oidc_routes import register_oidc_routes

pytestmark = [pytest.mark.unit]

CONFIGURED_OIDC = {
    'enabled': True,
    'provider_name': 'TestIdP',
    'issuer_url': 'https://idp.example.com',
    'client_id': 'cm-test',
    'client_secret': 'shh',
}


def _allow_all(_min_role):
    def decorator(fn):
        return fn
    return decorator


def _build(tmp_path, *, oidc=None, local_auth=False, users=True):
    dirs = {name: tmp_path / name for name in
            ("certificates", "data", "backups", "logs")}
    for d in dirs.values():
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=dirs["certificates"], data_dir=dirs["data"],
        backup_dir=dirs["backups"], logs_dir=dirs["logs"])
    settings_manager = SettingsManager(
        file_ops=file_ops, settings_file=dirs["data"] / "settings.json")
    settings_manager.load_settings()

    auth_manager = AuthManager(settings_manager)
    auth_manager.set_hmac_key('test-secret-for-hmac')
    auth_manager.require_role = _allow_all       # type: ignore[assignment]
    # Deterministic: the env of the machine running the suite must not decide
    # whether this instance has an operator bearer token.
    auth_manager._operator_bearer_token = False

    if users:
        auth_manager.create_user('admin-user', 'pw123abc', role='admin')

    def apply(settings):
        settings['local_auth_enabled'] = local_auth
        settings['setup_completed'] = True
        if oidc is not None:
            settings['oidc'] = dict(oidc)

    settings_manager.update(apply, 'test_setup')

    oidc_manager = OIDCManager(settings_manager, auth_manager)
    app = Flask(__name__)
    app.config['TESTING'] = True
    app.secret_key = 'test'
    managers = {'settings': settings_manager, 'auth': auth_manager,
                'oidc': oidc_manager, 'audit': None}
    register_oidc_routes(app, managers, auth_manager, oidc_manager,
                         lambda *a, **k: (True, None),
                         lambda *a, **k: None)
    register_auth_routes(app, managers, _allow_all, auth_manager,
                         lambda *a, **k: (True, None),
                         lambda *a, **k: None)
    return app, auth_manager


# --------------------------------------------------------------------------
# The transitions that must be refused
# --------------------------------------------------------------------------

def test_sso_only_instance_refuses_to_turn_off_its_only_credential(tmp_path):
    app, auth = _build(tmp_path, oidc=CONFIGURED_OIDC, local_auth=False)
    assert auth.is_setup_mode() is False, "fixture is wrong: already open"

    response = app.test_client().post('/api/auth/oidc/settings',
                                      json={**CONFIGURED_OIDC, 'enabled': False})

    assert response.status_code == 409, (
        f"unchecking Enable OIDC/SSO returned {response.status_code}; on an "
        f"SSO-only box that hands every endpoint to anonymous callers as admin"
    )
    assert auth.is_setup_mode() is False, (
        "the instance is in setup mode after the refusal — the write happened "
        "anyway and the status code was decoration"
    )


def test_clearing_the_issuer_url_cannot_open_the_door_either(tmp_path):
    """The other half of _is_oidc_configured(), closed by a different gate.

    Un-configuring OIDC would open the instance exactly like un-checking it,
    but a payload that clears issuer_url while `enabled` stays true is invalid:
    _validate_config rejects it with a 400 and NOTHING is written. The setup
    guard deliberately does not fire here, because "client_id is required"
    tells the admin what they got wrong and a security refusal does not.

    What this test pins is the outcome, not which gate produced it: the
    instance must still be closed afterwards.
    """
    app, auth = _build(tmp_path, oidc=CONFIGURED_OIDC, local_auth=False)

    response = app.test_client().post('/api/auth/oidc/settings',
                                      json={**CONFIGURED_OIDC, 'issuer_url': ''})

    assert response.status_code == 400, (
        f"got {response.status_code}: expected the config validator to refuse "
        f"an enabled OIDC block with no issuer_url"
    )
    assert auth.is_setup_mode() is False, (
        "an invalid OIDC payload was persisted anyway and opened the instance"
    )


def test_local_only_instance_refuses_to_turn_off_local_auth(tmp_path):
    app, auth = _build(tmp_path, oidc=None, local_auth=True)
    assert auth.is_setup_mode() is False

    response = app.test_client().post('/api/auth/config',
                                      json={'local_auth_enabled': False})

    assert response.status_code == 409, (
        f"got {response.status_code}: POST /api/auth/config guarded only the "
        f"ENABLE direction ('Create admin first'); disabling was unguarded"
    )
    assert auth.is_setup_mode() is False


# --------------------------------------------------------------------------
# The shapes that must keep working
# --------------------------------------------------------------------------

def test_sso_can_be_turned_off_when_local_auth_still_holds_the_door(tmp_path):
    app, auth = _build(tmp_path, oidc=CONFIGURED_OIDC, local_auth=True)

    response = app.test_client().post('/api/auth/oidc/settings',
                                      json={**CONFIGURED_OIDC, 'enabled': False})

    assert response.status_code == 200, (
        f"got {response.status_code}: an admin with local auth configured must "
        f"still be free to stop using SSO — a guard that blocks this is a "
        f"guard nobody can live with"
    )
    assert auth.is_setup_mode() is False


def test_a_bearer_token_makes_the_toggle_inert(tmp_path):
    """API_BEARER_TOKEN short-circuits is_setup_mode, so nothing to protect."""
    app, auth = _build(tmp_path, oidc=CONFIGURED_OIDC, local_auth=False)
    auth._operator_bearer_token = True

    response = app.test_client().post('/api/auth/oidc/settings',
                                      json={**CONFIGURED_OIDC, 'enabled': False})

    assert response.status_code == 200, (
        f"got {response.status_code}: with a bearer token configured the "
        f"instance never enters setup mode, so refusing is pure obstruction"
    )


def test_a_fresh_install_can_still_be_configured(tmp_path):
    """Already in setup mode: the guard is about not regressing, not about
    freezing a box that has not been secured yet."""
    app, auth = _build(tmp_path, oidc=None, local_auth=False, users=False)
    assert auth.is_setup_mode() is True

    response = app.test_client().post('/api/auth/config',
                                      json={'local_auth_enabled': False})

    assert response.status_code != 409, (
        "a brand-new install cannot be configured because the guard refuses "
        "to leave a state it is already in"
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
