"""#587 — running without authentication on purpose.

The one-way-door guard (#581) refuses to turn off the last credential because
the resulting state answers every endpoint to an anonymous caller as admin.
That closes the accidental case. An operator who fronts CertMate with a proxy
that authenticates for them is the deliberate case, and it is represented:
``{"local_auth_enabled": false, "confirm_unauthenticated": true}`` goes
through, and the audit entry says it was on purpose and by whom.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager
from modules.web.auth_routes import register_auth_routes

pytestmark = [pytest.mark.unit]


def _allow_all(_min_role):
    def decorator(fn):
        return fn
    return decorator


def _build(tmp_path, audit):
    """A local-auth-only instance: one admin, local auth on, no SSO, no token."""
    dirs = [tmp_path / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir()
    sm = SettingsManager(file_ops=FileOperations(*dirs), settings_file=dirs[1] / "settings.json")
    sm.load_settings()
    am = AuthManager(sm)
    am.set_hmac_key("k")
    am.require_role = _allow_all        # the route's role check is not what is under test
    am._operator_bearer_token = False   # no API_BEARER_TOKEN in this process
    am.create_user("admin", "Password123!", role="admin")
    am.enable_local_auth(True)
    app = Flask(__name__)
    app.secret_key = "t"
    register_auth_routes(app, {'settings': sm, 'auth': am, 'audit': audit},
                         _allow_all, am, lambda *a, **k: True, lambda *a, **k: None)
    return app, am


def test_without_the_flag_the_door_stays_closed_and_says_how_to_open_it(tmp_path):
    audit = MagicMock()
    app, am = _build(tmp_path, audit)
    assert am.is_setup_mode() is False

    r = app.test_client().post('/api/auth/config', json={'local_auth_enabled': False})

    assert r.status_code == 409
    body = r.get_json()
    assert body['confirm_unauthenticated_required'] is True
    assert 'confirm_unauthenticated' in body['hint']
    assert am.is_setup_mode() is False
    audit.log_auth_config_changed.assert_not_called()


def test_with_the_flag_the_choice_goes_through_and_is_audited_as_deliberate(tmp_path):
    audit = MagicMock()
    app, am = _build(tmp_path, audit)

    r = app.test_client().post('/api/auth/config',
                               json={'local_auth_enabled': False, 'confirm_unauthenticated': True})

    assert r.status_code == 200, r.get_json()
    assert am.is_local_auth_enabled() is False
    assert am.is_setup_mode() is True        # that is the state they asked for
    audit.log_auth_config_changed.assert_called_once()
    kwargs = audit.log_auth_config_changed.call_args.kwargs
    assert kwargs['local_auth_enabled_before'] is True
    assert kwargs['local_auth_enabled_after'] is False
    assert kwargs['confirm_unauthenticated'] is True


def test_the_flag_is_not_needed_and_not_recorded_when_the_door_would_not_open(tmp_path):
    """Turning local auth back ON never opens the door; the flag, if sent,
    is ignored and the audit entry does not claim a deliberate opening."""
    audit = MagicMock()
    app, am = _build(tmp_path, audit)
    app.test_client().post('/api/auth/config',
                           json={'local_auth_enabled': False, 'confirm_unauthenticated': True})
    audit.reset_mock()

    r = app.test_client().post('/api/auth/config',
                               json={'local_auth_enabled': True, 'confirm_unauthenticated': True})

    assert r.status_code == 200
    assert am.is_setup_mode() is False
    assert audit.log_auth_config_changed.call_args.kwargs['confirm_unauthenticated'] is False


def test_the_audit_entry_carries_the_flag():
    from modules.core.audit import AuditLogger
    logger = AuditLogger.__new__(AuditLogger)
    logger.log_operation = MagicMock()
    logger.log_auth_config_changed(local_auth_enabled_before=True, local_auth_enabled_after=False,
                                   user='admin', ip_address='10.0.0.5', confirm_unauthenticated=True)
    details = logger.log_operation.call_args.kwargs['details']
    assert details == {'before': True, 'after': False, 'confirm_unauthenticated': True}
