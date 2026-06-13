"""
Regression test for scheduler-failure surfacing on /health.

Previously, if APScheduler failed to start, the only signal was a single
ERROR line in the application log and a Python RuntimeWarning that nobody
saw. /health collapsed the failure into a bare `scheduler: not_running`
with no reason attached, so an operator looking at the endpoint had no way
to distinguish "scheduler intentionally not configured" from "scheduler
exploded on startup and automatic renewal is silently disabled".

The fix records the setup outcome on the AppContainer (and through to
`managers['scheduler_status']`). /health now surfaces:

  - state: "failed"
  - error: the original exception message
  - failed_at: utc-iso timestamp

These tests pin both the success and the failure paths.
"""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.web.misc_routes import register_misc_routes


def _build_app(managers: dict) -> Flask:
    """Mount /health against a stub auth_manager and the given managers dict."""
    app = Flask(__name__)
    app.config['VERSION'] = 'test'

    auth_manager = MagicMock()

    def _passthrough(role):
        def deco(fn):
            return fn
        return deco

    auth_manager.require_role = _passthrough
    auth_manager.is_local_auth_enabled.return_value = False
    auth_manager.has_any_users.return_value = False

    register_misc_routes(app, managers, require_web_auth=None, auth_manager=auth_manager)
    return app


def test_health_reports_scheduler_failed_with_error_message():
    """When setup_scheduler raised, /health must include state, error, ts."""
    managers = {
        'scheduler': None,
        'scheduler_status': {
            'state': 'failed',
            'error': 'sqlite3.OperationalError: unable to open database file',
            'timestamp': '2026-05-16T12:00:00Z',
        },
    }
    app = _build_app(managers)

    resp = app.test_client().get('/health')
    assert resp.status_code == 200
    body = resp.get_json()

    assert body['status'] == 'degraded', "scheduler failure must degrade /health"
    assert body['checks']['scheduler'] == 'failed'
    assert body['checks']['scheduler_error'] == (
        'sqlite3.OperationalError: unable to open database file'
    )
    assert body['checks']['scheduler_failed_at'] == '2026-05-16T12:00:00Z'


def test_health_reports_scheduler_running_when_alive():
    """Happy path: scheduler registered and .running == True."""
    mock_scheduler = MagicMock()
    mock_scheduler.running = True
    managers = {
        'scheduler': mock_scheduler,
        'scheduler_status': {
            'state': 'running',
            'error': None,
            'timestamp': '2026-05-16T12:00:00Z',
        },
    }
    app = _build_app(managers)

    resp = app.test_client().get('/health')
    body = resp.get_json()

    assert body['checks']['scheduler'] == 'running'
    assert 'scheduler_error' not in body['checks'], (
        "happy path must not leak a scheduler_error field"
    )
    # Status may still be 'degraded' if disk / cert_dir checks fail, but
    # the scheduler check itself must not be the cause.


def test_health_falls_back_to_not_running_when_status_unset():
    """Pre-fix behaviour for code paths that don't record a status yet.

    Pins backwards compatibility: a missing scheduler_status must NOT crash
    /health; it should still report `scheduler: not_running` and degrade."""
    managers = {
        'scheduler': None,
        # scheduler_status intentionally absent
    }
    app = _build_app(managers)

    resp = app.test_client().get('/health')
    body = resp.get_json()

    assert resp.status_code == 200
    assert body['status'] == 'degraded'
    assert body['checks']['scheduler'] == 'not_running'


def test_readiness_returns_503_when_scheduler_failed():
    """A broken renewal engine must FAIL readiness so orchestrators react.

    /health stays 200 (liveness), but /health/ready returns 503 so a
    Kubernetes readiness probe / deploy gate catches a scheduler that
    exploded on startup — the bug being that automatic renewal silently
    never runs while every health check passes."""
    managers = {
        'scheduler': None,
        'scheduler_status': {
            'state': 'failed',
            'error': 'sqlite3.OperationalError: unable to open database file',
            'timestamp': '2026-05-16T12:00:00Z',
        },
    }
    app = _build_app(managers)
    client = app.test_client()

    # Liveness unaffected.
    assert client.get('/health').status_code == 200

    resp = client.get('/health/ready')
    assert resp.status_code == 503
    body = resp.get_json()
    assert body['ready'] is False
    assert body['scheduler'] == 'failed'
    assert body['scheduler_error'] == (
        'sqlite3.OperationalError: unable to open database file'
    )


def test_readiness_returns_200_when_scheduler_running():
    mock_scheduler = MagicMock()
    mock_scheduler.running = True
    managers = {
        'scheduler': mock_scheduler,
        'scheduler_status': {'state': 'running', 'error': None, 'timestamp': 't'},
    }
    resp = _build_app(managers).test_client().get('/health/ready')
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['ready'] is True
    assert body['scheduler'] == 'running'
    assert 'scheduler_error' not in body


def test_readiness_returns_503_when_status_absent():
    """No recorded status (scheduler never set up) is also not-ready."""
    resp = _build_app({'scheduler': None}).test_client().get('/health/ready')
    assert resp.status_code == 503
    assert resp.get_json()['ready'] is False


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
