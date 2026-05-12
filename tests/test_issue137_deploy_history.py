"""Regression test for issue #137 — Settings → Deploy → "Recent Executions"
showed "Failed to load deploy history: unexpected response".

Root cause: ``GET /api/deploy/history`` returned ``{"history": [...]}``
but ``static/js/settings-deploy.js`` does ``Array.isArray(res.body)`` to
decide whether the payload is the list it expects. The object envelope
never matched the array predicate, so the panel always hit the error
branch — even on a clean install with an empty history.

The other event-log endpoint the same UI talks to,
``GET /api/webhooks/deliveries``, already returns a bare list. Aligning
``/api/deploy/history`` with that contract closes the bug without
touching the frontend.
"""

from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.web.settings_routes import register_settings_routes


pytestmark = [pytest.mark.unit]


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


def _build_app(history_entries):
    app = Flask(__name__)
    app.secret_key = 'test'

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    deploy_manager = MagicMock()
    deploy_manager.get_history.return_value = history_entries

    register_settings_routes(
        app,
        managers={'deployer': deploy_manager},
        require_web_auth=lambda f: f,
        auth_manager=auth_manager,
        settings_manager=MagicMock(),
        dns_manager=MagicMock(),
    )
    return app, deploy_manager


def test_deploy_history_returns_bare_array():
    """The frontend does ``Array.isArray(res.body)``; the response must
    be the list itself, not an object wrapper."""
    entries = [
        {'domain': 'a.example.com', 'hook_id': 'k8s', 'status': 'ok',
         'timestamp': '2026-05-10T10:00:00Z'},
        {'domain': 'b.example.com', 'hook_id': 'k8s', 'status': 'failed',
         'timestamp': '2026-05-09T09:00:00Z'},
    ]
    app, _ = _build_app(entries)
    client = app.test_client()

    r = client.get('/api/deploy/history')
    assert r.status_code == 200
    body = r.get_json()
    assert isinstance(body, list)
    assert body == entries


def test_deploy_history_empty_returns_empty_array_not_envelope():
    """The first-run case (no deploys yet) was the most visible
    symptom of the bug — the UI rendered an error toast on a fresh
    install. An empty deploy log must come back as ``[]``, not
    ``{"history": []}``."""
    app, _ = _build_app([])
    client = app.test_client()

    r = client.get('/api/deploy/history')
    assert r.status_code == 200
    body = r.get_json()
    assert body == []
    assert not isinstance(body, dict)


def test_deploy_history_forwards_limit_and_domain_filters():
    """The endpoint accepts ``?limit=N`` (capped at 200) and
    ``?domain=...`` and forwards them to ``get_history``. Confirms the
    query string is parsed correctly while changing the response shape."""
    app, deploy_manager = _build_app([])
    client = app.test_client()

    client.get('/api/deploy/history?limit=10&domain=foo.example.com')
    deploy_manager.get_history.assert_called_with(
        limit=10, domain='foo.example.com'
    )

    # Cap at 200 even if the caller asks for more.
    deploy_manager.get_history.reset_mock()
    client.get('/api/deploy/history?limit=10000')
    deploy_manager.get_history.assert_called_with(limit=200, domain=None)


def test_deploy_history_503_when_deploy_manager_missing():
    """If the deploy manager isn't wired in (feature disabled, partial
    boot), the endpoint returns a 503 with an error envelope — the
    frontend's ``Array.isArray`` check fails fast and the catch branch
    surfaces ``res.body.error`` instead of the generic
    'unexpected response' string."""
    app = Flask(__name__)
    app.secret_key = 'test'
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    register_settings_routes(
        app,
        managers={},  # no 'deployer' key
        require_web_auth=lambda f: f,
        auth_manager=auth_manager,
        settings_manager=MagicMock(),
        dns_manager=MagicMock(),
    )
    client = app.test_client()

    r = client.get('/api/deploy/history')
    assert r.status_code == 503
    body = r.get_json()
    assert 'error' in body
