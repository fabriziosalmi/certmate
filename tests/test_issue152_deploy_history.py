"""Contract test for issue #152 — align ``GET /api/deploy/history`` with
the bare-list convention already used by ``GET /api/webhooks/deliveries``
(``modules/web/misc_routes.py``).

The two endpoints serve the same role for their respective UI panels
(Settings → Deploy → "Recent Executions" and Settings → Notifications →
"Recent Deliveries"), yet they returned different shapes: the deliveries
endpoint returned a bare list, the deploy history endpoint wrapped it in
``{"history": [...]}``. The original frontend was written to the bare-list
convention; the v2.4.12 hotfix made it accept both shapes defensively
(see ``static/js/settings-deploy.js``) so flipping the backend to a bare
list is a no-op for the UI but removes the asymmetry the maintainer
flagged in pull/142#issuecomment-4430183618.

These four cases pin the post-#152 contract so a future maintainer
doesn't "tidy" the bare list back into an envelope and silently
re-introduce the divergence.
"""

from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.web.settings_routes import register_settings_routes


pytestmark = [pytest.mark.unit]


def _passthrough_decorator(_min_role):
    """Stand in for ``auth_manager.require_role(...)`` so the view runs
    without a real session."""
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
    """Happy path: the response body is the list itself, in the order
    ``deploy_manager.get_history`` returned it. Matches the shape
    ``/api/webhooks/deliveries`` already uses and the bare-list predicate
    in ``static/js/settings-notifications.js`` (``Array.isArray(data)``).
    """
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
    """First-run / no-deploys case. The body must be ``[]`` — not
    ``{"history": []}``. Locks the contract against an accidental
    re-wrap; the empty case was historically the most visible symptom
    when the wrap was in place (#137).
    """
    app, _ = _build_app([])
    client = app.test_client()

    r = client.get('/api/deploy/history')
    assert r.status_code == 200
    body = r.get_json()
    assert body == []
    assert not isinstance(body, dict)


def test_deploy_history_forwards_limit_and_domain_filters():
    """Shape change must not regress the query-string contract. The
    endpoint still parses ``?limit=N`` (capped at 200) and ``?domain=...``
    and forwards them verbatim to ``DeployManager.get_history``.
    """
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
    """Error path keeps the ``{"error": "..."}`` envelope. The success
    contract switched to a bare list, but errors still need a key the
    frontend's catch branch can read (``res.body.error``) instead of the
    generic 'unexpected response' literal.
    """
    app = Flask(__name__)
    app.secret_key = 'test'
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    register_settings_routes(
        app,
        managers={},  # no 'deployer' key — deploy_manager will be None
        require_web_auth=lambda f: f,
        auth_manager=auth_manager,
        settings_manager=MagicMock(),
        dns_manager=MagicMock(),
    )
    client = app.test_client()

    r = client.get('/api/deploy/history')
    assert r.status_code == 503
    body = r.get_json()
    assert isinstance(body, dict)
    assert 'error' in body
