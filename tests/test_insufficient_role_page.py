"""
Regression test for issue #256.

Before the fix, require_role's role-denial branch returned the API-style
JSON
    {"code":"INSUFFICIENT_ROLE","error":"admin privileges required"}
to every caller — including a browser where an authenticated operator
navigated to /settings. The user saw the raw JSON body in the tab with
no way out but the back button.

The fix splits the role-denial response the same way the auth-failure
branch already did: a browser GET to a non-/api page gets a styled
403.html (rendered inside the app chrome, nav intact); /api/ paths and
non-HTML clients keep the machine-readable JSON 403 so programmatic
callers are unaffected.

We pin all three branches so a future refactor can't quietly regress any.
"""
import os
from unittest.mock import MagicMock

import pytest
from flask import Flask, jsonify

from modules.core.auth import AuthManager


pytestmark = [pytest.mark.unit]

_TEMPLATES = os.path.join(os.path.dirname(__file__), "..", "templates")


@pytest.fixture
def auth_app():
    """Flask app whose routes authenticate successfully as a *viewer* but
    require *admin*, so every request reaches the role-denial branch.

    _authenticate_request is mocked to isolate the denial-response split
    from session mechanics — the only thing observed is which 403 shape
    the decorator picks.
    """
    sm = MagicMock()
    sm.load_settings.side_effect = lambda: {"local_auth_enabled": True}
    auth = AuthManager(sm)
    auth._authenticate_request = MagicMock(
        return_value=({"username": "viewer@example.com", "role": "viewer"}, None)
    )

    app = Flask(__name__, template_folder=_TEMPLATES)
    app.secret_key = "test"

    @app.route("/settings")
    @auth.require_role("admin")
    def settings_page():
        return "<html>settings body</html>"

    @app.route("/api/things")
    @auth.require_role("admin")
    def api_things():
        return jsonify(ok=True)

    return app


def test_settings_renders_styled_page_for_browser(auth_app):
    """Browser GET to /settings -> 403 HTML page, not JSON."""
    client = auth_app.test_client()
    r = client.get("/settings", headers={"Accept": "text/html,application/xhtml+xml"})

    assert r.status_code == 403
    assert "text/html" in r.headers.get("Content-Type", "")
    body = r.get_data(as_text=True)
    assert "Access restricted" in body
    # The required and current roles are surfaced to the user.
    assert "admin" in body and "viewer" in body
    # The app chrome (nav) is present so the user can navigate away.
    assert 'href="/settings"' in body and 'href="/help"' in body
    # It is a page, not the raw JSON envelope.
    assert "INSUFFICIENT_ROLE" not in body


def test_settings_returns_json_for_api_clients(auth_app):
    """`Accept: application/json` -> machine-readable 403, unchanged."""
    client = auth_app.test_client()
    r = client.get("/settings", headers={"Accept": "application/json"})

    assert r.status_code == 403
    body = r.get_json(silent=True) or {}
    assert body.get("code") == "INSUFFICIENT_ROLE"


def test_api_path_always_returns_json(auth_app):
    """An /api/ call returns JSON 403 even with an HTML Accept header."""
    client = auth_app.test_client()
    r = client.get("/api/things", headers={"Accept": "text/html,application/xhtml+xml"})

    assert r.status_code == 403
    body = r.get_json(silent=True) or {}
    assert body.get("code") == "INSUFFICIENT_ROLE"
