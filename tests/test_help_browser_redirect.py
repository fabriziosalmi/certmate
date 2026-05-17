"""
Regression test for the v2.5.1 auth-decorator UX bug.

Before the fix the require_role / require_auth decorators returned the
API-style JSON
    {"code":"AUTH_HEADER_MISSING","error":"Authorization header required"}
to every caller that wasn't authenticated, including browsers loading
the HTML help page. Users saw the raw JSON body in the tab.

The fix splits the auth-failure response by client type: browser GET
to a non-/api path gets a 302 to /login?next=<path>; everything else
keeps the JSON 401 it had before so curl / fetch / API clients are
unaffected.

We pin both branches here so a future refactor can't quietly regress
either path.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask, jsonify

from modules.core.auth import AuthManager


pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_store():
    """Minimal settings: local auth enabled, one user. Auth always
    fails because we never plant a valid session cookie."""
    return {
        "local_auth_enabled": True,
        "users": {
            "admin@example.com": {
                "password_hash": "$2b$12$dummy",
                "role": "admin",
                "enabled": True,
            }
        },
        "api_bearer_token_hash": "x",
    }


@pytest.fixture
def auth_app(settings_store):
    """Tiny Flask app with two routes protected by require_role.

    Both routes always fail auth (no session, no Authorization header),
    so the only thing the test observes is which failure response the
    decorator picks.
    """
    sm = MagicMock()
    sm.load_settings.side_effect = lambda: settings_store
    auth = AuthManager(sm)

    app = Flask(__name__)
    app.secret_key = "test"

    # url_for('login_page', next=...) needs a target endpoint.
    @app.route("/login")
    def login_page():
        return "login stub", 200

    @app.route("/help")
    @auth.require_role("viewer")
    def help_page():
        return "<html>help body</html>"

    @app.route("/api/things")
    @auth.require_role("viewer")
    def api_things():
        return jsonify(ok=True)

    return app


def test_help_redirects_browser_to_login(auth_app):
    """Browser-style GET to /help -> 302 to /login?next=/help."""
    client = auth_app.test_client()
    r = client.get("/help", headers={"Accept": "text/html,application/xhtml+xml"})

    assert r.status_code == 302, (
        f"expected 302 redirect for browser GET, got {r.status_code} "
        f"with body: {r.get_data(as_text=True)[:200]!r}"
    )
    location = r.headers.get("Location", "")
    assert "/login" in location, f"expected redirect to /login, got: {location!r}"
    assert "next=%2Fhelp" in location or "next=/help" in location, (
        f"expected ?next=/help in redirect target, got: {location!r}"
    )


def test_help_returns_json_for_api_clients(auth_app):
    """`Accept: application/json` -> API-style 401, same shape it always was."""
    client = auth_app.test_client()
    r = client.get("/help", headers={"Accept": "application/json"})

    assert r.status_code == 401
    body = r.get_json(silent=True) or {}
    assert body.get("code") == "AUTH_HEADER_MISSING"


def test_api_path_never_redirects(auth_app):
    """An unauthenticated /api/ call returns JSON 401 even with HTML Accept.

    Guards against the case where a browser-rendered HTML form posts to
    /api/... and we'd accidentally redirect away from the JSON error
    path. /api/ stays a JSON surface always.
    """
    client = auth_app.test_client()
    r = client.get(
        "/api/things",
        headers={"Accept": "text/html,application/xhtml+xml"},
    )
    assert r.status_code != 302, (
        f"/api/ paths must not redirect to /login regardless of Accept; "
        f"got {r.status_code} with Location: {r.headers.get('Location')!r}"
    )
    assert r.status_code == 401
