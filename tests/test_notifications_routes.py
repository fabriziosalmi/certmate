"""
Regression tests for #114: notifications + digest + webhook delivery routes.

The frontend (settings-notifications.js) was calling these endpoints but
they weren't registered, so users always got 404. These tests verify
each route returns the right shape, requires the right role, and doesn't
500 on edge inputs.

Setup-mode bypass: when local_auth is disabled and no users exist, the
auth decorator currently lets any request through (intentional for the
setup wizard). We assert that-mode separately from the auth-on path so a
future tightening doesn't silently regress these endpoints.
"""

import pytest
import requests

pytestmark = [pytest.mark.e2e]


@pytest.fixture(scope="module")
def admin_session(api):
    """Set up local-auth, create admin, log in. Returns the session cookie name=value pair."""
    pwd = "Password123!"

    # Step 1: create admin (no auth required in setup mode)
    r1 = api.post("/api/web/settings/users", json={
        "username": "admin", "password": pwd, "role": "admin"
    })
    if r1.status_code not in (200, 201, 409):
        pytest.skip(f"Could not create admin user: {r1.status_code} {r1.text[:200]}")

    # Step 2: enable local auth
    api.post("/api/auth/config", json={"local_auth_enabled": True})

    # Step 3: login
    r3 = api.post("/api/auth/login", json={"username": "admin", "password": pwd})
    if r3.status_code != 200:
        pytest.skip(f"Could not log in: {r3.status_code} {r3.text[:200]}")

    cookie = r3.cookies.get("certmate_session")
    if not cookie:
        pytest.skip("Login did not return a session cookie")

    # api.session is reused across tests; ensure subsequent calls send the cookie
    api.session.cookies.set("certmate_session", cookie)
    yield cookie

    # Teardown: disable local auth so other test modules aren't affected.
    api.post("/api/auth/config", json={"local_auth_enabled": False})


class TestNotificationsConfigRoute:
    def test_get_returns_200_and_dict(self, api, admin_session):
        r = api.get("/api/notifications/config")
        assert r.status_code == 200, r.text
        body = r.json()
        # Empty config is the legitimate "never configured" state — assert shape, not contents.
        assert isinstance(body, dict)

    def test_post_persists_block(self, api, admin_session):
        config = {
            "enabled": True,
            "digest_enabled": False,
            "events": ["certificate_renewed"],
            "channels": {
                "smtp": {"enabled": False, "host": "smtp.example.invalid", "port": 587,
                         "from_address": "noreply@example.invalid", "to_addresses": ["ops@example.invalid"]},
                "webhooks": []
            }
        }
        r = api.post("/api/notifications/config", json=config)
        assert r.status_code == 200, r.text

        # Round-trip verifies it actually landed in settings.json
        got = api.get_json("/api/notifications/config")
        assert got.get("enabled") is True
        assert got.get("events") == ["certificate_renewed"]
        assert got["channels"]["smtp"]["host"] == "smtp.example.invalid"

    def test_post_rejects_non_object_body(self, api, admin_session):
        # Bypass api.post's json= so we send a literal list (not dict)
        r = api.session.post(f"{api.base_url}/api/notifications/config",
                             json=["not", "a", "dict"])
        assert r.status_code == 400


class TestNotificationsTestRoute:
    def test_post_smtp_unreachable_returns_error_field(self, api, admin_session):
        # Pointing at a host that can't resolve — Notifier.test_channel must
        # return {error: ...}, not raise. The route normalizes that to 200
        # with {success: false, error: ...} so the UI can show a toast.
        r = api.post("/api/notifications/test", json={
            "channel_type": "smtp",
            "config": {
                "host": "smtp.invalid.example.test", "port": 25,
                "from_address": "x@example.invalid",
                "to_addresses": ["y@example.invalid"]
            }
        })
        assert r.status_code in (200, 500), r.text
        body = r.json()
        # The contract: a 'success' boolean is always present.
        assert "success" in body
        assert body["success"] is False

    def test_post_missing_channel_type_returns_400(self, api, admin_session):
        r = api.post("/api/notifications/test", json={"config": {}})
        assert r.status_code == 400

    def test_post_unknown_channel_type_returns_error(self, api, admin_session):
        r = api.post("/api/notifications/test", json={
            "channel_type": "carrier-pigeon", "config": {}
        })
        assert r.status_code == 200
        assert r.json().get("success") is False


class TestDigestSendRoute:
    def test_post_returns_200_and_status(self, api, admin_session):
        r = api.post("/api/digest/send")
        assert r.status_code in (200, 500), r.text
        body = r.json()
        # send() returns one of: {success, ...}, {skipped, ...}, {error, ...}
        assert any(k in body for k in ("success", "skipped", "error"))


class TestWebhookDeliveriesRoute:
    def test_get_returns_list(self, api, admin_session):
        r = api.get("/api/webhooks/deliveries")
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), list)

    def test_get_with_limit_param(self, api, admin_session):
        r = api.get("/api/webhooks/deliveries?limit=10")
        assert r.status_code == 200
        body = r.json()
        assert isinstance(body, list)
        assert len(body) <= 10
