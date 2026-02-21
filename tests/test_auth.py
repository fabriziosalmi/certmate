"""
Tests for authentication: setup-mode bypass, session management, user CRUD.
"""

import pytest

pytestmark = [pytest.mark.e2e]


class TestSetupModeBypass:
    """When auth is disabled and no users exist, all API endpoints
    should be accessible without credentials (setup mode)."""

    @pytest.mark.parametrize("path", [
        "/api/certificates",
        "/api/backups",
        "/api/users",
        "/api/auth/config",
        "/api/web/settings",
        "/api/web/cache/stats",
        "/api/client-certs",
        "/api/client-certs/stats",
    ])
    def test_api_accessible_without_auth(self, api, path):
        r = api.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}: {r.text[:200]}"

    def test_health_always_accessible(self, api):
        r = api.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "healthy"

    def test_web_settings_post_works(self, api):
        """Settings save should work in setup mode (no localhost restriction)."""
        r = api.get("/api/web/settings")
        assert r.status_code == 200
        settings = r.json()
        # POST back same settings — should not 403
        r = api.post_json("/api/web/settings", settings)
        assert r.status_code == 200, f"POST settings failed: {r.status_code} {r.text[:200]}"


class TestAuthConfig:
    """Auth configuration endpoint."""

    def test_get_auth_config(self, api):
        r = api.get("/api/auth/config")
        assert r.status_code == 200
        data = r.json()
        assert "local_auth_enabled" in data

    def test_auth_me_returns_401_without_session(self, api):
        """/api/auth/me should return 401 when no session exists."""
        r = api.get("/api/auth/me")
        assert r.status_code == 401


class TestUserManagement:
    """User CRUD operations (while in setup mode)."""

    def test_list_users_empty(self, api):
        r = api.get("/api/users")
        assert r.status_code == 200
        data = r.json()
        assert "users" in data

    def test_create_and_delete_user(self, api):
        # Create
        r = api.post_json("/api/users", {
            "username": "testuser",
            "password": "TestPass123!",
            "role": "user",
        })
        assert r.status_code in (200, 201), f"Create user failed: {r.text[:200]}"

        # Verify listed
        r = api.get("/api/users")
        data = r.json()
        assert "testuser" in data.get("users", {})

        # Delete
        r = api.delete("/api/users/testuser")
        assert r.status_code == 200

        # Verify gone
        r = api.get("/api/users")
        data = r.json()
        assert "testuser" not in data.get("users", {})
