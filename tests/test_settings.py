"""
Tests for settings management and DNS provider account CRUD.
"""

import pytest

pytestmark = [pytest.mark.e2e]


class TestSettingsLoad:
    """Settings GET endpoint."""

    def test_load_initial_settings(self, api):
        r = api.get("/api/web/settings")
        assert r.status_code == 200
        data = r.json()
        assert "dns_provider" in data

    def test_load_settings_has_email_field(self, api):
        r = api.get("/api/web/settings")
        data = r.json()
        assert "email" in data


class TestSettingsSave:
    """Settings POST endpoint."""

    def test_save_basic_settings(self, api):
        r = api.post_json("/api/web/settings", {
            "email": "test@example.com",
            "dns_provider": "cloudflare",
        })
        assert r.status_code == 200

    def test_save_and_reload(self, api):
        email = "reload-test@example.com"
        api.post_json("/api/web/settings", {
            "email": email,
            "dns_provider": "cloudflare",
        })
        r = api.get("/api/web/settings")
        data = r.json()
        assert data.get("email") == email


class TestDNSProviderAccounts:
    """DNS provider account CRUD."""

    def test_list_accounts_empty(self, api):
        r = api.get("/api/dns/cloudflare/accounts")
        assert r.status_code == 200

    def test_create_account(self, api):
        r = api.post_json("/api/dns/cloudflare/accounts", {
            "account_id": "test-cf-account",
            "config": {
                "api_token": "fake-token-for-testing-only",
            },
        })
        assert r.status_code == 200
        assert "success" in r.text.lower() or "created" in r.text.lower()

    def test_list_accounts_after_create(self, api):
        r = api.get("/api/dns/cloudflare/accounts")
        assert r.status_code == 200
        data = r.json()
        # Should contain our test account
        accounts = data if isinstance(data, list) else data.get("accounts", [])
        ids = [a.get("account_id", a.get("id", "")) for a in accounts]
        assert "test-cf-account" in ids

    def test_delete_account(self, api):
        r = api.delete("/api/dns/cloudflare/accounts/test-cf-account")
        assert r.status_code == 200

    def test_create_account_with_real_token(self, api, cloudflare_token):
        """Create a real Cloudflare account with a valid token.
        Only runs when CLOUDFLARE_API_TOKEN is set."""
        r = api.post_json("/api/dns/cloudflare/accounts", {
            "account_id": "e2e-cloudflare",
            "config": {
                "api_token": cloudflare_token,
            },
        })
        assert r.status_code == 200


class TestCacheEndpoints:
    """Cache stats and clear."""

    def test_cache_stats(self, api):
        r = api.get("/api/web/cache/stats")
        assert r.status_code == 200

    def test_cache_clear(self, api):
        r = api.post_json("/api/web/cache/clear", {})
        assert r.status_code == 200
