"""Tests for DNS provider account display in settings UI (Issue #59).

Verifies that the settings.html JavaScript correctly handles the
canonical multi-account format { accounts: { id: {...}, ... } }
that the backend writes to settings.json.
"""
import pytest
from pathlib import Path


class TestDNSAccountsSettingsUI:
    """Test that settings.html handles the canonical DNS accounts format."""

    SETTINGS_HTML = Path('templates/settings.html')

    def test_settings_template_exists(self):
        assert self.SETTINGS_HTML.exists()

    def test_canonical_accounts_format_handled(self):
        """Issue #59: JS must check config.accounts before flat-format detection."""
        content = self.SETTINGS_HTML.read_text()
        canonical_check = "config.accounts && typeof config.accounts === 'object'"
        flat_check = "Object.values(config).some(val => typeof val === 'object' && 'name' in val)"
        canonical_check_pos = content.find(canonical_check)
        flat_check_pos = content.find(flat_check)
        assert canonical_check_pos > 0, \
            "settings.html is missing the canonical accounts format check"
        assert flat_check_pos > 0, \
            "settings.html is missing the flat multi-account format check"
        assert canonical_check_pos < flat_check_pos, \
            "Canonical accounts check must appear BEFORE flat format check"

    def test_accounts_iteration_uses_config_accounts(self):
        """The canonical branch must iterate over config.accounts entries."""
        content = self.SETTINGS_HTML.read_text()
        assert "Object.entries(config.accounts)" in content, \
            "Missing iteration over config.accounts entries"

    def test_fallback_name_uses_account_id(self):
        """Accounts without a name field should display their account ID."""
        content = self.SETTINGS_HTML.read_text()
        assert "accountConfig.name || accountId" in content, \
            "Missing fallback: name should default to accountId"


class TestDNSAccountsBackendAPI:
    """Test that the DNS accounts API endpoint works correctly."""

    def test_dns_accounts_api_returns_list(self):
        """GET /api/dns/provider/accounts should return account data."""
        import app as app_module
        from modules.core.utils import generate_secure_token

        certmate = app_module.CertMateApp()
        flask_app = certmate.app

        test_token = generate_secure_token()

        settings = certmate.managers['settings'].load_settings()
        settings['api_bearer_token'] = test_token
        settings['dns_providers'] = {
            'cloudflare': {
                'accounts': {
                    'default': {
                        'name': 'Default CF Account',
                        'api_token': 'test-token-123'
                    },
                    'secondary': {
                        'name': 'Secondary Account',
                        'api_token': 'test-token-456'
                    }
                }
            }
        }
        certmate.managers['settings'].save_settings(settings)

        client = flask_app.test_client()
        response = client.get(
            '/api/dns/cloudflare/accounts',
            headers={'Authorization': 'Bearer ' + test_token}
        )
        assert response.status_code == 200

        data = response.get_json()
        assert data is not None
