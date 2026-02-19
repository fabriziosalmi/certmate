"""Tests for local authentication enforcement (Issue #61).

Verifies:
- /help route requires authentication when local auth is enabled
- All protected pages redirect to /login when unauthenticated
- Logout endpoint works correctly
- Logout button markup is present in all page templates
"""
import pytest
import json
from unittest.mock import MagicMock, patch
from pathlib import Path


@pytest.fixture
def auth_app():
    """Create a CertMate app with local auth enabled and a test user."""
    import app as app_module

    certmate = app_module.CertMateApp()
    flask_app = certmate.app

    # Enable local auth and create a fake user
    auth_mgr = certmate.managers['auth']
    auth_mgr.is_local_auth_enabled = MagicMock(return_value=True)
    auth_mgr.has_any_users = MagicMock(return_value=True)
    auth_mgr.validate_session = MagicMock(return_value=None)

    return flask_app


@pytest.fixture
def noauth_app():
    """Create a CertMate app with local auth disabled."""
    import app as app_module

    certmate = app_module.CertMateApp()
    flask_app = certmate.app

    auth_mgr = certmate.managers['auth']
    auth_mgr.is_local_auth_enabled = MagicMock(return_value=False)
    auth_mgr.has_any_users = MagicMock(return_value=False)

    return flask_app


class TestProtectedRoutes:
    """When auth is enabled, all web pages must redirect unauthenticated users to /login."""

    PROTECTED_PAGES = ['/', '/settings', '/help', '/client-certificates']

    def test_all_pages_redirect_when_unauthenticated(self, auth_app):
        """Issue #61: All pages must be protected behind login."""
        client = auth_app.test_client()
        for page in self.PROTECTED_PAGES:
            response = client.get(page)
            assert response.status_code == 302, \
                f"{page} should redirect (302) when unauthenticated, got {response.status_code}"
            assert '/login' in response.headers.get('Location', ''), \
                f"{page} should redirect to /login, got {response.headers.get('Location')}"

    def test_help_page_specifically_protected(self, auth_app):
        """Issue #61: /help was missing auth decorator — must redirect now."""
        client = auth_app.test_client()
        response = client.get('/help')
        assert response.status_code == 302
        assert '/login' in response.headers.get('Location', '')

    def test_pages_accessible_when_auth_disabled(self, noauth_app):
        """When auth is disabled, pages should be accessible."""
        client = noauth_app.test_client()
        for page in self.PROTECTED_PAGES:
            response = client.get(page)
            assert response.status_code == 200, \
                f"{page} should be accessible (200) when auth disabled, got {response.status_code}"


class TestLogoutEndpoint:
    """Test the logout API endpoint."""

    def test_logout_endpoint_exists(self, noauth_app):
        """POST /api/auth/logout must return 200 and clear session."""
        client = noauth_app.test_client()
        response = client.post('/api/auth/logout')
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert 'logged out' in data['message'].lower()


class TestLogoutButtonInTemplates:
    """Verify that all page templates include the logout button markup."""

    TEMPLATES = [
        'templates/index.html',
        'templates/settings.html',
        'templates/help.html',
        'templates/client-certificates.html',
    ]

    def test_logout_button_present(self):
        """Issue #61: Every page template must contain a logout button."""
        for tmpl in self.TEMPLATES:
            path = Path(tmpl)
            assert path.exists(), f"Template {tmpl} not found"
            content = path.read_text()
            assert 'logoutBtn' in content, \
                f"{tmpl} is missing the logout button (id='logoutBtn')"
            assert 'doLogout' in content, \
                f"{tmpl} is missing the doLogout() function"
            assert '/api/auth/logout' in content, \
                f"{tmpl} is missing the /api/auth/logout endpoint reference"
