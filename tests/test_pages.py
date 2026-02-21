"""
Tests for web page rendering: all pages load, contain expected elements,
and the welcome/setup banners are shown for first-time users.
"""

import pytest

pytestmark = [pytest.mark.e2e]


class TestPageLoading:
    """Every page must return 200."""

    @pytest.mark.parametrize("path", [
        "/",
        "/settings",
        "/help",
        "/activity",
        "/redoc",
        "/health",
    ])
    def test_page_returns_200(self, api, path):
        r = api.get(path, allow_redirects=True)
        assert r.status_code == 200, f"{path} → {r.status_code}"

    def test_client_certificates_redirects(self, api):
        """Client certificates page redirects to unified certificates page."""
        r = api.get("/client-certificates", allow_redirects=False)
        assert r.status_code == 302
        assert "/#client" in r.headers.get("Location", "")


class TestWelcomeBanner:
    """Dashboard page should load dashboard JS module and key UI elements."""

    def test_index_loads_dashboard_js(self, api):
        r = api.get("/", allow_redirects=True)
        assert "dashboard.js" in r.text

    def test_index_has_certificate_toggle(self, api):
        r = api.get("/", allow_redirects=True)
        assert "Server Certificates" in r.text


class TestHelpPage:
    """Help page should contain Docker Quick Start section."""

    def test_docker_quick_start(self, api):
        r = api.get("/help")
        assert "Docker Quick Start" in r.text

    def test_getting_started(self, api):
        r = api.get("/help")
        assert "Getting Started" in r.text


class TestSettingsPage:
    """Settings page should contain security reminder banner."""

    def test_auth_security_banner_element(self, api):
        r = api.get("/settings")
        assert "authSecurityBanner" in r.text

    def test_navbar_logo_size(self, api):
        """Logo should be responsive: w-9 h-9 on mobile, md:w-12 md:h-12 on desktop."""
        r = api.get("/settings")
        assert "md:w-12 md:h-12" in r.text
