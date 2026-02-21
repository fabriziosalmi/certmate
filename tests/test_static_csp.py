"""
Tests for static file serving and Content Security Policy headers.
Verifies that all CSS, fonts, images, and pages load without CDN dependencies.
"""

import pytest

pytestmark = [pytest.mark.e2e]


class TestStaticFiles:
    """All bundled static assets must return 200."""

    @pytest.mark.parametrize("path", [
        "/static/css/tailwind.min.css",
        "/static/css/fontawesome.min.css",
        "/static/webfonts/fa-solid-900.woff2",
        "/static/webfonts/fa-regular-400.woff2",
        "/static/webfonts/fa-brands-400.woff2",
        "/static/webfonts/fa-solid-900.ttf",
        "/static/webfonts/fa-regular-400.ttf",
        "/static/webfonts/fa-brands-400.ttf",
    ])
    def test_static_asset_returns_200(self, api, path):
        r = api.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"

    @pytest.mark.parametrize("path", [
        "/favicon.ico",
        "/certmate_logo_256.png",
        "/certmate_logo.png",
        "/apple-touch-icon.png",
    ])
    def test_image_alias_returns_200(self, api, path):
        r = api.get(path)
        assert r.status_code == 200, f"{path} returned {r.status_code}"


class TestCSPHeaders:
    """CSP headers should be strict (no external CDNs) on normal pages."""

    @pytest.mark.parametrize("path", ["/", "/settings", "/help", "/client-certificates"])
    def test_csp_no_external_cdn(self, api, path):
        r = api.get(path, allow_redirects=True)
        assert r.status_code == 200
        csp = r.headers.get("Content-Security-Policy", "")
        assert "cdn.tailwindcss.com" not in csp
        assert "cdnjs.cloudflare.com" not in csp

    @pytest.mark.parametrize("path", ["/", "/settings", "/help", "/client-certificates"])
    def test_csp_self_only(self, api, path):
        r = api.get(path, allow_redirects=True)
        csp = r.headers.get("Content-Security-Policy", "")
        assert "font-src 'self'" in csp
        assert "script-src 'self'" in csp

    def test_redoc_csp_allows_external(self, api):
        r = api.get("/redoc")
        assert r.status_code == 200
        csp = r.headers.get("Content-Security-Policy", "")
        assert "cdn.redoc.ly" in csp
        assert "fonts.googleapis.com" in csp


class TestNoCDNReferences:
    """HTML pages must not reference external CDNs."""

    @pytest.mark.parametrize("path", ["/", "/settings", "/help", "/client-certificates"])
    def test_html_no_cdn_scripts(self, api, path):
        r = api.get(path, allow_redirects=True)
        body = r.text
        assert "cdn.tailwindcss.com" not in body
        assert "cdnjs.cloudflare.com" not in body

    @pytest.mark.parametrize("path", ["/", "/settings", "/help", "/client-certificates"])
    def test_html_has_local_css(self, api, path):
        r = api.get(path, allow_redirects=True)
        body = r.text
        assert "/static/css/tailwind.min.css" in body
        assert "/static/css/fontawesome.min.css" in body
