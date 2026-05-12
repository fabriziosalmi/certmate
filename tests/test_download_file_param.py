"""Regression tests for #126: ?file= query param on the download endpoint.

The endpoint serves a ZIP by default and a single PEM (fullchain.pem,
privkey.pem, or a server-side fullchain||privkey concatenation as
combined.pem) when ?file=… is supplied. The whitelist check happens
*after* the cert-dir exists check, so for a nonexistent domain the
endpoint always returns 404 regardless of file param. The whitelist
behavior itself is exercised by the cert lifecycle tests once a real
cert exists.

Pinning here:
- 404 path (missing domain) is unaffected by the file param
- the ?file= surface didn't accidentally break the default ZIP path
"""
import pytest

pytestmark = [pytest.mark.e2e]

NONEXISTENT_DOMAIN = "regression-126-nonexistent.example.invalid"


class TestDownloadFileParamMissingDomain:
    def test_default_zip_path_still_returns_404_for_missing_domain(self, api):
        """Sanity: removing/renaming the file param hasn't broken the no-param path."""
        r = api.get(f"/api/certificates/{NONEXISTENT_DOMAIN}/download")
        assert r.status_code == 404

    def test_json_format_still_returns_404_for_missing_domain(self, api):
        """The JSON mode must not change the missing-domain response."""
        r = api.get(f"/api/certificates/{NONEXISTENT_DOMAIN}/download?format=json")
        assert r.status_code == 404

    @pytest.mark.parametrize("filename", [
        "fullchain.pem",
        "privkey.pem",
        "combined.pem",
    ])
    def test_valid_file_param_returns_404_for_missing_domain(self, api, filename):
        """All three whitelisted filenames return 404 (not 400, not 500) when
        the domain doesn't exist — the cert-dir check comes before the file
        whitelist."""
        r = api.get(f"/api/certificates/{NONEXISTENT_DOMAIN}/download?file={filename}")
        assert r.status_code == 404, (
            f"Expected 404 for missing domain with file={filename}, got {r.status_code}: {r.text[:200]}"
        )

    def test_invalid_file_param_still_returns_404_for_missing_domain(self, api):
        """An out-of-whitelist value (settings.json — sensitive) returns 404
        because the missing-cert check fires first. We assert NOT 200 so the
        whitelist isn't completely bypassed by a path-traversal-shaped value."""
        r = api.get(f"/api/certificates/{NONEXISTENT_DOMAIN}/download?file=settings.json")
        assert r.status_code in (400, 404), (
            f"Expected 400 or 404 for forbidden file param, got {r.status_code}"
        )
        # Whatever the order of checks, the response must not leak the cert
        # bytes for a domain that doesn't even exist.
        assert "BEGIN CERTIFICATE" not in r.text
        assert "BEGIN PRIVATE KEY" not in r.text
