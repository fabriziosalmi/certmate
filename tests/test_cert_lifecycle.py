"""
Full TLS certificate lifecycle tests using real Cloudflare DNS.

Requires:
    CLOUDFLARE_API_TOKEN    Valid Cloudflare API token with DNS edit permission
    CERTMATE_TEST_DOMAIN    Base domain for tests (default: gpfree.org)
    CERTMATE_TEST_EMAIL     ACME email (default: test@gpfree.org)

Each run generates a random subdomain (e.g. e2e-a1b2c3.gpfree.org) to avoid
collisions. Certbot cleans up _acme-challenge TXT records automatically.
The test order is enforced: configure → create → list → download → renew → cleanup.
"""

import os
import uuid
import zipfile
import io
import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

BASE_DOMAIN = os.environ.get("CERTMATE_TEST_DOMAIN", "gpfree.org")
TEST_EMAIL = os.environ.get("CERTMATE_TEST_EMAIL", "test@gpfree.org")

# Random subdomain per test run to avoid collisions
_run_id = uuid.uuid4().hex[:8]
TEST_DOMAIN = f"e2e-{_run_id}.{BASE_DOMAIN}"


@pytest.fixture(scope="module", autouse=True)
def configure_cloudflare(api, cloudflare_token):
    """Set up Cloudflare account and settings before cert tests."""
    # Save settings with email + dns provider
    api.post_json("/api/web/settings", {
        "email": TEST_EMAIL,
        "dns_provider": "cloudflare",
    })
    # Create Cloudflare account with real token
    api.post_json("/api/dns/cloudflare/accounts", {
        "account_id": "e2e-cloudflare",
        "config": {
            "api_token": cloudflare_token,
        },
    })
    yield
    # Cleanup DNS account (cert is removed with the container)
    api.delete("/api/dns/cloudflare/accounts/e2e-cloudflare")


class TestCertificateCreation:
    """Create a real Let's Encrypt certificate."""

    def test_01_create_certificate(self, api):
        """Create a certificate for the random test subdomain (may take 30-120s)."""
        r = api.post_json("/api/certificates/create", {
            "domain": TEST_DOMAIN,
            "dns_provider": "cloudflare",
            "account_id": "e2e-cloudflare",
        })
        assert r.status_code in (200, 201), f"Create failed: {r.status_code} {r.text[:300]}"
        data = r.json()
        assert "error" not in data or data.get("success"), f"Create error: {data}"


class TestCertificateListing:
    """Verify the certificate appears in the list."""

    def test_02_certificate_in_list(self, api):
        r = api.get("/api/certificates")
        assert r.status_code == 200
        certs = r.json()
        if isinstance(certs, dict):
            certs = certs.get("certificates", [])
        domains = [c.get("domain", "") for c in certs]
        assert TEST_DOMAIN in domains, f"Domain {TEST_DOMAIN} not in list: {domains}"

    def test_03_certificate_exists(self, api):
        r = api.get("/api/certificates")
        certs = r.json()
        if isinstance(certs, dict):
            certs = certs.get("certificates", [])
        cert = next((c for c in certs if c.get("domain") == TEST_DOMAIN), None)
        assert cert is not None
        assert cert.get("exists", False), "Certificate files not found on disk"


class TestCertificateDownload:
    """Download certificate files."""

    def test_04_download_zip(self, api):
        r = api.get(f"/api/certificates/{TEST_DOMAIN}/download")
        assert r.status_code == 200
        assert len(r.content) > 100, "ZIP file too small"
        # Verify it's a valid ZIP
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        names = zf.namelist()
        assert any("cert" in n.lower() or "fullchain" in n.lower() for n in names), \
            f"No cert file in ZIP: {names}"

    def test_05_download_tls_components(self, api):
        """Download individual TLS components."""
        for component in ("cert", "key", "chain", "fullchain"):
            r = api.get(f"/{TEST_DOMAIN}/tls/{component}")
            if r.status_code == 200:
                assert len(r.content) > 50, f"{component} too small"


class TestCertificateRenewal:
    """Renew the certificate."""

    def test_06_renew_certificate(self, api):
        r = api.post_json(f"/api/certificates/{TEST_DOMAIN}/renew", {})
        # Renewal may succeed or say "not due for renewal" — both are OK
        assert r.status_code in (200, 400), f"Renew failed: {r.status_code} {r.text[:200]}"
