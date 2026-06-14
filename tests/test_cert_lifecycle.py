"""
Full TLS certificate lifecycle tests using real Cloudflare DNS.

Requires:
    CLOUDFLARE_API_TOKEN    Valid Cloudflare API token with DNS edit permission
    CERTMATE_TEST_DOMAIN    Base domain for tests (default: gpfree.org)
    CERTMATE_TEST_EMAIL     ACME email (default: test@gpfree.org)

Each run generates a random subdomain (e.g. e2e-a1b2c3.gpfree.org) to avoid
collisions. Certbot cleans up _acme-challenge TXT records automatically.
The test order is enforced: configure → create → list → download → renew → cleanup.

Issuance defaults to Let's Encrypt STAGING (see tests/e2e_support.py): no
production rate limit is consumed and no publicly trusted certificate is
minted on the test domain. The issuer is asserted on the cert itself.
"""

import os
import uuid
import zipfile
import io
import pytest

from tests.e2e_support import (
    E2E_CA_PROVIDER,
    assert_staging_issuer,
    configure_e2e_provider,
)

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

BASE_DOMAIN = os.environ.get("CERTMATE_TEST_DOMAIN", "gpfree.org")
TEST_EMAIL = os.environ.get("CERTMATE_TEST_EMAIL", "test@gpfree.org")

# Random subdomain per test run to avoid collisions
_run_id = uuid.uuid4().hex[:8]
TEST_DOMAIN = f"e2e-{_run_id}.{BASE_DOMAIN}"


@pytest.fixture(scope="module", autouse=True)
def configure_cloudflare(api, cloudflare_token):
    """Set up the Cloudflare account and STAGING-pinned CA before cert tests."""
    configure_e2e_provider(api, cloudflare_token, "e2e-cloudflare")
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
            "ca_provider": E2E_CA_PROVIDER,
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

    def test_05_download_json_bundle(self, api):
        r = api.get(f"/api/certificates/{TEST_DOMAIN}/download?format=json")
        assert r.status_code == 200
        assert r.headers["Content-Type"].startswith("application/json")

        payload = r.json()
        assert payload["domain"] == TEST_DOMAIN
        assert set(payload.keys()) >= {
            "domain",
            "cert_pem",
            "chain_pem",
            "fullchain_pem",
            "private_key_pem",
        }
        assert "-----BEGIN CERTIFICATE-----" in payload["cert_pem"]
        assert "-----BEGIN CERTIFICATE-----" in payload["chain_pem"]
        assert "-----BEGIN CERTIFICATE-----" in payload["fullchain_pem"]
        assert "-----BEGIN" in payload["private_key_pem"]

    def test_05b_certificate_issued_by_staging(self, api):
        """Hard safety net: the issued leaf must chain to Let's Encrypt
        STAGING, never production — proven from the certificate's own issuer,
        not the requested ca_provider (which the API echoes back regardless)."""
        bundle = api.get(f"/api/certificates/{TEST_DOMAIN}/download?format=json").json()
        issuer = assert_staging_issuer(bundle["cert_pem"])
        print(f"[e2e] issued by staging issuer: {issuer}")

    def test_06_invalid_format_returns_400(self, api):
        r = api.get(f"/api/certificates/{TEST_DOMAIN}/download?format=tar")
        assert r.status_code == 400

    def test_07_download_tls_components(self, api):
        """Download individual TLS components."""
        for component in ("cert", "key", "chain", "fullchain"):
            r = api.get(f"/{TEST_DOMAIN}/tls/{component}")
            if r.status_code == 200:
                assert len(r.content) > 50, f"{component} too small"


class TestCertificateRenewal:
    """Renew the certificate."""

    def test_08_force_renew_certificate(self, api):
        """Force-renew actually re-issues — without --force-renewal a freshly
        issued cert is 'not due' and the renew is a no-op — and the re-issued
        cert must STAY on staging (a renew must never silently switch CA)."""
        r = api.post_json(f"/api/certificates/{TEST_DOMAIN}/renew", {"force": True})
        assert r.status_code == 200, f"Force-renew failed: {r.status_code} {r.text[:300]}"
        bundle = api.get(f"/api/certificates/{TEST_DOMAIN}/download?format=json").json()
        assert_staging_issuer(bundle["cert_pem"])
