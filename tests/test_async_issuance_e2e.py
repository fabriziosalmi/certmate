"""E2E for opt-in async certificate issuance through the in-process executor.

Requires Docker + CLOUDFLARE_API_TOKEN (skips otherwise); uses random
subdomains under CERTMATE_TEST_DOMAIN. Two properties:

1. ``async`` create returns 202 + a job that polls to ``succeeded`` and the
   certificate really exists afterwards.
2. The "draconian" non-starvation proof: while several slow issuances run in
   the background, ``/health`` stays snappy — i.e. certbot is off the request
   threads, which is the whole point of the executor.

Cert burn: ~3 real Let's Encrypt certs per run (1 + 2 concurrent).
"""
import os
import time
import uuid

import pytest
import requests

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

BASE_DOMAIN = os.environ.get("CERTMATE_TEST_DOMAIN", "gpfree.org")
TEST_EMAIL = os.environ.get("CERTMATE_TEST_EMAIL", "test@gpfree.org")
_RUN = uuid.uuid4().hex[:6]


@pytest.fixture(scope="module", autouse=True)
def configure_cloudflare(api, cloudflare_token):
    api.post_json("/api/web/settings", {
        "email": TEST_EMAIL, "dns_provider": "cloudflare"})
    api.post_json("/api/dns/cloudflare/accounts", {
        "account_id": "e2e-async",
        "config": {"api_token": cloudflare_token}})
    yield
    api.delete("/api/dns/cloudflare/accounts/e2e-async")


def _poll_job(api, status_url, timeout=240):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            r = api.get(status_url)
        except requests.exceptions.ConnectionError:
            # Backstop for the keep-alive race (the session adapter also
            # retries): a stale pooled connection raises here; reconnect.
            time.sleep(1)
            continue
        assert r.status_code == 200, f"{r.status_code} {r.text[:200]}"
        last = r.json()
        if last["status"] in ("succeeded", "failed"):
            return last
        time.sleep(2)
    raise AssertionError(f"job {status_url} not finished in {timeout}s; last={last}")


def _domains(api):
    certs = api.get("/api/certificates").json()
    if isinstance(certs, dict):
        certs = certs.get("certificates", [])
    return [c.get("domain", "") for c in certs]


class TestAsyncIssuance:
    def test_async_create_202_then_succeeds(self, api):
        domain = f"e2e-async-{_RUN}.{BASE_DOMAIN}"
        r = api.post_json("/api/certificates/create", {
            "domain": domain, "dns_provider": "cloudflare",
            "account_id": "e2e-async", "async": True})
        assert r.status_code == 202, f"{r.status_code} {r.text[:300]}"
        body = r.json()
        assert body["status"] == "queued"
        assert body["job_id"]
        assert body["status_url"].endswith(body["job_id"])

        job = _poll_job(api, body["status_url"])
        assert job["status"] == "succeeded", f"job failed: {job.get('error')}"
        assert domain in _domains(api), f"{domain} not listed after async create"

    def test_concurrent_async_creates_keep_health_responsive(self, api):
        domains = [f"e2e-conc-{_RUN}-{i}.{BASE_DOMAIN}" for i in range(2)]
        status_urls = []
        for d in domains:
            r = api.post_json("/api/certificates/create", {
                "domain": d, "dns_provider": "cloudflare",
                "account_id": "e2e-async", "async": True})
            assert r.status_code == 202, f"{r.status_code} {r.text[:300]}"
            status_urls.append(r.json()["status_url"])

        # While the slow issuances run on the executor threads, /health must
        # stay snappy on the request threads. A stall would mean certbot is
        # still blocking request handling (the bug this slice fixes).
        latencies = []
        for _ in range(6):
            t0 = time.time()
            h = api.get("/health")
            latencies.append(time.time() - t0)
            assert h.status_code in (200, 503), f"/health hung: {h.status_code}"
            time.sleep(0.5)
        assert max(latencies) < 2.0, f"/health stalled while issuing: {latencies}"

        for url in status_urls:
            job = _poll_job(api, url)
            assert job["status"] == "succeeded", f"job failed: {job.get('error')}"
