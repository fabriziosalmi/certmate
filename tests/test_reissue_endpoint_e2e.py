"""
Functional tests for POST /api/certificates/<domain>/reissue (#267).

Real issuance needs a live ACME flow, so the e2e surface pins the
request-validation contract: a reissue targets an EXISTING certificate
(404 otherwise — creation belongs to the create endpoint) and malformed
payloads fail before any side effect.
"""

import pytest

pytestmark = [pytest.mark.e2e]


class TestReissueEndpoint:
    def test_reissue_unknown_domain_404(self, api):
        r = api.post_json(
            "/api/certificates/nonexistent.example.com/reissue", {}
        )
        assert r.status_code == 404
        body = r.json()
        assert body.get("code") == "CERTIFICATE_NOT_FOUND"
        assert "create" in body.get("error", "").lower()

    def test_reissue_path_traversal_rejected(self, api):
        r = api.post_json(
            "/api/certificates/..%2F..%2Fetc/reissue", {}
        )
        assert r.status_code in (400, 404)
