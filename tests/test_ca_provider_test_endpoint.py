"""
Functional tests for POST /api/settings/test-ca-provider.

Before Actalis support landed, the endpoint only knew letsencrypt,
digicert and private_ca: every other CA the settings UI offers
(zerossl, google, buypass, sslcom) fell through to
"Invalid CA provider type" with HTTP 400, so the Test CA Connection
button could never succeed for them. The fixed-directory EAB CAs now
share one offline-validation branch, and buypass got an email-only
branch like letsencrypt.
"""

import pytest

pytestmark = [pytest.mark.e2e]

ACTALIS_DIRECTORY = "https://acme-api.actalis.com/acme/directory"


class TestCAProviderTestEndpoint:
    def test_actalis_requires_eab(self, api):
        r = api.post_json("/api/settings/test-ca-provider", {
            "ca_provider": "actalis",
            "config": {"email": "admin@example.com"},
        })
        assert r.status_code == 200
        body = r.json()
        assert body["success"] is False
        assert "EAB" in body["message"]

    def test_actalis_valid_config(self, api):
        r = api.post_json("/api/settings/test-ca-provider", {
            "ca_provider": "actalis",
            "config": {
                "eab_kid": "kid-from-actalis-portal",
                "eab_hmac": "hmac-from-actalis-portal",
                "email": "admin@example.com",
            },
        })
        assert r.status_code == 200
        body = r.json()
        assert body["success"] is True
        assert body["acme_url"] == ACTALIS_DIRECTORY

    def test_zerossl_accepts_canonical_field_spelling(self, api):
        # testCAProvider() in settings.js posts eab_key_id/eab_hmac_key
        # for zerossl/google/sslcom — both spellings must be accepted.
        r = api.post_json("/api/settings/test-ca-provider", {
            "ca_provider": "zerossl",
            "config": {
                "eab_key_id": "kid",
                "eab_hmac_key": "hmac",
                "email": "admin@example.com",
            },
        })
        assert r.status_code == 200
        assert r.json()["success"] is True

    def test_buypass_email_only(self, api):
        r = api.post_json("/api/settings/test-ca-provider", {
            "ca_provider": "buypass",
            "config": {"email": "admin@example.com"},
        })
        assert r.status_code == 200
        assert r.json()["success"] is True

    def test_unknown_provider_rejected(self, api):
        r = api.post_json("/api/settings/test-ca-provider", {
            "ca_provider": "not-a-ca",
            "config": {},
        })
        assert r.status_code == 400
