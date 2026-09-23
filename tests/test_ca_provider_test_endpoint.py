"""
Functional tests for POST /api/settings/test-ca-provider.

Before Actalis support landed, the endpoint only knew letsencrypt,
digicert and private_ca: every other CA the settings UI offers
(zerossl, google, sslcom) fell through to
"Invalid CA provider type" with HTTP 400, so the Test CA Connection
button could never succeed for them. The fixed-directory EAB CAs now
share one offline-validation branch.
"""

import pytest

pytestmark = [pytest.mark.e2e]

ACTALIS_DIRECTORY = "https://acme-api.actalis.com/acme/directory"


class TestCAProviderTestEndpoint:
    @pytest.mark.parametrize('url', [
        'https://acme.sectigo.com/v2/DV',
        'https://acme.sectigo.com/v2/OV',
    ])
    def test_sectigo_uses_supplied_directory_without_exposing_hmac(self, api, url):
        r = api.post_json('/api/settings/test-ca-provider', {
            'ca_provider': 'sectigo',
            'config': {'acme_url': url, 'eab_kid': 'example-kid',
                       'eab_hmac': 'example-secret', 'email': 'ops@example.com'},
        })
        assert r.status_code == 200
        assert r.json()['success'] is True
        assert r.json()['acme_url'] == url
        assert 'example-secret' not in r.text

    @pytest.mark.parametrize('missing, expected', [
        ('acme_url', 'ACME Directory URL'),
        ('eab_kid', 'EAB Key ID'),
        ('eab_hmac', 'HMAC Key'),
    ])
    def test_sectigo_missing_required_field(self, api, missing, expected):
        config = {'acme_url': 'https://acme.sectigo.com/v2/OV',
                  'eab_kid': 'example-kid', 'eab_hmac': 'example-secret',
                  'email': 'ops@example.com'}
        del config[missing]
        r = api.post_json('/api/settings/test-ca-provider', {
            'ca_provider': 'sectigo', 'config': config,
        })
        assert r.status_code == 200
        assert r.json()['success'] is False
        assert expected in r.json()['message']

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

    def test_digicert_accepts_canonical_field_spelling(self, api):
        # The DigiCert branch historically read only eab_kid/eab_hmac;
        # the canonical settings.json spelling must work too.
        r = api.post_json("/api/settings/test-ca-provider", {
            "ca_provider": "digicert",
            "config": {
                "acme_url": "https://one.digicert.com/mpki/api/v1/acme/v2/directory",
                "eab_key_id": "kid-canonical-spelling",
                "eab_hmac_key": "hmac-canonical-spelling-long-enough-to-pass",
                "email": "admin@example.com",
            },
        })
        assert r.status_code == 200
        assert r.json()["success"] is True

    def test_unknown_provider_rejected(self, api):
        r = api.post_json("/api/settings/test-ca-provider", {
            "ca_provider": "not-a-ca",
            "config": {},
        })
        assert r.status_code == 400
