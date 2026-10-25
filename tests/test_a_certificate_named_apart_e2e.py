"""Two real certificates for one host, one named apart from it (#1149).

Requires Docker and CLOUDFLARE_API_TOKEN (skips otherwise); uses random
subdomains under CERTMATE_TEST_DOMAIN, and Let's Encrypt STAGING (see
tests/e2e_support.py).

The unit tests stand in for certbot. This asks a real CA: the certificate
named apart is issued, renewed and reissued for its host, never for its name,
its deployment check probes the host, and deleting it leaves the certificate
named by the host as it was.

Cert burn: 4 staging orders per run (two creates, a renewal, a reissue).
"""
import os
import uuid

import pytest

from tests.e2e_support import (
    E2E_CA_PROVIDER,
    assert_staging_issuer,
    configure_e2e_provider,
    skip_if_the_ca_was_unavailable,
)

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

BASE_DOMAIN = os.environ.get("CERTMATE_TEST_DOMAIN", "gpfree.org")
_RUN = uuid.uuid4().hex[:8]
HOST = f"e2e-host-{_RUN}.{BASE_DOMAIN}"
NAME = f"e2e-named-{_RUN}.{BASE_DOMAIN}"
ACCOUNT = "e2e-named"

# What each step saw, for the steps after it.
_seen = {}


@pytest.fixture(scope="module", autouse=True)
def configure_cloudflare(api, cloudflare_token):
    configure_e2e_provider(api, cloudflare_token, ACCOUNT)
    yield
    for name in (NAME, HOST):
        api.delete(f"/api/certificates/{name}")
    api.delete(f"/api/dns/cloudflare/accounts/{ACCOUNT}")


def _issued(response, what):
    if response.status_code not in (200, 201):
        skip_if_the_ca_was_unavailable({"status": "failed", "error": response.text})
    assert response.status_code in (200, 201), f"{what}: {response.status_code} {response.text[:300]}"
    return response.json()


def _leaf(api, name):
    """The certificate served under *name*: its fingerprint, serial and DNS names."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    r = api.get(f"/api/certificates/{name}/download?format=json")
    assert r.status_code == 200, f"download {name}: {r.status_code} {r.text[:200]}"
    pem = r.json()["cert_pem"]
    assert_staging_issuer(pem)
    cert = x509.load_pem_x509_certificate(pem.encode())
    names = cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
    return cert.fingerprint(hashes.SHA256()).hex(), cert.serial_number, sorted(names)


class TestTwoCertificatesForOneHost:

    def test_01_the_host_is_issued_under_its_own_name(self, api):
        _issued(api.post_json("/api/certificates/create", {
            "domain": HOST, "dns_provider": "cloudflare", "account_id": ACCOUNT,
            "ca_provider": E2E_CA_PROVIDER,
        }), "create the host")
        _seen["host"] = _leaf(api, HOST)
        assert _seen["host"][2] == [HOST]

    def test_02_a_second_one_for_the_host_is_issued_under_a_name_apart(self, api):
        body = _issued(api.post_json("/api/certificates/create", {
            "domain": HOST, "name": NAME, "dns_provider": "cloudflare",
            "account_id": ACCOUNT, "ca_provider": E2E_CA_PROVIDER,
        }), "create the named one")
        assert (body["domain"], body["host"]) == (NAME, HOST)
        _seen["named"] = _leaf(api, NAME)
        # Issued for the host, never for the name, and a certificate of its own.
        assert _seen["named"][2] == [HOST]
        assert _seen["named"][0] != _seen["host"][0]

    def test_03_both_are_listed_each_for_the_host(self, api):
        listed = {c["domain"]: c.get("host") for c in api.get("/api/certificates").json()}
        assert (listed.get(HOST), listed.get(NAME)) == (HOST, HOST)

    def test_04_the_named_one_renews_for_the_host_and_the_other_is_untouched(self, api):
        _issued(api.post_json(f"/api/certificates/{NAME}/renew", {"force": True}), "renew")
        fingerprint, serial, names = _leaf(api, NAME)
        assert serial != _seen["named"][1] and names == [HOST]
        assert _leaf(api, HOST) == _seen["host"]
        _seen["named"] = (fingerprint, serial, names)

    def test_05_the_named_one_reissues_for_the_host(self, api):
        _issued(api.post_json(f"/api/certificates/{NAME}/reissue", {}), "reissue")
        _fingerprint, serial, names = _leaf(api, NAME)
        assert serial != _seen["named"][1] and names == [HOST]
        assert _leaf(api, HOST) == _seen["host"]

    def test_06_its_deployment_check_probes_the_host(self, api):
        r = api.get(f"/api/certificates/{NAME}/deployment-status?refresh=1")
        assert r.status_code == 200, f"{r.status_code} {r.text[:200]}"
        assert r.json()["probe_host"] == HOST

    def test_07_deleting_the_named_one_leaves_the_other_as_it_was(self, api):
        r = api.delete(f"/api/certificates/{NAME}")
        assert r.status_code == 200, f"{r.status_code} {r.text[:200]}"
        assert api.get(f"/api/certificates/{NAME}").status_code == 404
        assert _leaf(api, HOST) == _seen["host"]
        listed = [c["domain"] for c in api.get("/api/certificates").json()]
        assert HOST in listed and NAME not in listed
