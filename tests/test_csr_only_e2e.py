"""Real-CA proof that a CSR-only certificate works end to end (#599).

The unit tests pin the decisions; this pins the thing they cannot: that a CSR
generated outside CertMate, submitted over the API, produces a real certificate
from a real ACME server — and that the private key never lands on this node.

Issues against Let's Encrypt STAGING through Cloudflare DNS-01, like the other
real-cert tests. Cert burn: 2 staging certificates per run (one issuance, one
renewal from the stored CSR).

What it proves that nothing else can:

* certbot's ``--csr`` mode really is driven correctly by the built command —
  the golden master says what the argv looks like, not that a CA accepts it;
* the issued certificate covers the names in the CSR, which is the claim the
  whole feature rests on;
* **no privkey.pem is written**, which is the point;
* the certificate reports ``private_key_state: external`` and does NOT ask to
  be renewed — the #608 collision, checked against a real certificate rather
  than a constructed one;
* renewal re-issues from the stored CSR and produces a certificate for the same
  names, without ever having a key.
"""
import os
import uuid

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtensionOID, NameOID

from tests.e2e_support import (
    E2E_CA_PROVIDER,
    assert_staging_issuer,
    configure_e2e_provider,
    skip_if_the_ca_was_unavailable,
)

pytestmark = [pytest.mark.e2e, pytest.mark.slow]

BASE_DOMAIN = os.environ.get("CERTMATE_TEST_DOMAIN", "gpfree.org")
TEST_EMAIL = os.environ.get("CERTMATE_TEST_EMAIL", "test@gpfree.org")
_RUN = uuid.uuid4().hex[:6]


@pytest.fixture(scope="module", autouse=True)
def configure_cloudflare(api, cloudflare_token):
    configure_e2e_provider(api, cloudflare_token, "e2e-csr")
    yield
    api.delete("/api/dns/cloudflare/accounts/e2e-csr")


def _make_csr(primary, extra):
    """A CSR the way an appliance would produce one: key generated here and
    never handed over, CN plus a SAN list."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, primary)]))
           .add_extension(
               x509.SubjectAlternativeName(
                   [x509.DNSName(n) for n in [primary] + list(extra)]),
               critical=False)
           .sign(key, hashes.SHA256()))
    return csr.public_bytes(serialization.Encoding.PEM).decode()


def _skip_if_the_ca_declined(response):
    """The synchronous shape of `skip_if_the_ca_was_unavailable`.

    That helper reads a JOB dict, and this path returns an HTTP response — so
    passing the response to it would do nothing at all and read as a safety net
    that is not there. It is reused rather than reimplemented: the response is
    turned into the shape it expects.
    """
    if response.status_code < 400:
        return
    try:
        error = response.json().get('error') or response.text
    except ValueError:
        error = response.text
    skip_if_the_ca_was_unavailable({'status': 'failed', 'error': error})


def _leaf_names(cert_pem):
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    san = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    return set(san.value.get_values_for_type(x509.DNSName))


def test_a_csr_from_a_device_produces_a_real_certificate(api, docker_container):
    primary = f"csr-{_RUN}.{BASE_DOMAIN}"
    extra = f"csr-alt-{_RUN}.{BASE_DOMAIN}"
    csr_pem = _make_csr(primary, [extra])

    r = api.post_json("/api/certificates/create", {
        "domain": primary,
        "dns_provider": "cloudflare",
        "account_id": "e2e-csr",
        "ca_provider": E2E_CA_PROVIDER,
        "csr": csr_pem,
    }, timeout=600)
    _skip_if_the_ca_declined(r)
    assert r.status_code in (200, 201), f"{r.status_code} {r.text[:500]}"

    # The certificate itself, not the API's echo of what was requested.
    download = api.get(f"/api/certificates/{primary}/download/cert")
    assert download.status_code == 200, download.text[:300]
    cert_pem = download.text
    assert_staging_issuer(cert_pem)

    assert _leaf_names(cert_pem) == {primary, extra}, (
        "the issued certificate does not cover exactly the names in the CSR"
    )

    # THE point of the feature: no key on this node.
    key = api.get(f"/api/certificates/{primary}/download/privkey")
    assert key.status_code in (400, 404), (
        f"a private key was downloadable for a CSR-only certificate "
        f"({key.status_code}) — CertMate was never supposed to have one"
    )

    info = api.get(f"/api/certificates/{primary}").json()
    assert info["private_key_state"] == "external", info
    assert info["private_key_present"] is False, info
    assert info["usable"] is None, info
    assert info["needs_renewal"] is False, (
        "a fresh CSR-only certificate is asking to be renewed — #608's rule is "
        f"treating its deliberate keylessness as a lost key: {info}"
    )

    # Renewal: certbot renew cannot touch this, so CertMate must re-issue from
    # the CSR it stored. Forced, because nothing is due after five minutes.
    before = _leaf_names(cert_pem)
    renew = api.post_json(f"/api/certificates/{primary}/renew",
                          {"force": True}, timeout=600)
    _skip_if_the_ca_declined(renew)
    assert renew.status_code == 200, f"{renew.status_code} {renew.text[:500]}"

    after_pem = api.get(f"/api/certificates/{primary}/download/cert").text
    assert_staging_issuer(after_pem)
    assert _leaf_names(after_pem) == before, (
        "the renewal produced a certificate for different names — the stored "
        "CSR was not the one re-submitted"
    )
    still = api.get(f"/api/certificates/{primary}").json()
    assert still["private_key_state"] == "external", (
        f"the renewal left a key behind: {still}"
    )

    api.delete(f"/api/certificates/{primary}")
