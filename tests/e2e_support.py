"""Shared helpers for the real-cert E2E tests (staging-safe issuance).

These tests issue REAL certificates against a live ACME server via Cloudflare
DNS-01. To make that safe to run anywhere (CI, a developer laptop, a cron),
issuance defaults to Let's Encrypt STAGING: a run can never silently burn the
production rate limit (5 certs/registered-domain/week) or mint a publicly
trusted certificate on the test domain.

Two safety mechanisms, belt and suspenders:

1. ``configure_e2e_provider`` writes a NON-EMPTY ``ca_providers.letsencrypt_staging``
   entry and pins ``default_ca`` to it. An EMPTY staging entry aliases back to
   production Let's Encrypt in ``ca_manager.get_ca_config`` (ca_manager.py:123-133),
   so populating it is what actually keeps issuance on staging.
2. ``assert_staging_issuer`` inspects the ISSUED leaf. The requested
   ``ca_provider`` is echoed back on the response regardless of what the CA
   resolution did, so the only real proof that staging was used is the issuer
   on the certificate itself (LE staging issuers carry ``(STAGING)`` in their
   name). If anything ever downgraded a run to production, the assertion fails
   loudly instead of quietly issuing a trusted cert.
"""
import os

# Default to STAGING. Override with CERTMATE_E2E_CA_PROVIDER=letsencrypt for a
# deliberate production run (rare, and never in CI).
E2E_CA_PROVIDER = os.environ.get("CERTMATE_E2E_CA_PROVIDER", "letsencrypt_staging")
TEST_EMAIL = os.environ.get("CERTMATE_TEST_EMAIL", "test@gpfree.org")


def configure_e2e_provider(api, cloudflare_token, account_id):
    """Pin the CA to E2E_CA_PROVIDER and register a Cloudflare DNS account.

    Writes both ``ca_providers.letsencrypt`` and a non-empty
    ``ca_providers.letsencrypt_staging`` (each carrying an email) so the
    staging selection does not alias to production, and sets ``default_ca``
    so a create that omits ``ca_provider`` still stays on staging.
    """
    r = api.post_json("/api/web/settings", {
        "email": TEST_EMAIL,
        "dns_provider": "cloudflare",
        "default_ca": E2E_CA_PROVIDER,
        "ca_providers": {
            "letsencrypt": {"email": TEST_EMAIL},
            "letsencrypt_staging": {"email": TEST_EMAIL},
        },
    })
    assert r.status_code in (200, 201), \
        f"E2E settings setup failed: {r.status_code} {r.text[:300]}"
    r = api.post_json("/api/dns/cloudflare/accounts", {
        "account_id": account_id,
        "config": {"api_token": cloudflare_token},
    })
    assert r.status_code in (200, 201), \
        f"E2E Cloudflare account setup failed: {r.status_code} {r.text[:300]}"


def assert_staging_issuer(cert_pem):
    """Fail unless the leaf in *cert_pem* was issued by Let's Encrypt STAGING.

    This is the hard safety net against the staging->production alias trap:
    it reads the actual issuer off the issued certificate rather than trusting
    the requested ``ca_provider`` that the API echoes back. Returns the issuer
    string for logging.
    """
    from cryptography import x509
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    issuer = cert.issuer.rfc4514_string()
    assert "STAGING" in issuer.upper(), \
        f"certificate was NOT issued by Let's Encrypt staging — issuer={issuer!r}"
    return issuer


# Failures that come from the certificate authority, not from CertMate.
# An e2e failure has to mean "CertMate is broken"; when it can also mean
# "Let's Encrypt was busy", the reliable response becomes re-running until
# green, which is how a real regression gets waved through.
#
# Every phrase here is CA wording, matched as specifically as possible. A bare
# "internal error" was rejected during review for good reason: CertMate raises
# its own internal errors, and skipping one would convert a regression into
# silence — worse than the flakiness this replaces.
_CA_TRANSIENTS = (
    "service busy",
    "too many requests",
    "urn:ietf:params:acme:error:ratelimited",
    "rate limit",
    "timeout during connect",
    "the server experienced an internal error",
    "server experienced an internal error",
)


def skip_if_the_ca_was_unavailable(job):
    """Turn a CA-side refusal into a skip, naming what happened.

    Deliberately narrow: only an explicit CA phrase excuses a failed job.
    Anything else is CertMate's problem and must stay a failure.
    """
    import pytest

    if not isinstance(job, dict) or job.get("status") != "failed":
        return
    error = str(job.get("error") or "").lower()
    for phrase in _CA_TRANSIENTS:
        if phrase in error:
            pytest.skip(
                f"Let's Encrypt staging declined the order ({phrase}); this is "
                f"the CA refusing to serve, not a CertMate defect"
            )
