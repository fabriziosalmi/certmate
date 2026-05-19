"""Regression tests for the certbot stderr sanitiser (internal security
audit, May 2026, finding H3).

Before this fix, when ``certbot`` failed at credential parsing time the
plugin echoed the offending ``.ini`` line verbatim into stderr. The
``CertificateManager.create_certificate`` / ``renew_certificate`` flows
wrapped that stderr into a ``RuntimeError`` whose ``str(e)`` flowed back
into the API response body (``modules/web/cert_routes.py:145, 202``).
Net result: a misconfigured ``dns_azure_sp_client_secret = <REAL>`` line
landed in the JSON 422 the operator saw.

The fix splits the two consumers:

* The application log keeps the raw stderr — operators reading
  ``data/logs/`` still see every detail and can debug the failure.
* The exception that flows into the API response is sanitised:
  credential-bearing lines redact their value, paths to the
  credentials ``.ini`` are replaced with a generic marker, and the
  whole message is capped so a verbose certbot trace cannot bloat the
  response.

Helper lives in ``modules/core/utils.py::sanitize_certbot_stderr`` and
the contract pinned below is what the API depends on. Future regressions
that re-route credential text into the response will fail one of these
test cases.
"""

import pytest

from modules.core.utils import sanitize_certbot_stderr


pytestmark = [pytest.mark.unit]


class TestSanitizeCertbotStderr:
    """The core contract: secret values out, ACME / plugin narration in."""

    def test_redacts_azure_sp_client_secret_line(self):
        raw = (
            "Saving debug log to /app/certificates/example.com/logs/letsencrypt.log\n"
            "letsencrypt/config/azure.ini: parse error\n"
            "dns_azure_sp_client_secret = SUPER-SECRET-VALUE-do-not-leak\n"
            "Ask for help at https://community.letsencrypt.org.\n"
        )
        out = sanitize_certbot_stderr(raw)
        assert 'SUPER-SECRET-VALUE-do-not-leak' not in out
        assert 'dns_azure_sp_client_secret = [REDACTED]' in out
        # ACME help URL and the general narration must survive.
        assert 'community.letsencrypt.org' in out

    def test_redacts_route53_aws_keys(self):
        raw = (
            "dns_route53_access_key_id = AKIAIDISCLOSURE1234\n"
            "dns_route53_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "Error 403 from Route53\n"
        )
        out = sanitize_certbot_stderr(raw)
        assert 'AKIAIDISCLOSURE1234' not in out
        assert 'wJalrXUtnFEMI' not in out
        # And the operational error survives so the operator knows
        # *why* the plugin failed.
        assert 'Error 403' in out

    def test_redacts_cloudflare_api_token(self):
        raw = "dns_cloudflare_api_token = aZmRyZHNmbmFkc2tqaG\n"
        out = sanitize_certbot_stderr(raw)
        assert 'aZmRyZHNmbmFkc2tqaG' not in out
        assert '[REDACTED]' in out

    def test_redacts_generic_password_and_credential_lines(self):
        raw = (
            "dns_powerdns_api_key = AAAAAAAA\n"
            "smtp_password = HelloPass\n"
            "vault_token = hvs.SUPER-VAULT-TOKEN\n"
            "api_bearer_token = certmate_BEARER_xyz\n"
        )
        out = sanitize_certbot_stderr(raw)
        for needle in ('AAAAAAAA', 'HelloPass', 'hvs.SUPER-VAULT-TOKEN', 'certmate_BEARER_xyz'):
            assert needle not in out, f'{needle!r} leaked through'

    def test_redacts_credential_config_paths(self):
        raw = (
            "letsencrypt/config/azure.ini: parse error\n"
            "more output\n"
            "see /opt/certmate/letsencrypt/config/cloudflare.ini\n"
        )
        out = sanitize_certbot_stderr(raw)
        # Both the bare relative path and the rooted absolute path are
        # normalised to the same generic marker.
        assert 'letsencrypt/config/azure.ini' not in out
        assert 'letsencrypt/config/cloudflare.ini' not in out
        assert '<credential file>' in out

    def test_preserves_non_secret_narration(self):
        """Anything that does NOT name a credential field must survive
        unredacted so operators can still read the error narrative."""
        raw = (
            "Saving debug log to /app/log/letsencrypt.log\n"
            "An unexpected error occurred:\n"
            "Error finalizing order :: rate limit exceeded\n"
            "Ask for help or search for solutions at https://community.letsencrypt.org.\n"
        )
        out = sanitize_certbot_stderr(raw)
        # No credentials were present; the narration must round-trip.
        assert 'rate limit exceeded' in out
        assert 'community.letsencrypt.org' in out
        assert '[REDACTED]' not in out

    def test_caps_output_size(self):
        raw = 'A' * 10_000
        out = sanitize_certbot_stderr(raw)
        # Hard cap from the implementation is 4096; the truncation
        # marker is appended after.
        assert len(out) <= 4096 + len('\n[…truncated — see application log for full output]')
        assert '[…truncated' in out

    def test_empty_input_returns_empty_string(self):
        assert sanitize_certbot_stderr('') == ''
        assert sanitize_certbot_stderr(None) == ''

    def test_partial_word_does_not_trigger(self):
        """The pattern is anchored on whole credential-name fragments so
        a non-secret line containing the substring ``secret`` (e.g.
        somebody's domain name) is not corrupted by the regex."""
        raw = (
            "Validating https://mysecretrecipe.com — DNS challenge passed\n"
            "Order finalised successfully\n"
        )
        out = sanitize_certbot_stderr(raw)
        assert 'mysecretrecipe.com' in out
        assert 'Order finalised successfully' in out
