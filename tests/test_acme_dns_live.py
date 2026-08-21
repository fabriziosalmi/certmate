"""The acme-dns hook against a real acme-dns, including the DNS answer.

acme-dns is the one path in this product with a documented history of never
having worked: the certbot plugin CertMate used until v2.24.0 exposes no
credentials-file option at all, so certbot rejected the command line and every
acme-dns issuance failed — in every release that advertised it. The replacement
publishes the TXT record itself, and was verified by hand once, against
acme-dns.io. Nothing has verified it since.

A mock cannot verify it. The whole failure mode was an API contract that looked
right and was not, so the only test that means anything drives the real hook
against a real server and then asks DNS whether the record is there. That last
step is the point: "the POST returned 200" is what a fake would tell you.

    CERTMATE_TEST_ACMEDNS_URL=http://localhost:18080 \\
    CERTMATE_TEST_ACMEDNS_DNS=127.0.0.1:18053 \\
    pytest tests/test_acme_dns_live.py -m live

Skipped when unset; failed, never skipped, when set and the server is silent.
"""
import base64
import hashlib
import json
import os
import urllib.error
import urllib.request

import pytest

from modules.core.dns_alias_hook import DNSAliasError, _acme_dns_change

pytestmark = [pytest.mark.live]

API = os.getenv("CERTMATE_TEST_ACMEDNS_URL")
DNS = os.getenv("CERTMATE_TEST_ACMEDNS_DNS", "127.0.0.1:18053")


def _validation():
    """43 characters of base64url, which is what ACME actually sends.

    acme-dns rejects anything else with `bad_txt`, and it is right to: the
    value is a SHA-256 digest of the key authorization. A test that sends a
    friendly string tests the error path by accident.
    """
    digest = hashlib.sha256(os.urandom(32)).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@pytest.fixture(scope="module")
def account():
    if not API:
        pytest.skip("CERTMATE_TEST_ACMEDNS_URL not set")
    try:
        with urllib.request.urlopen(
                urllib.request.Request(API.rstrip("/") + "/register", method="POST"),
                timeout=20) as response:
            return json.loads(response.read())
    except Exception as error:
        pytest.fail(
            f"{API} is configured but registration failed ({error}). Treating "
            f"that as a skip is how a suite reports success against a server "
            f"that never started."
        )


def _txt_records(fqdn):
    import dns.resolver

    host, _, port = DNS.partition(":")
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [host]
    resolver.port = int(port or 53)
    resolver.lifetime = 15
    answer = resolver.resolve(fqdn, "TXT")
    return {b"".join(rdata.strings).decode() for rdata in answer}


def _config(account, password=None):
    return {
        "domain_alias": account["subdomain"],
        "config": {
            "api_url": API,
            "username": account["username"],
            "password": password or account["password"],
            "subdomain": account["subdomain"],
        },
    }


def test_the_hook_publishes_a_record_dns_will_serve(account):
    """The whole point: not that the POST succeeded, but that DNS answers."""
    validation = _validation()
    _acme_dns_change(_config(account), validation, "create")

    served = _txt_records(account["fulldomain"])
    assert validation in served, (
        f"the hook reported success and {account['fulldomain']} serves "
        f"{served or 'nothing'}. This is the shape of the failure that made "
        f"acme-dns unusable in every release before v2.24.1: the call looked "
        f"fine and no record existed."
    )


def test_acme_dns_keeps_the_last_two_validations_and_drops_the_third_oldest(account):
    """acme-dns serves the two most recent TXT values by design: an order for
    ``example.com`` + ``*.example.com`` needs two challenges live on the same
    subdomain at once. So a second validation does not replace the first — it
    joins it — and only a third pushes the first out. Asserting both halves is
    what distinguishes "the hook updates the record" from "the newest value
    happens to be present" (Copilot, #560)."""
    first, second, third = _validation(), _validation(), _validation()
    _acme_dns_change(_config(account), first, "create")
    _acme_dns_change(_config(account), second, "create")
    served = _txt_records(account["fulldomain"])
    assert first in served and second in served, (
        f"after two updates acme-dns should serve both values, got {served}")

    _acme_dns_change(_config(account), third, "create")
    served = _txt_records(account["fulldomain"])
    assert third in served and second in served, (
        f"the two newest validations are not both served: {served}")
    assert first not in served, (
        f"the oldest validation is still served after two newer ones: {served}")


def test_wrong_credentials_are_refused_rather_than_ignored(account):
    """A silently-ignored rejection is an issuance that fails much later."""
    with pytest.raises(DNSAliasError) as error:
        _acme_dns_change(_config(account, password="not-the-password"),
                         _validation(), "create")
    assert "401" in str(error.value) or "forbidden" in str(error.value).lower()


def test_a_mismatched_alias_is_caught_before_the_network(account):
    """CertMate's own guard: the alias must be the registered subdomain."""
    config = _config(account)
    config["domain_alias"] = "someone-elses-subdomain"
    with pytest.raises(DNSAliasError) as error:
        _acme_dns_change(config, _validation(), "create")
    assert "must match" in str(error.value)


def test_delete_is_a_no_op(account):
    """acme-dns has no delete: the record is replaced, never removed.

    Pinned because a hook that raised here would fail certbot's cleanup phase
    and leave every issuance reporting an error after a successful validation.
    """
    assert _acme_dns_change(_config(account), _validation(), "delete") is None
