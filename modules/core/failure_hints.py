"""What to check after certbot or the CA refused: the hints a failed issuance,
renewal or reissue carries.

Moved here from `modules/api/resources_lifecycle.py` (UX perception audit,
2026-11-18, P37), unchanged: a failed renewal is now kept beside the
certificate with its hint (`CertificateManager.record_renewal_failure`), and
the nightly sweep, which never passes through the API, has to say the same
thing the renewal job's toast says. The API module imports them back.
"""
import re

from .utils import classify_renewal_error, is_acme_rate_limit

# The CA refused the challenge answer: certbot's "The Certificate Authority
# reported these problems" block, or the ACME problem types for a failed
# validation. What to check then depends on the challenge, not on DNS
# credentials (#1460).
_CA_REFUSED_MARKERS = (
    'the certificate authority reported these problems',
    'some challenges have failed',
    'authorizations were not finalized',
    'acme:error:unauthorized',
    'acme:error:connection',
    'acme:error:dns',
    'acme:error:incorrectresponse',
    'invalid response from',
    'incorrect txt record',
    'dns problem',
)
# A DNS provider refusing CertMate's own credentials. "auth" alone also matched
# "authorizations", which is the CA's word for a validation.
_DNS_CREDENTIAL_MARKERS = ('unauthorized', 'authentication', 'invalid token', 'invalid api',
                           'credentials', 'forbidden')

_HTTP01_HINT = ('The CA could not reach the http-01 challenge: check that the name resolves to '
                'this host and that port 80 reaches CertMate.')
_DNS01_HINT = ('The CA could not verify the DNS TXT record: check that it was created in the '
               "name's zone and has had time to propagate.")


def _challenge_named_in(lowered: str):
    """The challenge the CA's own words point to, or None."""
    if '/.well-known/acme-challenge/' in lowered or 'http-01' in lowered:
        return 'http-01'
    if '_acme-challenge' in lowered or 'dns-01' in lowered or 'txt record' in lowered:
        return 'dns-01'
    return None


# certbot could not reach the CA's ACME directory at all (UX audit,
# 2026-11-17: a private CA on a closed port was told to check its DNS
# credentials). Recognised by urllib3's own words, which only certbot's own
# requests produce: "Connection refused" alone is also what the CA says when
# it cannot reach this host for http-01, and that keeps its own hint.
_CA_UNREACHABLE_MARKERS = (
    'max retries exceeded with url',
    'newconnectionerror',
    'connectionpool(host=',
)
_CA_TLS_MARKERS = ('certificate verify failed', 'sslcertverificationerror')
_POOL_URL = re.compile(r"(https?)connectionpool\(host='([^']+)', port=(\d+)\): max retries exceeded with url: (\S+)",
                       re.IGNORECASE)


def _ca_unreachable_hint(error_msg: str):
    """What to check when the CA's directory could not be reached, or None."""
    lowered = error_msg.lower()
    if not any(marker in lowered for marker in _CA_UNREACHABLE_MARKERS):
        return None
    tls = any(marker in lowered for marker in _CA_TLS_MARKERS)
    found = _POOL_URL.search(error_msg)
    where = f' at {found.group(1).lower()}://{found.group(2)}:{found.group(3)}{found.group(4)}' if found else ''
    if tls:
        return (f"CertMate could not verify the TLS certificate of the CA's ACME directory{where}: "
                "for a private CA, add its root certificate to the CA account's trust bundle.")
    return (f"CertMate could not reach the CA's ACME directory{where}: check the directory URL, "
            "that its name resolves from this host, and that outbound HTTPS to it is allowed.")


# The CA refused to register the ACME account, nearly always for its contact
# email (UX perception audit, 2026-11-18: Let's Encrypt refusing
# me@homelab.example was told to check DNS credentials). RFC 8555 names the
# problem types invalidContact and unsupportedContact; invalidEmail is the
# ACME v1 name, which a CA still on the old wording may send.
_ACCOUNT_REFUSED_MARKERS = ('unable to register an account', 'invalidcontact', 'unsupportedcontact',
                            'invalidemail', 'invalid email address')
_ACCOUNT_REFUSED_HINT = ('The CA refused to register the ACME account: check the contact email on the '
                         'CA account under Settings > CA (it must be a real, deliverable address).')
# certbot exited without a word (certificates.py): the one unmatched failure
# whose own text gives no cause, so the challenge's usual suspect is better
# than nothing.
_NOTHING_REPORTED = 'without reporting an error'
PREVIOUS_KEPT = 'The previous certificate is still in place.'
# An ACME problem document, which only the CA sends (RFC 8555 section 6.7).
_ACME_PROBLEM = 'urn:ietf:params:acme:error:'
# The CA refused the order itself, at new-order or at finalize: a name its
# policy forbids, a CAA record, an identifier or a CSR it rejects. Retrying
# against staging meets the same refusal.
_ORDER_REFUSED_MARKERS = (
    'error creating new order',
    'error finalizing order',
    'forbidden by policy',
    'acme:error:rejectedidentifier',
    'acme:error:caa',
    'caa record',
    'rechecking caa',
    'acme:error:badcsr',
)
_ACCOUNT_MARKERS = (*_ACCOUNT_REFUSED_MARKERS, 'acme:error:accountdoesnotexist',
                    'acme:error:externalaccountrequired')

# The CA answered with a fault of its own, not a refusal: a server error, a
# nonce to retry with, maintenance. Checked before the order markers, because
# certbot prefixes a server error at new-order with "Error creating new order".
_CA_SERVER_MARKERS = (
    'acme:error:serverinternal',
    'acme:error:badnonce',
    'service is down for maintenance',
    'had an internal error',
)

CA_FAILURE_VALIDATION = 'validation'
CA_FAILURE_RATE_LIMIT = 'rate_limit'
CA_FAILURE_ACCOUNT = 'account'
CA_FAILURE_ORDER = 'order'
CA_FAILURE_OTHER = 'other'


def ca_failure(error_msg: str | None) -> str | None:
    """What the CA's answer, in the failure's own words, says went wrong.

    Read from the whole error, in this order (the first that matches wins):

    * None: the CA's directory could not be reached (urllib3's own words), or
      nothing in the error shows the CA answered (no certbot lineage to renew,
      a certificate that already exists, a DNS provider refusing CertMate's
      credentials before any challenge).
    * "rate_limit": `is_acme_rate_limit` (the rateLimited problem type, Let's
      Encrypt's "too many certificates", "too many failed authorizations",
      "too many new orders", "too many new registrations", its rate-limits
      page).
    * "other", first: the CA's own fault, not a refusal (serverInternal,
      badNonce, "service is down for maintenance", "had an internal error"),
      even inside "Error creating new order :: ...".
    * "account": the account registration or the account was refused
      (unable to register an account, invalidContact, unsupportedContact,
      invalidEmail, "invalid email address", accountDoesNotExist,
      externalAccountRequired).
    * "order": the CA refused the order at new-order or at finalize ("Error
      creating new order", "Error finalizing order", "forbidden by policy",
      rejectedIdentifier, caa or a CAA record, badCSR).
    * "validation": a challenge failed at the CA (_CA_REFUSED_MARKERS: "Some
      challenges have failed", "DNS problem", "Invalid response from", the
      unauthorized, connection, dns and incorrectResponse problem types).
    * "other": any other ACME problem document (serverInternal, malformed...).

    The dashboard suggests testing with staging only for "validation" and
    "rate_limit" at production Let's Encrypt (UX perception audit, 2026-11-18,
    P22): what staging helps with is repeating validation attempts without
    spending production's limits. Staging refuses the same account email and
    the same order.
    """
    lowered = (error_msg or '').lower()
    if not lowered or _ca_unreachable_hint(error_msg or ''):
        return None
    if is_acme_rate_limit(error_msg):
        return CA_FAILURE_RATE_LIMIT
    if any(marker in lowered for marker in _CA_SERVER_MARKERS):
        return CA_FAILURE_OTHER
    if any(marker in lowered for marker in _ACCOUNT_MARKERS):
        return CA_FAILURE_ACCOUNT
    if any(marker in lowered for marker in _ORDER_REFUSED_MARKERS):
        return CA_FAILURE_ORDER
    if any(marker in lowered for marker in _CA_REFUSED_MARKERS):
        return CA_FAILURE_VALIDATION
    if _ACME_PROBLEM in lowered:
        return CA_FAILURE_OTHER
    return None


def certbot_hint(error_msg: str, challenge_type: str | None = None, fallback: bool = True) -> str | None:
    """The same, for a failure certbot reported.

    Rate limits are tested first, and with `is_acme_rate_limit` rather than
    the substring `rate limit`. The substring matched none of the markers the
    CA actually sends: `urn:ietf:params:acme:error:rateLimited` has no space
    in it, and `too many certificates already issued` does not contain the
    words at all. Measured before this, on real refusals:

        rateLimited: too many certificates -> "Check DNS provider credentials"
        too many certificates (5) issued   -> "Check DNS provider credentials"
        too many failed authorizations     -> "DNS provider authentication
                                               failed. Verify your API
                                               credentials in settings."

    The third is the one that decided the order. It contains "auth", so it
    reached the authentication branch and told an operator to go and rotate
    credentials that were working, about a refusal that retrying makes worse.

    An error no rule knows ends on the generic DNS or port-80 hint when
    *fallback* is set: the synchronous 422 answers with a string hint, and
    a caller may rely on it. A job's explanation passes fallback=False and
    gets None instead: the generic hint guessed a wrong cause (CertMate's
    own "HTTP-01 challenge does not support wildcard domains" was told to
    check port 80), and the dashboard's toast shows the error's cause first.
    """
    if is_acme_rate_limit(error_msg):
        return "You've hit the certificate authority's rate limit. Wait before trying again."
    lowered = (error_msg or '').lower()
    unreachable = _ca_unreachable_hint(error_msg or '')
    if unreachable:
        return unreachable
    if any(marker in lowered for marker in _ACCOUNT_REFUSED_MARKERS):
        return _ACCOUNT_REFUSED_HINT
    # The CA's words name the challenge more surely than the request does: an
    # IP certificate is http-01 whatever the request or the default said.
    challenge = _challenge_named_in(lowered) or (challenge_type or '').lower() or None
    http01 = challenge == 'http-01'
    if any(marker in lowered for marker in _CA_REFUSED_MARKERS):
        return _HTTP01_HINT if http01 else _DNS01_HINT
    if not http01 and any(marker in lowered for marker in _DNS_CREDENTIAL_MARKERS):
        return 'DNS provider authentication failed. Verify your API credentials in settings.'
    if 'timeout' in lowered or 'timed out' in lowered:
        if http01:
            return 'The CA timed out reaching this host: check that port 80 is open and reaches CertMate.'
        return 'DNS propagation timed out. Try increasing DNS propagation time in settings.'
    if not fallback and _NOTHING_REPORTED not in lowered:
        return None
    if http01:
        return 'Check that the name resolves to this host and that port 80 reaches CertMate.'
    return 'Check DNS provider credentials and ensure DNS records can be created.'


def with_previous_kept(hint: str | None) -> str:
    """*hint*, then the sentence a failed reissue or renewal always earns."""
    return f'{hint} {PREVIOUS_KEPT}' if hint else PREVIOUS_KEPT


def renewal_failure(error_msg: str, challenge_type: str | None = None):
    """What a renewal job that failed says to check (UX perception audit,
    2026-11-18: the async renew passed no explanation, so the dashboard
    showed certbot's raw output and nothing said the site was still up).

    The code is the one the synchronous renew answers with, from the same
    `classify_renewal_error`. When it knows the cause (any code but the
    generic RENEWAL_FAILED), its message is the hint, as the synchronous
    renew answers; otherwise certbot's hint, with no generic fallback. A
    failed renewal leaves the previous certificate served, and the hint ends
    by saying so. With no rule matching, that sentence is the whole hint,
    and the dashboard's toast leads with the error's own cause.
    """
    message, code = classify_renewal_error(error_msg)
    hint = message if code != 'RENEWAL_FAILED' else certbot_hint(error_msg, challenge_type, fallback=False)
    return {'code': code, 'hint': with_previous_kept(hint)}
