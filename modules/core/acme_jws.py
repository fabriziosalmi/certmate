"""The checks every POST to the ACME server passes (RFC 8555 section 6).

An ACME request is a JWS: the body says what the client wants, the protected
header says which key signed it, for which URL, with which nonce. Every rule
below is a place where a server that skipped it would accept a request it
should not, so each one refuses with the problem type the RFC names, and each
one has a test that breaks it.

The parsing and the signature arithmetic are josepy's and the `acme`
package's (the same code certbot signs with), pinned in requirements.txt.
What is ours is the order of the checks and what each refusal says.
"""
import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import josepy
from acme import jws as acme_jws
from josepy import b64

from .acme_problems import AcmeProblem

# RFC 8555 section 6.2: never `none`, never a MAC for a request. ES256 is the
# one a server MUST implement; RS256 is what most clients still default to
# for an RSA account key. josepy has no EdDSA, so it is not offered.
SIGNATURE_ALGORITHMS = ('ES256', 'ES384', 'ES512', 'RS256')
MAC_ALGORITHMS = ('HS256', 'HS384', 'HS512')

MIN_RSA_BITS = 2048
MAX_RSA_BITS = 8192
EC_CURVES = frozenset({'secp256r1', 'secp384r1', 'secp521r1'})

JOSE_CONTENT_TYPE = 'application/jose+json'
_FLATTENED_MEMBERS = frozenset({'protected', 'payload', 'signature'})


@dataclass
class VerifiedRequest:
    """A request whose signature, nonce and URL have been checked."""
    header: Any                 # acme.jws.Header, protected members only
    payload: bytes
    jwk: josepy.JWK             # the key that signed it
    account: dict | None        # set when the request named an account by `kid`

    @property
    def is_post_as_get(self):
        return self.payload == b''

    def json(self):
        """The payload as a JSON object, or a `malformed` refusal."""
        try:
            value = json.loads(self.payload)
        except ValueError:
            raise AcmeProblem('malformed', 'The payload is not JSON') from None
        if not isinstance(value, dict):
            raise AcmeProblem('malformed', 'The payload must be a JSON object')
        return value


def parse_flattened(value, what='request', algorithms=SIGNATURE_ALGORITHMS):
    """A flattened-JSON JWS with one signature, no unprotected header, and an accepted alg.

    The algorithm is read from the protected header before josepy parses the
    JWS: josepy cannot parse `none` or a name it does not know, and section
    6.2 wants those refused as badSignatureAlgorithm, with the list of the
    ones that are accepted, not as a parse error.
    """
    if isinstance(value, (bytes, str)):
        try:
            value = json.loads(value)
        except ValueError:
            raise AcmeProblem('malformed', f'The {what} is not JSON') from None
    if not isinstance(value, dict) or set(value) != _FLATTENED_MEMBERS:
        # Section 6.2: flattened serialization only, so one signature, and
        # no unprotected header, whose members nobody signed.
        raise AcmeProblem('malformed', f'The {what} must be a flattened JWS with exactly '
                          'the members protected, payload and signature')
    try:
        protected = json.loads(b64.b64decode(value['protected']))
        alg = protected.get('alg')
    except (ValueError, TypeError, AttributeError):
        raise AcmeProblem('malformed', f'The {what} protected header is not base64url JSON') from None
    if 'crit' in protected:
        # RFC 7515 section 4.1.11: an extension listed in crit must be
        # understood, and this server understands none. Read here, raw:
        # josepy cannot decode crit at all, and would refuse it as a parse
        # error that says nothing of why.
        raise AcmeProblem('malformed', f'The {what} header marks {protected["crit"]!r} as critical, '
                          'and this server implements no JWS extension')
    if alg not in algorithms:
        if algorithms is SIGNATURE_ALGORITHMS:
            raise AcmeProblem('badSignatureAlgorithm', f'The algorithm {alg!r} is not accepted',
                              algorithms=list(SIGNATURE_ALGORITHMS))
        raise AcmeProblem('malformed', f'The {what} must be signed with {", ".join(algorithms)}, not {alg!r}')
    try:
        parsed = acme_jws.JWS.from_json(value)
    except (josepy.errors.Error, ValueError, TypeError, KeyError) as error:
        raise AcmeProblem('malformed', f'The {what} is not a valid JWS: {error}') from None
    if len(parsed.signatures) != 1 or not parsed.signature.protected:
        raise AcmeProblem('malformed', f'The {what} must carry one signature over a protected header')
    return parsed


def check_public_key(jwk):
    """The account keys this server accepts: RSA of 2048 bits or more, or EC on the NIST curves."""
    key = getattr(jwk, 'key', None)
    if isinstance(jwk, josepy.JWKRSA):
        bits = key.key_size
        if not MIN_RSA_BITS <= bits <= MAX_RSA_BITS:
            raise AcmeProblem('badPublicKey', f'An RSA account key must have {MIN_RSA_BITS} to '
                              f'{MAX_RSA_BITS} bits, and this one has {bits}')
        return
    if isinstance(jwk, josepy.JWKEC):
        curve = key.curve.name
        if curve not in EC_CURVES:
            raise AcmeProblem('badPublicKey', f'An EC account key must be on P-256, P-384 or P-521, not {curve}')
        return
    raise AcmeProblem('badPublicKey', 'The account key must be an RSA or EC public key')


def thumbprint(jwk):
    """RFC 7638 thumbprint, SHA-256, base64url: how an account key is looked up."""
    return b64.b64encode(jwk.thumbprint()).decode('ascii')


def verify_signature(parsed, key, what):
    try:
        valid = parsed.signature.verify(parsed.payload, key)
    except (josepy.errors.Error, ValueError, TypeError, AttributeError):
        valid = False
    if not valid:
        raise AcmeProblem('malformed', f'The {what} signature does not verify')


def verify_request(raw_body, content_type, request_url, nonces, *, key_from,
                   account_url_prefix=None, find_account: Callable[[str], dict | None] | None = None):
    """Check a POST and return what it carries.

    key_from is 'jwk' for the requests that introduce a key (new-account) and
    'kid' for every request made as an existing account.
    """
    if (content_type or '').split(';')[0].strip().lower() != JOSE_CONTENT_TYPE:
        raise AcmeProblem('malformed', f'The Content-Type must be {JOSE_CONTENT_TYPE}', status=415)
    parsed = parse_flattened(raw_body)
    header = parsed.signature.combined

    nonce = b64.b64encode(header.nonce).decode('ascii') if header.nonce else None
    if not nonces.consume(nonce):
        raise AcmeProblem('badNonce', 'The nonce is missing, used already, or unknown to this server')

    if header.url != request_url:
        # Section 6.4: a request signed for another URL is not this request.
        raise AcmeProblem('unauthorized', f'The url in the protected header ({header.url!r}) '
                          f'is not the URL this request was sent to ({request_url!r})')

    if (header.jwk is None) == (header.kid is None):
        raise AcmeProblem('malformed', 'The protected header must carry exactly one of jwk and kid')

    account = None
    if key_from == 'jwk':
        if header.jwk is None:
            raise AcmeProblem('malformed', 'This request introduces a key: sign it with jwk, not kid')
        key = header.jwk
        check_public_key(key)
    else:
        if header.kid is None:
            raise AcmeProblem('malformed', 'This request is made as an account: sign it with kid, not jwk')
        account = _account_for_kid(header.kid, account_url_prefix, find_account)
        key = josepy.JWK.from_json(json.loads(account['jwk']))

    verify_signature(parsed, key, 'request')
    return VerifiedRequest(header=header, payload=parsed.payload, jwk=key, account=account)


def _account_for_kid(kid, account_url_prefix, find_account):
    if not account_url_prefix or not kid.startswith(account_url_prefix):
        raise AcmeProblem('accountDoesNotExist', 'The kid is not an account URL of this server')
    account = find_account(kid[len(account_url_prefix):])
    if account is None:
        raise AcmeProblem('accountDoesNotExist', 'No account has that URL')
    if account.get('status') != 'valid':
        # Section 7.3.6: a deactivated account's key authorizes nothing more.
        raise AcmeProblem('unauthorized', f'The account is {account.get("status")}')
    return account
