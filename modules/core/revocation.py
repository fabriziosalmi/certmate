"""Revocation check for a served certificate — OCSP first, the CRL as fallback.

The deep TLS probe (:mod:`cert_probe`) describes a certificate: who issued it,
when it expires, what key it carries. None of that says whether the issuer has
since *revoked* it, and a revoked certificate that is still being served looks
perfectly healthy on every other axis. This module answers that one question.

What "checked" means here, because a revocation answer that is not verified is
worse than no answer at all:

* **OCSP** — the response must be ``successful``, name this certificate's
  serial under this issuer's key hash, be signed by the issuer itself or by a
  delegated responder that the issuer signed *and* that carries the
  ``id-kp-OCSPSigning`` extended key usage, and be fresh (``thisUpdate`` not in
  the future, ``nextUpdate`` not in the past).
* **CRL** — the list must be issued by this certificate's issuer, carry a
  signature that verifies against the issuer's key, and not be past its
  ``nextUpdate``. Absence of the serial on such a list is a ``good`` answer.

Anything short of that is ``unavailable``, with the reason, and never ``good``.

The issuer certificate comes from the served chain when the peer sends one and
the interpreter exposes it (Python 3.13+), otherwise from the certificate's own
AIA ``caIssuers`` URL, and it must actually have signed the leaf either way.

Statuses returned in ``status``:

* ``good`` — a verified OCSP or CRL answer says the certificate is not revoked.
* ``revoked`` — a verified answer says it is; ``revoked_at`` and ``reason``
  carry what the issuer published.
* ``unknown`` — the OCSP responder said it does not know this certificate and
  no CRL settled it.
* ``unavailable`` — no verified answer could be obtained (no OCSP or CRL URL,
  the issuer could not be found, a responder was unreachable, a signature did
  not verify, a response was stale). ``error`` says which.
* ``not_applicable`` — the certificate is self-signed, so there is no issuer
  that could revoke it.

Safety: every URL fetched here comes from a certificate CertMate did not issue,
so each fetch goes through the same SSRF guard as the probe itself — the name
is resolved, refused if any address is private/loopback/non-global unless the
caller opted in, and the connection is pinned to the validated address. Only
plain ``http`` is fetched (RFC 5280 and RFC 6960 publish these over HTTP; the
payloads are signed, so TLS adds nothing to their integrity), redirects are not
followed, and every response body is capped.

No new dependencies: standard library plus ``cryptography``.
"""

import http.client
import logging
import threading
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509 import ocsp
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    ExtendedKeyUsageOID,
    ExtensionOID,
)

from .utils import utc_now_iso

logger = logging.getLogger(__name__)

STATUS_GOOD = 'good'
STATUS_REVOKED = 'revoked'
STATUS_UNKNOWN = 'unknown'
STATUS_UNAVAILABLE = 'unavailable'
STATUS_NOT_APPLICABLE = 'not_applicable'

METHOD_OCSP = 'ocsp'
METHOD_CRL = 'crl'

# Tolerated clock difference between CertMate and a responder when judging
# whether a response is from the future or already stale.
CLOCK_SKEW = timedelta(minutes=5)

# Body caps. An OCSP response or an issuer certificate is a few KB; a CRL can
# legitimately be large (a busy CA's unpartitioned list), so it gets more room.
MAX_OCSP_BYTES = 64 * 1024
MAX_ISSUER_BYTES = 64 * 1024
MAX_CRL_BYTES = 20 * 1024 * 1024

# How many CRL distribution points to try before giving up.
MAX_CRL_URLS = 2

_USER_AGENT = 'CertMate-revocation-check'


class FetchError(Exception):
    """A revocation-related fetch failed; the message is safe to surface."""


# --------------------------------------------------------------------------- #
# Guarded HTTP
# --------------------------------------------------------------------------- #

def fetch_url(url, *, timeout, max_bytes, allow_private, body=None,
              content_type=None):
    """GET (or POST when *body* is given) *url* through the SSRF guard.

    Returns the response body as bytes. Raises :class:`FetchError` for a
    refused target, a non-http scheme, a non-200 answer (redirects included) or
    a body over *max_bytes*.
    """
    # Imported here, not at module level: cert_probe imports this module.
    from .cert_probe import _resolve_and_guard

    parts = urlsplit(url)
    if parts.scheme != 'http':
        raise FetchError(f'unsupported URL scheme {parts.scheme!r} in {url}')
    host = parts.hostname
    if not host:
        raise FetchError(f'no host in {url}')
    try:
        port = parts.port or 80
    except ValueError:
        raise FetchError(f'invalid port in {url}')

    _family, connect_ip, reason = _resolve_and_guard(host, port, allow_private)
    if reason is not None:
        raise FetchError(f'{host}: {reason}')

    path = parts.path or '/'
    if parts.query:
        path += '?' + parts.query
    host_header = host if port == 80 else f'{host}:{port}'
    if ':' in host and not host.startswith('['):
        host_header = f'[{host}]' if port == 80 else f'[{host}]:{port}'
    headers = {'Host': host_header, 'User-Agent': _USER_AGENT, 'Accept': '*/*'}
    if content_type:
        headers['Content-Type'] = content_type

    # Passing the port explicitly stops http.client from parsing a port out of
    # an IPv6 literal; the Host header carries the original name, so the
    # connection is pinned to the address the guard validated.
    conn = http.client.HTTPConnection(connect_ip, port, timeout=timeout)
    try:
        conn.request('POST' if body is not None else 'GET', path,
                     body=body, headers=headers)
        resp = conn.getresponse()
        if resp.status != 200:
            raise FetchError(f'{url} answered HTTP {resp.status}')
        data = resp.read(max_bytes + 1)
    except FetchError:
        raise
    except (OSError, http.client.HTTPException) as e:
        raise FetchError(f'{url}: {e.__class__.__name__}: {e}') from e
    finally:
        conn.close()
    if len(data) > max_bytes:
        raise FetchError(f'{url} returned more than {max_bytes} bytes')
    return data


class _TTLCache:
    """A small thread-safe cache of URL -> (expires_at, value).

    A discovery sweep probes many hosts that share a handful of issuers, so the
    issuer certificate and the CRL are fetched once per sweep, not once per
    host. Bounded, so a sweep over many distinct CAs cannot grow it forever.
    """

    def __init__(self, max_entries):
        self._max = max_entries
        self._data = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            hit = self._data.get(key)
            if hit is None:
                return None
            expires_at, value = hit
            if expires_at <= time.monotonic():
                del self._data[key]
                return None
            return value

    def put(self, key, value, ttl_seconds):
        if ttl_seconds <= 0:
            return
        with self._lock:
            if len(self._data) >= self._max and key not in self._data:
                # Drop the entry closest to expiry.
                oldest = min(self._data, key=lambda k: self._data[k][0])
                del self._data[oldest]
            self._data[key] = (time.monotonic() + ttl_seconds, value)

    def clear(self):
        with self._lock:
            self._data.clear()


_ISSUER_CACHE = _TTLCache(max_entries=64)
_CRL_CACHE = _TTLCache(max_entries=16)
_ISSUER_TTL_SECONDS = 24 * 3600
_CRL_MAX_TTL_SECONDS = 3600


def clear_caches():
    """Forget every cached issuer certificate and CRL (used by tests)."""
    _ISSUER_CACHE.clear()
    _CRL_CACHE.clear()


# --------------------------------------------------------------------------- #
# Certificate helpers
# --------------------------------------------------------------------------- #

def _load_cert(data):
    try:
        return x509.load_der_x509_certificate(data)
    except ValueError:
        return x509.load_pem_x509_certificate(data)


def _now():
    return datetime.now(timezone.utc)


def _iso(dt):
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace('+00:00', 'Z')


def _aia_urls(cert, method_oid):
    try:
        aia = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
    except x509.ExtensionNotFound:
        return []
    return [
        d.access_location.value for d in aia
        if d.access_method == method_oid
        and isinstance(d.access_location, x509.UniformResourceIdentifier)
    ]


def _crl_urls(cert):
    try:
        cdp = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS).value
    except x509.ExtensionNotFound:
        return []
    urls = []
    for point in cdp:
        for name in point.full_name or []:
            if isinstance(name, x509.UniformResourceIdentifier):
                urls.append(name.value)
    return urls


def _signed_by(child, issuer):
    """True if *issuer* signed *child* (names match and the signature verifies)."""
    try:
        child.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def _verify_signature(public_key, signature, data, hash_algorithm):
    """Verify *signature* over *data*; raises InvalidSignature or TypeError."""
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
    elif isinstance(public_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        public_key.verify(signature, data)
    else:
        raise TypeError(f'unsupported responder key type {type(public_key).__name__}')


def _issuer_from_aia(leaf, *, timeout, allow_private):
    """Fetch and return the leaf's issuer from its AIA caIssuers URL(s)."""
    urls = _aia_urls(leaf, AuthorityInformationAccessOID.CA_ISSUERS)
    if not urls:
        raise FetchError(
            'certificate names no caIssuers URL and the served chain did not include the issuer')
    last_error = None
    for url in urls[:2]:
        cached = _ISSUER_CACHE.get(url)
        candidates = cached
        if candidates is None:
            try:
                data = fetch_url(url, timeout=timeout, max_bytes=MAX_ISSUER_BYTES,
                                 allow_private=allow_private)
            except FetchError as e:
                last_error = str(e)
                continue
            candidates = _parse_issuer_payload(data)
            if candidates:
                _ISSUER_CACHE.put(url, candidates, _ISSUER_TTL_SECONDS)
        for candidate in candidates:
            if _signed_by(leaf, candidate):
                return candidate
        last_error = f'{url} did not return the certificate that signed this one'
    raise FetchError(last_error or 'issuer not found')


def _parse_issuer_payload(data):
    """An AIA caIssuers payload is DER, PEM, or a PKCS#7 bundle of certs."""
    for loader in (
        lambda d: [x509.load_der_x509_certificate(d)],
        lambda d: [x509.load_pem_x509_certificate(d)],
        pkcs7.load_der_pkcs7_certificates,
        pkcs7.load_pem_pkcs7_certificates,
    ):
        try:
            certs = loader(data)
        except (ValueError, TypeError):
            continue
        if certs:
            return certs
    return []


def find_issuer(leaf, chain_ders=(), *, timeout, allow_private):
    """Return the certificate that signed *leaf*: from the chain, else via AIA."""
    for der in chain_ders or ():
        try:
            candidate = _load_cert(der)
        except ValueError:
            continue
        if candidate.fingerprint(hashes.SHA256()) == leaf.fingerprint(hashes.SHA256()):
            continue
        if _signed_by(leaf, candidate):
            return candidate
    return _issuer_from_aia(leaf, timeout=timeout, allow_private=allow_private)


# --------------------------------------------------------------------------- #
# OCSP
# --------------------------------------------------------------------------- #

def _key_hash(cert):
    """SHA-1 of the subjectPublicKey bits — the OCSP ResponderID/issuerKeyHash."""
    return x509.SubjectKeyIdentifier.from_public_key(cert.public_key()).digest


def _ocsp_signer(response, issuer):
    """Return the certificate that must have signed *response*.

    Either the issuer itself, or a delegated responder certificate included in
    the response that the issuer signed and that is authorised for OCSP
    signing. Raises FetchError when the named responder is neither.
    """
    def names_responder(cert):
        if response.responder_key_hash is not None:
            return _key_hash(cert) == response.responder_key_hash
        return cert.subject == response.responder_name

    if names_responder(issuer):
        return issuer
    for cert in response.certificates:
        if not names_responder(cert):
            continue
        if not _signed_by(cert, issuer):
            raise FetchError('OCSP responder certificate was not issued by the certificate issuer')
        try:
            eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE).value
        except x509.ExtensionNotFound:
            eku = []
        if ExtendedKeyUsageOID.OCSP_SIGNING not in eku:
            raise FetchError('OCSP responder certificate is not authorised for OCSP signing')
        return cert
    raise FetchError('OCSP response is signed by a responder that is neither the issuer nor a delegate it included')


def _check_ocsp(leaf, issuer, url, *, timeout, allow_private, now):
    """Query one OCSP responder. Returns a partial result dict, or raises FetchError."""
    # SHA-1 is what RFC 6960 names for the CertID and what every responder
    # accepts; it identifies the certificate, it does not protect anything.
    request = (ocsp.OCSPRequestBuilder()
               .add_certificate(leaf, issuer, hashes.SHA1())  # nosec B303
               .build())
    data = fetch_url(url, timeout=timeout, max_bytes=MAX_OCSP_BYTES,
                     allow_private=allow_private,
                     body=request.public_bytes(serialization.Encoding.DER),
                     content_type='application/ocsp-request')
    try:
        response = ocsp.load_der_ocsp_response(data)
    except ValueError as e:
        raise FetchError(f'{url} returned something that is not an OCSP response: {e}')
    if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise FetchError(f'{url} answered {response.response_status.name}')

    signer = _ocsp_signer(response, issuer)
    try:
        _verify_signature(signer.public_key(), response.signature,
                          response.tbs_response_bytes, response.signature_hash_algorithm)
    except (InvalidSignature, TypeError, ValueError) as e:
        raise FetchError(f'OCSP response signature does not verify: {e.__class__.__name__}')

    issuer_key_hash = _key_hash(issuer)
    single = None
    for candidate in response.responses:
        if candidate.serial_number != leaf.serial_number:
            continue
        # The CertID hash algorithm is the responder's choice; recompute ours in
        # the same algorithm when it is not SHA-1.
        if isinstance(candidate.hash_algorithm, hashes.SHA1):
            expected = issuer_key_hash
        else:
            spki = issuer.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
            digest = hashes.Hash(candidate.hash_algorithm)
            digest.update(_subject_public_key_bits(spki))
            expected = digest.finalize()
        if candidate.issuer_key_hash == expected:
            single = candidate
            break
    if single is None:
        raise FetchError('OCSP response does not cover this certificate')

    this_update = single.this_update_utc
    next_update = single.next_update_utc
    if this_update > now + CLOCK_SKEW:
        raise FetchError('OCSP response is dated in the future')
    if next_update is not None and next_update < now - CLOCK_SKEW:
        raise FetchError('OCSP response is stale (past its nextUpdate)')

    status = single.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return {'status': STATUS_GOOD}
    if status == ocsp.OCSPCertStatus.REVOKED:
        reason = single.revocation_reason
        return {
            'status': STATUS_REVOKED,
            'revoked_at': _iso(single.revocation_time_utc),
            'reason': reason.name if reason is not None else None,
        }
    return {'status': STATUS_UNKNOWN}


def _subject_public_key_bits(spki_der):
    """Extract the subjectPublicKey BIT STRING contents from a DER SPKI.

    Only needed when a responder uses a CertID hash other than SHA-1, which is
    rare; parsed by hand to avoid an ASN.1 dependency. SPKI is
    SEQUENCE { AlgorithmIdentifier, BIT STRING }.
    """
    def read_len(buf, i):
        first = buf[i]
        i += 1
        if first < 0x80:
            return first, i
        n = first & 0x7F
        return int.from_bytes(buf[i:i + n], 'big'), i + n

    i = 1  # outer SEQUENCE tag
    _, i = read_len(spki_der, i)
    i += 1  # AlgorithmIdentifier SEQUENCE tag
    alg_len, i = read_len(spki_der, i)
    i += alg_len
    i += 1  # BIT STRING tag
    bits_len, i = read_len(spki_der, i)
    return spki_der[i + 1:i + bits_len]  # skip the unused-bits octet


# --------------------------------------------------------------------------- #
# CRL
# --------------------------------------------------------------------------- #

def _fetch_crl(url, issuer, *, timeout, allow_private, now):
    """Fetch, verify and cache the CRL at *url*. Raises FetchError."""
    cached = _CRL_CACHE.get(url)
    if cached is not None:
        crl = cached
    else:
        data = fetch_url(url, timeout=timeout, max_bytes=MAX_CRL_BYTES,
                         allow_private=allow_private)
        try:
            crl = x509.load_der_x509_crl(data)
        except ValueError:
            try:
                crl = x509.load_pem_x509_crl(data)
            except ValueError as e:
                raise FetchError(f'{url} returned something that is not a CRL: {e}')

    if crl.issuer != issuer.subject:
        raise FetchError(f'CRL at {url} was not issued by this certificate\'s issuer')
    if not crl.is_signature_valid(issuer.public_key()):
        raise FetchError(f'CRL at {url} has a signature that does not verify')
    next_update = crl.next_update_utc
    if next_update is not None and next_update < now - CLOCK_SKEW:
        raise FetchError(f'CRL at {url} is stale (past its nextUpdate)')

    if cached is None:
        ttl = _CRL_MAX_TTL_SECONDS
        if next_update is not None:
            ttl = min(ttl, (next_update - now).total_seconds())
        _CRL_CACHE.put(url, crl, ttl)
    return crl


def _check_crl(leaf, issuer, url, *, timeout, allow_private, now):
    crl = _fetch_crl(url, issuer, timeout=timeout, allow_private=allow_private, now=now)
    entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
    if entry is None:
        return {'status': STATUS_GOOD}
    reason = None
    try:
        reason = entry.extensions.get_extension_for_class(x509.CRLReason).value.reason.name
    except x509.ExtensionNotFound:
        pass
    return {
        'status': STATUS_REVOKED,
        'revoked_at': _iso(entry.revocation_date_utc),
        'reason': reason,
    }


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #

def _result(status, *, method=None, url=None, error=None, revoked_at=None,
            reason=None, attempts=None):
    return {
        'status': status,
        'method': method,
        'url': url,
        'revoked_at': revoked_at,
        'reason': reason,
        'error': error,
        'checked_at': utc_now_iso(),
        'attempts': attempts or [],
    }


def check_revocation(leaf_der, chain_ders=(), *, timeout=5.0, allow_private=False,
                     now=None):
    """Return the revocation status of the certificate in *leaf_der*.

    *chain_ders* is the served chain (DER bytes) when available; the issuer is
    looked for there first. Never raises: every failure becomes an
    ``unavailable`` result with the reason in ``error``, and ``attempts`` lists
    what was tried (method, url, outcome) so an operator can see why.
    """
    now = now or _now()
    attempts = []
    try:
        leaf = _load_cert(leaf_der)
    except ValueError as e:
        return _result(STATUS_UNAVAILABLE, error=f'certificate could not be parsed: {e}')

    if leaf.subject == leaf.issuer and _signed_by(leaf, leaf):
        return _result(STATUS_NOT_APPLICABLE, error=None)

    ocsp_urls = _aia_urls(leaf, AuthorityInformationAccessOID.OCSP)
    crl_urls = _crl_urls(leaf)
    if not ocsp_urls and not crl_urls:
        return _result(STATUS_UNAVAILABLE,
                       error='certificate names neither an OCSP responder nor a CRL')

    try:
        issuer = find_issuer(leaf, chain_ders, timeout=timeout, allow_private=allow_private)
    except FetchError as e:
        return _result(STATUS_UNAVAILABLE, error=f'issuer not available: {e}')

    saw_unknown = None
    for url in ocsp_urls[:1]:
        try:
            outcome = _check_ocsp(leaf, issuer, url, timeout=timeout,
                                  allow_private=allow_private, now=now)
        except FetchError as e:
            attempts.append({'method': METHOD_OCSP, 'url': url, 'outcome': 'error', 'error': str(e)})
            continue
        attempts.append({'method': METHOD_OCSP, 'url': url, 'outcome': outcome['status'], 'error': None})
        if outcome['status'] == STATUS_UNKNOWN:
            saw_unknown = url
            continue
        return _result(outcome['status'], method=METHOD_OCSP, url=url,
                       revoked_at=outcome.get('revoked_at'),
                       reason=outcome.get('reason'), attempts=attempts)

    for url in crl_urls[:MAX_CRL_URLS]:
        try:
            outcome = _check_crl(leaf, issuer, url, timeout=timeout,
                                 allow_private=allow_private, now=now)
        except FetchError as e:
            attempts.append({'method': METHOD_CRL, 'url': url, 'outcome': 'error', 'error': str(e)})
            continue
        attempts.append({'method': METHOD_CRL, 'url': url, 'outcome': outcome['status'], 'error': None})
        return _result(outcome['status'], method=METHOD_CRL, url=url,
                       revoked_at=outcome.get('revoked_at'),
                       reason=outcome.get('reason'), attempts=attempts)

    if saw_unknown:
        return _result(STATUS_UNKNOWN, method=METHOD_OCSP, url=saw_unknown,
                       error='the OCSP responder does not know this certificate',
                       attempts=attempts)
    last = attempts[-1]['error'] if attempts else 'no revocation source could be reached'
    return _result(STATUS_UNAVAILABLE, error=last, attempts=attempts)
