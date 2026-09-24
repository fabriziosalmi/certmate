"""ACME Renewal Information (RFC 9773) — asking the CA when to renew.

CertMate decides renewal from one number: `days_left <= renewal_threshold_days`,
default 30. That number is CertMate's opinion, and it is the same opinion for
every certificate and every CA. The CA has a better one, and since RFC 9773 it
publishes it: a `renewalInfo` endpoint that answers, per certificate, a window
during which it would like that certificate replaced.

The window matters most when it moves **earlier**. A CA that has to replace a
batch of certificates — a mis-issuance, a compromised intermediate, a
CA/Browser Forum ruling — announces it through ARI, days before the revocation
lands. An instance that renews on a fixed 30-day rule learns about it when the
certificate stops working.

**What this module does, and what it deliberately does not.**

ARI here can only bring a renewal *forward*. The operator's threshold remains
the backstop, so nothing this module does can delay a renewal that would
otherwise have happened, and a CA that is down, slow, or wrong cannot push a
certificate towards expiry. Honouring the other direction — letting ARI defer
past the operator's threshold — is the half that matters for short-lived
certificates, where a fixed 30-day rule is nonsense against a 6-day
certificate. That needs the certbot 5.x stack for the profiles that issue
them (#395, blocked on #103), so it is not guesswork we have to do now.

**Why this is native rather than certbot's.** `acme` 3.3.0, the version the
pinned stack ships, has no ARI method at all: `ClientV2` exposes nothing for
`renewalInfo`, and the `certbot` half is 2.10.0. But ARI is an unauthenticated
GET that only informs *when* — issuance stays exactly where it is, on certbot.
So this does not wait for #103, and the issue that said it was a child of
#103 was reading the dependency the wrong way round.
"""

import base64
import hashlib
import json
import logging
import urllib.parse
from datetime import datetime, timedelta, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

logger = logging.getLogger(__name__)

# The directory key that says a CA speaks ARI at all. Absent on a CA that does
# not, which is the whole detection mechanism — there is nothing to probe.
DIRECTORY_KEY = 'renewalInfo'

DEFAULT_TIMEOUT_SECONDS = 10.0

# A directory answer is good for a sweep, not for the life of the process: a
# CA that turns ARI on should not need a restart to be noticed.
DIRECTORY_TTL_SECONDS = 3600

# Refuse an answer whose window is implausible rather than act on it. A CA
# that says "renew in three years" would park a certificate outside every
# check; one that says "renew in 1970" would renew it every night.
MAX_WINDOW_LENGTH = timedelta(days=365)


def _b64(raw: bytes) -> str:
    """base64url, unpadded — the encoding RFC 9773 §4.1 specifies."""
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')


def _serial_octets(serial: int) -> bytes:
    """The DER INTEGER content octets of *serial*.

    Not `to_bytes(length, 'big')` with a length from `byte_length`: DER
    integers are signed, so a serial whose top bit is set carries a leading
    zero byte and one whose is not must not. `(bit_length + 8) // 8` leaves
    room for exactly that sign bit — 1 encodes as `01`, 255 as `00 ff`.
    """
    if serial < 0:
        raise ValueError('a certificate serial is never negative')
    length = max(1, (serial.bit_length() + 8) // 8)
    return serial.to_bytes(length, 'big')


def certificate_id(cert) -> str:
    """The RFC 9773 §4.1 certificate identifier for a parsed certificate.

    ``base64url(AKI keyIdentifier) "." base64url(serial)``, both unpadded.

    Raises ValueError when the certificate carries no Authority Key
    Identifier — ARI cannot name it, so there is nothing to ask. Every
    publicly-trusted certificate has one; a hand-rolled self-signed one may
    not, and that is a real case for a private CA.
    """
    try:
        aki = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER).value
    except x509.ExtensionNotFound:
        raise ValueError('certificate has no Authority Key Identifier')
    key_identifier = getattr(aki, 'key_identifier', None)
    if not key_identifier:
        raise ValueError('Authority Key Identifier carries no keyIdentifier')
    return f'{_b64(key_identifier)}.{_b64(_serial_octets(cert.serial_number))}'


def renewal_info_url(directory: dict, cert_id: str):
    """The URL to GET for *cert_id*, or None when the CA does not speak ARI.

    The base comes from the directory rather than being built from the
    directory's own URL: Let's Encrypt serves `/acme/renewal-info` while the
    directory is at `/directory`, and nothing says the two are related.
    """
    if not isinstance(directory, dict):
        return None
    base = directory.get(DIRECTORY_KEY)
    if not isinstance(base, str) or not base:
        return None
    # `cert_id` is base64url — no character in that alphabet needs escaping,
    # but quoting it costs nothing and means a malformed id cannot add a path
    # segment or a query to the URL.
    return base.rstrip('/') + '/' + urllib.parse.quote(cert_id, safe='')


def _parse_instant(value):
    """RFC 3339 → naive UTC, or None. The rest of this codebase is naive-UTC."""
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith('Z'):
        text = text[:-1] + '+00:00'
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def parse_window(payload):
    """``(start, end)`` from an ARI response, or None if it does not carry one.

    None rather than a default: a malformed answer is not evidence about the
    certificate, and inventing a window from one would be CertMate's opinion
    wearing the CA's name.
    """
    if not isinstance(payload, dict):
        return None
    window = payload.get('suggestedWindow')
    if not isinstance(window, dict):
        return None
    start = _parse_instant(window.get('start'))
    end = _parse_instant(window.get('end'))
    if start is None or end is None or end < start:
        return None
    if end - start > MAX_WINDOW_LENGTH:
        logger.warning('Ignoring an ARI window of %s; longer than %s',
                       end - start, MAX_WINDOW_LENGTH)
        return None
    return start, end


def due_at(cert_id: str, start: datetime, end: datetime) -> datetime:
    """The instant in ``[start, end)`` this certificate renews at.

    RFC 9773 §4.2 asks a client to pick a time uniformly at random in the
    window, so that every client of a CA does not renew at the same instant.
    Picked from a hash of the certificate id rather than from `random`, for
    two reasons: the choice has to be the *same* on every sweep — a nightly
    re-roll would fire on the first night that rolled low, which is not
    randomness, it is a race against the sweep — and a deterministic point is
    one a test can assert and an operator can be told.

    Different certificates land on different points because their ids differ,
    which is the property the RFC actually asks for.
    """
    span = (end - start).total_seconds()
    if span <= 0:
        return start
    digest = hashlib.sha256(cert_id.encode('utf-8')).digest()
    fraction = int.from_bytes(digest[:8], 'big') / float(1 << 64)
    return start + timedelta(seconds=span * fraction)


def is_due(cert_id: str, payload, now: datetime) -> bool:
    """True when the CA's window says this certificate should be renewed now."""
    window = parse_window(payload)
    if window is None:
        return False
    return now >= due_at(cert_id, *window)


class RenewalInfoClient:
    """Reads ARI over HTTP, with the directory cached per CA.

    *get* is injected: it takes ``(url, timeout)`` and returns
    ``(status, body_bytes)``. The default uses ``requests``, which verifies
    TLS (this is the CA, the one host whose certificate must be trusted) and
    honours the proxy variables like the rest of CertMate's HTTP clients.

    Never raises. Every failure — unreachable CA, non-200, malformed JSON —
    is an absence of information, and the caller falls back to the threshold.
    """

    def __init__(self, timeout=DEFAULT_TIMEOUT_SECONDS, get=None, clock=None):
        self.timeout = timeout
        self._get = get or _requests_get
        self._clock = clock or (lambda: datetime.utcnow())
        self._directories = {}

    def _fetch_json(self, url):
        try:
            status, body = self._get(url, self.timeout)
        except (OSError, ValueError) as e:
            # Every `requests` failure is one of these: `RequestException`
            # derives from `OSError` (checked, not assumed), and a malformed
            # URL raises ValueError. Narrow rather than bare `Exception`, so
            # a programming error in here still surfaces instead of being
            # reported as "the CA did not answer".
            logger.info('ARI request to %s failed: %s', url, e.__class__.__name__)
            return None
        if status != 200:
            logger.info('ARI request to %s answered HTTP %s', url, status)
            return None
        try:
            return json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError) as e:
            logger.info('ARI response from %s is not JSON: %s', url, e)
            return None

    def directory(self, directory_url):
        """The CA's directory document, cached for DIRECTORY_TTL_SECONDS."""
        if not directory_url:
            return None
        now = self._clock()
        hit = self._directories.get(directory_url)
        if hit is not None:
            fetched_at, document = hit
            if (now - fetched_at).total_seconds() < DIRECTORY_TTL_SECONDS:
                return document
        document = self._fetch_json(directory_url)
        # Cached even when it is None: a CA that is down must not be asked
        # once per certificate for the whole sweep.
        self._directories[directory_url] = (now, document)
        return document

    def renewal_info(self, directory_url, cert_id):
        """The ARI payload for *cert_id*, or None when there is no answer."""
        url = renewal_info_url(self.directory(directory_url), cert_id)
        if url is None:
            return None
        return self._fetch_json(url)

    def says_renew_now(self, directory_url, cert_id, now=None):
        """True when the CA's window for this certificate has opened."""
        payload = self.renewal_info(directory_url, cert_id)
        if payload is None:
            return False
        return is_due(cert_id, payload, now or self._clock())


def _requests_get(url, timeout):
    """The default transport. Imported here so the module stays importable
    (and unit-testable) without touching the network stack."""
    import requests

    response = requests.get(
        url, timeout=timeout,
        headers={'User-Agent': 'CertMate-ARI', 'Accept': 'application/json'},
    )
    return response.status_code, response.content
