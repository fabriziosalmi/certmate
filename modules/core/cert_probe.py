"""Deep TLS certificate probe — inspect the certificate served at host:port.

CertMate's existing deployment-status probe (``modules/api/resources.py``)
opens ``host:443`` and compares only a fingerprint. To build a certificate
inventory we need the *full* served certificate as structured data: subject,
SAN list, serial, SHA-256 fingerprint, validity window, issuer DN, public-key
algorithm/size, signature algorithm, and the served chain where the peer sends
one.

This module provides two independently useful pieces:

* :func:`parse_certificate` — pure, offline parsing of a DER/PEM certificate
  into the structured metadata dict (no network, fully unit-testable).
* :func:`probe_certificate` — connect to ``host:port``, read the served
  certificate with ``getpeercert(binary_form=True)``, and return the parsed
  metadata plus a classified status. It never validates PKI trust (so it can
  still describe an expired or self-signed cert), but it *derives* a clean
  validation summary (expired / not-yet-valid / self-signed / hostname match)
  from the parsed certificate instead of surfacing a bare "error".

Safety:

* An **SSRF guard** resolves the target first and refuses private, loopback,
  link-local, reserved, multicast and unspecified addresses unless the caller
  explicitly opts in (``allow_private=True`` or
  ``CERTMATE_PROBE_ALLOW_PRIVATE``). The validated IP is then pinned for the
  connection with SNI = the original hostname, so a DNS rebind between the
  guard check and the handshake cannot redirect the probe to an internal host.
* The probe is **failure-isolated**: every connection/parse error is caught and
  reported as a status, never raised, so an inventory sweep over many hosts can
  never be stalled or aborted by one bad target.

No new dependencies: only the standard library plus ``cryptography`` (already a
CertMate dependency).
"""

import ipaddress
import logging
import os
import socket
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import (
    dsa, ec, ed448, ed25519, rsa,
)
from cryptography.x509.oid import ExtensionOID, NameOID

from .utils import utc_now_iso

logger = logging.getLogger(__name__)

# Default connect/handshake timeout. Kept short: a probe blocks one worker for
# up to this long on an unreachable host, and an inventory sweep multiplies it.
DEFAULT_PROBE_TIMEOUT_SECONDS = 5.0
_TIMEOUT_MIN = 1.0
_TIMEOUT_MAX = 30.0

# Status values returned in the ``status`` field.
STATUS_OK = 'ok'
STATUS_BLOCKED = 'blocked'          # SSRF guard refused the target
STATUS_UNREACHABLE = 'unreachable'  # DNS / connect / handshake failure

# error_class values for STATUS_UNREACHABLE (a stable, machine-readable reason).
ERR_DNS = 'dns_error'
ERR_CONNECTION = 'connection_error'
ERR_TIMEOUT = 'timeout'
ERR_TLS = 'tls_error'
ERR_NO_CERTIFICATE = 'no_certificate'
ERR_PARSE = 'parse_error'


def _probe_timeout_seconds(timeout=None):
    """Resolve the probe timeout, clamped to [1, 30] seconds.

    An explicit *timeout* wins; otherwise ``CERTMATE_PROBE_TIMEOUT_SECONDS`` is
    read, falling back to :data:`DEFAULT_PROBE_TIMEOUT_SECONDS`.
    """
    if timeout is None:
        raw = os.getenv('CERTMATE_PROBE_TIMEOUT_SECONDS', '').strip()
        if not raw:
            timeout = DEFAULT_PROBE_TIMEOUT_SECONDS
        else:
            try:
                timeout = float(raw)
            except ValueError:
                timeout = DEFAULT_PROBE_TIMEOUT_SECONDS
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        timeout = DEFAULT_PROBE_TIMEOUT_SECONDS
    return max(_TIMEOUT_MIN, min(timeout, _TIMEOUT_MAX))


def _env_allow_private():
    """True when ``CERTMATE_PROBE_ALLOW_PRIVATE`` opts into private targets."""
    return os.getenv('CERTMATE_PROBE_ALLOW_PRIVATE', '').strip().lower() in (
        '1', 'true', 'yes', 'on',
    )


def ip_is_blocked(ip_str):
    """Return a reason string if *ip_str* is an SSRF-sensitive address, else None.

    Rejects loopback, private (RFC 1918 / ULA), link-local, reserved,
    multicast, and the unspecified address, in both IPv4 and IPv6 — including
    an IPv4-mapped IPv6 address (``::ffff:10.0.0.1``) whose embedded v4 address
    is itself sensitive.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not parseable as an IP → treat as blocked; the caller only ever feeds
        # this addresses resolved from getaddrinfo, so this is defensive.
        return f'unparseable address {ip_str!r}'

    # Unwrap IPv4-mapped IPv6 so an embedded private v4 address is caught.
    mapped = getattr(ip, 'ipv4_mapped', None)
    if mapped is not None:
        ip = mapped

    checks = (
        ('loopback', ip.is_loopback),
        ('private', ip.is_private),
        ('link-local', ip.is_link_local),
        ('reserved', ip.is_reserved),
        ('multicast', ip.is_multicast),
        ('unspecified', ip.is_unspecified),
    )
    for label, hit in checks:
        if hit:
            return f'{label} address {ip}'
    return None


def _resolve_and_guard(host, port, allow_private):
    """Resolve *host* and enforce the SSRF guard.

    Returns ``(family, connect_ip, None)`` for the first allowed address, or
    ``(None, None, reason)`` when resolution fails or any resolved address is
    blocked (and *allow_private* is False). Blocking is conservative: if *any*
    resolved address is sensitive we refuse the whole host, so a name that
    resolves to both a public and an internal address cannot be used to reach
    the internal one.
    """
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        return None, None, f'DNS resolution failed: {e}'
    except (UnicodeError, ValueError) as e:
        return None, None, f'invalid host: {e}'

    if not infos:
        return None, None, 'no addresses resolved'

    first_allowed = None
    for family, _type, _proto, _canon, sockaddr in infos:
        ip_str = sockaddr[0]
        if not allow_private:
            reason = ip_is_blocked(ip_str)
            if reason is not None:
                return None, None, f'target refused by SSRF guard: {reason}'
        if first_allowed is None:
            first_allowed = (family, ip_str)

    family, connect_ip = first_allowed
    return family, connect_ip, None


def _public_key_info(cert):
    """Describe the certificate's public key: {type, size, curve}."""
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return {'type': 'RSA', 'size': pub.key_size, 'curve': None}
    if isinstance(pub, ec.EllipticCurvePublicKey):
        curve = pub.curve
        return {'type': 'ECDSA', 'size': curve.key_size, 'curve': curve.name}
    if isinstance(pub, ed25519.Ed25519PublicKey):
        return {'type': 'Ed25519', 'size': 256, 'curve': None}
    if isinstance(pub, ed448.Ed448PublicKey):
        return {'type': 'Ed448', 'size': 448, 'curve': None}
    if isinstance(pub, dsa.DSAPublicKey):
        return {'type': 'DSA', 'size': pub.key_size, 'curve': None}
    return {'type': 'Unknown', 'size': None, 'curve': None}


def _first_cn(name):
    """Return the first Common Name value of an x509 Name, or None."""
    attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def _san_values(cert):
    """Return ({dns_names}, {ip_addresses}) from the SAN extension."""
    dns_names, ip_names = [], []
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
    except x509.ExtensionNotFound:
        return dns_names, ip_names
    dns_names = list(ext.value.get_values_for_type(x509.DNSName))
    ip_names = [str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress)]
    return dns_names, ip_names


def _load_certificate(cert_bytes):
    """Load a certificate from DER or PEM bytes."""
    try:
        return x509.load_der_x509_certificate(cert_bytes)
    except ValueError:
        return x509.load_pem_x509_certificate(cert_bytes)


def _naive_utc(dt):
    """Return *dt* as a naive UTC datetime, accepting aware or naive input.

    ``cryptography`` exposes ``not_valid_before_utc`` (aware) on modern
    releases and the deprecated naive ``not_valid_before`` on older ones; this
    normalises either to a comparable naive-UTC value.
    """
    if dt.tzinfo is not None:
        return dt.astimezone(_UTC).replace(tzinfo=None)
    return dt


try:  # datetime.UTC is 3.11+; fall back for older interpreters.
    from datetime import UTC as _UTC
except ImportError:  # pragma: no cover
    from datetime import timezone as _tz
    _UTC = _tz.utc


def _cert_datetimes(cert):
    """Return (not_before, not_after) as naive-UTC datetimes."""
    before = getattr(cert, 'not_valid_before_utc', None)
    after = getattr(cert, 'not_valid_after_utc', None)
    if before is None:
        before = cert.not_valid_before
    if after is None:
        after = cert.not_valid_after
    return _naive_utc(before), _naive_utc(after)


def parse_certificate(cert_bytes, server_name=None):
    """Parse a DER/PEM certificate into structured inventory metadata.

    Pure and offline — no network. Returns a dict with two keys:

    * ``certificate``: subject/issuer (CN + full RFC 4514 DN), serial (decimal
      and hex), SHA-256 fingerprint, validity window + days-until-expiry, SAN
      DNS names and IPs, public-key ``{type, size, curve}``, and the signature
      algorithm.
    * ``validation``: ``is_expired``, ``not_yet_valid``, ``is_self_signed``,
      and ``hostname_match`` (None when *server_name* is not supplied).

    Raises ``ValueError`` if the bytes are not a parseable certificate; callers
    that probe untrusted hosts should catch it (``probe_certificate`` does).
    """
    from datetime import datetime

    cert = _load_certificate(cert_bytes)

    not_before, not_after = _cert_datetimes(cert)
    now = datetime.utcnow()
    days_until_expiry = (not_after - now).days

    dns_names, ip_names = _san_values(cert)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    serial = cert.serial_number

    subject_cn = _first_cn(cert.subject)
    is_self_signed = cert.subject == cert.issuer

    certificate = {
        'subject_cn': subject_cn,
        'subject': cert.subject.rfc4514_string(),
        'issuer_cn': _first_cn(cert.issuer),
        'issuer': cert.issuer.rfc4514_string(),
        'serial_number': str(serial),
        'serial_hex': format(serial, 'x'),
        'fingerprint_sha256': fingerprint,
        'not_before': not_before.replace(microsecond=0).isoformat() + 'Z',
        'not_after': not_after.replace(microsecond=0).isoformat() + 'Z',
        'days_until_expiry': days_until_expiry,
        'san_dns': dns_names,
        'san_ip': ip_names,
        'key': _public_key_info(cert),
        'signature_algorithm': getattr(
            cert.signature_algorithm_oid, '_name', None
        ) or cert.signature_algorithm_oid.dotted_string,
    }

    validation = {
        'is_expired': now > not_after,
        'not_yet_valid': now < not_before,
        'is_self_signed': is_self_signed,
        'hostname_match': (
            _hostname_matches(server_name, subject_cn, dns_names, ip_names)
            if server_name else None
        ),
    }

    return {'certificate': certificate, 'validation': validation}


def _hostname_matches(server_name, subject_cn, dns_names, ip_names):
    """Best-effort RFC 6125 hostname check against SAN (falling back to CN).

    Supports a single leading ``*`` wildcard label. IP targets match the SAN IP
    list. Purely descriptive — it never gates the probe, only reports whether
    the served certificate names the host we asked for.
    """
    name = (server_name or '').strip().rstrip('.').lower()
    if not name:
        return None

    # Literal IP target: only a SAN IPAddress entry counts.
    try:
        ipaddress.ip_address(name)
        return name in {ip.lower() for ip in ip_names}
    except ValueError:
        pass

    candidates = list(dns_names)
    # CN is only consulted when the certificate carries no dNSName SANs, which
    # matches how modern clients treat legacy CN-only certificates.
    if not dns_names and subject_cn:
        candidates = [subject_cn]

    for candidate in candidates:
        if _match_dns_name(candidate.lower().rstrip('.'), name):
            return True
    return False


def _match_dns_name(pattern, host):
    """Match *host* against a certificate DNS *pattern* (one leftmost wildcard)."""
    if pattern == host:
        return True
    if pattern.startswith('*.'):
        suffix = pattern[1:]  # keep the leading dot: '*.a.com' -> '.a.com'
        host_first_dot = host.find('.')
        if host_first_dot < 1:
            return False
        # A wildcard covers exactly one label: the remainder must equal suffix
        # and the wildcarded label must not itself contain a dot.
        return host[host_first_dot:] == suffix
    return False


def _chain_entry(cert):
    """One chain element's summary: subject CN, issuer CN, SHA-256 fingerprint."""
    return {
        'subject_cn': _first_cn(cert.subject),
        'issuer_cn': _first_cn(cert.issuer),
        'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(),
    }


def _served_chain(tls_sock):
    """Return the served (unverified) chain as a list of metadata dicts.

    Uses ``SSLSocket.get_unverified_chain()`` (Python 3.13+); returns ``[]``
    when the interpreter or peer does not provide it, in which case the caller
    falls back to the leaf certificate alone. Best-effort: any error is
    swallowed so chain extraction never fails the probe.
    """
    getter = getattr(tls_sock, 'get_unverified_chain', None)
    if getter is None:
        return []
    try:
        chain = getter() or []
    except (ssl.SSLError, OSError, ValueError):
        return []

    out = []
    for entry in chain:
        try:
            der = entry.public_bytes(_DER_ENCODING)
            cert = x509.load_der_x509_certificate(der)
            out.append(_chain_entry(cert))
        except (ValueError, TypeError):
            continue
    return out


try:  # Encoding enum for get_unverified_chain() DER export.
    from cryptography.hazmat.primitives.serialization import Encoding as _Enc
    _DER_ENCODING = _Enc.DER
except ImportError:  # pragma: no cover
    _DER_ENCODING = None


def _blocked_result(host, port, reason):
    return {
        'host': host,
        'port': port,
        'status': STATUS_BLOCKED,
        'error': reason,
        'error_class': None,
        'connect_ip': None,
        'certificate': None,
        'validation': None,
        'chain': [],
    }


def _unreachable_result(host, port, connect_ip, error_class, error):
    return {
        'host': host,
        'port': port,
        'status': STATUS_UNREACHABLE,
        'error': error,
        'error_class': error_class,
        'connect_ip': connect_ip,
        'certificate': None,
        'validation': None,
        'chain': [],
    }


def probe_certificate(host, port=443, timeout=None, allow_private=None,
                      server_name=None):
    """Inspect the TLS certificate served at *host*:*port*.

    Returns a dict describing the served certificate and never raises:

    * ``status`` is one of ``ok`` / ``blocked`` / ``unreachable``.
    * On ``ok``: ``certificate`` and ``validation`` carry the parsed metadata
      (see :func:`parse_certificate`) and ``chain`` the served intermediates.
    * On ``blocked``: the SSRF guard refused the target (``error`` says why).
    * On ``unreachable``: ``error_class`` is a stable reason
      (``dns_error`` / ``connection_error`` / ``timeout`` / ``tls_error`` /
      ``no_certificate`` / ``parse_error``) and ``error`` the detail.

    PKI trust is intentionally NOT validated, so an expired or self-signed cert
    is still fully described; the ``validation`` block reports those conditions.
    *server_name* overrides the SNI / hostname-match target (defaults to *host*).

    IPv6 and any port are supported. Set *allow_private* True (or the
    ``CERTMATE_PROBE_ALLOW_PRIVATE`` env var) to probe private/loopback targets.
    """
    if allow_private is None:
        allow_private = _env_allow_private()
    timeout = _probe_timeout_seconds(timeout)
    sni = (server_name or host)

    family, connect_ip, reason = _resolve_and_guard(host, port, allow_private)
    if reason is not None:
        # A DNS failure is unreachable; an SSRF refusal is a distinct status.
        if reason.startswith('target refused'):
            return _blocked_result(host, port, reason)
        return _unreachable_result(host, port, None, ERR_DNS, reason)

    context = ssl.create_default_context()
    # Read the served certificate regardless of trust: the whole point is to
    # inventory whatever a host presents, including expired/self-signed certs.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    try:
        # Connect to the validated IP with SNI = the requested name, defeating
        # a DNS rebind between the guard check and the handshake.
        with socket.socket(family, socket.SOCK_STREAM) as raw:
            raw.settimeout(timeout)
            raw.connect((connect_ip, port))
            with context.wrap_socket(raw, server_hostname=sni) as tls_sock:
                cert_bytes = tls_sock.getpeercert(binary_form=True)
                chain = _served_chain(tls_sock)
    except socket.timeout as e:
        return _unreachable_result(host, port, connect_ip, ERR_TIMEOUT, str(e) or 'timed out')
    except ssl.SSLError as e:
        return _unreachable_result(host, port, connect_ip, ERR_TLS, str(e))
    except (ConnectionError, OSError) as e:
        return _unreachable_result(host, port, connect_ip, ERR_CONNECTION, str(e))

    if not cert_bytes:
        return _unreachable_result(
            host, port, connect_ip, ERR_NO_CERTIFICATE, 'peer sent no certificate'
        )

    try:
        parsed = parse_certificate(cert_bytes, server_name=sni)
    except ValueError as e:
        return _unreachable_result(host, port, connect_ip, ERR_PARSE, str(e))

    # get_unverified_chain() is only available on Python 3.13+, so on older
    # interpreters (or when the peer sends no chain) fall back to the leaf
    # certificate alone — the chain always names at least the served cert.
    if not chain:
        try:
            chain = [_chain_entry(_load_certificate(cert_bytes))]
        except ValueError:
            chain = []

    return {
        'host': host,
        'port': port,
        'status': STATUS_OK,
        'error': None,
        'error_class': None,
        'connect_ip': connect_ip,
        'certificate': parsed['certificate'],
        'validation': parsed['validation'],
        'chain': chain,
        'probed_at': utc_now_iso(),
    }
