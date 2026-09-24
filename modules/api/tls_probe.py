"""Probing a live TLS endpoint, and describing the certificate it presents.

Extracted from `resources.py` (#667). These helpers are one cluster: the
deployment-status endpoint uses the probe and the fingerprint to answer "is the
certificate this host is actually serving the one we issued?", and the
certificate detail endpoint uses the protocol list.

They moved because the endpoints did. Left behind, a resource group in its own
module could only reach them by importing `resources.py`, which imports the
group back.

A test that stubs the probe must patch it in the module that CALLS it.
Patching a name re-exported somewhere else rebinds that copy and leaves the
call site untouched — a test that still runs and no longer tests anything.
"""
from ..core.constants import PROBE_PROTOCOLS
from ..core.cert_probe import (
    _resolve_and_guard, deployment_target_refusal, proxy_for,
)
import http.client
import logging
import os
import socket
import ssl
import time

logger = logging.getLogger(__name__)


def _certificate_fingerprint(cert_bytes):
    """Return a stable SHA-256 fingerprint for a PEM or DER certificate."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    cert_bytes = cert_bytes or b''
    if not cert_bytes:
        return None

    try:
        cert = x509.load_pem_x509_certificate(cert_bytes)
    except ValueError:
        cert = x509.load_der_x509_certificate(cert_bytes)
    return cert.fingerprint(hashes.SHA256()).hex()

def _san_dns_names(cert):
    """Return the dNSName SANs of a parsed x509 cert, or [] if it has none."""
    from cryptography import x509

    try:
        san_ext = cert.extensions.get_extension_for_oid(
            x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        return san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []

def _certificate_subject_summary(cert_bytes):
    """Return a short human-readable identity for a served certificate.

    Emits the subject CN plus the first few SAN dNSNames, e.g.
    ``CN=example.com; SAN=example.com, www.example.com``. Best-effort and
    purely diagnostic: it feeds the deployment-status mismatch reason so an
    operator can see WHICH cert a host is actually serving. Never used for a
    trust decision. Returns '' when the bytes cannot be parsed.
    """
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    if not cert_bytes:
        return ''
    try:
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
        except ValueError:
            cert = x509.load_der_x509_certificate(cert_bytes)
        parts = []
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn:
            parts.append('CN=' + str(cn[0].value))
        sans = _san_dns_names(cert)
        if sans:
            shown = ', '.join(sans[:3]) + (', ...' if len(sans) > 3 else '')
            parts.append('SAN=' + shown)
        return '; '.join(parts)
    except Exception:
        return ''

def _tls_probe_timeout_seconds():
    """Read CERTMATE_TLS_PROBE_TIMEOUT_SECONDS, clamped to [1, 30]. Default 3s.

    Each probe blocks one Flask worker thread for up to this many seconds on
    an unreachable host. Lower = workers free up faster; higher = fewer false
    negatives on legitimately-slow targets. The default of 3s is a deliberate
    drop from the previous 5s — production /api/certificates dashboards that
    surface deployment status for ~50 domains can otherwise stall an
    operator-facing handler for tens of seconds when several targets are
    down.
    """
    raw = os.getenv('CERTMATE_TLS_PROBE_TIMEOUT_SECONDS', '').strip()
    if not raw:
        return 3.0
    try:
        value = float(raw)
    except ValueError:
        return 3.0
    return max(1.0, min(value, 30.0))

# Moved to core.constants (#672); re-exported so the existing
# imports of `_PROBE_PROTOCOLS` from here keep working.
_PROBE_PROTOCOLS = PROBE_PROTOCOLS

def _https_proxy_for(host):
    """Return (proxy_host, proxy_port, auth_headers) for tunneling to *host*.

    One line, because the rule moved to `core.cert_probe.proxy_for` when the
    inventory probe, the weak-TLS check and the header check needed the same
    answer. It stays reachable under this name: `resources.py` re-exports it
    and the #326 tests import it from there.
    """
    return proxy_for(host, 'https')

def _open_probe_socket(host, port, timeout):
    """A TCP connection to *host*, honouring the proxy and the SSRF policy.

    One place, because the two legs had drifted apart: the direct-TLS path
    tunnelled through HTTPS_PROXY and the SMTP-STARTTLS path opened a raw
    socket, so on a host that requires an outbound proxy the first worked and
    the second could not connect at all. Neither checked where it was going.

    With a proxy, the proxy is the egress control and does its own
    resolution — there is no address to pin, so the guard cannot apply and
    does not pretend to. Without one, the name is resolved ONCE, checked, and
    the connection is made to that same address, so a name cannot answer with
    a permitted address here and a different one at connect time.

    Returns ``(socket, closer)``: the caller wraps the socket in TLS and then
    calls the closer.
    """
    proxy = _https_proxy_for(host)
    if proxy:
        proxy_host, proxy_port, proxy_headers = proxy
        conn = http.client.HTTPConnection(proxy_host, proxy_port, timeout=timeout)
        conn.set_tunnel(host, port, headers=proxy_headers)
        conn.connect()
        return conn.sock, conn.close

    family, connect_ip, refusal = _resolve_and_guard(host, port, allow_private=True)
    if refusal:
        raise ConnectionError(refusal)
    refusal = deployment_target_refusal(connect_ip)
    if refusal:
        raise ConnectionError(f'{host} resolves to {refusal}')
    sock = socket.create_connection((connect_ip, port), timeout=timeout)
    return sock, sock.close


def _probe_tls_certificate(domain, port=443, protocol='https-tls', timeout=None,
                           probe_host=None):
    """Return the live TLS certificate for a domain, if reachable.

    Supports three protocol modes:
      - ``https-tls`` (default): direct TLS on the given port (like HTTPS).
      - ``tls``:           same wire format as https-tls, no HTTP assumption.
      - ``smtp-starttls``: plain-text SMTP connection, then STARTTLS upgrade.

    ``timeout=None`` reads ``CERTMATE_TLS_PROBE_TIMEOUT_SECONDS`` (default 3s,
    clamped [1, 30]). ``port`` defaults to 443 for https-tls/tls, 587 for
    smtp-starttls when left at the sentinel 0.

    ``probe_host`` overrides both the TCP target and the SNI server name. The
    caller MUST pass it for a wildcard cert (``*.example.com``): a wildcard does
    NOT cover its own apex per RFC 6125, so the legacy apex-stripping fallback
    below probes the wrong host and reports a false "wrong cert" (#207/#381).
    When omitted, a non-wildcard domain probes itself; a wildcard falls back to
    the (incorrect) apex only for direct/legacy callers.
    """
    if timeout is None:
        timeout = _tls_probe_timeout_seconds()
    if protocol not in _PROBE_PROTOCOLS:
        raise ValueError(f"Unsupported probe protocol: {protocol!r}. "
                         f"Use one of {_PROBE_PROTOCOLS}")

    # Port defaults per protocol
    if port is None or port == 0:
        port = 587 if protocol == 'smtp-starttls' else 443

    if probe_host:
        host = probe_host
    else:
        host = domain[2:] if domain.startswith('*.') else domain
    context = ssl.create_default_context()
    # We intentionally disable PKI validation here. The goal is to compare the
    # served certificate fingerprint against the stored certificate, even when
    # the live cert is invalid or otherwise not trusted.
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # create_default_context() already floors at TLS 1.2; pin it explicitly so
    # the fingerprint-comparison probe can never negotiate a dead protocol and
    # to make CodeQL's py/insecure-protocol check provably satisfied.
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    started = time.monotonic()
    try:
        if protocol == 'smtp-starttls':
            cert_bytes = _probe_smtp_starttls(host, port, context, timeout)
        else:
            # Direct TLS (https-tls, tls). When an HTTPS_PROXY applies (and the
            # host isn't in NO_PROXY) tunnel the TCP leg through the proxy with
            # HTTP CONNECT, then run the TLS handshake over that tunnel so we
            # still read the real peer certificate (#326).
            raw_sock, closer = _open_probe_socket(host, port, timeout)
            try:
                with context.wrap_socket(raw_sock, server_hostname=host) as tls_sock:
                    cert_bytes = tls_sock.getpeercert(binary_form=True)
            finally:
                closer()

        return {
            'reachable': True,
            'certificate_bytes': cert_bytes,
            'port': port,
            'protocol': protocol,
        }
    finally:
        elapsed = time.monotonic() - started
        # A probe that takes more than 1s is a strong hint the target is slow
        # or unreachable. Surfacing it in the application log lets an operator
        # spot the offending domain without reproducing a multi-second
        # dashboard stall — and lets them tune CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
        # if the slowness is real but expected.
        if elapsed > 1.0:
            logger.warning(
                "Slow %s probe for %s:%d: %.2fs (timeout=%.1fs).",
                protocol, host, port, elapsed, timeout,
            )

def _probe_smtp_starttls(host, port, context, timeout):
    """Connect to an SMTP server and upgrade to TLS via STARTTLS.

    SMTP wire: banner → ``EHLO certmate.local`` → ``STARTTLS`` →
    220 response → ``context.wrap_socket``.
    """

    recv_timeout = max(1.0, timeout * 0.5)
    # Through the same opener as the direct-TLS leg. This used to be a raw
    # `socket.create_connection`, so an instance behind an outbound proxy
    # could probe an HTTPS endpoint and not an SMTP one — the fix for #326
    # reached one of the two.
    raw_sock, closer = _open_probe_socket(host, port, timeout)
    try:
        raw_sock.settimeout(recv_timeout)
        f = raw_sock.makefile('rwb')

        # Read banner
        banner = f.readline()
        if not banner:
            raise ConnectionError("SMTP: no banner received")

        # EHLO
        f.write(b'EHLO certmate.local\r\n')
        f.flush()
        _consume_smtp_multiline(f)

        # STARTTLS
        f.write(b'STARTTLS\r\n')
        f.flush()
        response = f.readline()
        if not response or not response.startswith(b'220'):
            raise ConnectionError(
                f"SMTP STARTTLS rejected: {response!r}"
            )

        # Upgrade to TLS
        tls_sock = context.wrap_socket(raw_sock, server_hostname=host)
        return tls_sock.getpeercert(binary_form=True)
    finally:
        closer()


def _consume_smtp_multiline(f):
    """Read SMTP multi-line response until a line starting with a digit
    followed by a space (not '-') is seen."""
    while True:
        line = f.readline()
        if not line:
            break
        if len(line) > 3 and line[3:4] == b' ':
            break
