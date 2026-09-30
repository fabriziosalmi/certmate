"""The one HTTPS client a key-carrying deploy target sends through.

A target that hands a private key to a URL has to be able to say three things
about where the bytes go, and each one has a way of being half true:

**Which address.** The host is resolved once, the answers are checked, and the
connection is made to the address that was checked. Checking the name and then
letting the library resolve it again is how an answer that changes in between
(a rebind) gets past the check. Every address the name resolves to is classified
and one that is refused spoils the whole set, so a dual record cannot smuggle a
metadata address past a check of the first.

**Who answers.** TLS is always verified: against the system store, against a CA
the operator supplied (which then replaces the system store), or against a
pinned SHA-256 fingerprint of the server's own certificate, for an appliance that
signs itself. There is no parameter that turns verification off, and a test
holds it that way.

**What happens next.** A redirect is reported and not followed: a 307 or 308
keeps the method and the body, so following one sends the key wherever the answer
points. The answer is not kept either, only its status: a receiver can echo the
body it was sent, and this result is written to a log that cannot be edited.

`http.client` rather than `requests`: it never follows a redirect, it lets the
connection go to a chosen address while the certificate is checked against the
name, and it does not carry a session that could be made to do otherwise.
"""

import hashlib
import hmac
import http.client
import ipaddress
import socket
import ssl
from dataclasses import dataclass
from urllib.parse import urlparse

# Never a destination, whatever the operator allows: nothing CertMate is asked to
# deliver a certificate to lives on its own loopback or on a link-local address,
# and the cloud metadata services do.
_ALWAYS_REFUSED = tuple(ipaddress.ip_network(n) for n in (
    '127.0.0.0/8', '0.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4',
    '::1/128', '::/128', 'fe80::/10', 'ff00::/8',
    '100.100.100.200/32',          # Alibaba Cloud metadata, inside the carrier-grade range
    '192.0.0.192/32',              # Oracle Cloud metadata
    'fd00:ec2::254/128',           # AWS metadata over IPv6
))

# How much of an answer is read and thrown away, so the sender can finish and
# close cleanly without being made to wait for an endless body.
_DRAIN_LIMIT = 64 * 1024


class UnsafeDestination(Exception):
    """The address cannot be used as a destination."""


class TLSVerificationFailed(Exception):
    """The server could not be shown to be the one that was meant."""


class TransportError(Exception):
    """The request did not complete for a reason that may pass (refused, reset, timed out)."""


@dataclass(frozen=True)
class Reply:
    """What is kept of an answer: its status, and that it asked to be redirected.

    Deliberately no body and no headers. A receiver that echoes its input would
    otherwise hand the key to whatever records this.
    """
    status: int
    redirected: bool


def classify(address):
    """'refused', 'internal' or 'global' for an IP address given as text."""
    ip = ipaddress.ip_address(address)
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if any(ip in network for network in _ALWAYS_REFUSED):
        return 'refused'
    return 'global' if ip.is_global else 'internal'


def resolve(host, port, allow_internal):
    """Resolve *host* once, check every answer, and return the address to connect to."""
    try:
        literal = ipaddress.ip_address(host)
        addresses = [str(literal)]
    except ValueError:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError) as error:
            raise UnsafeDestination(f'{host} does not resolve: {error}')
        addresses = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
    if not addresses:
        raise UnsafeDestination(f'{host} does not resolve to any address')
    classes = {address: classify(address) for address in addresses}
    refused = [a for a, c in classes.items() if c == 'refused']
    if refused:
        raise UnsafeDestination(
            f'{host} resolves to an address that is never a valid destination '
            f'(loopback, link-local or a metadata address)')
    internal = [a for a, c in classes.items() if c == 'internal']
    if internal and not allow_internal:
        raise UnsafeDestination(
            f'{host} resolves to a private address. Set allow_internal on this target '
            f'to deliver to it.')
    return addresses[0]


PIN_FORMAT = 'pin_sha256 must be a SHA-256 fingerprint: 64 hexadecimal digits'


def normalise_pin(pin):
    cleaned = ''.join(ch for ch in str(pin) if ch not in ': \t').lower()
    if len(cleaned) != 64 or any(ch not in '0123456789abcdef' for ch in cleaned):
        raise UnsafeDestination(PIN_FORMAT)
    return cleaned


def _context(ca_pem, pin):
    if pin:
        # The pin authenticates the peer, so the chain is not asked for. It is
        # an exact match on the server's own certificate, which is the stronger
        # statement, and the only one an appliance that signs itself can make.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    elif ca_pem:
        # A CA that was supplied replaces the system store rather than joining it:
        # the operator named who may vouch for this server.
        context = ssl.create_default_context(cadata=ca_pem)
    else:
        context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class _PinnedConnection(http.client.HTTPSConnection):
    """Connects to a chosen address while checking the certificate against the name."""

    def __init__(self, host, port, *, address, context, timeout, pin):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._address = address
        self._pin = pin

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout)
        try:
            # server_hostname is the NAME: SNI and, unless a pin replaces it,
            # the certificate's subject are checked against it, not the address.
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except (ssl.SSLError, OSError):
            # What wrap_socket raises (SSLError is an OSError); the socket is ours to close.
            sock.close()
            raise
        if self._pin:
            presented = hashlib.sha256(self.sock.getpeercert(binary_form=True)).hexdigest()
            if not hmac.compare_digest(presented, self._pin):
                self.sock.close()
                raise TLSVerificationFailed(
                    'the server presented a certificate whose fingerprint is not the pinned one')


def send(url, *, method, body, headers, timeout=15, ca_pem=None, pin_sha256=None,
         allow_internal=False, resolver=None):
    """Send one request and return a :class:`Reply`.

    Raises :class:`UnsafeDestination` (nothing was sent), :class:`TLSVerificationFailed`
    (the server was not shown to be the right one, and nothing was sent), or
    :class:`TransportError` (a fault that may pass).
    """
    try:
        parsed = urlparse(url)
        host, port = parsed.hostname, parsed.port
    except ValueError as error:
        raise UnsafeDestination(f'not a valid URL: {error}')
    if parsed.scheme != 'https':
        raise UnsafeDestination('the URL must use https: the request carries key material')
    if not host:
        raise UnsafeDestination('the URL has no host')
    if parsed.username or parsed.password:
        raise UnsafeDestination('the URL must not carry credentials; use the authentication fields')
    port = port or 443
    pin = normalise_pin(pin_sha256) if pin_sha256 else None

    address = (resolver or resolve)(host, port, allow_internal)
    path = (parsed.path or '/') + (f'?{parsed.query}' if parsed.query else '')
    connection = _PinnedConnection(host, port, address=address, timeout=timeout, pin=pin,
                                   context=_context(ca_pem, pin))
    try:
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
        except (ssl.SSLCertVerificationError, ssl.CertificateError) as error:
            raise TLSVerificationFailed(
                f'certificate verification failed: {getattr(error, "verify_message", None) or error}')
        except ssl.SSLError as error:
            raise TLSVerificationFailed(f'TLS handshake failed: {error.reason or error}')
        except (TimeoutError, socket.timeout):
            raise TransportError('the request timed out')
        except OSError as error:
            raise TransportError(f'the connection failed: {error.strerror or type(error).__name__}')
        status = response.status
        try:
            response.read(_DRAIN_LIMIT)
        except (OSError, http.client.HTTPException):
            pass
        return Reply(status=status, redirected=300 <= status < 400)
    finally:
        connection.close()
