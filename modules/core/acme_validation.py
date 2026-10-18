"""The http-01 check of CertMate's ACME server (RFC 8555 section 8.3, #476).

To show it controls a name, a client serves the key authorization at
http://<name>/.well-known/acme-challenge/<token>, and the server fetches it.
This fetch is the one place where the ACME server reaches into the network
on a client's behalf, so it is guarded (decision F2 on #476):

- every address a name resolves to is checked, and the connection is pinned
  to the checked address (pinned_https.resolve). Private networks are
  allowed, since an internal CA exists to certify internal names; loopback,
  link-local (cloud metadata among it), unspecified, multicast and the
  metadata addresses are refused, for the name and for every redirect;
- up to 5 redirects, only to http or https on ports 80 or 443, as section
  8.3 allows; an https hop is not verified, because the certificate it
  presents may be the one being replaced;
- 10 seconds in all, and at most 8 KiB of body.

The check runs inside the client's POST to the challenge (decision F3), so a
slow target holds one request thread for at most that budget.
"""
import http.client
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

from . import pinned_https

BUDGET_SECONDS = 10
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 8192
REDIRECT_PORTS = {'http': 80, 'https': 443}
_USER_AGENT = 'CertMate-ACME-validation'


class ValidationFailed(Exception):
    """The check did not pass; `kind` is the ACME problem type to report."""

    def __init__(self, kind, detail):
        super().__init__(detail)
        self.kind = kind
        self.detail = detail


def http01(name, token, key_authorization, *, port=80, https_port=443, resolve=pinned_https.resolve,
           budget=BUDGET_SECONDS, clock=time.monotonic):
    """Return when http://<name>/.well-known/acme-challenge/<token> serves *key_authorization*."""
    deadline = clock() + budget
    url = f'http://{name}:{port}/.well-known/acme-challenge/{token}' if port != 80 \
        else f'http://{name}/.well-known/acme-challenge/{token}'
    # 80 and 443 in production; a test serves both on ports of its own.
    allowed_ports = {'http': port, 'https': https_port}
    for _hop in range(MAX_REDIRECTS + 1):
        status, location, body = _get(url, resolve, deadline, clock)
        if status in (301, 302, 303, 307, 308) and location:
            url = _next_hop(url, location, allowed_ports)
            continue
        if status != 200:
            raise ValidationFailed('incorrectResponse', f'{url} answered HTTP {status}, not 200')
        # Section 8.3: whitespace at the end of the body is ignored.
        served = body.decode('utf-8', 'replace').rstrip()
        if served != key_authorization:
            raise ValidationFailed('incorrectResponse', f'{url} served {served[:80]!r}, '
                                   'not the key authorization of this challenge')
        return
    raise ValidationFailed('connection', f'More than {MAX_REDIRECTS} redirects')


def _next_hop(current, location, allowed_ports):
    target = urljoin(current, location)
    parts = urlsplit(target)
    if parts.scheme not in allowed_ports:
        raise ValidationFailed('connection', f'A redirect to {parts.scheme or "a relative"} URL is not followed')
    try:
        hop_port = parts.port or REDIRECT_PORTS[parts.scheme]
    except ValueError:
        raise ValidationFailed('connection', f'A redirect to {target!r} has no valid port') from None
    if hop_port != allowed_ports[parts.scheme]:
        raise ValidationFailed('connection', f'A redirect to port {hop_port} is not followed: '
                               'only 80 for http and 443 for https')
    return target


def _get(url, resolve, deadline, clock):
    parts = urlsplit(url)
    host = parts.hostname
    port = parts.port or REDIRECT_PORTS[parts.scheme]
    remaining = deadline - clock()
    if remaining <= 0:
        raise ValidationFailed('connection', f'The check ran out of its {BUDGET_SECONDS} seconds')
    try:
        address = resolve(host, port, True)
    except pinned_https.UnsafeDestination as refused:
        kind = 'dns' if 'does not resolve' in str(refused) else 'connection'
        raise ValidationFailed(kind, str(refused)) from None
    conn = None
    path = parts.path or '/'
    if parts.query:
        path += '?' + parts.query
    host_header = host if port == REDIRECT_PORTS[parts.scheme] else f'{host}:{port}'
    try:
        if parts.scheme == 'https':
            # Not verified, on purpose: in http-01 the proof is the key
            # authorization, and the first hop is plain http by design, so an
            # unverified https hop adds no exposure that http-01 does not
            # already accept. Requiring a valid certificate would refuse the
            # very hosts whose certificate this order is meant to replace.
            # Connected to the pinned address, with the name as SNI.
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(host, port, timeout=remaining, context=context)
            conn.sock = context.wrap_socket(socket.create_connection((address, port), timeout=remaining),
                                            server_hostname=host)
        else:
            conn = http.client.HTTPConnection(address, port, timeout=remaining)
        conn.request('GET', path, headers={'Host': host_header, 'User-Agent': _USER_AGENT,
                                           'Accept': '*/*', 'Connection': 'close'})
        response = conn.getresponse()
        body = response.read(MAX_BODY_BYTES + 1)
        location = response.getheader('Location')
        return response.status, location, body[:MAX_BODY_BYTES]
    except (OSError, http.client.HTTPException) as error:
        raise ValidationFailed('connection', f'{url}: {error.__class__.__name__}: {error}') from None
    finally:
        if conn is not None:
            conn.close()
