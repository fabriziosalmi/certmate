"""The http-01 and dns-01 checks of CertMate's ACME server (RFC 8555 sections 8.3 and 8.4, #476).

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

dns-01 asks the resolver the instance is configured with (decision I1 on #476:
dns_resolver.nameservers, else the system's), with no cache, for the TXT
records at _acme-challenge.<name>, CNAMEs followed: that is how a DNS alias
delegates the record to a zone the client can write.

tls-alpn-01 (RFC 8737, #1339) connects to the identifier on port 443, under
the same guards and budget as http-01, offering the ALPN protocol acme-tls/1
alone and the identifier as SNI (for an address, its reverse-mapping name, RFC
8738 section 6), and reads the certificate the handshake shows: one SAN, the
identifier, and a critical acmeIdentifier extension holding the SHA-256 of the
key authorization. Nothing is sent after the handshake, and the certificate's
own signature is not checked, as section 4 allows: it proves nothing here.
"""
import base64
import hashlib
import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import urljoin, urlsplit

from cryptography import x509
from cryptography.x509.oid import ObjectIdentifier

from . import pinned_https

BUDGET_SECONDS = 10
MAX_REDIRECTS = 5
MAX_BODY_BYTES = 8192
REDIRECT_PORTS = {'http': 80, 'https': 443}
_USER_AGENT = 'CertMate-ACME-validation'
ACME_TLS_PROTOCOL = 'acme-tls/1'
# id-pe-acmeIdentifier (RFC 8737 section 6.1): its extnValue is the DER of an
# OCTET STRING of 32 bytes, the SHA-256 of the key authorization.
ACME_IDENTIFIER_OID = ObjectIdentifier('1.3.6.1.5.5.7.1.31')


def dns01_digest(key_authorization):
    """Section 8.4: base64url of the SHA-256 of the key authorization, unpadded."""
    digest = hashlib.sha256(key_authorization.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


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


def tls_alpn01(identifier, key_authorization, *, port=443, resolve=pinned_https.resolve,
               budget=BUDGET_SECONDS, clock=time.monotonic):
    """Return when the identifier, on port 443, shows the tls-alpn-01 certificate of *key_authorization*."""
    deadline = clock() + budget
    value = identifier['value']
    if identifier['type'] == 'ip':
        address_text, server_name = value, ipaddress.ip_address(value).reverse_pointer
    else:
        address_text, server_name = value, value
    try:
        address = resolve(address_text, port, True)
    except pinned_https.UnsafeDestination as refused:
        kind = 'dns' if 'does not resolve' in str(refused) else 'connection'
        raise ValidationFailed(kind, str(refused)) from None
    context = tls_alpn_context()
    remaining = deadline - clock()
    if remaining <= 0:
        raise ValidationFailed('connection', f'The check ran out of its {BUDGET_SECONDS} seconds')
    where = f'{address_text}:{port}'
    try:
        raw = socket.create_connection((address, port), timeout=remaining)
    except OSError as error:
        raise ValidationFailed('connection', f'{where}: {error.__class__.__name__}: {error}') from None
    try:
        with context.wrap_socket(raw, server_hostname=server_name) as conn:
            negotiated = conn.selected_alpn_protocol()
            der = conn.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as error:
        raise ValidationFailed('tls', f'{where}: the TLS handshake failed: {error}') from None
    finally:
        raw.close()
    if negotiated != ACME_TLS_PROTOCOL:
        raise ValidationFailed('incorrectResponse', f'{where} negotiated {negotiated!r}, not {ACME_TLS_PROTOCOL}')
    refusal = _validation_certificate_refusal(der, identifier, key_authorization)
    if refusal:
        raise ValidationFailed('incorrectResponse', f'{where}: {refusal}')


def tls_alpn_context():
    """The client side of a tls-alpn-01 check: acme-tls/1 alone, TLS 1.2 at least, nothing verified.

    TLS 1.2 is RFC 8737's floor (section 4). OpenSSL 3's default security level
    refuses older versions already; the floor is set here so that the check
    does not depend on how the library under it is configured.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE                 # the certificate is read, not trusted
    context.set_alpn_protocols([ACME_TLS_PROTOCOL])
    return context


def _validation_certificate_refusal(der, identifier, key_authorization):
    """Why the certificate a tls-alpn-01 handshake showed does not prove *identifier*, or None."""
    try:
        certificate = x509.load_der_x509_certificate(der or b'')
        names = list(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
    except x509.ExtensionNotFound:
        return 'the certificate has no subjectAltName'
    except ValueError as error:
        return f'the certificate could not be read: {error}'
    if identifier['type'] == 'ip':
        wanted = x509.IPAddress(ipaddress.ip_address(identifier['value']))
        matches = names == [wanted]
    else:
        matches = (len(names) == 1 and isinstance(names[0], x509.DNSName)
                   and names[0].value.lower() == identifier['value'].lower())
    if not matches:
        return f'the certificate names {[str(n.value) for n in names]}, not {identifier["value"]} alone'
    try:
        extension = certificate.extensions.get_extension_for_oid(ACME_IDENTIFIER_OID)
    except x509.ExtensionNotFound:
        return 'the certificate has no acmeIdentifier extension'
    except ValueError as error:
        return f'the certificate could not be read: {error}'
    if not extension.critical:
        return 'the acmeIdentifier extension is not critical'
    expected = b'\x04\x20' + hashlib.sha256(key_authorization.encode('ascii')).digest()
    if getattr(extension.value, 'value', None) != expected:
        return 'the acmeIdentifier extension does not hold the digest of this challenge\'s key authorization'
    return None


def dns01(name, key_authorization, *, resolver):
    """Return when a TXT record at _acme-challenge.<name> holds the key authorization's digest."""
    import dns.exception
    import dns.resolver

    qname = f'_acme-challenge.{name}'
    try:
        answer = resolver.resolve(qname, 'TXT', search=False)
    except dns.resolver.NXDOMAIN:
        raise ValidationFailed('dns', f'{qname} does not exist') from None
    except dns.resolver.NoAnswer:
        raise ValidationFailed('dns', f'{qname} has no TXT record') from None
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as error:
        raise ValidationFailed('dns', f'{qname} could not be resolved: {error.__class__.__name__}') from None
    found = [b''.join(record.strings).decode('utf-8', 'replace') for record in answer]
    if dns01_digest(key_authorization) not in found:
        raise ValidationFailed('incorrectResponse', f'{qname} holds {found[:3]!r}, not the digest of '
                               'this challenge\'s key authorization')
