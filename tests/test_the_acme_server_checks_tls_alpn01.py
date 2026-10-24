"""The ACME server checks tls-alpn-01 (RFC 8737, #1339).

A client that can answer only on port 443 proves a name, or an address, with a
TLS server that negotiates the ALPN protocol acme-tls/1 and shows a certificate
naming that identifier alone, with a critical acmeIdentifier extension holding
the SHA-256 of the key authorization. The server connects to the address it
checked, offers acme-tls/1 alone, sends the name as SNI (an address's
reverse-mapping name, RFC 8738 section 6), and reads what it is shown. A
wildcard is never offered tls-alpn-01. Every refusal below was measured against
the local responder before it was written down.
"""
import datetime
import hashlib
import ipaddress
import socket
import ssl
import tempfile
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from modules.core import acme_validation, pinned_https
from tests.acme_support import (
    ChallengeServer,
    b64s,
    eab_for,
    registered_client,
    resolve_for_tests,
    served_app,
)

pytestmark = [pytest.mark.unit]

NAME = 'web.lab.internal'
ADDRESS = '10.20.0.5'


class AlpnResponder:
    """A TLS server on 127.0.0.1 answering each connection with what the test set."""

    def __init__(self):
        self.certificate = None          # (cert, key)
        self.alpn = [acme_validation.ACME_TLS_PROTOCOL]
        self.speaks_tls = True           # False: it answers in plain HTTP, as a misrouted port would
        self.server_names = []
        self._dir = Path(tempfile.mkdtemp())
        self._listener = socket.create_server(('127.0.0.1', 0))
        self.port = self._listener.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            try:
                if not self.speaks_tls:
                    conn.recv(1024)
                    conn.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
                    continue
                context = self._context()
                with context.wrap_socket(conn, server_side=True):
                    pass
            except (OSError, ssl.SSLError):
                pass
            finally:
                conn.close()

    def _context(self):
        cert, key = self.certificate
        (self._dir / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (self._dir / 'key.pem').write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self._dir / 'cert.pem', self._dir / 'key.pem')
        if self.alpn:
            context.set_alpn_protocols(self.alpn)
        context.sni_callback = lambda _sock, name, _ctx: self.server_names.append(name)
        return context

    def close(self):
        # Shut down first: on Linux a listening socket closed while a thread
        # waits in accept() goes on accepting connections, on macOS it does not.
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self._listener.close()


def validation_certificate(key_authorization, names, critical=True, digest=None, with_extension=True):
    """The self-signed certificate a tls-alpn-01 client shows (RFC 8737 section 3)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    builder = (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(x509.Name([]))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(minutes=1))
               .not_valid_after(now + datetime.timedelta(days=1)))
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=True)
    if with_extension:
        value = digest or hashlib.sha256(key_authorization.encode()).digest()
        builder = builder.add_extension(
            x509.UnrecognizedExtension(acme_validation.ACME_IDENTIFIER_OID, b'\x04\x20' + value), critical=critical)
    return builder.sign(key, hashes.SHA256()), key


@pytest.fixture
def alpn():
    responder = AlpnResponder()
    yield responder
    responder.close()


@pytest.fixture
def app(alpn):
    challenge_server = ChallengeServer()
    application = served_app(challenge_server)
    server = application.extensions['certmate_container'].managers['acme_server']
    server.tls_alpn_port = alpn.port

    def resolve(host, port, allow_internal):
        if host == ADDRESS:
            return '127.0.0.1'
        return resolve_for_tests(host, port, allow_internal)

    server.resolve = resolve
    yield application
    challenge_server.close()


@pytest.fixture
def client(app):
    return registered_client(app, eab_for(app, ['*.lab.internal', '10.20.0.0/16']))


def _challenge(client, identifier):
    kind = 'ip' if identifier == ADDRESS else 'dns'
    order = client.post('new-order', {'identifiers': [{'type': kind, 'value': identifier}]})
    assert order.status_code == 201, order.get_json()
    authz = client.post(order.get_json()['authorizations'][0], None).get_json()
    challenge = next(c for c in authz['challenges'] if c['type'] == 'tls-alpn-01')
    return challenge, f'{challenge["token"]}.{b64s(client.key.thumbprint())}'


def _answer(client, challenge):
    return client.post(challenge['url'], {}).get_json()


# --- accepted ------------------------------------------------------------------------

def test_a_name_is_proved_on_port_443_with_acme_tls_1(client, alpn):
    challenge, key_authorization = _challenge(client, NAME)
    alpn.certificate = validation_certificate(key_authorization, [x509.DNSName(NAME)])
    assert _answer(client, challenge)['status'] == 'valid'
    assert alpn.server_names == [NAME]


def test_an_address_is_proved_with_its_reverse_name_as_sni(client, alpn):
    challenge, key_authorization = _challenge(client, ADDRESS)
    alpn.certificate = validation_certificate(key_authorization, [x509.IPAddress(ipaddress.ip_address(ADDRESS))])
    assert _answer(client, challenge)['status'] == 'valid'
    assert alpn.server_names == ['5.0.20.10.in-addr.arpa'], 'RFC 8738 section 6: no IP address as SNI'


def test_a_name_compares_without_case(client, alpn):
    challenge, key_authorization = _challenge(client, NAME)
    alpn.certificate = validation_certificate(key_authorization, [x509.DNSName(NAME.upper())])
    assert _answer(client, challenge)['status'] == 'valid'


# --- refused -----------------------------------------------------------------------------

@pytest.mark.parametrize('identifier,certificate,because', [
    (NAME, lambda ka: validation_certificate(ka, [x509.DNSName(NAME)], with_extension=False),
     'no acmeIdentifier extension'),
    (NAME, lambda ka: validation_certificate(ka, [x509.DNSName(NAME)], critical=False), 'not critical'),
    (NAME, lambda ka: validation_certificate(ka, [x509.DNSName(NAME)], digest=hashlib.sha256(b'other').digest()),
     'does not hold the digest'),
    (NAME, lambda ka: validation_certificate(ka, [x509.DNSName(NAME), x509.DNSName('api.lab.internal')]),
     f'not {NAME} alone'),
    (NAME, lambda ka: validation_certificate(ka, [x509.DNSName('api.lab.internal')]), f'not {NAME} alone'),
    (NAME, lambda ka: validation_certificate(ka, []), 'no subjectAltName'),
    (ADDRESS, lambda ka: validation_certificate(ka, [x509.DNSName(ADDRESS)]), f'not {ADDRESS} alone'),
    (ADDRESS, lambda ka: validation_certificate(ka, [x509.IPAddress(ipaddress.ip_address('10.20.9.9'))]),
     f'not {ADDRESS} alone'),
])
def test_a_certificate_that_does_not_prove_the_identifier_is_refused(client, alpn, identifier, certificate, because):
    challenge, key_authorization = _challenge(client, identifier)
    alpn.certificate = certificate(key_authorization)
    answered = _answer(client, challenge)
    assert answered['status'] == 'invalid'
    assert answered['error']['type'] == 'urn:ietf:params:acme:error:incorrectResponse'
    assert because in answered['error']['detail']


@pytest.mark.parametrize('protocols', [['h2'], None], ids=['another-protocol', 'no-alpn'])
def test_a_server_that_does_not_negotiate_acme_tls_1_is_refused(client, alpn, protocols):
    challenge, key_authorization = _challenge(client, NAME)
    alpn.certificate = validation_certificate(key_authorization, [x509.DNSName(NAME)])
    alpn.alpn = protocols
    answered = _answer(client, challenge)
    assert answered['status'] == 'invalid'
    assert 'negotiated None, not acme-tls/1' in answered['error']['detail']


def test_the_check_asks_for_tls_1_2_at_least_and_trusts_nothing():
    """The floor is the check's own, not only OpenSSL's. OpenSSL 3's default
    security level refuses TLS 1.1 already (measured: with the floor lowered, a
    TLS 1.1 responder still failed the handshake), so the setting is pinned
    here rather than through a responder that would pass either way, and the
    tests run no TLS below 1.2 at all."""
    context = acme_validation.tls_alpn_context()
    assert context.minimum_version == ssl.TLSVersion.TLSv1_2
    assert context.verify_mode == ssl.CERT_NONE and context.check_hostname is False


def test_a_handshake_that_fails_is_a_tls_problem(client, alpn):
    """A port that does not speak TLS. Before the "tls" problem type was
    registered, this answered 500 instead of an invalid challenge."""
    challenge, _key_authorization = _challenge(client, NAME)
    alpn.speaks_tls = False
    answered = _answer(client, challenge)
    assert answered['status'] == 'invalid'
    assert answered['error']['type'] == 'urn:ietf:params:acme:error:tls'


def _a_port_nothing_listens_on():
    """Bound and closed without listen(): refused on Linux and macOS alike, where
    a listener closed during accept() is not (it goes on accepting on Linux)."""
    probe = socket.socket()
    probe.bind(('127.0.0.1', 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_nothing_listening_is_a_connection_error(app, client):
    challenge, _key_authorization = _challenge(client, NAME)
    app.extensions['certmate_container'].managers['acme_server'].tls_alpn_port = _a_port_nothing_listens_on()
    answered = _answer(client, challenge)
    assert answered['status'] == 'invalid'
    assert answered['error']['type'] == 'urn:ietf:params:acme:error:connection'


def test_a_wildcard_is_never_offered_tls_alpn01(client):
    order = client.post('new-order', {'identifiers': [{'type': 'dns', 'value': '*.lab.internal'}]})
    authz = client.post(order.get_json()['authorizations'][0], None).get_json()
    assert [c['type'] for c in authz['challenges']] == ['dns-01']


# --- the guards the check shares with http-01 ------------------------------------------------

def test_a_name_that_resolves_to_loopback_is_never_connected_to():
    with pytest.raises(acme_validation.ValidationFailed) as failed:
        acme_validation.tls_alpn01({'type': 'dns', 'value': 'localhost'}, 'k.a', port=443,
                                   resolve=pinned_https.resolve)
    assert failed.value.kind == 'connection'
    assert 'never a valid destination' in failed.value.detail


def test_the_check_keeps_to_its_budget(alpn):
    ticks = iter([0, acme_validation.BUDGET_SECONDS + 1])
    with pytest.raises(acme_validation.ValidationFailed, match='ran out'):
        acme_validation.tls_alpn01({'type': 'dns', 'value': NAME}, 'k.a', port=alpn.port,
                                   resolve=lambda h, p, a: '127.0.0.1', clock=lambda: next(ticks))


def test_the_check_ends_with_the_handshake(alpn):
    """Section 4: no application data after the handshake. The responder reads
    nothing, so a client that sent any would not be told; what is checked is
    that the call returns at once rather than waiting on the connection."""
    key_authorization = 'token.thumbprint'
    alpn.certificate = validation_certificate(key_authorization, [x509.DNSName(NAME)])
    started = time.monotonic()
    acme_validation.tls_alpn01({'type': 'dns', 'value': NAME}, key_authorization, port=alpn.port,
                               resolve=lambda h, p, a: '127.0.0.1')
    assert time.monotonic() - started < 2


def test_a_certificate_that_cannot_be_read_is_refused_not_an_error(client, alpn):
    """Measured before the fix: subjectAltName twice raised DuplicateExtension,
    which is not a ValueError, out of the check, and the challenge answered
    HTTP 500 instead of an invalid challenge.

    Which refusal it is depends on the TLS library serving the responder,
    measured: OpenSSL 3.5.9 (macOS) presents the certificate and the check says
    it could not be read; OpenSSL 3.5.7 (Linux, CI) closes the connection first
    and the handshake fails. Either way the challenge is invalid, never a 500;
    the reading itself is pinned below, apart from any TLS library."""
    challenge, key_authorization = _challenge(client, NAME)
    alpn.certificate = _with_two_subject_alt_names(key_authorization)
    answered = _answer(client, challenge)
    assert answered['status'] == 'invalid'
    assert answered['error']['type'] in ('urn:ietf:params:acme:error:incorrectResponse',
                                         'urn:ietf:params:acme:error:tls')


def _with_an_x400_address():
    """A subjectAltName holding an x400Address ([3]), a kind of name cryptography
    does not parse: reading the extensions raises UnsupportedGeneralNameType."""
    from cryptography.x509.oid import ExtensionOID
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    return (x509.CertificateBuilder().subject_name(x509.Name([])).issuer_name(x509.Name([]))
            .public_key(key.public_key()).serial_number(1)
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.UnrecognizedExtension(ExtensionOID.SUBJECT_ALTERNATIVE_NAME,
                                                      bytes.fromhex('3002a300')), critical=True)
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))


@pytest.mark.parametrize('der', [
    pytest.param(b'', id='nothing'),
    pytest.param(b'not a certificate', id='not-der'),
    pytest.param('x400', id='a-name-of-an-unparsed-kind'),
    pytest.param('duplicate', id='subject-alt-name-twice'),
])
def test_bytes_that_are_no_readable_certificate_are_refused(der):
    if der == 'x400':
        der = _with_an_x400_address()
    elif der == 'duplicate':
        der = _with_two_subject_alt_names('k.a')[0].public_bytes(serialization.Encoding.DER)
    refusal = acme_validation._validation_certificate_refusal(der, {'type': 'dns', 'value': NAME}, 'k.a')
    assert refusal.startswith('the certificate could not be read')


def _with_two_subject_alt_names(key_authorization):
    """A certificate no parser accepts: subjectAltName twice. cryptography's
    builder refuses that, so an extension under a placeholder OID of the same
    DER length is renamed in the encoding (the signature then no longer
    verifies, which the check does not ask about)."""
    from cryptography.x509.oid import ObjectIdentifier
    cert, key = validation_certificate(key_authorization, [x509.DNSName(NAME)])
    placeholder = (x509.CertificateBuilder().subject_name(cert.subject).issuer_name(cert.issuer)
                   .public_key(key.public_key()).serial_number(cert.serial_number)
                   .not_valid_before(cert.not_valid_before_utc).not_valid_after(cert.not_valid_after_utc))
    for extension in cert.extensions:
        placeholder = placeholder.add_extension(extension.value, extension.critical)
    placeholder = placeholder.add_extension(x509.UnrecognizedExtension(
        ObjectIdentifier('2.5.29.99'), x509.SubjectAlternativeName([x509.DNSName(NAME)]).public_bytes()), False)
    der = placeholder.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)
    assert der.count(bytes.fromhex('0603551d63')) == 1
    return x509.load_der_x509_certificate(der.replace(bytes.fromhex('0603551d63'), bytes.fromhex('0603551d11'))), key
