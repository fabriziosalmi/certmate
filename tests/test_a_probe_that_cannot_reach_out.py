"""The inventory probe could not see anything from behind an outbound proxy.

#326 taught the *deployment-status* probe to tunnel through `HTTPS_PROXY` with
HTTP CONNECT. Four other things that dial a host kept opening raw sockets, and
a raw socket does not read those variables at all:

* the deep TLS probe (`cert_probe.probe_certificate`) — the inventory sweep,
  and `POST /api/probe`;
* the OCSP/CRL fetch behind every revocation answer;
* the HSTS / security-header check;
* the TLS 1.0/1.1 check.

On a host whose only route out is a proxy, an inventory scan therefore
reported every endpoint `unreachable`, every revocation `unavailable` and
every header check `unknown` — a whole feature answering "I don't know" with
nothing to say why.

The fix is one opener, `cert_probe.open_probe_transport`, and its order
matters:

1. a target that resolves to a **non-global** address is dialled directly,
   whatever the environment says, because no outbound proxy serves `10.0.0.5`
   and routing it through one would break a probe that works today;
2. otherwise the proxy, when one applies (`HTTPS_PROXY` minus `NO_PROXY`);
3. otherwise the validated address, pinned, exactly as before.

The SSRF guard runs first either way: what a caller resolved still decides
whether the connection happens at all.
"""
import http.client
import socket
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from modules.core import cert_probe
from modules.core.cert_probe import (
    STATUS_OK, open_probe_transport, probe_certificate, proxy_for,
)

pytestmark = [pytest.mark.unit]

# The tunnel is only chosen for a target the guard considers PUBLIC, and
# `ip_is_blocked` refuses every documentation range — `is_global` is False for
# 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 alike. The first draft
# pointed these tests at 203.0.113.10, which took the direct leg by design and
# exercised nothing.
#
# So the address stays loopback and the *verdict* is what the fixture
# replaces. A regression that takes the direct leg then dials 127.0.0.1:443
# and is refused immediately, instead of opening a socket to a stranger — the
# suite reaches no network. One test below uses a real global address, so the
# rule itself is covered where it is decided rather than only where it is
# stubbed.
PINNED = '127.0.0.1'
A_REAL_GLOBAL_ADDRESS = '1.2.3.4'
PROBE_HOST = 'probe.example.test'


# --------------------------------------------------------------------------- #
# A TLS server and a CONNECT proxy, both in-process
# --------------------------------------------------------------------------- #

def _self_signed(common_name, tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(common_name)]),
                           critical=False)
            .sign(key, hashes.SHA256()))
    certfile = tmp_path / 'cert.pem'
    keyfile = tmp_path / 'key.pem'
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()))
    return cert, str(certfile), str(keyfile)


class _TLSBackend:
    """A TLS server on 127.0.0.1 that completes a handshake and hangs up."""

    def __init__(self, certfile, keyfile, refuse_starttls=False):
        self.refuse_starttls = refuse_starttls
        # What the sessions actually did. A fake that fails inside its own
        # thread is otherwise invisible: the test waits out the probe's read
        # timeout and reports a timeout, which says nothing about why.
        self.sessions = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handshake, args=(conn,),
                             daemon=True).start()

    def _handshake(self, conn):
        try:
            with self._ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(16)
        except (OSError, ssl.SSLError):
            pass

    def close(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass


class _ConnectProxy:
    """A minimal HTTP proxy on 127.0.0.1.

    It answers CONNECT by tunnelling to ONE fixed backend port, whatever host
    the client asked for — which is what makes the end-to-end test conclusive:
    the probe asks for a name that resolves to an address nothing is listening
    on, and gets a certificate back. Only the tunnel can have delivered it.

    It also answers an absolute-URI GET/POST (the wire form a plain-http proxy
    takes), so the OCSP/CRL leg can be driven through the same object.
    """

    def __init__(self, backend_port, require_auth=None, http_body=None):
        self.backend_port = backend_port
        self.require_auth = require_auth
        self.http_body = http_body
        self.connect_targets = []
        self.absolute_requests = []
        self.credentials = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._running = True
        threading.Thread(target=self._serve, daemon=True).start()

    @property
    def url(self):
        return f'http://127.0.0.1:{self.port}'

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,),
                             daemon=True).start()

    def _handle(self, conn):
        try:
            head = b''
            while b'\r\n\r\n' not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    conn.close()
                    return
                head += chunk
            lines = head.split(b'\r\n')
            method, target, _version = lines[0].decode().split(' ', 2)
            for line in lines[1:]:
                if line.lower().startswith(b'proxy-authorization:'):
                    self.credentials.append(line.split(b': ', 1)[1].decode())
            if self.require_auth and self.require_auth not in self.credentials:
                conn.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n')
                conn.close()
                return
            if method == 'CONNECT':
                self.connect_targets.append(target)
                self._tunnel(conn)
                return
            self.absolute_requests.append((method, target))
            body = self.http_body or b''
            conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: '
                         + str(len(body)).encode() + b'\r\n\r\n' + body)
            conn.close()
        except OSError:
            try:
                conn.close()
            except OSError:
                pass

    def _tunnel(self, client):
        try:
            upstream = socket.create_connection(('127.0.0.1', self.backend_port),
                                                timeout=5)
        except OSError:
            client.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
            client.close()
            return
        client.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')

        def pump(src, dst):
            try:
                while True:
                    data = src.recv(4096)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                for s in (src, dst):
                    try:
                        s.close()
                    except OSError:
                        pass

        threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
        threading.Thread(target=pump, args=(upstream, client), daemon=True).start()

    def close(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass


@pytest.fixture
def backend(tmp_path):
    cert, certfile, keyfile = _self_signed(PROBE_HOST, tmp_path)
    server = _TLSBackend(certfile, keyfile)
    yield server, cert
    server.close()


@pytest.fixture
def proxy(backend):
    server, _cert = backend
    p = _ConnectProxy(server.port)
    yield p
    p.close()


@pytest.fixture
def through_proxy(proxy, monkeypatch):
    """`HTTPS_PROXY` set, and the probe's name resolving somewhere unreachable.

    `no_proxy` is removed first: conftest sets it so no test inherits a real
    proxy, and `proxy_bypass` reads the same environment — left in place it
    would bypass the proxy this fixture just configured.
    """
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', proxy.url)
    monkeypatch.setenv('http_proxy', proxy.url)
    monkeypatch.setattr(
        cert_probe, '_resolve_and_guard',
        lambda host, port, allow_private: (socket.AF_INET, PINNED, None))
    monkeypatch.setattr(cert_probe, 'ip_is_blocked', lambda ip: None)
    return proxy


# --------------------------------------------------------------------------- #
# THE regression, end to end
# --------------------------------------------------------------------------- #

def test_the_probe_reads_a_certificate_through_the_proxy(through_proxy, backend):
    """The name resolves to an address nothing is listening on. A certificate
    came back, so the handshake ran over the tunnel."""
    _server, cert = backend

    result = probe_certificate(PROBE_HOST, port=443, timeout=5)

    assert result['status'] == STATUS_OK, result.get('error')
    assert result['certificate']['fingerprint_sha256'] == \
        cert.fingerprint(hashes.SHA256()).hex()
    assert through_proxy.connect_targets == [f'{PROBE_HOST}:443']


def test_without_the_proxy_the_same_probe_cannot_connect(backend, monkeypatch):
    """THE control. Same target, no proxy: the probe fails, which is what the
    whole defect looked like. Without this the test above would pass just as
    well against a probe that had never learned to tunnel and happened to
    reach the host some other way.

    A connection to TEST-NET-3 would sit there until the timeout, so the
    direct leg is made to refuse at once instead — the point being WHICH leg
    runs, not how long it waits.
    """
    refused = {'n': 0}

    def refuse(family, type_):
        refused['n'] += 1
        raise ConnectionRefusedError('nothing is listening there')

    monkeypatch.setattr(
        cert_probe, '_resolve_and_guard',
        lambda host, port, allow_private: (socket.AF_INET, PINNED, None))
    monkeypatch.setattr(cert_probe, 'ip_is_blocked', lambda ip: None)
    monkeypatch.setattr(cert_probe.socket, 'socket', refuse)

    result = probe_certificate(PROBE_HOST, port=443, timeout=2)

    assert result['status'] == 'unreachable'
    assert result['error_class'] == 'connection_error'
    assert refused['n'] == 1, 'the direct leg was not the one that ran'


def test_the_failure_says_the_proxy_was_involved(backend, monkeypatch):
    """A refusal that names 127.0.0.1:<port> and not the target sends an
    operator to the wrong host."""
    dead = socket.socket()
    dead.bind(('127.0.0.1', 0))
    dead_port = dead.getsockname()[1]
    dead.close()

    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', f'http://127.0.0.1:{dead_port}')
    monkeypatch.setattr(
        cert_probe, '_resolve_and_guard',
        lambda host, port, allow_private: (socket.AF_INET, PINNED, None))
    monkeypatch.setattr(cert_probe, 'ip_is_blocked', lambda ip: None)

    result = probe_certificate(PROBE_HOST, port=443, timeout=2)

    assert result['status'] == 'unreachable'
    assert 'proxy' in (result['error'] or '').lower()
    assert str(dead_port) in result['error']


def test_a_guard_refusal_is_not_tunnelled(through_proxy, monkeypatch):
    """The proxy does not become a way around the SSRF guard.

    The guard runs before the transport is chosen, so a refusal is still a
    refusal — and the proxy is never asked, which is the part that matters:
    `POST /api/probe` takes the viewer role and a host from the request body.
    """
    monkeypatch.setattr(
        cert_probe, '_resolve_and_guard',
        lambda host, port, allow_private: (
            None, None, 'target refused by SSRF guard: private address 10.0.0.5'))

    result = probe_certificate('internal.example.test', port=443, timeout=2)

    assert result['status'] == 'blocked'
    assert through_proxy.connect_targets == [], 'the refused target was dialled'


def test_a_private_target_is_still_dialled_directly(proxy, monkeypatch, tmp_path):
    """An operator who monitors `10.0.0.5` with `allow_private` has a target
    no outbound proxy can reach. Routing it through one would break a probe
    that works today, so a non-global address never takes the tunnel."""
    cert, certfile, keyfile = _self_signed('localhost', tmp_path)
    local = _TLSBackend(certfile, keyfile)
    try:
        monkeypatch.delenv('no_proxy', raising=False)
        monkeypatch.setenv('https_proxy', proxy.url)

        result = probe_certificate('127.0.0.1', port=local.port, timeout=5,
                                   allow_private=True, server_name='localhost')

        assert result['status'] == STATUS_OK, result.get('error')
        assert result['certificate']['fingerprint_sha256'] == \
            cert.fingerprint(hashes.SHA256()).hex()
        assert proxy.connect_targets == [], 'a loopback target went to the proxy'
    finally:
        local.close()


def test_proxy_credentials_reach_the_proxy(backend, monkeypatch):
    """A proxy that requires authentication is the common corporate case, and
    a 407 is indistinguishable from a broken target unless the header is
    actually sent."""
    server, _cert = backend
    authenticated = _ConnectProxy(server.port, require_auth='Basic dTpw')  # u:p
    try:
        monkeypatch.delenv('no_proxy', raising=False)
        monkeypatch.setenv('https_proxy', f'http://u:p@127.0.0.1:{authenticated.port}')
        monkeypatch.setattr(
            cert_probe, '_resolve_and_guard',
            lambda host, port, allow_private: (socket.AF_INET, PINNED, None))
        monkeypatch.setattr(cert_probe, 'ip_is_blocked', lambda ip: None)

        result = probe_certificate(PROBE_HOST, port=443, timeout=5)

        assert result['status'] == STATUS_OK, result.get('error')
        assert authenticated.credentials == ['Basic dTpw']
    finally:
        authenticated.close()


# --------------------------------------------------------------------------- #
# Which transport gets chosen
# --------------------------------------------------------------------------- #

def test_no_proxy_configured_means_a_direct_connection(backend):
    server, _cert = backend
    sock, closer, via = open_probe_transport('localhost', server.port,
                                             socket.AF_INET, '127.0.0.1', 5)
    try:
        assert via is None
        assert sock.getpeername()[1] == server.port
    finally:
        closer()


def test_the_bypass_list_is_honoured(proxy, backend, monkeypatch):
    """`NO_PROXY` is how an operator keeps internal names off the proxy, and
    it is the mechanism the direct path depends on for a name that resolves
    publicly but is served internally."""
    server, _cert = backend
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', proxy.url)
    monkeypatch.setenv('no_proxy', 'internal.example.test')

    assert proxy_for('internal.example.test') is None
    assert proxy_for('elsewhere.example.test') == ('127.0.0.1', proxy.port, {})

    sock, closer, via = open_probe_transport('localhost', server.port,
                                             socket.AF_INET, '127.0.0.1', 5)
    closer()
    assert via is None


@pytest.mark.parametrize('value,expected', [
    ('http://proxy.internal:3128', ('proxy.internal', 3128, {})),
    ('proxy.internal:3128', ('proxy.internal', 3128, {})),
    ('http://proxy.internal', ('proxy.internal', 8080, {})),
])
def test_how_the_variable_is_read(monkeypatch, value, expected):
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', value)
    assert proxy_for('example.com') == expected


def test_the_plain_http_variable_is_a_different_one(monkeypatch):
    """OCSP and CRL endpoints are `http://`, so they read HTTP_PROXY. An
    instance that sets only one of the two must not have the other invented
    for it."""
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('http_proxy', 'http://plain.internal:3128')

    assert proxy_for('example.com', 'http') == ('plain.internal', 3128, {})
    assert proxy_for('example.com', 'https') is None


# --------------------------------------------------------------------------- #
# The other three legs
# --------------------------------------------------------------------------- #

def test_the_revocation_fetch_goes_through_the_proxy(monkeypatch):
    """The handshake succeeding and the revocation answer timing out is worse
    than either alone: every certificate reports `unavailable`, which reads as
    an outage rather than as a missing proxy."""
    from modules.core import revocation

    served = b'der-bytes'
    plain = _ConnectProxy(backend_port=0, http_body=served)
    try:
        monkeypatch.delenv('no_proxy', raising=False)
        monkeypatch.setenv('http_proxy', plain.url)
        monkeypatch.setattr(
            cert_probe, '_resolve_and_guard',
            lambda host, port, allow_private: (socket.AF_INET, PINNED, None))
        monkeypatch.setattr(cert_probe, 'ip_is_blocked', lambda ip: None)

        body = revocation.fetch_url('http://ocsp.example.test/status',
                                    timeout=5, max_bytes=4096,
                                    allow_private=False)

        assert body == served
        # Absolute-URI request line: the wire form a plain-http proxy takes.
        assert plain.absolute_requests == [
            ('GET', 'http://ocsp.example.test/status')]
    finally:
        plain.close()


def test_the_header_check_and_the_weak_tls_check_use_the_same_opener(monkeypatch):
    """Both used to open their own socket, so the #326 fix reached neither.
    Driven rather than read: the opener is replaced and each check is run.
    """
    from modules.core import domain_health, weak_tls

    calls = []
    real = cert_probe.open_probe_transport

    def spy(host, port, family, connect_ip, timeout):
        calls.append((host, port))
        raise ConnectionRefusedError('not today')

    monkeypatch.setattr(cert_probe, 'open_probe_transport', spy)
    monkeypatch.setattr(
        cert_probe, '_resolve_and_guard',
        lambda host, port, allow_private: (socket.AF_INET, PINNED, None))

    assert domain_health.fetch_response_headers('headers.example.test') is None
    assert weak_tls.probe('tls.example.test', 'TLSv1') == weak_tls.UNAVAILABLE

    assert calls == [('headers.example.test', 443), ('tls.example.test', 443)]
    assert real is not spy  # the real one is what production runs


def test_a_global_address_takes_the_tunnel(proxy, backend, monkeypatch):
    """The rule where it is really decided: no stubbed verdict, a genuinely
    global address, and `ip_is_blocked` asked for real.

    It is also the only test here that could put a packet on the wire, and
    only by regressing: if the direct leg were chosen it would dial
    1.2.3.4:443 and wait out the timeout instead of answering.
    """
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', proxy.url)

    sock, closer, via = open_probe_transport(PROBE_HOST, 443, socket.AF_INET,
                                             A_REAL_GLOBAL_ADDRESS, 4)
    try:
        assert via == f'127.0.0.1:{proxy.port}'
        assert proxy.connect_targets == [f'{PROBE_HOST}:443']
    finally:
        closer()


def test_the_tunnel_carries_the_timeout(through_proxy, backend):
    """A socket handed back with no timeout blocks a worker thread until the
    kernel gives up, which on a stalled proxy is minutes."""
    sock, closer, via = open_probe_transport(PROBE_HOST, 443, socket.AF_INET,
                                             PINNED, 4)
    try:
        assert via == f'127.0.0.1:{through_proxy.port}'
        assert sock.gettimeout() == pytest.approx(4, abs=0.5)
    finally:
        closer()


def test_a_proxy_that_answers_nonsense_raises_a_connection_error(monkeypatch):
    """`http.client` can raise HTTPException, which is not an OSError — and
    all three callers promise never to raise. Measured against a server that
    answers a CONNECT with a status line longer than http.client accepts."""
    junk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    junk.bind(('127.0.0.1', 0))
    junk.listen(1)
    junk_port = junk.getsockname()[1]

    def answer():
        try:
            conn, _ = junk.accept()
            conn.recv(4096)
            conn.sendall(b'HTTP/1.1 200 ' + b'x' * 70000 + b'\r\n\r\n')
            time.sleep(0.2)
            conn.close()
        except OSError:
            pass

    threading.Thread(target=answer, daemon=True).start()
    try:
        monkeypatch.delenv('no_proxy', raising=False)
        monkeypatch.setenv('https_proxy', f'http://127.0.0.1:{junk_port}')
        monkeypatch.setattr(cert_probe, 'ip_is_blocked', lambda ip: None)

        with pytest.raises(ConnectionError) as raised:
            open_probe_transport(PROBE_HOST, 443, socket.AF_INET, PINNED, 3)

        assert 'proxy' in str(raised.value).lower()
        assert not isinstance(raised.value, http.client.HTTPException)
    finally:
        junk.close()


# --------------------------------------------------------------------------- #
# The deployment probe: both of its legs, over the tunnel
# --------------------------------------------------------------------------- #

class _SMTPBackend:
    """A server that offers STARTTLS and then speaks TLS.

    The SMTP leg was the half of #326 the fix did not reach — it opened a raw
    socket while the direct-TLS leg tunnelled — and nothing drove it end to
    end afterwards. This is that probe, over a real tunnel, on the real wire
    sequence: banner, EHLO, STARTTLS, upgrade.
    """

    def __init__(self, certfile, keyfile, refuse_starttls=False):
        self.refuse_starttls = refuse_starttls
        # What the sessions actually did. A fake that fails inside its own
        # thread is otherwise invisible: the test waits out the probe's read
        # timeout and reports a timeout, which says nothing about why.
        self.sessions = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', 0))
        self._sock.listen(4)
        self.port = self._sock.getsockname()[1]
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,),
                             daemon=True).start()

    def _session(self, conn):
        try:
            stream = conn.makefile('rwb')
            stream.write(b'220 smtp.example.test ESMTP\r\n')
            stream.flush()
            stream.readline()                       # EHLO
            if self.refuse_starttls:
                stream.write(b'250 smtp.example.test\r\n')
                stream.flush()
                stream.readline()                   # STARTTLS
                stream.write(b'454 TLS not available\r\n')
                stream.flush()
                self.sessions.append('refused')
                return
            stream.write(b'250-smtp.example.test\r\n250 STARTTLS\r\n')
            stream.flush()
            stream.readline()                       # STARTTLS
            stream.write(b'220 ready\r\n')
            stream.flush()
            with self._ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(16)
            self.sessions.append('upgraded')
        except (OSError, ssl.SSLError, ValueError) as error:
            self.sessions.append(f'{type(error).__name__}: {error}')
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass


def test_the_deployment_probe_still_tunnels(proxy, backend, monkeypatch):
    """#326's own leg, driven rather than assumed: it has unit tests for how
    the variable is parsed and none that read a certificate through a
    tunnel."""
    from modules.api.tls_probe import _probe_tls_certificate

    _server, cert = backend
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.setenv('https_proxy', proxy.url)

    result = _probe_tls_certificate(PROBE_HOST, port=443, timeout=5)

    assert result['reachable'] is True
    assert result['certificate_bytes']
    assert proxy.connect_targets == [f'{PROBE_HOST}:443']


def test_the_smtp_leg_tunnels_too(tmp_path, monkeypatch):
    """The other half. A STARTTLS upgrade over a CONNECT tunnel, end to end:
    the certificate that comes back is the one the SMTP server presented
    after the upgrade, which is the only thing that proves the sequence ran.
    """
    from modules.api.tls_probe import _certificate_fingerprint, _probe_tls_certificate

    cert, certfile, keyfile = _self_signed('smtp.example.test', tmp_path)
    smtp = _SMTPBackend(certfile, keyfile)
    relay = _ConnectProxy(smtp.port)
    try:
        monkeypatch.delenv('no_proxy', raising=False)
        monkeypatch.setenv('https_proxy', relay.url)

        result = _probe_tls_certificate('smtp.example.test', port=587,
                                        protocol='smtp-starttls', timeout=5)

        assert result['reachable'] is True
        assert result['protocol'] == 'smtp-starttls'
        assert _certificate_fingerprint(result['certificate_bytes']) == \
            cert.fingerprint(hashes.SHA256()).hex()
        assert relay.connect_targets == ['smtp.example.test:587']
    finally:
        relay.close()
        smtp.close()

def test_an_smtp_server_that_refuses_starttls_is_not_reachable(tmp_path, monkeypatch):
    """CONTROL on the leg above: a server that answers the upgrade with a
    refusal must not be reported as having served a certificate.

    This used to hand-roll its own listener, with a SINGLE `accept()` in a
    daemon thread whose failures were swallowed, and it failed once in a
    release gate: a 2.5s read timeout — the probe spends half its budget on
    each read — with nothing to say why. A one-shot accept is consumed by
    whatever connects first, and a helper that fails in silence turns that
    into a timeout instead of an explanation. It uses the same backend as the
    test above now, which serves in a loop and records what each session did.
    """
    from modules.api.tls_probe import _probe_tls_certificate

    _cert, certfile, keyfile = _self_signed('smtp.example.test', tmp_path)
    smtp = _SMTPBackend(certfile, keyfile, refuse_starttls=True)
    relay = _ConnectProxy(smtp.port)
    try:
        monkeypatch.delenv('no_proxy', raising=False)
        monkeypatch.setenv('https_proxy', relay.url)

        with pytest.raises(ConnectionError) as raised:
            _probe_tls_certificate('smtp.example.test', port=587,
                                   protocol='smtp-starttls', timeout=5)

        assert 'STARTTLS' in str(raised.value)
        # The refusal must have come from the server, not from a helper that
        # died before answering: that is the difference the timeout hid.
        assert smtp.sessions == ['refused'], smtp.sessions
    finally:
        relay.close()
        smtp.close()
