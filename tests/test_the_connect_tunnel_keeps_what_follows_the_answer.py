"""A server that speaks first must not lose its first words to the proxy's answer.

A mail server sends its banner the moment it is connected. Through an HTTP proxy
that banner sits right behind the proxy's own `200 Connection established`, and a
proxy can deliver both in one read. The tunnel the probes used was the standard
library's `HTTPConnection.set_tunnel`, which reads the answer through a buffered
reader and then hands back the bare socket: the banner went into a buffer nobody
could reach and the SMTP probe waited out its read timeout for a line it had
already been sent.

It showed up as a test that failed one run in a few on a slow runner
(`test_an_smtp_server_that_refuses_starttls_is_not_reachable`, 2.5 s, no reason
given) and as a docstring that put it down to a one-shot `accept()`. The fix to the
fake was real and did not touch the cause. A client that speaks first (the TLS
legs) never notices, so nothing else could have shown it.

`open_connect_tunnel` reads the answer one byte at a time, up to the blank line, so
nothing past it is consumed. These tests drive it against a proxy that delivers the
banner in the same `send` as the answer, which makes the case deterministic instead
of a matter of timing.
"""
import http.client
import socket
import threading
import time

import pytest

from modules.core.cert_probe import open_connect_tunnel

pytestmark = [pytest.mark.unit]

ESTABLISHED = b'HTTP/1.1 200 Connection established\r\n\r\n'
BANNER = b'220 smtp.example.test ESMTP\r\n'


class FakeProxy:
    """A proxy that reads one CONNECT request and runs `script(conn)` on it."""

    def __init__(self, script):
        self.requests = []
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._srv.bind(('127.0.0.1', 0))
        self._srv.listen(2)
        self.port = self._srv.getsockname()[1]
        self._script = script
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self._srv.accept()
        except OSError:
            return
        try:
            head = b''
            while b'\r\n\r\n' not in head:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                head += chunk
            self.requests.append(head)
            self._script(conn)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self._srv.close()


@pytest.fixture
def proxies():
    made = []

    def make(script):
        proxy = FakeProxy(script)
        made.append(proxy)
        return proxy
    yield make
    for proxy in made:
        proxy.close()


def _hold(conn, seconds=2.0):
    time.sleep(seconds)


def _tunnel(proxy, host='smtp.example.test', port=587, headers=None, timeout=3):
    return open_connect_tunnel('127.0.0.1', proxy.port, headers or {}, host, port, timeout)


# --------------------------------------------------------------------------
# What this exists for.
# --------------------------------------------------------------------------

def test_a_banner_sent_in_the_same_read_as_the_answer_survives(proxies):
    def script(conn):
        conn.sendall(ESTABLISHED + BANNER)
        _hold(conn)

    sock = _tunnel(proxies(script))
    try:
        assert sock.makefile('rb').readline() == BANNER
    finally:
        sock.close()


def test_a_banner_sent_after_the_answer_survives_too(proxies):
    def script(conn):
        conn.sendall(ESTABLISHED)
        time.sleep(0.2)
        conn.sendall(BANNER)
        _hold(conn)

    sock = _tunnel(proxies(script))
    try:
        assert sock.makefile('rb').readline() == BANNER
    finally:
        sock.close()


def test_an_answer_that_arrives_a_byte_at_a_time_is_still_one_answer(proxies):
    def script(conn):
        for byte in ESTABLISHED:
            conn.sendall(bytes([byte]))
            time.sleep(0.002)
        conn.sendall(BANNER)
        _hold(conn)

    sock = _tunnel(proxies(script))
    try:
        assert sock.makefile('rb').readline() == BANNER
    finally:
        sock.close()


def test_the_standard_librarys_tunnel_loses_that_banner_on_this_interpreter(proxies):
    """CONTROL, on the instrument: the same proxy and the same banner through the
    mechanism that was replaced. If this passes the helper has a reason to exist;
    if the interpreter ever stops losing it, the helper is no longer needed and
    this says so instead of failing a build for a harmless reason."""
    def script(conn):
        conn.sendall(ESTABLISHED + BANNER)
        _hold(conn, 3.0)

    proxy = proxies(script)
    conn = http.client.HTTPConnection('127.0.0.1', proxy.port, timeout=1.0)
    conn.set_tunnel('smtp.example.test', 587)
    conn.connect()
    try:
        try:
            got = conn.sock.makefile('rb').readline()
        except TimeoutError:
            got = None
        if got == BANNER:
            pytest.skip('this interpreter no longer loses the banner behind the '
                        'tunnel answer: open_connect_tunnel is not needed for it')
        assert got is None
    finally:
        conn.close()


# --------------------------------------------------------------------------
# What goes on the wire.
# --------------------------------------------------------------------------

def test_the_request_names_the_target_and_carries_the_proxys_credentials(proxies):
    proxy = proxies(lambda conn: (conn.sendall(ESTABLISHED), _hold(conn, 0.2)))
    sock = _tunnel(proxy, headers={'Proxy-Authorization': 'Basic Zm9vOmJhcg=='})
    sock.close()
    lines = proxy.requests[0].split(b'\r\n')
    assert lines[0] == b'CONNECT smtp.example.test:587 HTTP/1.1'
    assert b'Host: smtp.example.test:587' in lines
    assert b'Proxy-Authorization: Basic Zm9vOmJhcg==' in lines
    assert proxy.requests[0].endswith(b'\r\n\r\n')


def test_a_caller_supplied_host_header_is_not_sent_twice(proxies):
    proxy = proxies(lambda conn: (conn.sendall(ESTABLISHED), _hold(conn, 0.2)))
    sock = _tunnel(proxy, headers={'host': 'elsewhere.test'})
    sock.close()
    hosts = [line for line in proxy.requests[0].split(b'\r\n') if line.lower().startswith(b'host:')]
    assert hosts == [b'Host: smtp.example.test:587']


def test_an_ipv6_literal_is_bracketed(proxies):
    proxy = proxies(lambda conn: (conn.sendall(ESTABLISHED), _hold(conn, 0.2)))
    sock = _tunnel(proxy, host='2001:db8::1', port=443)
    sock.close()
    assert proxy.requests[0].split(b'\r\n')[0] == b'CONNECT [2001:db8::1]:443 HTTP/1.1'


def test_an_international_name_goes_out_as_punycode(proxies):
    proxy = proxies(lambda conn: (conn.sendall(ESTABLISHED), _hold(conn, 0.2)))
    sock = _tunnel(proxy, host='münchen.example')
    sock.close()
    assert proxy.requests[0].split(b'\r\n')[0] == b'CONNECT xn--mnchen-3ya.example:587 HTTP/1.1'


# --------------------------------------------------------------------------
# What an operator reads when the proxy says no. The wording is the standard
# library's, so a message that was in a runbook yesterday still is today.
# --------------------------------------------------------------------------

def test_a_refusal_keeps_the_wording_it_always_had(proxies):
    proxy = proxies(lambda conn: conn.sendall(
        b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic\r\n\r\n'))
    with pytest.raises(OSError) as raised:
        _tunnel(proxy)
    assert str(raised.value) == 'Tunnel connection failed: 407 Proxy Authentication Required'


def test_a_refusal_with_no_reason_phrase_is_still_a_refusal(proxies):
    proxy = proxies(lambda conn: conn.sendall(b'HTTP/1.1 403\r\n\r\n'))
    with pytest.raises(OSError, match=r'^Tunnel connection failed: 403$'):
        _tunnel(proxy)


def test_a_proxy_that_hangs_up_before_answering_is_a_connection_error(proxies):
    proxy = proxies(lambda conn: None)
    with pytest.raises(ConnectionError, match='closed the connection before answering'):
        _tunnel(proxy)


@pytest.mark.parametrize('answer', [b'SSH-2.0-OpenSSH_9.6\r\n\r\n', b'HTTP/1.1 abc OK\r\n\r\n', b'\r\n\r\n'])
def test_something_that_is_not_an_answer_is_not_taken_for_one(proxies, answer):
    proxy = proxies(lambda conn: conn.sendall(answer))
    with pytest.raises(ConnectionError, match='answered CONNECT with'):
        _tunnel(proxy)


def test_an_answer_with_no_end_is_cut_off(proxies):
    def script(conn):
        try:
            while True:
                conn.sendall(b'X-Padding: ' + b'a' * 1000 + b'\r\n')
        except OSError:
            pass

    with pytest.raises(ConnectionError, match='more than 65536 bytes'):
        _tunnel(proxies(script))


def test_a_proxy_that_never_answers_times_out_as_a_timeout(proxies):
    """The callers classify a timeout apart from a refusal; it must arrive as one."""
    proxy = proxies(lambda conn: _hold(conn, 2.0))
    started = time.monotonic()
    with pytest.raises(TimeoutError):
        _tunnel(proxy, timeout=0.3)
    assert time.monotonic() - started < 1.5


def test_a_failed_tunnel_does_not_leave_the_proxy_connection_open(proxies):
    """The socket is closed on every failure, not left to the collector.

    The exception is kept alive while the proxy is asked: its traceback holds the
    frame, so the socket is still reachable, which is the case where only an
    explicit close frees the descriptor. Without that, CPython's reference
    counting closes it the moment the exception is gone and a missing `close()`
    cannot be seen (the first version of this test passed with it removed).
    """
    seen = []

    def script(conn):
        conn.sendall(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
        conn.settimeout(2.0)
        try:
            seen.append(conn.recv(1))        # b'' when the client closed its end
        except OSError as error:
            seen.append(error)

    with pytest.raises(OSError) as raised:
        _tunnel(proxies(script))
    deadline = time.monotonic() + 2.5
    while not seen and time.monotonic() < deadline:
        time.sleep(0.01)
    assert raised.value.__traceback__ is not None      # keeps the frame, and the socket, alive
    assert seen == [b''], seen


# --------------------------------------------------------------------------
# Both ways into it.
# --------------------------------------------------------------------------

def test_the_inventory_probes_opener_has_the_same_fix(proxies, monkeypatch):
    """`open_probe_transport` is the other caller. It speaks TLS first, so it could
    not lose anything, but two tunnels is how the SMTP leg drifted away from the
    fix for #326 once already: one helper, and a test that both go through it."""
    from modules.core import cert_probe

    def script(conn):
        conn.sendall(ESTABLISHED + BANNER)
        _hold(conn)

    proxy = proxies(script)
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.setenv('https_proxy', f'http://127.0.0.1:{proxy.port}')

    sock, closer, via = cert_probe.open_probe_transport(
        'smtp.example.test', 587, socket.AF_INET, '93.184.216.34', 3)
    try:
        assert via == f'127.0.0.1:{proxy.port}'
        assert sock.makefile('rb').readline() == BANNER
    finally:
        closer()


def test_the_inventory_probes_opener_names_the_proxy_when_it_refuses(proxies, monkeypatch):
    from modules.core import cert_probe

    proxy = proxies(lambda conn: conn.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n\r\n'))
    monkeypatch.delenv('no_proxy', raising=False)
    monkeypatch.delenv('NO_PROXY', raising=False)
    monkeypatch.setenv('https_proxy', f'http://127.0.0.1:{proxy.port}')

    with pytest.raises(ConnectionError) as raised:
        cert_probe.open_probe_transport('smtp.example.test', 587, socket.AF_INET, '93.184.216.34', 3)
    assert str(raised.value) == (
        f'via proxy 127.0.0.1:{proxy.port}: Tunnel connection failed: 407 Proxy Authentication Required')
