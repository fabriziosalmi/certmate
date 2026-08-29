"""Webhook redirects are re-checked against the SSRF guard, and credentials do
not cross to a different host.

_webhook_url_is_internal was evaluated once, on the configured URL, and then the
default opener followed 3xx redirects with no further check. An external
(allowed) receiver answering `302 Location: http://169.254.169.254/…` made
CertMate issue the follow-up request to the internal target from inside the
trust boundary, carrying the webhook's Authorization header and
X-CertMate-Signature. The opener now re-applies the guard on every hop and drops
those headers on a cross-host redirect.
"""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import URLError
from urllib.request import Request

import pytest

from modules.core.notifier import _webhook_opener

pytestmark = [pytest.mark.unit]


class _Recorder:
    """A tiny HTTP server: /external 302s to /internal; both record headers."""

    def __init__(self):
        self.hits = {}
        recorder = self

        class H(BaseHTTPRequestHandler):
            def _h(self):
                # Drain the request body before responding, or a 302 mid-POST
                # can reset the client connection.
                clen = int(self.headers.get('Content-Length', 0) or 0)
                if clen:
                    self.rfile.read(clen)
                recorder.hits[self.path] = dict(self.headers)
                if self.path == '/external':
                    self.send_response(302)
                    self.send_header(
                        'Location',
                        f'http://127.0.0.1:{self.server.server_port}/internal')
                    self.end_headers()
                elif self.path == '/samehost':
                    self.send_response(302)
                    self.send_header(
                        'Location',
                        f'http://127.0.0.1:{self.server.server_port}/final')
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
            do_POST = _h
            do_GET = _h

            def log_message(self, *a):
                pass

        self.srv = HTTPServer(('127.0.0.1', 0), H)
        self.port = self.srv.server_port
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def url(self, path):
        return f'http://127.0.0.1:{self.port}{path}'

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


@pytest.fixture
def server():
    s = _Recorder()
    yield s
    s.stop()


def _req(url):
    r = Request(url, data=b'{}', method='POST')
    r.add_header('Authorization', 'Bearer SECRET-TOKEN')
    r.add_header('X-CertMate-Signature', 'HMAC-SIG')
    return r


def test_a_redirect_to_an_internal_target_is_refused(server):
    """allow_internal=False: the 302 to a loopback address is blocked, the
    internal endpoint is never reached, and no credential leaves."""
    with pytest.raises(URLError):
        with _webhook_opener(False).open(_req(server.url('/external')), timeout=5):
            pass
    assert '/internal' not in server.hits, "internal target was reached"


def test_the_internal_endpoint_never_sees_the_token(server):
    try:
        with _webhook_opener(False).open(_req(server.url('/external')), timeout=5):
            pass
    except URLError:
        pass
    internal = server.hits.get('/internal', {})
    assert 'SECRET-TOKEN' not in internal.get('Authorization', '')


def test_allow_internal_follows_the_redirect(server):
    """CONTROL: with internal explicitly allowed, the hop completes (same host,
    so it is not blocked)."""
    with _webhook_opener(True).open(_req(server.url('/external')), timeout=5) as r:
        assert r.status == 200
    assert '/internal' in server.hits


def test_cross_host_redirect_strips_credentials():
    """Unit-test the redirect handler directly: a redirect to a DIFFERENT host
    must drop Authorization / X-CertMate-Signature so a token never leaves for a
    host the operator did not configure. (Deterministic, no second server.)"""
    from urllib.request import Request
    from modules.core.notifier import _GuardedRedirectHandler

    handler = _GuardedRedirectHandler(allow_internal=True)  # allow, so only the
    #                                          host-change strip is under test
    req = Request('https://receiver.example.com/hook', data=b'{}', method='POST')
    req.add_header('Authorization', 'Bearer SECRET-TOKEN')
    req.add_header('X-certmate-signature', 'HMAC-SIG')

    new = handler.redirect_request(
        req, fp=None, code=302, msg='Found', headers={},
        newurl='https://elsewhere.example.net/x')
    assert new is not None
    assert not new.has_header('Authorization')
    assert not new.has_header('X-certmate-signature')


def test_same_host_redirect_via_handler_keeps_credentials():
    """CONTROL for the strip: a same-host redirect must keep the headers."""
    from urllib.request import Request
    from modules.core.notifier import _GuardedRedirectHandler

    handler = _GuardedRedirectHandler(allow_internal=True)
    req = Request('https://receiver.example.com/hook', data=b'{}', method='POST')
    req.add_header('Authorization', 'Bearer SECRET-TOKEN')

    new = handler.redirect_request(
        req, fp=None, code=302, msg='Found', headers={},
        newurl='https://receiver.example.com/hook2')
    assert new is not None
    assert new.has_header('Authorization')


def test_a_same_host_redirect_keeps_the_credentials(server):
    """CONTROL: a redirect that stays on the same host must keep Authorization,
    or the fix would break legitimate receivers that 302 within themselves."""
    with _webhook_opener(True).open(_req(server.url('/samehost')), timeout=5) as r:
        assert r.status == 200
    assert 'SECRET-TOKEN' in server.hits.get('/final', {}).get('Authorization', '')


def test_a_scheme_downgrade_strips_credentials():
    """origin is scheme+host+port: https->http on the same host must drop the
    token so it never goes over an insecure channel."""
    from urllib.request import Request
    from modules.core.notifier import _GuardedRedirectHandler
    h = _GuardedRedirectHandler(allow_internal=True)
    req = Request('https://x.example/hook', data=b'{}', method='POST')
    req.add_header('Authorization', 'Bearer SECRET')
    new = h.redirect_request(req, None, 302, 'Found', {}, 'http://x.example/hook')
    assert not new.has_header('Authorization')


def test_a_port_change_strips_credentials():
    from urllib.request import Request
    from modules.core.notifier import _GuardedRedirectHandler
    h = _GuardedRedirectHandler(allow_internal=True)
    req = Request('https://x.example/hook', data=b'{}', method='POST')
    req.add_header('Authorization', 'Bearer SECRET')
    new = h.redirect_request(req, None, 302, 'Found', {},
                             'https://x.example:8443/hook')
    assert not new.has_header('Authorization')


def test_an_explicit_default_port_is_the_same_origin():
    """CONTROL: https://x:443 must not be treated as a different origin from
    https://x, or a legitimate same-origin redirect would lose its token."""
    from urllib.request import Request
    from modules.core.notifier import _GuardedRedirectHandler
    h = _GuardedRedirectHandler(allow_internal=True)
    req = Request('https://x.example/hook', data=b'{}', method='POST')
    req.add_header('Authorization', 'Bearer SECRET')
    new = h.redirect_request(req, None, 302, 'Found', {},
                             'https://x.example:443/hook2')
    assert new.has_header('Authorization')
