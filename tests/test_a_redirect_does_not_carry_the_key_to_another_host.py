"""A storage backend's endpoint answering with a redirect must not take the key anywhere else.

HashiCorp Vault is the one remote backend that followed a redirect with
everything attached. hvac follows them by default, `requests` drops only
`Authorization` when the host changes, and Vault authenticates with
`X-Vault-Token`, so a 307 from the configured address delivered the private key
AND the token that opens the whole vault to whichever host the answer named,
while `store_certificate` reported success. (Measured against the real backend
and two local servers; S3, AWS Secrets Manager and Azure Key Vault do not.)

A redirect is a normal part of Vault's protocol: a standby node that is not
forwarding answers 307 to the active one. So the rule is not "never": a redirect
to the same origin is followed, a redirect to another host is refused with a
message that says what to do about it, and a downgrade to plain http never is.

The session half runs anywhere (it needs only `requests`). The backend half
needs hvac, which lives in the optional Vault set and is installed in the
storage-live CI job, where it runs.
"""
import http.server
import json
import threading

import pytest
import requests

from modules.core.redirect_guard import GuardedSession, RedirectRefused

pytestmark = [pytest.mark.unit]

KEY = (b'-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgBENCHMARKKEY0123\n'
       b'-----END PRIVATE KEY-----\n')
TOKEN = 'hvs.SECRET-VAULT-TOKEN'


class _Server:
    def __init__(self, handler):
        self.httpd = http.server.HTTPServer(('127.0.0.1', 0), handler)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def servers():
    """(configured, elsewhere): the address the operator set, and another host."""
    received = []
    made = []

    class Elsewhere(http.server.BaseHTTPRequestHandler):
        def _do(self):
            n = int(self.headers.get('Content-Length') or 0)
            received.append({'method': self.command, 'path': self.path,
                             'headers': {k.lower(): v for k, v in self.headers.items()},
                             'body': self.rfile.read(n) if n else b''})
            payload = json.dumps({'data': {'id': 'x', 'policies': ['root'], 'version': 1}}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _do

        def log_message(self, *a):
            pass

    elsewhere = _Server(Elsewhere)
    made.append(elsewhere)

    def configured(status=307, location=None):
        class Redirect(http.server.BaseHTTPRequestHandler):
            hits = []

            def _do(self):
                n = int(self.headers.get('Content-Length') or 0)
                if n:
                    self.rfile.read(n)
                Redirect.hits.append(self.path)
                target = location(self.path) if callable(location) else (
                    location or f'http://127.0.0.1:{elsewhere.port}{self.path}')
                self.send_response(status)
                self.send_header('Location', target)
                self.send_header('Content-Length', '0')
                self.end_headers()
            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _do

            def log_message(self, *a):
                pass
        server = _Server(Redirect)
        made.append(server)
        server.hits = Redirect.hits
        return server

    yield configured, elsewhere, received
    for s in made:
        s.close()


# --------------------------------------------------------------------------
# The session
# --------------------------------------------------------------------------

@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_a_redirect_to_another_host_is_refused_before_anything_is_sent_there(servers, status):
    configured, _, received = servers
    server = configured(status)
    session = GuardedSession()

    with pytest.raises(RedirectRefused) as refused:
        session.post(f'http://127.0.0.1:{server.port}/v1/secret/data/x', data=KEY,
                     headers={'X-Vault-Token': TOKEN})

    assert received == [], 'the request was repeated at the address the answer named'
    # It names the host, not the path or query (which can carry credentials).
    assert '127.0.0.1' in str(refused.value)
    assert '/v1/secret' not in str(refused.value) and TOKEN not in str(refused.value)


def test_a_redirect_to_the_same_origin_is_followed(servers):
    """The control: a path normalisation or trailing-slash redirect is ordinary."""
    configured, _, received = servers
    port_holder = {}

    def to_same_origin(path):
        return f'http://127.0.0.1:{port_holder["port"]}/final'
    server = configured(307, location=to_same_origin)
    port_holder['port'] = server.port
    session = GuardedSession()

    with pytest.raises(requests.exceptions.TooManyRedirects):
        # It IS followed: the redirector redirects its own /final again, so the
        # standard redirect limit is what ends it. A refusal would be RedirectRefused.
        session.get(f'http://127.0.0.1:{server.port}/start')
    assert len(server.hits) > 1


def test_a_relative_location_is_the_same_origin(servers):
    configured, elsewhere, received = servers

    class Once(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == '/start':
                self.send_response(301)
                self.send_header('Location', '/finish')
                self.send_header('Content-Length', '0')
                self.end_headers()
            else:
                body = b'done'
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        def log_message(self, *a):
            pass
    server = _Server(Once)
    try:
        assert GuardedSession().get(f'http://127.0.0.1:{server.port}/start').text == 'done'
    finally:
        server.close()


def test_a_redirect_from_https_to_http_is_refused_even_to_the_same_host():
    class Fake:
        url = 'https://vault.example.com:8200/v1/x'
        is_redirect = True
        headers = {'location': 'http://vault.example.com:8200/v1/x'}
        status_code = 307
        is_permanent_redirect = False
        content = b''
    with pytest.raises(RedirectRefused) as refused:
        GuardedSession().get_redirect_target(Fake())
    assert 'http' in str(refused.value).lower()


def test_a_redirect_to_another_port_on_the_same_host_is_another_origin():
    class Fake:
        url = 'https://vault.example.com:8200/v1/x'
        is_redirect = True
        headers = {'location': 'https://vault.example.com:9999/v1/x'}
        status_code = 307
        content = b''
    with pytest.raises(RedirectRefused):
        GuardedSession().get_redirect_target(Fake())


def test_the_refusal_is_not_mistaken_for_a_transient_error():
    """A refused redirect repeated three times is three copies of the key sent to the configured address."""
    from modules.core.storage_backends import _is_transient
    assert _is_transient(RedirectRefused('redirect to vault-b.example.org refused: not the configured origin')) is False
    assert not isinstance(RedirectRefused('x'), OSError)


# --------------------------------------------------------------------------
# The Vault backend, with the real hvac
# --------------------------------------------------------------------------

def _hvac():
    """hvac, or a skip of THIS test only: the session tests above need nothing but requests."""
    return pytest.importorskip(
        'hvac', reason='hvac is in the optional Vault set; the storage-live CI job installs it')


@pytest.mark.parametrize('status', [307, 308])
def test_the_vault_backend_does_not_send_the_key_or_the_token_to_another_host(servers, status):
    _hvac()
    from modules.core.storage_backends import HashiCorpVaultBackend
    configured, _, received = servers
    server = configured(status)
    backend = HashiCorpVaultBackend({'vault_url': f'http://127.0.0.1:{server.port}',
                                     'vault_token': TOKEN, 'engine_version': 'v2'})

    stored = backend.store_certificate('bench.example.com', {'privkey.pem': KEY, 'cert.pem': b'CERT'}, {})

    assert stored is False
    assert received == [], [(r['method'], r['path']) for r in received]


def test_the_vault_backend_still_stores_when_nothing_redirects():
    """The control: the guard must not break the ordinary case."""
    _hvac()
    from modules.core.storage_backends import HashiCorpVaultBackend
    seen = []

    class Vault(http.server.BaseHTTPRequestHandler):
        def _do(self):
            n = int(self.headers.get('Content-Length') or 0)
            seen.append((self.command, self.path, self.rfile.read(n) if n else b''))
            payload = json.dumps({'data': {'id': 'x', 'policies': ['root'], 'version': 1}}).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        do_GET = do_POST = do_PUT = _do

        def log_message(self, *a):
            pass
    server = _Server(Vault)
    try:
        backend = HashiCorpVaultBackend({'vault_url': f'http://127.0.0.1:{server.port}',
                                         'vault_token': TOKEN, 'engine_version': 'v2'})
        assert backend.store_certificate('bench.example.com', {'privkey.pem': KEY}, {}) is True
    finally:
        server.close()
    assert any(b'BENCHMARKKEY' in body for _, _, body in seen)


def test_the_vault_client_is_built_with_the_guarded_session(monkeypatch):
    hvac = _hvac()
    from modules.core.storage_backends import HashiCorpVaultBackend
    captured = {}

    class Stop(Exception):
        pass

    def spy(*args, **kwargs):
        captured.update(kwargs)
        raise Stop

    monkeypatch.setattr(hvac, 'Client', spy)
    backend = HashiCorpVaultBackend({'vault_url': 'http://127.0.0.1:1', 'vault_token': TOKEN})
    with pytest.raises(Stop):
        backend._get_client()
    assert isinstance(captured.get('session'), GuardedSession)
    # And the operator is told what to do about the one legitimate redirect.
    assert 'active node' in captured['session']._hint
