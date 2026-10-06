"""What a deploy target sends out, and what it lets back in to the records.

A typed deploy target hands the private key to a URL the operator configured,
and what comes back (a status, a few hundred characters of the answer) is
written to the audit log, the deploy history and the failure alert. Three
things have to hold for that to be safe, and each one has a way of being
half true:

* **The request goes where it was pointed, and nowhere else.** A 307 or 308
  keeps the method and the body, so following one sends the key to whichever
  host the answer names, while the operator is told `success`.
* **The answer cannot carry the key into the records.** A receiver that echoes
  its input back hands the key to the audit chain, which cannot be edited.
  The key comes back as PEM, JSON-escaped PEM, base64, URL-encoded, or a slice
  of a line; redacting only the first shape is how the rest get through.
* **Scrubbing happens before truncating.** Cutting a response to its first few
  hundred characters and then scrubbing leaves whatever fragment of the key
  fell inside the cut.

Real sockets for the first, because a mock that returns a 307 would pass
whether or not anything followed it.
"""

import base64
import http.server
import json
import threading
import time
import urllib.parse
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from modules.core.deploy_targets import KubernetesSecretTarget
from modules.core.structured_logging import sanitize_text

pytestmark = [pytest.mark.unit]


def _key_pem():
    """A key whose body holds '+' and '/', so the URL-encoded form differs from the plain one.

    Without them a URL-encoded PEM has the same lines as the plain one and the
    encoded forms cannot be told apart from it.
    """
    while True:
        pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption())
        body = ''.join(pem.decode().strip().splitlines()[1:-1])
        if '+' in body and '/' in body:
            return pem


KEY = _key_pem()
KEY_TEXT = KEY.decode()
KEY_BODY = ''.join(KEY_TEXT.strip().splitlines()[1:-1])       # the base64 inside the PEM


def _markers():
    """Pieces of KEY that would identify it in any shape it could come back in."""
    lines = [line for line in KEY_TEXT.splitlines() if len(line) >= 40 and '-----' not in line]
    found = set(lines + [KEY_BODY[:40], KEY_BODY[-40:]])
    for line in lines:
        found.add(urllib.parse.quote(line))                 # '/' kept
        found.add(urllib.parse.quote(line, safe=''))        # '/' encoded
        found.add(urllib.parse.quote_plus(line))
        for shift in range(3):                     # every alignment base64 can take
            raw = (b'.' * shift) + line.encode()
            found.add(base64.b64encode(raw).decode()[8:44])
            found.add(base64.urlsafe_b64encode(raw).decode()[8:44])
    # The PEM as a whole, which is what base64 of the file looks like.
    for shift in range(3):
        raw = (b'.' * shift) + KEY
        found.add(base64.b64encode(raw).decode()[20:60])
        found.add(base64.urlsafe_b64encode(raw).decode()[20:60])
    return found


MARKERS = _markers()


def _leaks(text):
    """Whether any recognisable piece of KEY is still in *text*."""
    return [m for m in MARKERS if m in text]


# --------------------------------------------------------------------------
# The request does not go anywhere it was not pointed
# --------------------------------------------------------------------------

class _Server:
    def __init__(self, handler):
        self.httpd = http.server.HTTPServer(('127.0.0.1', 0), handler)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def two_servers():
    received = []

    class Elsewhere(http.server.BaseHTTPRequestHandler):
        def do_PATCH(self):
            received.append(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass

    elsewhere = _Server(Elsewhere)
    made = []

    def redirecting(status):
        class Redirect(http.server.BaseHTTPRequestHandler):
            def do_PATCH(self):
                self.rfile.read(int(self.headers.get('Content-Length', 0)))
                self.send_response(status)
                self.send_header('Location', f'http://127.0.0.1:{elsewhere.port}/elsewhere')
                self.end_headers()

            def log_message(self, *a):
                pass
        server = _Server(Redirect)
        made.append(server)
        return server

    yield redirecting, received
    for s in made + [elsewhere]:
        s.close()


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_a_redirect_is_not_followed_and_is_reported_as_a_failure(two_servers, status):
    redirecting, received = two_servers
    server = redirecting(status)
    target = KubernetesSecretTarget({
        'api_server': f'http://127.0.0.1:{server.port}', 'token': 'sa-token',
        'secret_name': 's', 'namespace': 'n'})

    out = target.deploy(b'CERT', KEY)

    assert received == [], 'the key was sent to the host the redirect named'
    assert out['success'] is False
    assert out['status_code'] == status
    assert 'redirect' in out['message'].lower()
    # The operator can act on it: it says what to change.
    assert 'api_server' in out['message']
    # And the Location (which can carry credentials in its query) is not quoted.
    assert 'elsewhere' not in out['message']


def test_a_normal_answer_still_succeeds(two_servers):
    """The control: refusing redirects must not refuse a plain 200."""
    _, received = two_servers

    class Ok(http.server.BaseHTTPRequestHandler):
        def do_PATCH(self):
            received.append(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            self.send_response(200)
            self.end_headers()

        def log_message(self, *a):
            pass
    server = _Server(Ok)
    try:
        out = KubernetesSecretTarget({
            'api_server': f'http://127.0.0.1:{server.port}', 'token': 'sa-token-0a1b2c',
            'secret_name': 's', 'namespace': 'n'}).deploy(b'CERT', KEY)
    finally:
        server.close()
    assert out['success'] is True and len(received) == 1


class _Resp:
    def __init__(self, status_code, text):
        self.status_code, self.text = status_code, text


class _Answer:
    """A fake transport that answers with a fixed body, and records the call."""

    def __init__(self, status, text):
        self.status, self.text, self.kwargs = status, text, None

    def __call__(self, url, **kwargs):
        self.kwargs = kwargs
        return _Resp(self.status, self.text)


def test_the_request_is_made_with_redirects_off():
    answer = _Answer(200, '{}')
    KubernetesSecretTarget({'api_server': 'https://k.local', 'token': 'sa-token-0a1b2c', 'secret_name': 's',
                            'namespace': 'n'}, http_patch=answer).deploy(b'C', KEY)
    assert answer.kwargs['allow_redirects'] is False


# --------------------------------------------------------------------------
# What a receiver says back cannot carry the key into the records
# --------------------------------------------------------------------------

def _echo_forms():
    body_lines = KEY_TEXT.strip().splitlines()
    return {
        'pem': KEY_TEXT,
        'json-escaped pem': json.dumps({'received': KEY_TEXT}),
        'base64 of the pem': base64.b64encode(KEY).decode(),
        'urlsafe base64 of the pem': base64.urlsafe_b64encode(KEY).decode(),
        'url-encoded pem': urllib.parse.quote(KEY_TEXT),
        'url-encoded pem, slash encoded too': urllib.parse.quote(KEY_TEXT, safe=''),
        'plus-encoded pem': urllib.parse.quote_plus(KEY_TEXT),
        'the body without its header lines': KEY_BODY,
        'one line of the body': body_lines[1],
        # A URL-encoded PEM keeps its -----BEGIN/END----- markers (a dash is not
        # encoded), so the sanitiser already takes that whole; it is the body on
        # its own, and single lines of it, that only the exact scrub can find.
        'url-encoded body': urllib.parse.quote(KEY_BODY),
        'url-encoded body, slash encoded too': urllib.parse.quote(KEY_BODY, safe=''),
        'plus-encoded body': urllib.parse.quote_plus(KEY_BODY),
        'one url-encoded line': urllib.parse.quote(body_lines[1]),
        'one url-encoded line, slash encoded too': urllib.parse.quote(body_lines[1], safe=''),
        'base64 of the json that wraps it': base64.b64encode(
            json.dumps({'k': KEY_TEXT}).encode()).decode(),
    }


@pytest.mark.parametrize('form', list(_echo_forms()))
def test_a_receiver_that_echoes_the_key_does_not_get_it_into_the_message(form):
    echoed = _echo_forms()[form]
    answer = _Answer(422, f'invalid certificate: {echoed} (rejected)')

    out = KubernetesSecretTarget({'api_server': 'https://k.local', 'token': 'sa-token-0a1b2c',
                                  'secret_name': 's', 'namespace': 'n'},
                                 http_patch=answer).deploy(b'C', KEY)

    assert out['success'] is False and out['status_code'] == 422
    assert not _leaks(out['message']), f'{form}: {out["message"]!r}'
    # The diagnosis is still there: scrubbing must not eat the whole answer.
    assert 'invalid certificate' in out['message']


def test_scrubbing_happens_before_the_answer_is_cut_short():
    """The cut lands in the middle of the first line of the key's body.

    The header line is 28 characters, so 222 of padding puts the 300th character
    50 characters into that line: a fragment, which matches no whole form, and
    which is what is left if the answer is shortened before it is scrubbed.
    """
    padding = 'x' * (300 - 28 - 50)
    answer = _Answer(500, padding + KEY_TEXT + ' tail')

    out = KubernetesSecretTarget({'api_server': 'https://k.local', 'token': 'sa-token-0a1b2c',
                                  'secret_name': 's', 'namespace': 'n'},
                                 http_patch=answer).deploy(b'C', KEY)

    assert not _leaks(out['message']), out['message']
    assert len(out['message']) < 600


def test_an_exception_message_cannot_carry_the_key_either():
    class Boom:
        def __call__(self, url, **kwargs):
            raise ConnectionError(f'reset while sending {base64.b64encode(KEY).decode()}')

    out = KubernetesSecretTarget({'api_server': 'https://k.local', 'token': 'sa-token-0a1b2c',
                                  'secret_name': 's', 'namespace': 'n'},
                                 http_patch=Boom()).deploy(b'C', KEY)
    assert out['success'] is False
    assert not _leaks(out['message'])


# --------------------------------------------------------------------------
# The shared sanitiser sees a PEM that was base64-encoded
# --------------------------------------------------------------------------

@pytest.mark.parametrize('encode', [
    lambda pem: base64.b64encode(pem).decode(),
    lambda pem: base64.urlsafe_b64encode(pem).decode(),
    lambda pem: base64.b64encode(pem).decode().rstrip('='),
    lambda pem: base64.b64encode(json.dumps({'k': pem.decode()}).encode()).decode(),
    lambda pem: base64.b64encode(b'.' + pem).decode(),       # shifted by one byte
    lambda pem: base64.b64encode(b'..' + pem).decode(),      # shifted by two
    # A word of base64 characters stuck to the front of the stream: the run
    # then starts mid-stream, at every alignment base64 can have.
    lambda pem: 'k' + base64.b64encode(pem).decode(),
    lambda pem: 'ke' + base64.b64encode(pem).decode(),
    lambda pem: 'key' + base64.b64encode(pem).decode(),
])
def test_sanitize_text_redacts_an_encoded_pem(encode):
    out = sanitize_text('answer: ' + encode(KEY) + ' end')
    assert '[PEM REDACTED]' in out
    assert not _leaks(out)
    assert out.startswith('answer: ') and out.endswith(' end')


def test_sanitize_text_leaves_ordinary_base64_alone():
    benign = base64.b64encode(bytes(range(256)) * 2).decode()
    assert sanitize_text(f'digest {benign}') == f'digest {benign}'
    assert sanitize_text('short ' + base64.b64encode(b'hello world').decode()) == \
        'short ' + base64.b64encode(b'hello world').decode()


def test_sanitize_text_redacts_an_encoded_certificate_too():
    """Consistent with the plain-text rule, which redacts every PEM block."""
    cert_pem = b'-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----\n'
    assert '[PEM REDACTED]' in sanitize_text(base64.b64encode(cert_pem * 3).decode())


# Text made to cost the scan as much as it can, at any size: one run of
# base64 characters, runs too short to be looked at, runs that decode, and
# runs just over the length at which a run is looked at.
HOSTILE = {
    'one long run': lambda size: 'A' * size,
    'runs too short to look at': lambda size: 'AAAA ' * (size // 5),
    'twenty runs that decode': lambda size: ('QUJD' * (size // 80) + '!') * 20,
    'runs just long enough to look at': lambda size: ('A' * 119 + ' ') * (size // 120),
}


def _cpu_seconds(text):
    """The least CPU time of this thread that sanitising `text` took, of up to five tries.

    CPU time and not the clock: on a machine busy with something else the
    clock counts the something else. The least of several, because what makes
    one try slower than another is never the scan. And no more tries once
    they have taken half a second together: nothing is learnt from repeating
    a measurement that long, and a scan gone wrong would repeat for minutes.
    """
    least, spent = float('inf'), 0.0
    for _ in range(5):
        start = time.thread_time()
        sanitize_text(text)
        took = time.thread_time() - start
        least, spent = min(least, took), spent + took
        if spent > 0.5:
            break
    return least


@pytest.mark.parametrize('shape', sorted(HOSTILE))
def test_the_encoded_pem_scan_cannot_be_made_to_stall(shape):
    """sanitize_text sees unbounded hook output on a worker thread; it must stay linear.

    Linear is a statement about growth, so growth is what is measured: sixteen
    times the text may cost sixteen times the work, and a scan that has gone
    quadratic costs 256 times. The line is drawn at 64, four times away from
    both. A number of seconds says how fast the machine is instead: this test
    had one (3.0 s of CPU for all the shapes together, 1.5 s where it was
    written) and a hosted runner took 3.14 s with nothing wrong in the scan.

    Twice, at a few kilobytes and at a few megabytes. The small sizes come
    first because a quadratic scan shows there in seconds, and at the sizes
    hook output can really have it would take hours to say so.
    """
    for size in (5_000, 200_000):
        small, large = _cpu_seconds(HOSTILE[shape](size)), _cpu_seconds(HOSTILE[shape](16 * size))
        assert large < 64 * small, (
            f'{shape}: 16 times the text ({size} characters, then {16 * size}) took '
            f'{large / small:.0f} times the CPU ({small * 1000:.2f} ms, then {large * 1000:.1f} ms)')


# --------------------------------------------------------------------------
# The records a target result is written to
# --------------------------------------------------------------------------

def test_a_target_result_is_sanitised_before_audit_history_and_the_failure_alert(tmp_path):
    from modules.core.deployer import DeployManager
    from modules.core.shell import MockShellExecutor

    audit, bus = MagicMock(), MagicMock()
    manager = DeployManager(settings_manager=MagicMock(), shell_executor=MockShellExecutor(),
                            audit_logger=audit, event_bus=bus,
                            cert_dir=tmp_path / 'certs', data_dir=str(tmp_path / 'data'))
    history = []
    manager._log_history = history.append

    leaky = f'receiver said: {KEY_TEXT} and {base64.b64encode(KEY).decode()}'
    manager._record_target({'success': False, 'target': 't', 'type': 'kubernetes-secret',
                            'status_code': 500, 'message': leaky}, 'example.com', 'renewed')

    audit_call = audit.log_operation.call_args.kwargs
    alert = bus.publish.call_args.args[1]
    for where, text in (('audit details', json.dumps(audit_call['details'])),
                        ('audit error', audit_call['error']),
                        ('alert', alert['error']),
                        ('history', json.dumps(history[-1]))):
        assert not _leaks(text), f'{where}: {text[:200]!r}'
        assert 'receiver said' in text, where


# --------------------------------------------------------------------------
# The scrub's own edges
# --------------------------------------------------------------------------

def test_scrub_takes_the_key_as_text_or_bytes_and_leaves_empty_text_alone():
    from modules.core.secret_scrub import scrub
    assert scrub('', key_pem=KEY) == ''
    assert scrub(None, key_pem=KEY) is None
    for key in (KEY, KEY_TEXT):
        out = scrub(f'echo {KEY_BODY} done', key_pem=key)
        assert 'echo' in out and 'done' in out and not _leaks(out)


def test_scrub_removes_the_token_and_says_so():
    from modules.core.secret_scrub import scrub
    assert scrub('bad token sa-token-0a1b2c here', token='sa-token-0a1b2c') == 'bad token [REDACTED] here'
    assert scrub('nothing to hide', token=None, key_pem=None) == 'nothing to hide'
