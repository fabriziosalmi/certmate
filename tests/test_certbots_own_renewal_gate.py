"""When does the pinned certbot renew on its own? (#393)

CertMate decides whether to RUN certbot from `days_left <= renewal_threshold_days`, and
`_threshold_outruns_certbot` (#966) models certbot's own unforced gate as "30 days before
expiry" (`CERTBOT_RENEWAL_WINDOW_SECONDS`). That was true of certbot 2.10, whose
`renew_before_expiry` defaulted to "30 days". The stack moved to 5.8 (#103) and nothing
measured the gate again.

This runs the real `certbot renew --cert-name` on synthetic lineages (a self-signed
certificate with the lifetime and age chosen, a local fake ACME directory) and reads the
decision from certbot's own words, which it prints before any network action: "not yet
due for renewal", or an attempt, which fails against the fake CA with "Failed to renew
certificate". It characterizes certbot; it does not specify CertMate. When a certbot bump
changes one of these answers, this fails and says so, and #393 is the place to read before
adjusting the expectation.

What the pinned certbot (5.8.0) does, measured:

  * With no ARI, there is no 30-day default any more: it renews at 2/3 of the
    certificate's life, or at half of it when the life is under 10 days. For a 90-day
    certificate that is 30 days left, which is why nothing looked wrong. For 45 days it is
    15 days left, for 180 days it is 60.
  * With ARI, the CA's window decides, in both directions: a window already open renews a
    certificate that has 70 days left, and one still closed does NOT renew a certificate
    inside the old 30-day gate. That is what a short-lived certificate needs.
  * `renew_before_expiry` in the lineage's renewal config (it is not a command-line option
    in 5.8) turns the operator's threshold into a floor ARI cannot postpone.
  * A deferral does not outlive the call that asked the CA: inside `ari_retry_after` the
    next call does not ask, treats ARI as absent, and applies the 2/3 rule, so it renews
    what the CA said to wait for. CertMate calls certbot at most nightly, so it asks every
    time; a design that leans on certbot to remember the CA's answer would not be safe.

Windows are placed entirely in the past or entirely in the future: RFC 9773 has the client
pick a random instant inside the window, so one that straddles now gives a different answer
from one run to the next.
"""
import datetime as dt
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytestmark = [pytest.mark.unit]

NOT_DUE, DUE = 'not due', 'due'


class FakeCA:
    """A directory that serves `renewalInfo` (or leaves it out, like a CA without ARI),
    with the window under the test's control, and counts how often it was asked."""

    def __init__(self, ari=True):
        self.ari = ari
        self.window = None
        self.asked = 0
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, body, headers=None):
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(data)))
                for key, value in (headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                base = f'http://127.0.0.1:{self.server.server_port}'
                if self.path == '/directory':
                    directory = {'newNonce': base + '/nonce', 'newAccount': base + '/acct',
                                 'newOrder': base + '/order', 'revokeCert': base + '/revoke',
                                 'keyChange': base + '/key', 'meta': {}}
                    if outer.ari:
                        directory['renewalInfo'] = base + '/renewalInfo'
                    return self._send(directory)
                if self.path.startswith('/renewalInfo/') and outer.ari:
                    outer.asked += 1
                    start, end = outer.window
                    stamp = '%Y-%m-%dT%H:%M:%SZ'
                    return self._send({'suggestedWindow': {'start': start.strftime(stamp),
                                                           'end': end.strftime(stamp)}},
                                      {'Retry-After': '3600'})
                self.send_response(404)
                self.end_headers()

        self._server = HTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.directory = f'http://127.0.0.1:{self._server.server_port}/directory'

    def open_window(self, days_from_now, width_days=1):
        """The window opens that many days from now; negative means it is already over."""
        start = dt.datetime.now(dt.UTC) + dt.timedelta(days=days_from_now)
        self.window = (start, start + dt.timedelta(days=width_days))

    def close(self):
        self._server.shutdown()
        self._server.server_close()


def _lineage(root, ca, lifetime_days, age_days, renew_before_expiry=None):
    key = ec.generate_private_key(ec.SECP256R1())
    not_before = dt.datetime.now(dt.UTC) - dt.timedelta(days=age_days)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'gate.example.test')])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_before + dt.timedelta(days=lifetime_days))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('gate.example.test')]), False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    archive, live = root / 'archive' / 'gate', root / 'live' / 'gate'
    archive.mkdir(parents=True)
    live.mkdir(parents=True)
    (root / 'renewal').mkdir()
    for name, data in (('cert', pem), ('chain', pem), ('fullchain', pem + pem), ('privkey', private)):
        (archive / f'{name}1.pem').write_bytes(data)
        (live / f'{name}.pem').symlink_to(f'../../archive/gate/{name}1.pem')
    # Only the knob under test goes above the section header; in the renewal config a key
    # before the first section header is a top-level setting of the lineage.
    head = f'renew_before_expiry = {renew_before_expiry}\n' if renew_before_expiry else ''
    (root / 'renewal' / 'gate.conf').write_text(
        f'{head}version = 5.8.0\narchive_dir = {archive}\ncert = {live}/cert.pem\n'
        f'privkey = {live}/privkey.pem\nchain = {live}/chain.pem\nfullchain = {live}/fullchain.pem\n\n'
        f'[renewalparams]\naccount = 0123456789abcdef0123456789abcdef\nauthenticator = manual\n'
        f'server = {ca.directory}\n')


def _renew(root):
    """Run the real certbot once and say what it decided."""
    done = subprocess.run(
        [sys.executable, '-c', 'import sys; from certbot.main import main; sys.exit(main())',
         'renew', '--cert-name', 'gate', '--config-dir', str(root),
         '--work-dir', str(root / 'work'), '--logs-dir', str(root / 'logs'),
         '--no-random-sleep-on-renew', '--non-interactive'],
        capture_output=True, text=True, timeout=120)
    output = done.stdout + done.stderr
    if 'not yet due for renewal' in output:
        return NOT_DUE
    # Due: certbot goes on to try, and the fake CA has no account to renew with.
    assert 'Failed to renew certificate' in output, f'certbot said neither yes nor no:\n{output[-700:]}'
    return DUE


@pytest.fixture
def ca():
    fake = FakeCA(ari=True)
    yield fake
    fake.close()


@pytest.fixture
def ca_without_ari():
    fake = FakeCA(ari=False)
    yield fake
    fake.close()


def _decide(ca, lifetime, age, window=None, renew_before_expiry=None):
    root = pathlib.Path(tempfile.mkdtemp())
    if window is not None:
        ca.open_window(window)
    _lineage(root, ca, lifetime, age, renew_before_expiry)
    return _renew(root), root


# --------------------------------------------------------------------------
# No ARI: the 2/3 rule, and no 30-day default.
# --------------------------------------------------------------------------

@pytest.mark.parametrize('lifetime, not_yet, due, rule', [
    (6, 2.4, 3.3, 'half of the life, because it is under 10 days'),
    (45, 24.75, 31.5, '2/3 of the life: 15 days left, not 30'),
    (90, 49.5, 63.0, '2/3 of the life: 30 days left, the one length where it matches the old default'),
    (180, 99.0, 126.0, '2/3 of the life: 60 days left, not 30'),
])
def test_without_ari_certbot_renews_at_two_thirds_of_the_life(ca_without_ari, lifetime, not_yet, due, rule):
    before, _ = _decide(ca_without_ari, lifetime, not_yet)
    after, _ = _decide(ca_without_ari, lifetime, due)
    assert (before, after) == (NOT_DUE, DUE), (
        f'a {lifetime}-day certificate: certbot decided {before!r} at {not_yet} days old and '
        f'{after!r} at {due}, and the pinned stack renews at {rule}. If a bump changed this, '
        f'CertMate\'s CERTBOT_RENEWAL_WINDOW_SECONDS and #393 assume the old answer.')
    assert ca_without_ari.asked == 0, 'the CA without ARI was asked for renewal information'


# --------------------------------------------------------------------------
# With ARI: the CA's window decides, both ways.
# --------------------------------------------------------------------------

def test_a_window_already_open_renews_a_certificate_with_most_of_its_life_left(ca):
    decision, _ = _decide(ca, 90, 20, window=-3)

    assert decision == DUE
    assert ca.asked == 1, 'CONTROL: certbot was not asked-for-and-told, so this proves nothing about ARI'


@pytest.mark.parametrize('lifetime, age', [(90, 70), (45, 25), (6, 3.5)], ids=['90-day', '45-day', '6-day'])
def test_a_window_still_closed_defers_a_certificate_inside_the_old_gate(ca, lifetime, age):
    """The half of #393 that is about postponing: with 20 days left of 90, 20 of 45, or past
    the half-life of 6, the 2/3 rule and the old 30-day gate would all say renew; the CA says
    its window is days away, and certbot waits."""
    decision, _ = _decide(ca, lifetime, age, window=5 if lifetime > 6 else 2)

    assert decision == NOT_DUE
    assert ca.asked == 1, 'CONTROL: ARI was not consulted, so a "not due" here is the default rule talking'


def test_renew_before_expiry_in_the_lineage_is_a_floor_ari_cannot_postpone(ca):
    """Set in the lineage's renewal config (it is not a command-line option in 5.8). The
    same lineage as the deferral above, which ARI postpones, is now renewed."""
    decision, _ = _decide(ca, 90, 70, window=5, renew_before_expiry='30 days')

    assert decision == DUE
    assert ca.asked == 1


def test_a_deferral_does_not_outlive_the_call_that_asked_the_ca(ca):
    """The assumption any design that leans on certbot to remember the CA's answer would
    break on. The first call asks and waits. The second, inside `ari_retry_after`, does not
    ask, treats ARI as absent, and applies the 2/3 rule: it renews what the CA said to wait
    for. If certbot changes this the test fails, and the design can be simpler."""
    root = pathlib.Path(tempfile.mkdtemp())
    ca.open_window(5)
    _lineage(root, ca, 90, 70)

    first = _renew(root)
    second = _renew(root)

    assert (first, second) == (NOT_DUE, DUE)
    assert ca.asked == 1, 'the second call asked the CA again, so the deferral does survive it now'
    assert 'ari_retry_after' in (root / 'renewal' / 'gate.conf').read_text()
