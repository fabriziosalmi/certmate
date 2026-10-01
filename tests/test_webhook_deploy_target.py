"""The webhook deploy target: delivering a certificate, and sometimes its key, to an HTTPS endpoint (#218).

Each promise in the module's docstring is pinned here by a test that does the
thing it forbids, against a real TLS server, rather than by one that reads the
code and agrees with it.
"""
import base64
import hashlib
import hmac
import json
import pathlib
import re
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from modules.core import deploy_target_webhook as wh
from modules.core import pinned_https as ph
from modules.core.deploy_targets import target_needs_key
from tests.tls_support import TLSServer, build_pki, handler, make_cert, pem

pytestmark = [pytest.mark.unit]

DOMAIN = 'shop.example.com'
HOST = 'appliance.internal'


@pytest.fixture(scope='module')
def pki(tmp_path_factory):
    return build_pki(tmp_path_factory.mktemp('pki'))


def _loopback(host, port, allow_internal):
    return '127.0.0.1'


def _certificate_dir(tmp_path, key=None):
    """A certificate directory as certbot leaves it, with a private key of the given type."""
    leaf, leaf_key = make_cert(DOMAIN, san_dns=[DOMAIN])
    issuer, _ = make_cert('Issuer CA', is_ca=True)
    key = key or leaf_key
    d = tmp_path / 'certificates' / DOMAIN
    d.mkdir(parents=True)
    (d / 'cert.pem').write_bytes(pem(leaf))
    (d / 'chain.pem').write_bytes(pem(issuer))
    (d / 'fullchain.pem').write_bytes(pem(leaf) + pem(issuer))
    (d / 'privkey.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL
        if isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey))
        else serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return d, leaf


class Reader:
    """A `material` callable that records which files were opened."""

    def __init__(self, directory):
        self.directory, self.opened = directory, []

    def __call__(self, name):
        self.opened.append(name)
        return (self.directory / name).read_bytes()


CERT_ONLY = '{"domain": "{{domain}}", "certificate": "{{fullchain}}", "sha256": "{{certificate_sha256}}"}'
WITH_KEY = '{"name": "{{domain}}", "certificate": "{{fullchain}}", "key": "{{privkey_pkcs8}}"}'


def _target(server_port, pki, template=CERT_ONLY, **config):
    cfg = {'url': f'https://{HOST}:{server_port}/api/certificate', 'method': 'POST',
           'payload_template': template, 'ca_cert': pki['ca_pem']}
    cfg.update(config)
    target = {'type': 'webhook', 'id': 't1', 'name': 'Appliance', 'enabled': True,
              'domains': [DOMAIN], 'config': cfg}
    if wh.key_variables(template):
        target['delivery_consent'] = {'host': HOST, 'by': 'admin', 'at': '2026-10-01T00:00:00Z'}
    return target


def _run(target, directory, *, sleep=None, event='renewed', send=None):
    reader = Reader(directory)
    instance = wh.WebhookTarget(target, sleep=sleep or (lambda s: None), resolver=_loopback, send=send)
    return instance.deploy_from(reader, DOMAIN, event), reader


@pytest.fixture
def receiver(pki):
    seen = []
    servers = []

    def start(status=200, **kw):
        server = TLSServer(*pki['files']['leaf'], handler(status=status, record=seen, **kw))
        servers.append(server)
        return server
    yield start, seen
    for server in servers:
        server.close()


# --------------------------------------------------------------------------
# Delivery
# --------------------------------------------------------------------------

def test_the_certificate_is_delivered_as_json_with_pem_escaped(tmp_path, pki, receiver):
    start, seen = receiver
    directory, leaf = _certificate_dir(tmp_path)
    server = start()

    outcome, _ = _run(_target(server.port, pki), directory)

    assert outcome['success'] is True and outcome['status_code'] == 200
    assert len(seen) == 1 and seen[0]['method'] == 'POST' and seen[0]['path'] == '/api/certificate'
    body = json.loads(seen[0]['body'])
    assert body['domain'] == DOMAIN
    assert body['certificate'] == (directory / 'fullchain.pem').read_text()
    assert body['sha256'] == hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest()
    assert seen[0]['headers']['content-type'] == 'application/json'
    assert outcome['key_sent_to'] is None
    # A target that sends only the certificate says nothing about a key.
    assert 'privkey' not in seen[0]['body'].decode().lower()


def test_the_private_key_is_delivered_in_the_form_asked_for(tmp_path, pki, receiver):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    server = start()

    outcome, _ = _run(_target(server.port, pki, template=WITH_KEY), directory)

    assert outcome['success'] is True and outcome['key_sent_to'] == HOST
    sent = json.loads(seen[0]['body'])['key']
    assert sent.startswith('-----BEGIN PRIVATE KEY-----\n')     # PKCS#8, although the file on disk is SEC1
    stored = serialization.load_pem_private_key((directory / 'privkey.pem').read_bytes(), None)
    assert serialization.load_pem_private_key(sent.encode(), None).public_key().public_numbers() == \
        stored.public_key().public_numbers()


@pytest.mark.parametrize('kind, marker', [
    ('rsa', '-----BEGIN RSA PRIVATE KEY-----'), ('ec', '-----BEGIN EC PRIVATE KEY-----')])
def test_the_traditional_form_is_produced_for_rsa_and_ec(tmp_path, pki, receiver, kind, marker):
    start, seen = receiver
    key = (rsa.generate_private_key(public_exponent=65537, key_size=2048) if kind == 'rsa'
           else ec.generate_private_key(ec.SECP256R1()))
    directory, _ = _certificate_dir(tmp_path, key=key)
    server = start()
    template = '{"key": "{{privkey_traditional}}"}'

    outcome, _ = _run(_target(server.port, pki, template=template), directory)

    assert outcome['success'] is True
    assert json.loads(seen[0]['body'])['key'].startswith(marker)


def test_a_key_with_no_traditional_form_fails_without_sending_anything(tmp_path, pki, receiver):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path, key=ed25519.Ed25519PrivateKey.generate())
    server = start()

    outcome, _ = _run(_target(server.port, pki, template='{"key": "{{privkey_traditional}}"}'), directory)

    assert outcome['success'] is False and 'traditional' in outcome['message']
    assert seen == []
    assert outcome['key_sent_to'] is None


def test_the_private_key_is_read_only_when_the_template_names_it(tmp_path, pki, receiver):
    start, _ = receiver
    directory, _ = _certificate_dir(tmp_path)
    server = start()

    _, without = _run(_target(server.port, pki, template=CERT_ONLY), directory)
    _, with_key = _run(_target(server.port, pki, template=WITH_KEY), directory)

    assert 'privkey.pem' not in without.opened
    assert 'privkey.pem' in with_key.opened
    # And a template that uses only the leaf does not open the chain files either.
    leaf_only = '{"cert": "{{cert}}"}'
    _, narrow = _run(_target(server.port, pki, template=leaf_only), directory)
    assert sorted(narrow.opened) == ['cert.pem', 'cert.pem']


def test_required_files_follow_the_template(pki):
    assert wh.WebhookTarget(_target(1, pki, CERT_ONLY)).required_files() == ('cert.pem', 'fullchain.pem')
    assert wh.WebhookTarget(_target(1, pki, WITH_KEY)).required_files() == (
        'cert.pem', 'fullchain.pem', 'privkey.pem')
    assert wh.WebhookTarget(_target(1, pki, '{"c": "{{chain}}"}')).required_files() == ('cert.pem', 'chain.pem')
    assert target_needs_key(_target(1, pki, WITH_KEY)) is True
    assert target_needs_key(_target(1, pki, CERT_ONLY)) is False


def test_a_certificate_with_no_key_on_this_node_can_still_be_delivered_without_it(tmp_path, pki, receiver):
    """A CSR issuance: the key is on the device. A certificate-only target does not need it."""
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    (directory / 'privkey.pem').unlink()
    server = start()
    outcome, _ = _run(_target(server.port, pki, template=CERT_ONLY), directory)
    assert outcome['success'] is True and len(seen) == 1


def test_a_missing_file_is_reported_without_a_path(tmp_path, pki, receiver):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    (directory / 'fullchain.pem').unlink()
    server = start()
    outcome, _ = _run(_target(server.port, pki), directory)
    assert outcome['success'] is False and outcome['message'] == 'certificate files unreadable'
    assert str(tmp_path) not in outcome['message'] and seen == []


# --------------------------------------------------------------------------
# Sending the key is a decision about a destination
# --------------------------------------------------------------------------

def test_a_target_that_sends_the_key_without_a_confirmation_does_not_send_it(tmp_path, pki, receiver):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    server = start()
    target = _target(server.port, pki, template=WITH_KEY)
    del target['delivery_consent']

    outcome, reader = _run(target, directory)

    assert outcome['success'] is False and 'has not been confirmed' in outcome['message']
    assert seen == [] and reader.opened == [], 'the key was read for a destination nobody confirmed'


def test_a_confirmation_for_another_host_does_not_apply(tmp_path, pki, receiver):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    server = start()
    target = _target(server.port, pki, template=WITH_KEY)
    target['delivery_consent']['host'] = 'the-old-appliance.internal'

    outcome, _ = _run(target, directory)
    assert outcome['success'] is False and seen == []
    assert HOST in outcome['message']


def test_a_certificate_only_target_needs_no_confirmation(tmp_path, pki, receiver):
    start, _ = receiver
    directory, _ = _certificate_dir(tmp_path)
    outcome, _ = _run(_target(start().port, pki, template=CERT_ONLY), directory)
    assert outcome['success'] is True


# --------------------------------------------------------------------------
# Nothing the receiver says is kept
# --------------------------------------------------------------------------

def test_a_receiver_that_echoes_the_key_does_not_get_it_into_the_outcome(tmp_path, pki, receiver):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    echo = json.dumps({'received': 'x'}).encode()
    # The server answers with exactly the body it was sent, then the test checks the outcome.
    key_text = serialization.load_pem_private_key((directory / 'privkey.pem').read_bytes(), None).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    body_lines = [ln for ln in key_text.splitlines() if '-----' not in ln]
    server = start(status=422, body=key_text.encode() + base64.b64encode(key_text.encode()) + echo)

    outcome, _ = _run(_target(server.port, pki, template=WITH_KEY), directory)

    blob = json.dumps(outcome)
    assert outcome['status_code'] == 422 and outcome['success'] is False
    assert not any(line in blob for line in body_lines)
    assert base64.b64encode(key_text.encode()).decode()[:40] not in blob
    assert outcome['message'] == f'{HOST} answered HTTP 422'


def test_the_outcome_names_the_host_never_the_address_or_credentials_in_it(tmp_path, pki, receiver):
    start, _ = receiver
    directory, _ = _certificate_dir(tmp_path)
    server = start(status=500)
    target = _target(server.port, pki, attempts=1)
    target['config']['url'] += '?token=SECRET-IN-THE-QUERY'
    outcome, _ = _run(target, directory)
    assert 'SECRET-IN-THE-QUERY' not in json.dumps(outcome) and '/api/certificate' not in outcome['message']


@pytest.mark.parametrize('status', [301, 302, 307, 308])
def test_a_redirect_is_a_failure_that_says_so_and_goes_nowhere(tmp_path, pki, receiver, status):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    elsewhere = start()
    server = start(status=status, location=f'https://{HOST}:{elsewhere.port}/landing?token=abc')

    outcome, _ = _run(_target(server.port, pki, template=WITH_KEY), directory)

    assert outcome['success'] is False and 'redirect' in outcome['message']
    assert len(seen) == 1, 'a second request was made at the address the answer named'
    assert 'landing' not in json.dumps(outcome) and 'token=abc' not in json.dumps(outcome)
    assert outcome['key_sent_to'] == HOST        # it did leave, to the configured host, and is recorded


# --------------------------------------------------------------------------
# Retrying
# --------------------------------------------------------------------------

def test_a_server_error_is_retried_with_backoff_and_then_stops(tmp_path, pki, receiver):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    waits = []
    outcome, _ = _run(_target(start(status=503).port, pki, attempts=3), directory, sleep=waits.append)
    assert outcome['success'] is False and outcome['attempts'] == 3
    assert len(seen) == 3 and waits == [1, 2]


@pytest.mark.parametrize('status', [400, 401, 403, 404, 409, 422])
def test_a_client_error_is_not_retried(tmp_path, pki, receiver, status):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    outcome, _ = _run(_target(start(status=status).port, pki, attempts=5), directory)
    assert len(seen) == 1 and outcome['attempts'] == 1


@pytest.mark.parametrize('status', [408, 425, 429])
def test_the_client_errors_that_describe_the_attempt_are_retried(tmp_path, pki, receiver, status):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    _run(_target(start(status=status).port, pki, attempts=2), directory)
    assert len(seen) == 2


def test_a_success_after_a_failure_stops_retrying(tmp_path, pki):
    directory, _ = _certificate_dir(tmp_path)
    replies = iter([ph.Reply(503, False), ph.Reply(200, False)])
    calls = []

    def send(url, **kw):
        calls.append(kw['headers']['Idempotency-Key'])
        return next(replies)
    outcome, _ = _run(_target(1, pki, attempts=5), directory, send=send)
    assert outcome['success'] is True and outcome['attempts'] == 2
    assert len(set(calls)) == 1, 'the retry of one delivery must carry the same idempotency key'


def test_a_transport_error_is_retried_and_the_key_is_recorded_as_possibly_sent(tmp_path, pki):
    directory, _ = _certificate_dir(tmp_path)

    def send(url, **kw):
        raise ph.TransportError('the connection failed: Connection reset by peer')
    waits = []
    outcome, _ = _run(_target(1, pki, template=WITH_KEY, attempts=2), directory, send=send, sleep=waits.append)
    assert outcome['success'] is False and outcome['attempts'] == 2 and waits == [1]
    assert outcome['key_sent_to'] == HOST


@pytest.mark.parametrize('error', [ph.TLSVerificationFailed('no'), ph.UnsafeDestination('no')])
def test_a_refusal_before_anything_is_sent_is_not_retried_and_says_nothing_was_sent(tmp_path, pki, error):
    directory, _ = _certificate_dir(tmp_path)
    calls = []

    def send(url, **kw):
        calls.append(1)
        raise error
    outcome, _ = _run(_target(1, pki, template=WITH_KEY, attempts=5), directory, send=send)
    assert len(calls) == 1 and outcome['key_sent_to'] is None
    assert 'nothing was sent' in outcome['message']


def test_the_same_certificate_delivered_again_carries_the_same_idempotency_key(tmp_path, pki):
    """That is the point of the key: a receiver can tell a repeat from a new certificate."""
    directory, _ = _certificate_dir(tmp_path)
    keys = []

    def send(url, **kw):
        keys.append(kw['headers']['Idempotency-Key'])
        return ph.Reply(200, False)
    _run(_target(1, pki), directory, send=send)
    _run(_target(1, pki), directory, send=send)
    assert keys[0] == keys[1]


def test_the_idempotency_key_differs_between_certificates(tmp_path, pki):
    keys = []

    def send(url, **kw):
        keys.append(kw['headers']['Idempotency-Key'])
        return ph.Reply(200, False)
    for index in range(2):
        directory, _ = _certificate_dir(tmp_path / f'run{index}')
        _run(_target(1, pki), directory, send=send)
    assert keys[0] != keys[1]


# --------------------------------------------------------------------------
# TLS and destination
# --------------------------------------------------------------------------

def test_a_pinned_certificate_is_accepted_and_a_wrong_pin_sends_nothing(tmp_path, pki):
    directory, _ = _certificate_dir(tmp_path)
    seen = []
    server = TLSServer(*pki['files']['self'], handler(record=seen))
    try:
        target = _target(server.port, pki, template=WITH_KEY)
        target['config'].pop('ca_cert')
        good = dict(target, config=dict(target['config'], pin_sha256=pki['self_sha256']))
        bad = dict(target, config=dict(target['config'], pin_sha256=pki['leaf_sha256']))
        assert _run(good, directory)[0]['success'] is True
        seen.clear()
        outcome, _ = _run(bad, directory)
    finally:
        server.close()
    assert outcome['success'] is False and 'fingerprint' in outcome['message'] and seen == []
    assert outcome['key_sent_to'] is None


def test_a_certificate_no_trusted_ca_vouches_for_sends_nothing(tmp_path, pki):
    directory, _ = _certificate_dir(tmp_path)
    seen = []
    server = TLSServer(*pki['files']['self'], handler(record=seen))
    try:
        target = _target(server.port, pki, template=WITH_KEY)
        target['config'].pop('ca_cert')                       # system store only
        outcome, _ = _run(target, directory)
    finally:
        server.close()
    assert outcome['success'] is False and seen == [] and outcome['key_sent_to'] is None


def test_the_policy_reaches_the_client(tmp_path, pki):
    directory, _ = _certificate_dir(tmp_path)
    captured = {}

    def send(url, **kw):
        captured.update(kw, url=url)
        return ph.Reply(200, False)
    target = _target(443, pki, allow_internal=True, timeout=7)
    target['config']['ca_cert'] = pki['ca_pem']
    _run(target, directory, send=send)
    assert captured['allow_internal'] is True and captured['timeout'] == 7
    assert captured['ca_pem'] == pki['ca_pem'] and captured['method'] == 'POST'
    captured.clear()
    _run(_target(443, pki), directory, send=send)
    assert captured['allow_internal'] is False, 'internal destinations must be opt-in'


def test_the_default_send_refuses_a_private_destination_without_allow_internal(tmp_path, pki, monkeypatch):
    import socket
    monkeypatch.setattr(socket, 'getaddrinfo', lambda h, p, *a, **k: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.5', p))])
    directory, _ = _certificate_dir(tmp_path)
    instance = wh.WebhookTarget(_target(443, pki, template=WITH_KEY))         # default send and resolver
    outcome = instance.deploy_from(Reader(directory), DOMAIN, 'renewed')
    assert outcome['success'] is False and 'allow_internal' in outcome['message']
    assert outcome['key_sent_to'] is None


# --------------------------------------------------------------------------
# Authentication and signing
# --------------------------------------------------------------------------

@pytest.mark.parametrize('auth, expect', [
    ({'auth_type': 'bearer', 'auth_token': 'tok-123'}, ('authorization', 'Bearer tok-123')),
    ({'auth_type': 'basic', 'auth_username': 'u', 'auth_password': 'p'},
     ('authorization', 'Basic ' + base64.b64encode(b'u:p').decode())),
    ({'auth_type': 'header', 'auth_header': 'X-Auth-Token', 'auth_token': 'abc'}, ('x-auth-token', 'abc')),
])
def test_authentication_is_sent_as_configured(tmp_path, pki, receiver, auth, expect):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    _run(_target(start().port, pki, **auth), directory)
    assert seen[0]['headers'][expect[0]] == expect[1]


def test_the_body_is_signed_when_a_secret_is_configured(tmp_path, pki, receiver):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    _run(_target(start().port, pki, signing_secret='s3cret'), directory)
    stamp, signature = re.match(r't=(\d+),v1=([0-9a-f]+)', seen[0]['headers']['x-certmate-signature']).groups()
    expected = hmac.new(b's3cret', f'{stamp}.'.encode() + seen[0]['body'], hashlib.sha256).hexdigest()
    assert hmac.compare_digest(signature, expected)


# --------------------------------------------------------------------------
# Preview: what would be sent, without sending or reading
# --------------------------------------------------------------------------

def test_the_preview_shows_the_request_without_a_network_or_a_file(pki):
    calls = []
    instance = wh.WebhookTarget(_target(443, pki, template=WITH_KEY, auth_type='bearer', auth_token='tok',
                                        signing_secret='sig'),
                                send=lambda *a, **k: calls.append(1))
    preview = instance.preview()
    assert calls == []
    assert preview['sends_private_key'] is True and preview['key_variables'] == ['privkey_pkcs8']
    assert preview['host'] == HOST and preview['tls_verified_with'] == 'the supplied CA'
    assert preview['headers']['Authorization'] == '[masked]' and 'tok' not in json.dumps(preview)
    assert 'sig' not in json.dumps(preview['headers']).replace('X-CertMate-Signature', '')
    assert 'EXAMPLE-NOT-A-REAL-KEY' in preview['body']
    assert preview['files_needed'] == ['cert.pem', 'fullchain.pem', 'privkey.pem']
    assert json.loads(preview['body'])


@pytest.mark.parametrize('url,port', [
    ('https://lb.internal:8443/api/cert', 8443),
    ('https://lb.internal/api/cert', 443),
    ('https://[2001:db8::1]:9443/api/cert', 9443),
])
def test_the_preview_names_the_port_the_request_goes_to(pki, url, port):
    """A preview that left the port out showed a destination that was not the real one."""
    preview = wh.WebhookTarget(_target(443, pki, url=url)).preview()
    assert preview['port'] == port


def test_the_preview_of_a_certificate_only_target_says_no_key_is_sent(pki):
    preview = wh.WebhookTarget(_target(443, pki, template=CERT_ONLY)).preview()
    assert preview['sends_private_key'] is False and 'privkey.pem' not in preview['files_needed']


# --------------------------------------------------------------------------
# Save-time validation and consent
# --------------------------------------------------------------------------

def _valid(pki, **over):
    target = _target(443, pki, template=CERT_ONLY)
    target.update(over)
    return target


def test_a_valid_target_passes(pki):
    assert wh.validate_webhook_target(_valid(pki)) == (True, None)


@pytest.mark.parametrize('mutate, needle', [
    (lambda t: t.pop('id'), 'id'),
    (lambda t: t.update(name=''), 'name'),
    (lambda t: t.pop('domains'), 'explicit list of domains'),
    (lambda t: t.update(domains=[]), 'explicit list of domains'),
    (lambda t: t.update(domains='example.com'), 'explicit list of domains'),
    (lambda t: t.update(domains=[5]), 'explicit list of domains'),
    (lambda t: t.update(on_events=['deleted']), 'on_events'),
    (lambda t: t['config'].update(url='http://appliance.internal/x'), 'https'),
    (lambda t: t['config'].update(url='https://u:p@appliance.internal/x'), 'credentials'),
    (lambda t: t['config'].update(url='https:///x'), 'https'),
    (lambda t: t['config'].update(url='https://appliance.internal:99999/x'), 'valid URL'),
    (lambda t: t['config'].update(url=None), 'https'),
    (lambda t: t['config'].update(method='DELETE'), 'method'),
    (lambda t: t['config'].update(auth_type='bearer'), 'auth_token'),
    (lambda t: t['config'].update(auth_type='magic'), 'auth_type'),
    (lambda t: t['config'].update(timeout=0), 'timeout'),
    (lambda t: t['config'].update(timeout=True), 'timeout'),
    (lambda t: t['config'].update(attempts=9), 'attempts'),
    (lambda t: t['config'].update(allow_internal='yes'), 'allow_internal'),
    (lambda t: (t['config'].pop('ca_cert'), t['config'].update(pin_sha256='abc')), 'SHA-256'),
    (lambda t: t['config'].update(pin_sha256='0' * 64), 'either ca_cert or pin_sha256'),
    (lambda t: t['config'].update(ca_cert='not a cert'), 'ca_cert'),
    (lambda t: t['config'].pop('payload_template'), 'payload_template is required'),
    (lambda t: t['config'].update(payload_template='{"a": '), 'valid JSON'),
    (lambda t: t['config'].update(payload_template='{"a": "{{nothing_like_this}}"}'), 'unknown variable'),
    (lambda t: t['config'].update(payload_template='{"a": "{{details.domain}}"}'), 'unknown variable'),
    (lambda t: t['config'].update(payload_template='{"a":"x"}' + ' ' * 70000), '64 KiB'),
])
def test_an_invalid_target_is_refused_with_a_reason(pki, mutate, needle):
    target = _valid(pki)
    mutate(target)
    ok, reason = wh.validate_webhook_target(target)
    assert ok is False and needle in reason, reason


def test_a_template_that_is_not_json_is_located_without_passing_on_the_parsers_text(pki):
    """The reason says WHERE, as numbers; the parser's own wording is not forwarded."""
    target = _valid(pki)
    target['config']['payload_template'] = '{"a": '
    ok, reason = wh.validate_webhook_target(target)
    assert ok is False
    assert 'line 1, column 7' in reason
    for parser_wording in ('Expecting', 'char 6', 'delimiter', 'Unterminated'):
        assert parser_wording not in reason, reason


@pytest.mark.parametrize('url,accepted', [
    ('https://[2001:db8::1]:8443/api/cert', True),     # an IPv6 literal is a valid destination
    ('https://[::1]/x', True),                           # valid here; the delivery still refuses loopback
    ('https://10.0.0.5:8443/x', True),
    ('https://lb.internal/x', True),
    ('https://[2001:db8::zz]/x', False),                 # not an address
    ('https://bad_host/x', False),                       # underscore: neither a name nor an address
])
def test_the_destination_host_may_be_a_name_or_an_address(pki, url, accepted):
    """The validator matched IPv6 against a bracketed pattern that `urlparse().hostname` never produces,
    so a valid IPv6 literal was refused with a message that blamed the URL's shape."""
    target = _valid(pki)
    target['config']['url'] = url
    ok, reason = wh.validate_webhook_target(target)
    assert ok is accepted, reason


def test_a_plain_http_receiver_is_refused_with_a_way_out(pki):
    """A receiver that listens on plain HTTP by default is the first thing a user meets: the refusal says
    what to do, and the documentation it points at has that section."""
    target = _valid(pki)
    target['config']['url'] = 'http://n8n.lan:5678/webhook/certmate'
    ok, reason = wh.validate_webhook_target(target)
    assert ok is False and 'https://' in reason and 'TLS' in reason and 'n8n' in reason
    docs = (pathlib.Path(__file__).resolve().parent.parent / 'docs' / 'deploy-hooks.md').read_text()
    assert 'Receiving it in n8n' in docs, 'the message points at a section that does not exist'


def test_a_bare_privkey_is_refused_and_the_two_real_names_are_offered(pki):
    target = _valid(pki)
    target['config']['payload_template'] = '{"key": "{{privkey}}"}'
    ok, reason = wh.validate_webhook_target(target)
    assert ok is False and 'privkey_pkcs8' in reason and 'privkey_traditional' in reason


def test_a_template_that_names_the_key_needs_a_matching_confirmation(pki):
    target = _valid(pki)
    target['config']['payload_template'] = WITH_KEY
    ok, reason = wh.validate_webhook_target(target)
    assert ok is False and HOST in reason and 'acknowledge_key_delivery_to' in reason
    target['delivery_consent'] = {'host': HOST, 'by': 'a', 'at': 'now'}
    assert wh.validate_webhook_target(target) == (True, None)
    target['delivery_consent'] = {'host': 'other.internal', 'by': 'a', 'at': 'now'}
    assert wh.validate_webhook_target(target)[0] is False


def test_the_notification_webhook_still_does_not_know_the_key_variables():
    """The other half of the decision: the key is not a placeholder of a notification."""
    from modules.core.notifier import CERT_MATERIAL_FILES
    assert not set(CERT_MATERIAL_FILES) & set(wh.KEY_MATERIAL)
    assert 'privkey' not in CERT_MATERIAL_FILES


def _keyed(pki, **over):
    target = _target(443, pki, template=WITH_KEY)
    target.pop('delivery_consent')
    target['config']['acknowledge_key_delivery_to'] = HOST
    target.update(over)
    return target


def test_an_acknowledgement_becomes_a_consent_recorded_by_the_server(pki):
    out, error = wh.stamp_consent([_keyed(pki)], [], 'fab', when='2026-10-01T10:00:00Z')
    assert error is None
    assert out[0]['delivery_consent'] == {'host': HOST, 'by': 'fab', 'at': '2026-10-01T10:00:00Z'}
    assert 'acknowledge_key_delivery_to' not in out[0]['config']
    assert wh.validate_webhook_target(out[0]) == (True, None)


def test_the_acknowledgement_is_compared_without_regard_to_case(pki):
    target = _keyed(pki)
    target['config']['acknowledge_key_delivery_to'] = HOST.upper()
    assert wh.stamp_consent([target], [], 'fab')[1] is None


@pytest.mark.parametrize('ack', [None, '', 'some-other-host.internal'])
def test_a_missing_or_wrong_acknowledgement_is_refused_naming_the_host(pki, ack):
    target = _keyed(pki)
    target['config']['acknowledge_key_delivery_to'] = ack
    out, error = wh.stamp_consent([target], [], 'fab')
    assert out is None and HOST in error and 'acknowledge_key_delivery_to' in error


def test_an_existing_consent_carries_over_while_the_host_is_the_same(pki):
    earlier, _ = wh.stamp_consent([_keyed(pki)], [], 'fab', when='2026-09-30T08:00:00Z')
    resaved = _keyed(pki)
    resaved['config'].pop('acknowledge_key_delivery_to')
    resaved['config']['timeout'] = 30                          # an unrelated edit
    out, error = wh.stamp_consent([resaved], earlier, 'someone-else', when='2026-10-01T10:00:00Z')
    assert error is None
    assert out[0]['delivery_consent'] == {'host': HOST, 'by': 'fab', 'at': '2026-09-30T08:00:00Z'}


def test_changing_the_host_ends_the_consent(pki):
    earlier, _ = wh.stamp_consent([_keyed(pki)], [], 'fab')
    moved = _keyed(pki)
    moved['config'].pop('acknowledge_key_delivery_to')
    moved['config']['url'] = 'https://new-appliance.internal/api/certificate'
    out, error = wh.stamp_consent([moved], earlier, 'fab')
    assert out is None and 'new-appliance.internal' in error


def test_a_consent_posted_by_the_client_is_ignored(pki):
    forged = _keyed(pki)
    forged['config'].pop('acknowledge_key_delivery_to')
    forged['delivery_consent'] = {'host': HOST, 'by': 'admin', 'at': '2020-01-01T00:00:00Z'}
    out, error = wh.stamp_consent([forged], [], 'fab')
    assert out is None and error, 'a client confirmed for itself'


def test_a_target_that_no_longer_sends_the_key_loses_its_consent(pki):
    earlier, _ = wh.stamp_consent([_keyed(pki)], [], 'fab')
    plain = _target(443, pki, template=CERT_ONLY)
    plain['delivery_consent'] = earlier[0]['delivery_consent']
    out, error = wh.stamp_consent([plain], earlier, 'fab')
    assert error is None and 'delivery_consent' not in out[0]


def test_other_target_types_pass_through_untouched(pki):
    k8s = {'type': 'kubernetes-secret', 'name': 'k', 'config': {'token': 'x'}}
    assert wh.stamp_consent([k8s], [], 'fab') == ([k8s], None)


# --------------------------------------------------------------------------
# Through the deploy manager
# --------------------------------------------------------------------------

def _deployer(tmp_path):
    from modules.core.deployer import DeployManager
    from modules.core.shell import MockShellExecutor
    audit, bus = MagicMock(), MagicMock()
    manager = DeployManager(settings_manager=MagicMock(), shell_executor=MockShellExecutor(),
                            audit_logger=audit, event_bus=bus, cert_dir=tmp_path / 'certificates',
                            data_dir=str(tmp_path / 'data'))
    manager._log_history = MagicMock()
    return manager, audit, bus


def test_the_deploy_manager_delivers_and_audits_where_the_key_went_not_the_key(tmp_path, pki, receiver, monkeypatch):
    start, seen = receiver
    _certificate_dir(tmp_path)
    manager, audit, _ = _deployer(tmp_path)
    target = _target(start().port, pki, template=WITH_KEY)
    monkeypatch.setattr(ph, 'resolve', _loopback)

    results = manager._execute_targets(DOMAIN, 'renewed', {'enabled': True, 'targets': [target]}, targets=[target])

    assert results[0]['success'] is True
    details = audit.log_operation.call_args.kwargs['details']
    assert details['key_sent_to'] == HOST and len(details['certificate_sha256']) == 64
    assert details['status_code'] == 200 and details['attempts'] == 1
    key_body = ''.join(json.loads(seen[0]['body'])['key'].strip().splitlines()[1:-1])
    assert key_body not in json.dumps(details) and key_body not in json.dumps(manager._log_history.call_args_list, default=str)


def test_a_csr_certificate_is_delivered_by_a_certificate_only_target_and_refused_for_a_keyed_one(tmp_path, pki, receiver, monkeypatch):
    start, seen = receiver
    directory, _ = _certificate_dir(tmp_path)
    (directory / 'privkey.pem').unlink()
    manager, _, _ = _deployer(tmp_path)
    server = start()
    plain = _target(server.port, pki, template=CERT_ONLY)
    plain['id'], plain['name'] = 'plain', 'plain'
    keyed = _target(server.port, pki, template=WITH_KEY)
    keyed['id'], keyed['name'] = 'keyed', 'keyed'
    monkeypatch.setattr(ph, 'resolve', _loopback)

    results = manager._execute_targets(DOMAIN, 'renewed', {'enabled': True, 'targets': [plain, keyed]},
                                       targets=[plain, keyed])

    assert len(seen) == 1 and json.loads(seen[0]['body'])['domain'] == DOMAIN
    assert any('issued from a CSR' in r['message'] for r in results)
    assert any(r.get('success') is True and r.get('target') == 'plain' for r in results)
