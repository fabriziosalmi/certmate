"""The HTTPS client a key-carrying deploy target sends through.

A target that hands a private key to a URL has to be able to say three things
about where the bytes go, and each has a way of being half true:

* **Which address.** The host is resolved ONCE, the answer is checked, and the
  connection is made to that address. Checking the name and then letting the
  library resolve it again is how a DNS answer that changes in between (a
  rebind) gets past the check.
* **Who answers.** TLS is always verified: against the system store, a CA the
  operator supplied, or a pinned fingerprint of the server's certificate for an
  appliance that signs its own. There is no way to turn verification off.
* **What happens next.** A redirect is a failure, and the answer is not kept:
  only its status is, because a receiver can echo the body it was sent.

Real sockets and real TLS throughout: a mocked connection would pass whether or
not any of this was true.
"""
import socket

import pytest

from modules.core import pinned_https as ph
from tests.tls_support import TLSServer, build_pki, handler

pytestmark = [pytest.mark.unit]

BODY = b'{"key": "-----BEGIN PRIVATE KEY-----\\nTHE-KEY\\n-----END PRIVATE KEY-----\\n"}'


@pytest.fixture(scope='module')
def pki(tmp_path_factory):
    return build_pki(tmp_path_factory.mktemp('pki'))


def _loopback(host, port, allow_internal):
    """Stands in for the resolver: every test server is on the loopback."""
    return '127.0.0.1'


def _send(url, *, resolver=_loopback, **kw):
    return ph.send(url, method='POST', body=BODY, headers={'Content-Type': 'application/json'},
                   resolver=resolver, timeout=5, **kw)


# --------------------------------------------------------------------------
# Who answers: TLS is always verified
# --------------------------------------------------------------------------

def test_a_certificate_signed_by_a_supplied_ca_is_accepted(pki):
    seen = []
    server = TLSServer(*pki['files']['leaf'], handler(record=seen))
    try:
        reply = _send(f'https://appliance.internal:{server.port}/upload', ca_pem=pki['ca_pem'])
    finally:
        server.close()
    assert reply.status == 200 and seen[0]['body'] == BODY
    # The Host and SNI are the NAME, although the connection went to the pinned address.
    assert seen[0]['headers']['host'] == f'appliance.internal:{server.port}'


def test_a_supplied_ca_replaces_the_system_store_it_does_not_join_it(pki, monkeypatch):
    """The operator named who may vouch for this server; the system store does not also get a say."""
    monkeypatch.setenv('SSL_CERT_FILE', pki['system_ca_file'])
    seen = []
    server = TLSServer(*pki['files']['system'], handler(record=seen))
    try:
        # Control: with no CA supplied, the (stand-in) system store vouches for it.
        assert _send(f'https://appliance.internal:{server.port}/up').status == 200
        with pytest.raises(ph.TLSVerificationFailed):
            _send(f'https://appliance.internal:{server.port}/up', ca_pem=pki['ca_pem'])
    finally:
        server.close()
    assert len(seen) == 1, 'the second request should have been refused before any body was sent'


def test_a_certificate_that_chains_to_no_trusted_ca_is_refused(pki):
    seen = []
    server = TLSServer(*pki['files']['self'], handler(record=seen))
    try:
        with pytest.raises(ph.TLSVerificationFailed):
            _send(f'https://appliance.internal:{server.port}/upload')      # system store only
    finally:
        server.close()
    assert seen == [], 'the body was sent over a connection that was not verified'


def test_a_name_the_certificate_does_not_cover_is_refused(pki):
    seen = []
    server = TLSServer(*pki['files']['leaf'], handler(record=seen))
    try:
        with pytest.raises(ph.TLSVerificationFailed):
            _send(f'https://some-other-name.example:{server.port}/upload', ca_pem=pki['ca_pem'])
    finally:
        server.close()
    assert seen == []


def test_a_pinned_fingerprint_accepts_a_self_signed_certificate(pki):
    seen = []
    server = TLSServer(*pki['files']['self'], handler(record=seen))
    try:
        reply = _send(f'https://appliance.internal:{server.port}/upload', pin_sha256=pki['self_sha256'])
    finally:
        server.close()
    assert reply.status == 200 and len(seen) == 1


def test_a_pinned_fingerprint_that_does_not_match_is_refused_before_the_body_is_sent(pki):
    seen = []
    server = TLSServer(*pki['files']['self'], handler(record=seen))
    try:
        with pytest.raises(ph.TLSVerificationFailed) as refused:
            _send(f'https://appliance.internal:{server.port}/upload', pin_sha256=pki['leaf_sha256'])
    finally:
        server.close()
    assert seen == []
    assert 'fingerprint' in str(refused.value).lower()


def test_the_pin_is_compared_case_and_colon_insensitively(pki):
    server = TLSServer(*pki['files']['self'], handler())
    colon = ':'.join(pki['self_sha256'][i:i + 2] for i in range(0, 64, 2)).upper()
    try:
        assert _send(f'https://appliance.internal:{server.port}/', pin_sha256=colon).status == 200
    finally:
        server.close()


def test_there_is_no_way_to_turn_verification_off():
    import inspect
    parameters = inspect.signature(ph.send).parameters
    assert not any('verify' in name or 'insecure' in name for name in parameters)


def test_plain_http_is_refused(pki):
    with pytest.raises(ph.UnsafeDestination):
        _send('http://appliance.internal:8080/upload')


@pytest.mark.parametrize('url', ['https://user:pass@appliance.internal/x', 'https:///nohost', 'https://[::1/x'])
def test_a_url_with_credentials_or_no_host_is_refused(url):
    with pytest.raises(ph.UnsafeDestination):
        _send(url)


# --------------------------------------------------------------------------
# What happens next: no redirect, and the answer is not kept
# --------------------------------------------------------------------------

@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_a_redirect_is_reported_and_not_followed(pki, status):
    elsewhere = []
    other = TLSServer(*pki['files']['leaf'], handler(record=elsewhere))
    seen = []
    server = TLSServer(*pki['files']['leaf'], handler(
        status=status, location=f'https://appliance.internal:{other.port}/landing?token=abc', record=seen))
    try:
        reply = _send(f'https://appliance.internal:{server.port}/upload', ca_pem=pki['ca_pem'])
    finally:
        server.close()
        other.close()
    assert reply.status == status and reply.redirected is True
    assert elsewhere == [], 'the request was repeated at the address the answer named'
    assert len(seen) == 1


def test_the_answer_body_is_not_returned(pki):
    echoing = handler(status=422, body=b'invalid: ' + BODY)
    server = TLSServer(*pki['files']['leaf'], echoing)
    try:
        reply = _send(f'https://appliance.internal:{server.port}/upload', ca_pem=pki['ca_pem'])
    finally:
        server.close()
    assert reply.status == 422
    assert not hasattr(reply, 'body') and not hasattr(reply, 'text')
    assert 'THE-KEY' not in repr(reply)


def test_a_huge_answer_does_not_stall_the_sender(pki):
    big = handler(body=b'x' * 5_000_000)
    server = TLSServer(*pki['files']['leaf'], big)
    try:
        reply = _send(f'https://appliance.internal:{server.port}/upload', ca_pem=pki['ca_pem'])
    finally:
        server.close()
    assert reply.status == 200


# --------------------------------------------------------------------------
# Which address: resolved once, checked, and connected to
# --------------------------------------------------------------------------

def test_the_connection_goes_to_the_address_the_resolver_chose(pki):
    """The name in the URL resolves to nothing real; only the pinned address works."""
    seen = []
    server = TLSServer(*pki['files']['leaf'], handler(record=seen))
    asked = []

    def resolver(host, port, allow_internal):
        asked.append(host)
        return '127.0.0.1'
    try:
        _send(f'https://appliance.internal:{server.port}/upload', ca_pem=pki['ca_pem'], resolver=resolver)
    finally:
        server.close()
    assert asked == ['appliance.internal'], 'the name was resolved more than once'
    assert len(seen) == 1


def test_a_rebind_between_the_check_and_the_connection_cannot_redirect_the_request(pki, monkeypatch):
    """The resolver is asked once; nothing after it resolves the name again."""
    calls = []
    real = socket.getaddrinfo

    def counting(host, *a, **k):
        calls.append(host)
        return real(host, *a, **k)
    monkeypatch.setattr(socket, 'getaddrinfo', counting)
    server = TLSServer(*pki['files']['leaf'], handler())
    try:
        _send(f'https://appliance.internal:{server.port}/upload', ca_pem=pki['ca_pem'])
    finally:
        server.close()
    assert 'appliance.internal' not in calls


# --------------------------------------------------------------------------
# The default resolver: what is allowed to be a destination
# --------------------------------------------------------------------------

@pytest.mark.parametrize('address', [
    '127.0.0.1', '127.1.2.3', '::1', '0.0.0.0', '169.254.169.254', '169.254.0.1', 'fe80::1',
    'fd00:ec2::254', '100.100.100.200', '192.0.0.192', '224.0.0.1', 'ff02::1', '240.0.0.1',
    '::ffff:127.0.0.1', '::ffff:169.254.169.254'])
def test_loopback_link_local_and_metadata_addresses_are_refused_even_when_internal_is_allowed(address):
    assert ph.classify(address) == 'refused'


@pytest.mark.parametrize('address', [
    '10.1.2.3', '172.16.0.9', '192.168.1.50', 'fd12:3456::1', '100.64.0.7', '::ffff:10.0.0.1'])
def test_private_addresses_are_internal(address):
    assert ph.classify(address) == 'internal'


@pytest.mark.parametrize('address', ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111', '93.184.216.34'])
def test_public_addresses_are_global(address):
    assert ph.classify(address) == 'global'


def _fake_dns(monkeypatch, answers):
    def fake(host, port, *a, **k):
        return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, port))
                for ip in answers]
    monkeypatch.setattr(socket, 'getaddrinfo', fake)


def test_an_internal_destination_needs_the_targets_own_consent(monkeypatch):
    _fake_dns(monkeypatch, ['10.0.0.5'])
    with pytest.raises(ph.UnsafeDestination) as refused:
        ph.resolve('appliance.lan', 443, allow_internal=False)
    assert 'allow_internal' in str(refused.value)
    assert ph.resolve('appliance.lan', 443, allow_internal=True) == '10.0.0.5'


def test_a_public_destination_needs_no_consent(monkeypatch):
    _fake_dns(monkeypatch, ['93.184.216.34'])
    assert ph.resolve('api.example.com', 443, allow_internal=False) == '93.184.216.34'


def test_one_refused_answer_spoils_the_whole_set(monkeypatch):
    """A dual record cannot smuggle a metadata address past a check of the first."""
    _fake_dns(monkeypatch, ['93.184.216.34', '169.254.169.254'])
    with pytest.raises(ph.UnsafeDestination):
        ph.resolve('api.example.com', 443, allow_internal=True)


def test_loopback_is_refused_by_name_too(monkeypatch):
    _fake_dns(monkeypatch, ['127.0.0.1'])
    with pytest.raises(ph.UnsafeDestination):
        ph.resolve('localhost', 443, allow_internal=True)


def test_an_address_literal_in_the_url_is_classified_without_asking_dns(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *a, **k: pytest.fail('DNS was asked'))
    with pytest.raises(ph.UnsafeDestination):
        ph.resolve('169.254.169.254', 443, allow_internal=True)
    assert ph.resolve('10.0.0.5', 443, allow_internal=True) == '10.0.0.5'


def test_a_name_that_does_not_resolve_is_a_refusal_not_a_crash(monkeypatch):
    def nothing(*a, **k):
        raise socket.gaierror('no such host')
    monkeypatch.setattr(socket, 'getaddrinfo', nothing)
    with pytest.raises(ph.UnsafeDestination):
        ph.resolve('nowhere.invalid', 443, allow_internal=True)


def test_the_default_send_uses_the_default_resolver():
    """Loopback, asked for through the normal path, is refused: no resolver is injected."""
    with pytest.raises(ph.UnsafeDestination):
        ph.send('https://127.0.0.1:1/upload', method='POST', body=b'x', headers={}, timeout=2)
