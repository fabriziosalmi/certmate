"""Tests for the deprecated-TLS probe (``modules/core/weak_tls.py``).

This check is the easiest one in the project to write so that it can never
find anything, and the tests are shaped around that. A modern OpenSSL build
often refuses to *offer* TLS 1.0/1.1 at all — the handshake fails on this
machine, before a byte leaves it — and a probe that reads that as "the server
said no" reports a clean estate having asked nothing. So most of what is
pinned here is the difference between the host declining and this process
being unable to ask.

Everything runs offline: the probe is injected. One test is marked ``network``
and offers a real TLS 1.0 handshake to a server that exists to accept one,
because a probe nobody has ever seen succeed is not evidence of anything.
"""
import socket
import ssl

import pytest

from modules.core import domain_health as dh
from modules.core import weak_tls as wt

pytestmark = [pytest.mark.unit]

BOTH_OFFERABLE = {'TLSv1': True, 'TLSv1_1': True}


def _prober(answers, default=wt.REFUSED):
    """A probe over ``{version_name: verdict}``."""
    asked = []

    def prober(host, version_name):
        asked.append((host, version_name))
        return answers.get(version_name, default)

    prober.asked = asked
    return prober


# --------------------------------------------------------------------------- #
# What the host said
# --------------------------------------------------------------------------- #

def test_a_host_that_refuses_both_is_ok():
    result = wt.check('example.com', prober=_prober({}), capability=dict(BOTH_OFFERABLE))
    assert result['status'] == dh.OK
    assert result['refused'] == ['TLS 1.0', 'TLS 1.1']
    assert result['accepted'] == []


def test_a_host_that_accepts_tls_1_0_is_a_finding():
    result = wt.check('example.com', prober=_prober({'TLSv1': wt.ACCEPTED}),
                      capability=dict(BOTH_OFFERABLE))
    assert result['status'] == dh.FAILING
    assert result['accepted'] == ['TLS 1.0']
    assert 'RFC 8996' in result['detail']


def test_a_host_that_accepts_tls_1_1_is_a_finding():
    result = wt.check('example.com', prober=_prober({'TLSv1_1': wt.ACCEPTED}),
                      capability=dict(BOTH_OFFERABLE))
    assert result['status'] == dh.FAILING
    assert result['accepted'] == ['TLS 1.1']


def test_a_host_that_accepts_both_names_both():
    result = wt.check('example.com', prober=_prober({}, default=wt.ACCEPTED),
                      capability=dict(BOTH_OFFERABLE))
    assert result['status'] == dh.FAILING
    assert result['accepted'] == ['TLS 1.0', 'TLS 1.1']


def test_both_versions_are_offered_not_just_one():
    prober = _prober({})
    wt.check('example.com', prober=prober, capability=dict(BOTH_OFFERABLE))
    assert prober.asked == [('example.com', 'TLSv1'), ('example.com', 'TLSv1_1')]


# --------------------------------------------------------------------------- #
# When nothing was established — the whole point of the module
# --------------------------------------------------------------------------- #

def test_a_build_that_cannot_offer_anything_reports_unknown_not_clean():
    """The defect this module exists to avoid. With both offers impossible,
    every handshake fails on this machine, and 'refuses old TLS' would be this
    process's silence reported as the host's answer."""
    result = wt.check('example.com', prober=_prober({}),
                      capability={'TLSv1': False, 'TLSv1_1': False})
    assert result['status'] == dh.UNKNOWN
    assert result['refused'] == []
    assert len(result['unasked']) == 2
    assert 'cannot offer it' in result['unasked'][0]


def test_a_build_that_cannot_offer_never_touches_the_network():
    prober = _prober({})
    wt.check('example.com', prober=prober,
             capability={'TLSv1': False, 'TLSv1_1': False})
    assert prober.asked == []


def test_an_unreachable_host_reports_unknown_not_clean():
    result = wt.check('example.com', prober=_prober({}, default=wt.UNAVAILABLE),
                      capability=dict(BOTH_OFFERABLE))
    assert result['status'] == dh.UNKNOWN
    assert 'could not be reached' in result['unasked'][0]


def test_one_version_unaskable_still_reports_what_the_other_said():
    result = wt.check('example.com', prober=_prober({}),
                      capability={'TLSv1': True, 'TLSv1_1': False})
    assert result['status'] == dh.OK
    assert result['refused'] == ['TLS 1.0']
    assert len(result['unasked']) == 1
    assert 'could not be asked' in result['detail']


def test_an_acceptance_outweighs_a_version_that_could_not_be_asked():
    result = wt.check('example.com', prober=_prober({'TLSv1': wt.ACCEPTED}),
                      capability={'TLSv1': True, 'TLSv1_1': False})
    assert result['status'] == dh.FAILING


def test_the_capability_is_established_once_and_shared():
    """It is a fact about the runtime, identical for every host, and each
    answer costs a handshake attempt."""
    calls = []
    original = wt.can_offer

    def counted(version_name):
        calls.append(version_name)
        return original(version_name)

    shared = {}
    try:
        wt.can_offer = counted
        for host in ('a.example', 'b.example', 'c.example'):
            wt.check(host, prober=_prober({}), capability=shared)
    finally:
        wt.can_offer = original
    assert calls == ['TLSv1', 'TLSv1_1']


def test_without_a_shared_dict_each_call_stands_alone():
    result = wt.check('example.com', prober=_prober({}))
    assert result['status'] in (dh.OK, dh.UNKNOWN)


# --------------------------------------------------------------------------- #
# Can this build make the offer at all?
# --------------------------------------------------------------------------- #

def test_this_build_can_offer_both_old_versions():
    """Not a property of the code — a property of the OpenSSL underneath it.
    If this fails, the check is honest but useless here, and the `unknown`
    above is what CI would report."""
    assert wt.can_offer('TLSv1') is True
    assert wt.can_offer('TLSv1_1') is True


def test_a_version_this_build_does_not_know_cannot_be_offered():
    assert wt.can_offer('TLSv1_7') is False


def test_a_build_that_refuses_the_cipher_list_cannot_offer(monkeypatch):
    """Security level 2 excludes every cipher TLS 1.0 can use, and then
    set_ciphers raises before anything is sent."""
    real = ssl.SSLContext.set_ciphers

    def refuse(self, spec):
        raise ssl.SSLError('no cipher match')

    monkeypatch.setattr(ssl.SSLContext, 'set_ciphers', refuse)
    assert wt.can_offer('TLSv1') is False
    monkeypatch.setattr(ssl.SSLContext, 'set_ciphers', real)


def test_a_build_that_produces_no_client_hello_cannot_offer(monkeypatch):
    """MinProtocol in openssl.cnf: configuration succeeds, and then nothing
    goes on the wire."""
    class Silent:
        def __init__(self, *a, **k):
            pass

        def read(self, *a):
            return b''

        def write(self, *a):
            return 0

    monkeypatch.setattr(wt.ssl, 'MemoryBIO', Silent)
    monkeypatch.setattr(ssl.SSLContext, 'wrap_bio',
                        lambda self, i, o, **kw: type('H', (), {
                            'do_handshake': lambda s: None})())
    assert wt.can_offer('TLSv1') is False


def test_a_build_that_raises_while_starting_the_handshake_cannot_offer(monkeypatch):
    def explode(self, incoming, outgoing, **kwargs):
        raise ssl.SSLError('NO_PROTOCOLS_AVAILABLE')

    monkeypatch.setattr(ssl.SSLContext, 'wrap_bio', explode)
    assert wt.can_offer('TLSv1') is False


def test_checking_the_capability_opens_no_socket(monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError('can_offer must not touch the network')

    monkeypatch.setattr(wt.socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    assert wt.can_offer('TLSv1') is True


# --------------------------------------------------------------------------- #
# The probe itself
# --------------------------------------------------------------------------- #

class _Socket:
    def __init__(self, connect_error=None):
        self._connect_error = connect_error
        self.closed = False
        self.timeout = None

    def settimeout(self, t):
        self.timeout = t

    def connect(self, addr):
        if self._connect_error:
            raise self._connect_error

    def close(self):
        self.closed = True


@pytest.fixture
def scripted(monkeypatch):
    state = {'socket': _Socket(), 'wrap': None, 'guard': (2, '192.0.2.13', None),
             'sni': []}
    monkeypatch.setattr('modules.core.cert_probe._resolve_and_guard',
                        lambda host, port, allow_private: state['guard'])
    monkeypatch.setattr(wt.socket, 'socket', lambda f, t: state['socket'])

    def wrap_socket(self, sock, server_hostname=None):
        state['sni'].append(server_hostname)
        outcome = state['wrap']
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', wrap_socket)
    return state


class _Tls:
    def __init__(self, version):
        self._version = version

    def version(self):
        return self._version

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_a_completed_handshake_is_an_acceptance(scripted):
    scripted['wrap'] = _Tls('TLSv1')
    assert wt.probe('example.com', 'TLSv1') == wt.ACCEPTED


def test_an_alert_after_the_connection_opened_is_a_refusal(scripted):
    scripted['wrap'] = ssl.SSLError('TLSV1_ALERT_PROTOCOL_VERSION')
    assert wt.probe('example.com', 'TLSv1') == wt.REFUSED


def test_a_reset_after_the_connection_opened_is_also_a_refusal(scripted):
    """Plenty of servers drop the connection instead of sending an alert;
    both mean the same thing, and neither is an acceptance."""
    scripted['wrap'] = ConnectionResetError('peer reset')
    assert wt.probe('example.com', 'TLSv1') == wt.REFUSED


def test_a_connection_that_never_opened_has_declined_nothing(scripted):
    scripted['socket'] = _Socket(connect_error=ConnectionRefusedError('closed'))
    assert wt.probe('example.com', 'TLSv1') == wt.UNAVAILABLE


def test_a_timeout_connecting_is_unavailable_not_refused(scripted):
    scripted['socket'] = _Socket(connect_error=socket.timeout('too slow'))
    assert wt.probe('example.com', 'TLSv1') == wt.UNAVAILABLE


def test_the_ssrf_guard_refusing_makes_it_unavailable(scripted):
    scripted['guard'] = (None, None, 'target refused by SSRF guard: loopback')
    assert wt.probe('internal.example.com', 'TLSv1') == wt.UNAVAILABLE


def test_the_probe_carries_the_name_as_sni(scripted):
    scripted['wrap'] = _Tls('TLSv1')
    wt.probe('example.com', 'TLSv1')
    assert scripted['sni'] == ['example.com']


def test_the_socket_is_closed_even_when_the_handshake_fails(scripted):
    scripted['wrap'] = ssl.SSLError('nope')
    wt.probe('example.com', 'TLSv1')
    assert scripted['socket'].closed is True


def test_a_version_this_build_cannot_configure_is_unavailable(scripted):
    assert wt.probe('example.com', 'TLSv1_7') == wt.UNAVAILABLE


def test_the_context_pins_the_version_at_both_ends(scripted):
    """Only a maximum keeps a modern host from negotiating TLS 1.3 and being
    reported as accepting TLS 1.0."""
    import ssl as _ssl
    context = wt._context('TLSv1')
    assert context.minimum_version == _ssl.TLSVersion.TLSv1
    assert context.maximum_version == _ssl.TLSVersion.TLSv1


def test_a_handshake_that_negotiated_a_modern_version_is_not_an_acceptance(scripted):
    """The failure a missing maximum_version would cause, asserted on the
    outcome rather than on the configuration: a completed handshake is only an
    acceptance when it completed at the version that was offered."""
    scripted['wrap'] = _Tls('TLSv1.3')
    assert wt.probe('example.com', 'TLSv1') == wt.REFUSED


def test_an_acceptance_must_be_at_the_version_offered(scripted):
    scripted['wrap'] = _Tls('TLSv1.1')
    assert wt.probe('example.com', 'TLSv1') == wt.REFUSED
    assert wt.probe('example.com', 'TLSv1_1') == wt.ACCEPTED


def test_a_handshake_reporting_no_version_is_not_an_acceptance(scripted):
    scripted['wrap'] = _Tls(None)
    assert wt.probe('example.com', 'TLSv1') == wt.REFUSED


# --------------------------------------------------------------------------- #
# Wired into the sweep
# --------------------------------------------------------------------------- #

def test_the_check_does_not_run_unless_it_is_asked_for():
    checks = dh.check_name('example.com', lookups=(lambda n: [],) * 4,
                           mail=False, blocklists=False, headers=False)
    assert checks == {}


def test_the_check_appears_when_it_is_asked_for():
    checks = dh.check_name(
        'example.com', lookups=(lambda n: [],) * 4, mail=False, blocklists=False,
        headers=False, weak_tls=True, tls_capability=dict(BOTH_OFFERABLE),
        weak_tls_prober=_prober({}))
    assert set(checks) == {'weak_tls'}
    assert checks['weak_tls']['status'] == dh.OK


def test_an_accepted_old_version_makes_the_whole_name_failing():
    checks = dh.check_name(
        'example.com', lookups=(lambda n: [],) * 4, mail=False, blocklists=False,
        headers=False, weak_tls=True, tls_capability=dict(BOTH_OFFERABLE),
        weak_tls_prober=_prober({'TLSv1': wt.ACCEPTED}))
    assert dh.worst_status(checks) == dh.FAILING


# --------------------------------------------------------------------------- #
# Against a server that really does accept TLS 1.0
# --------------------------------------------------------------------------- #

@pytest.mark.network
def test_a_real_server_that_accepts_tls_1_0_is_detected():
    """badssl.com runs endpoints whose whole purpose is to accept a
    deprecated version. A probe nobody has ever seen succeed proves nothing,
    so this one is run for real — and it is what showed the probe works at
    all, rather than failing identically everywhere."""
    verdict = wt.probe('tls-v1-0.badssl.com', 'TLSv1', port=1010)
    assert verdict == wt.ACCEPTED, (
        'the probe could not complete a TLS 1.0 handshake against a server '
        'that exists to accept one, so every "refused" it reports elsewhere '
        'may be this machine refusing instead'
    )


@pytest.mark.network
def test_a_modern_server_refuses_both():
    result = wt.check('github.com')
    assert result['status'] == dh.OK
    assert result['refused'] == ['TLS 1.0', 'TLS 1.1']


def test_a_socket_that_cannot_even_be_created_is_unavailable(scripted, monkeypatch):
    """Out of file descriptors, or a family the host stack refuses. Nothing
    was asked, so nothing is known."""
    def refuse(family, type_):
        raise OSError('too many open files')

    monkeypatch.setattr(wt.socket, 'socket', refuse)
    assert wt.probe('example.com', 'TLSv1') == wt.UNAVAILABLE


def test_a_socket_that_fails_to_close_does_not_lose_the_verdict(scripted):
    """The verdict is already decided by then; a close that raises must not
    turn an answer into an exception the sweep has to absorb."""
    class Awkward(_Socket):
        def close(self):
            raise OSError('already gone')

    scripted['socket'] = Awkward()
    scripted['wrap'] = _Tls('TLSv1')
    assert wt.probe('example.com', 'TLSv1') == wt.ACCEPTED
