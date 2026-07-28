"""Tests for the discovery sweep (``modules/core/cert_discovery.py``), #469:

* endpoint spec parsing (host / host:port / IPv6, bracketed and bare),
* the sweep upserts probe results into the inventory,
* managed endpoints are recorded as issued+managed and linked,
* one cert on many endpoints collapses to one inventory record,
* failure isolation: a bad spec / unreachable host / crashing probe never
  aborts the sweep and is reported as a per-endpoint status.
"""

import pytest

from modules.core.cert_discovery import discover_endpoints, parse_endpoint
from modules.core.cert_inventory import CertInventory

pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------- #
# parse_endpoint
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('spec,expected', [
    ('example.com', ('example.com', 443)),
    ('example.com:8443', ('example.com', 8443)),
    ('  example.com : 443 '.replace(' : ', ':').strip(), ('example.com', 443)),
    ('10.0.0.5', ('10.0.0.5', 443)),
    ('10.0.0.5:9443', ('10.0.0.5', 9443)),
    ('2001:db8::1', ('2001:db8::1', 443)),          # bare IPv6 -> default port
    ('[2001:db8::1]', ('2001:db8::1', 443)),
    ('[2001:db8::1]:8443', ('2001:db8::1', 8443)),
    ('::1', ('::1', 443)),
])
def test_parse_endpoint_ok(spec, expected):
    assert parse_endpoint(spec) == expected


@pytest.mark.parametrize('spec', [
    '', '   ', None,
    'example.com:0', 'example.com:70000', 'example.com:abc',
    '[2001:db8::1', '[2001:db8::1]x', ':443',
])
def test_parse_endpoint_invalid(spec):
    with pytest.raises(ValueError):
        parse_endpoint(spec)


# --------------------------------------------------------------------------- #
# fake probe
# --------------------------------------------------------------------------- #

def _ok(host, port, fingerprint='fp', cn=None):
    return {
        'host': host, 'port': port, 'status': 'ok', 'error': None,
        'certificate': {
            'subject_cn': cn or host, 'subject': f'CN={cn or host}',
            'issuer_cn': 'CA', 'issuer': 'CN=CA', 'serial_number': '1',
            'not_before': '2026-01-01T00:00:00Z',
            'not_after': '2026-04-01T00:00:00Z',
            'fingerprint_sha256': fingerprint,
            'key': {'type': 'RSA', 'size': 2048, 'curve': None},
            'signature_algorithm': 'sha256WithRSAEncryption',
            'san_dns': [host],
        },
        'validation': {}, 'chain': [],
    }


class _FakeProbe:
    """A scripted probe: maps host -> result dict (or an exception to raise)."""

    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, host, port=443, timeout=None, allow_private=False):
        self.calls.append((host, port, allow_private))
        outcome = self.mapping.get(host)
        if isinstance(outcome, Exception):
            raise outcome
        if callable(outcome):
            return outcome(host, port)
        return outcome


@pytest.fixture
def inv(tmp_path):
    return CertInventory(tmp_path / 'data')


# --------------------------------------------------------------------------- #
# sweep behaviour
# --------------------------------------------------------------------------- #

def test_sweep_upserts_ok_result(inv):
    probe = _FakeProbe({'a.example.com': _ok('a.example.com', 443, 'fpA')})
    results = discover_endpoints(['a.example.com'], inv, probe=probe)

    assert results[0]['status'] == 'ok'
    assert results[0]['fingerprint'] == 'fpA'
    rec = inv.get('fpA')
    assert rec is not None
    assert rec['source'] == 'probed'
    assert rec['managed'] is False
    assert rec['endpoints'][0] == {
        'host': 'a.example.com', 'port': 443,
        'first_seen': rec['endpoints'][0]['first_seen'],
        'last_seen': rec['endpoints'][0]['last_seen'],
    }


def test_sweep_passes_port_and_allow_private(inv):
    probe = _FakeProbe({'h': _ok('h', 8443)})
    discover_endpoints(['h:8443'], inv, probe=probe, allow_private=True)
    assert probe.calls == [('h', 8443, True)]


def test_managed_endpoint_recorded_as_issued(inv):
    probe = _FakeProbe({'m.example.com': _ok('m.example.com', 443, 'fpM')})
    discover_endpoints(
        ['m.example.com'], inv, probe=probe,
        managed_domains={'m.example.com': 'example.com'},
    )
    rec = inv.get('fpM')
    assert rec['source'] == 'issued'
    assert rec['managed'] is True
    assert rec['managed_domain'] == 'example.com'


def test_managed_lookup_is_case_insensitive(inv):
    probe = _FakeProbe({'M.Example.com': _ok('M.Example.com', 443, 'fpM')})
    discover_endpoints(
        ['M.Example.com'], inv, probe=probe,
        managed_domains={'m.example.com': 'example.com'},
    )
    assert inv.get('fpM')['managed'] is True


def test_one_cert_many_endpoints_collapses(inv):
    # Same fingerprint served on two hosts -> one inventory record, 2 endpoints.
    probe = _FakeProbe({
        'a.example.com': _ok('a.example.com', 443, 'shared'),
        'b.example.com': _ok('b.example.com', 443, 'shared'),
    })
    discover_endpoints(['a.example.com', 'b.example.com'], inv, probe=probe)
    assert inv.count() == 1
    assert len(inv.get('shared')['endpoints']) == 2


def test_invalid_spec_is_isolated(inv):
    probe = _FakeProbe({'good.example.com': _ok('good.example.com', 443, 'fp')})
    results = discover_endpoints(
        ['bad:port', 'good.example.com'], inv, probe=probe)
    statuses = {r['endpoint']: r['status'] for r in results}
    assert statuses['bad:port'] == 'invalid'
    assert statuses['good.example.com'] == 'ok'
    # The good endpoint was still probed and recorded despite the bad one.
    assert inv.count() == 1


def test_unreachable_endpoint_reported_not_recorded(inv):
    probe = _FakeProbe({'down.example.com': {
        'host': 'down.example.com', 'port': 443, 'status': 'unreachable',
        'error': 'connection refused', 'error_class': 'connection_error',
        'certificate': None,
    }})
    results = discover_endpoints(['down.example.com'], inv, probe=probe)
    assert results[0]['status'] == 'unreachable'
    assert results[0]['error'] == 'connection refused'
    assert inv.count() == 0


def test_blocked_endpoint_reported(inv):
    probe = _FakeProbe({'10.0.0.1': {
        'host': '10.0.0.1', 'port': 443, 'status': 'blocked',
        'error': 'target refused by SSRF guard: private address 10.0.0.1',
        'certificate': None,
    }})
    results = discover_endpoints(['10.0.0.1'], inv, probe=probe)
    assert results[0]['status'] == 'blocked'
    assert inv.count() == 0


def test_crashing_probe_is_isolated(inv):
    probe = _FakeProbe({
        'boom.example.com': RuntimeError('kaboom'),
        'ok.example.com': _ok('ok.example.com', 443, 'fp'),
    })
    results = discover_endpoints(
        ['boom.example.com', 'ok.example.com'], inv, probe=probe)
    statuses = {r['endpoint']: r['status'] for r in results}
    assert statuses['boom.example.com'] == 'unreachable'
    assert 'probe error' in [r for r in results
                             if r['endpoint'] == 'boom.example.com'][0]['error']
    # The sweep continued past the crash and recorded the good endpoint.
    assert statuses['ok.example.com'] == 'ok'
    assert inv.count() == 1


def test_empty_endpoint_list(inv):
    assert discover_endpoints([], inv, probe=_FakeProbe({})) == []
    assert inv.count() == 0
