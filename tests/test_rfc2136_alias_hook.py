"""rfc2136 DNS-alias hook (CNAME delegation via TSIG dynamic update, #330).

domain_alias mode writes _acme-challenge.<alias> TXT directly into the alias
zone. For rfc2136 that means a dnspython dynamic UPDATE signed with the same
TSIG key used for normal issuance, addressed to the zone discovered by an SOA
walk.
"""
import dns.name
import dns.rcode
import dns.tsig
import pytest

from modules.core import dns_alias_hook
from modules.core.dns_alias_hook import (
    DNSAliasError,
    _rfc2136_change,
    _rfc2136_keyalgorithm,
    _rfc2136_server,
)

pytestmark = [pytest.mark.unit]


# --- algorithm + server parsing -------------------------------------------

def test_keyalgorithm_default_is_sha512():
    assert _rfc2136_keyalgorithm(None) == dns.tsig.HMAC_SHA512
    assert _rfc2136_keyalgorithm('') == dns.tsig.HMAC_SHA512


@pytest.mark.parametrize('name,expected', [
    ('HMAC-SHA256', dns.tsig.HMAC_SHA256),
    ('hmac-sha512', dns.tsig.HMAC_SHA512),
    ('HMAC-MD5', dns.tsig.HMAC_MD5),
])
def test_keyalgorithm_maps_known(name, expected):
    assert _rfc2136_keyalgorithm(name) == expected


def test_keyalgorithm_rejects_unknown():
    with pytest.raises(DNSAliasError):
        _rfc2136_keyalgorithm('ROT13')


@pytest.mark.parametrize('value,expected', [
    ('ns1.example.com', ('ns1.example.com', 53)),
    ('10.0.0.1', ('10.0.0.1', 53)),
    ('10.0.0.1:5353', ('10.0.0.1', 5353)),
    ('[2001:db8::1]:5353', ('2001:db8::1', 5353)),
    ('[2001:db8::1]', ('2001:db8::1', 53)),
    ('2001:db8::1', ('2001:db8::1', 53)),  # bare IPv6 -> not split into port
])
def test_server_parsing(value, expected):
    assert _rfc2136_server(value) == expected


# --- the update itself ----------------------------------------------------

_CFG = {
    'provider': 'rfc2136',
    'domain_alias': 'validation.example.com',
    'config': {
        'nameserver': '10.0.0.1',
        'tsig_key': 'certmate-key',
        # base64 secret (dnspython requires valid base64)
        'tsig_secret': 'c2VjcmV0LXNlY3JldC1zZWNyZXQ=',
        'tsig_algorithm': 'HMAC-SHA512',
    },
}


@pytest.fixture
def captured_update(monkeypatch):
    """Stub the SOA walk + the wire send; capture the UPDATE message built."""
    monkeypatch.setattr(dns_alias_hook, '_rfc2136_find_zone',
                        lambda *a, **k: dns.name.from_text('example.com.'))
    sent = {}

    class _Resp:
        def __init__(self, rcode):
            self._rcode = rcode

        def rcode(self):
            return self._rcode

    def fake_tcp(message, host, port=53, timeout=None):
        sent['message'] = message
        sent['host'] = host
        sent['port'] = port
        return _Resp(sent.get('rcode', dns.rcode.NOERROR))

    import dns.query
    monkeypatch.setattr(dns.query, 'tcp', fake_tcp)
    return sent


def test_create_builds_tsig_update_to_alias_record(captured_update):
    _rfc2136_change(_CFG, 'validation-token-123', 'create')

    assert captured_update['host'] == '10.0.0.1'
    assert captured_update['port'] == 53
    msg = captured_update['message']
    # Signed with TSIG, addressed to the discovered zone.
    assert msg.keyname is not None
    assert msg.origin == dns.name.from_text('example.com.')
    rendered = msg.to_text()
    assert '_acme-challenge.validation' in rendered
    assert 'TXT' in rendered
    assert 'validation-token-123' in rendered


def test_delete_uses_delete_action(captured_update):
    _rfc2136_change(_CFG, 'validation-token-123', 'delete')
    rendered = captured_update['message'].to_text()
    assert '_acme-challenge.validation' in rendered
    # a delete carries the record in the update section with TTL 0 / NONE class
    assert 'TXT' in rendered


def test_delete_tolerates_nxrrset(captured_update):
    captured_update['rcode'] = dns.rcode.NXRRSET
    # already-gone on cleanup must not raise
    _rfc2136_change(_CFG, 'validation-token-123', 'delete')


def test_nonzero_rcode_on_create_raises(captured_update):
    captured_update['rcode'] = dns.rcode.REFUSED
    with pytest.raises(DNSAliasError):
        _rfc2136_change(_CFG, 'validation-token-123', 'create')


def test_missing_credentials_raises():
    cfg = {'provider': 'rfc2136', 'domain_alias': 'a.example.com',
           'config': {'nameserver': '10.0.0.1'}}
    with pytest.raises(DNSAliasError):
        _rfc2136_change(cfg, 'v', 'create')


# --- dispatch -------------------------------------------------------------

def test_change_txt_routes_rfc2136(monkeypatch):
    called = {}
    monkeypatch.setattr(dns_alias_hook, '_rfc2136_change',
                        lambda c, v, a: called.update({'v': v, 'a': a}))
    monkeypatch.setenv('CERTBOT_VALIDATION', 'tok')
    dns_alias_hook._change_txt({'provider': 'rfc2136', 'domain_alias': 'x.example.com'}, 'create')
    assert called == {'v': 'tok', 'a': 'create'}
