"""Tests for domain registration expiry (``modules/core/domain_registration.py``).

The parsers run against real answers captured from the registries on
2026-09-22 (``tests/fixtures/domain_registration``): Verisign, PIR, Nominet,
AFNIC and Google Registry over RDAP; NIC.it, DENIC and EURid over WHOIS. People's
names and street addresses were replaced with ``REDACTED``; the structure the
parsers read is untouched.

The client, the storage, the sweep and the API are then driven with injected
transports, so nothing here touches the network except the one test marked
``network``, which asks the real registries.
"""
import json
import socket
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from modules.core import domain_registration as dr
from modules.core.cert_inventory import CertInventory
from modules.core.domain_registration import (
    STATUS_NOT_PUBLISHED,
    STATUS_NOT_REGISTERED,
    STATUS_OK,
    STATUS_UNAVAILABLE,
    DomainRegistrationManager,
    LookupError_,
    RegistrationClient,
    is_due,
    parse_rdap,
    parse_whois,
    registrable_domain,
)
from modules.core.inventory_view import build_registrations_view

pytestmark = [pytest.mark.unit]

FIXTURES = Path(__file__).resolve().parent / 'fixtures' / 'domain_registration'


def _rdap(name):
    return json.loads((FIXTURES / f'rdap-{name}.json').read_text(encoding='utf-8'))


def _whois(name):
    return (FIXTURES / f'whois-{name}.txt').read_text(encoding='utf-8')


# --------------------------------------------------------------------------- #
# Registrable domain
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('name, expected', [
    ('www.shop.example.co.uk', 'example.co.uk'),
    ('example.com', 'example.com'),
    ('*.example.it', 'example.it'),
    ('A.B.Example.COM.', 'example.com'),
    ('user.github.io', 'github.io'),      # who registered it at a registry
    ('1.2.3.4', None),
    ('co.uk', None),                       # a bare public suffix
    ('localhost', None),
    ('intranet.corp', None),               # under no public suffix
    ('', None),
    (None, None),
    ('https://example.com/x', None),
])
def test_registrable_domain(name, expected):
    assert registrable_domain(name) == expected


# --------------------------------------------------------------------------- #
# RDAP parsing, on real answers
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('fixture, expires, registrar', [
    ('verisign-google.com', '2028-09-14T04:00:00Z', 'MarkMonitor Inc.'),
    ('pir-wikipedia.org', '2027-01-13T00:12:14Z', 'MarkMonitor Inc.'),
    ('nominet-bbc.co.uk', '2034-12-13T03:49:48Z', 'British Broadcasting Corporation'),
    ('afnic-afnic.fr', '2029-07-18T08:26:59Z', 'Registry Operations'),
    ('google-registry-web.dev', '2026-10-29T15:57:39Z', 'MarkMonitor Inc.'),
])
def test_parse_rdap_real_answers(fixture, expires, registrar):
    parsed = parse_rdap(_rdap(fixture))
    assert parsed['expires_at'] == expires
    assert parsed['registrar'] == registrar
    assert parsed['registry_status']


@pytest.mark.parametrize('payload', [
    {},
    {'events': 'not a list', 'entities': None, 'status': 'active'},
    {'events': [None, 7, 'x', {'eventAction': None}], 'entities': [None, {'roles': 'registrar'}]},
    {'entities': [{'roles': ['registrar'], 'vcardArray': ['vcard', 'broken']}]},
])
def test_parse_rdap_survives_odd_shapes(payload):
    parsed = parse_rdap(payload)
    assert parsed['expires_at'] is None


# --------------------------------------------------------------------------- #
# WHOIS parsing, on real answers
# --------------------------------------------------------------------------- #

def test_whois_it_publishes_expiry_and_registrar():
    status, fields = parse_whois(_whois('nic.it'))
    assert status == STATUS_OK
    assert fields['expires_at'] == '2026-12-31T00:00:00Z'
    assert fields['registrar'] == "ccTLD 'it' Registry"


def test_whois_it_available_is_not_registered():
    status, fields = parse_whois(_whois('notfound.it'))
    assert status == STATUS_NOT_REGISTERED


def test_whois_de_registered_without_expiry_is_not_published():
    """DENIC answers `Status: connect` and nothing about expiry."""
    status, fields = parse_whois(_whois('google.de'))
    assert status == STATUS_NOT_PUBLISHED
    assert fields['expires_at'] is None
    assert fields['registry_status'] == ['connect']


def test_whois_eu_registered_without_expiry_is_not_published():
    status, fields = parse_whois(_whois('google.eu'))
    assert status == STATUS_NOT_PUBLISHED
    assert fields['registrar'] == 'Markmonitor Inc.'


def test_whois_expiry_in_a_form_not_understood_is_refused():
    with pytest.raises(LookupError_, match='unrecognised expiry'):
        parse_whois('Domain: example.xx\nExpiry Date: sometime next spring\n')


def test_whois_answer_about_nothing_is_refused():
    """A rate-limit notice or an error page names no domain; it is not a
    registration without expiry."""
    with pytest.raises(LookupError_):
        parse_whois('Error: too many queries from your IP address, try later\n')


def test_whois_created_date_is_never_taken_for_expiry():
    status, fields = parse_whois('Domain: example.xx\nCreated: 2020-01-01\nStatus: ok\n')
    assert status == STATUS_NOT_PUBLISHED


@pytest.mark.parametrize('raw, expected', [
    ('2026-12-31', '2026-12-31T00:00:00Z'),
    ('2028-09-14T04:00:00Z', '2028-09-14T04:00:00Z'),
    ('2026-10-29T15:57:39.435Z', '2026-10-29T15:57:39Z'),
    ('2027-01-13 00:12:14', '2027-01-13T00:12:14Z'),
    ('2027.03.01', '2027-03-01T00:00:00Z'),
    ('01.03.2027', '2027-03-01T00:00:00Z'),
    ('13-Jan-2027', '2027-01-13T00:00:00Z'),
    ('2027-01-13T02:12:14+02:00', '2027-01-13T00:12:14Z'),
    ('not a date', None),
    ('', None),
])
def test_dates_are_normalised_to_utc(raw, expected):
    assert dr._normalise_date(raw) == expected


# --------------------------------------------------------------------------- #
# The client: routing, failures, caching
# --------------------------------------------------------------------------- #

BOOTSTRAP = {'services': [
    [['com', 'net'], ['https://rdap.verisign.example/com/v1/']],
    [['uk'], ['https://rdap.nominet.example/uk/']],
    [['plain'], ['http://insecure.example/']],        # must be ignored
]}


class _Transports:
    """Scripted RDAP + WHOIS answers, recording what was asked."""

    def __init__(self, rdap=None, whois=None, bootstrap=BOOTSTRAP, bootstrap_status=200):
        self.rdap = rdap or {}
        self.whois_answers = whois or {}
        self.bootstrap = bootstrap
        self.bootstrap_status = bootstrap_status
        self.http_calls, self.whois_calls = [], []

    def http_get(self, url, *, timeout):
        self.http_calls.append(url)
        if url == dr.BOOTSTRAP_URL:
            if isinstance(self.bootstrap_status, Exception):
                raise self.bootstrap_status
            return self.bootstrap_status, self.bootstrap
        answer = self.rdap.get(url, (404, None))
        if isinstance(answer, Exception):
            raise answer
        return answer

    def whois(self, server, query, *, timeout):
        self.whois_calls.append((server, query))
        answer = self.whois_answers.get((server, query))
        if answer is None:
            raise LookupError_(f'{server} timed out')
        return answer


def _client(transports, tmp_path=None, clock=None):
    return RegistrationClient(tmp_path, http_get=transports.http_get,
                              whois=transports.whois, clock=clock or (lambda: 1_000_000.0))


def test_rdap_tld_is_asked_over_rdap():
    t = _Transports(rdap={'https://rdap.verisign.example/com/v1/domain/google.com':
                          (200, _rdap('verisign-google.com'))})
    r = _client(t).lookup('google.com')
    assert (r['status'], r['source'], r['expires_at']) == (STATUS_OK, 'rdap', '2028-09-14T04:00:00Z')
    assert t.whois_calls == []


def test_tld_without_rdap_goes_to_the_whois_server_iana_names():
    t = _Transports(whois={
        ('whois.iana.org', 'it'): _whois('iana-it'),
        ('whois.nic.it', 'nic.it'): _whois('nic.it'),
        ('whois.nic.it', 'other.it'): _whois('notfound.it'),
    })
    client = _client(t)
    assert client.lookup('nic.it')['status'] == STATUS_OK
    assert client.lookup('other.it')['status'] == STATUS_NOT_REGISTERED
    # IANA is asked once per TLD, not once per domain.
    assert [c for c in t.whois_calls if c[0] == 'whois.iana.org'] == [('whois.iana.org', 'it')]


def test_rdap_404_is_not_registered():
    assert _client(_Transports()).lookup('nothing-here.com')['status'] == STATUS_NOT_REGISTERED


def test_rdap_rate_limit_is_unavailable_and_says_so():
    t = _Transports(rdap={'https://rdap.verisign.example/com/v1/domain/busy.com': (429, None)})
    r = _client(t).lookup('busy.com')
    assert r['status'] == STATUS_UNAVAILABLE
    assert '429' in r['error']


def test_rdap_server_error_is_unavailable():
    t = _Transports(rdap={'https://rdap.verisign.example/com/v1/domain/x.com': (503, None)})
    assert _client(t).lookup('x.com')['status'] == STATUS_UNAVAILABLE


def test_rdap_answer_without_expiry_is_not_published():
    payload = _rdap('verisign-google.com')
    payload['events'] = [e for e in payload['events'] if e['eventAction'] != 'expiration']
    t = _Transports(rdap={'https://rdap.verisign.example/com/v1/domain/google.com': (200, payload)})
    assert _client(t).lookup('google.com')['status'] == STATUS_NOT_PUBLISHED


def test_a_transport_failure_never_raises_out_of_lookup():
    t = _Transports(rdap={'https://rdap.verisign.example/com/v1/domain/x.com':
                          LookupError_('ConnectionError fetching ...')})
    r = _client(t).lookup('x.com')
    assert r['status'] == STATUS_UNAVAILABLE
    assert 'ConnectionError' in r['error']


def test_whois_failure_is_unavailable():
    t = _Transports(whois={('whois.iana.org', 'it'): _whois('iana-it')})
    r = _client(t).lookup('nic.it')
    assert r['status'] == STATUS_UNAVAILABLE
    assert 'timed out' in r['error']


def test_tld_with_neither_rdap_nor_whois_is_unavailable():
    t = _Transports(whois={('whois.iana.org', 'zz'): 'domain: ZZ\nstatus: ACTIVE\n'})
    r = _client(t).lookup('example.zz')
    assert r['status'] == STATUS_UNAVAILABLE
    assert 'neither an RDAP service' in r['error']


def test_plain_http_rdap_servers_are_ignored():
    t = _Transports(whois={('whois.iana.org', 'plain'): 'whois: whois.plain.example\n',
                           ('whois.plain.example', 'x.plain'): 'Domain: x.plain\nStatus: ok\n'})
    r = _client(t).lookup('x.plain')
    assert r['source'] == 'whois'
    assert not any(u.startswith('http://') for u in t.http_calls)


def test_bootstrap_is_cached_on_disk_and_reused(tmp_path):
    t = _Transports()
    now = [1_000_000.0]
    _client(t, tmp_path, clock=lambda: now[0]).lookup('a.com')
    assert t.http_calls.count(dr.BOOTSTRAP_URL) == 1
    # A new client (a restart) within a day reads the disk copy.
    _client(t, tmp_path, clock=lambda: now[0] + 3600).lookup('b.com')
    assert t.http_calls.count(dr.BOOTSTRAP_URL) == 1


def test_stale_bootstrap_is_used_when_iana_is_unreachable(tmp_path):
    good = _Transports()
    _client(good, tmp_path, clock=lambda: 1_000_000.0).lookup('a.com')
    down = _Transports(bootstrap_status=LookupError_('iana down'),
                       rdap={'https://rdap.verisign.example/com/v1/domain/b.com':
                             (200, _rdap('verisign-google.com'))})
    r = _client(down, tmp_path, clock=lambda: 1_000_000.0 + 3 * 86400).lookup('b.com')
    assert r['status'] == STATUS_OK


def test_no_bootstrap_at_all_is_unavailable(tmp_path):
    t = _Transports(bootstrap_status=LookupError_('iana down'))
    r = _client(t, tmp_path).lookup('a.com')
    assert r['status'] == STATUS_UNAVAILABLE
    assert 'iana down' in r['error']


def test_http_transport_refuses_plain_http():
    with pytest.raises(LookupError_, match='non-https'):
        dr.http_get_json('http://rdap.example/domain/x.com', timeout=1)


# --------------------------------------------------------------------------- #
# The WHOIS transport itself
# --------------------------------------------------------------------------- #

def _whois_server(answer):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('127.0.0.1', 0))
    srv.listen(1)
    received = []

    def serve():
        conn, _ = srv.accept()
        with conn:
            received.append(conn.recv(256))
            conn.sendall(answer)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], received


def test_whois_transport_refuses_a_private_server():
    with pytest.raises(LookupError_, match='SSRF guard'):
        dr.whois_query('127.0.0.1', 'example.it', timeout=2)


def test_whois_transport_talks_port_43_protocol(monkeypatch):
    port, received = _whois_server(_whois('nic.it').encode())
    real_connect = socket.socket.connect
    monkeypatch.setattr(socket.socket, 'connect',
                        lambda self, addr: real_connect(self, (addr[0], port)))
    answer = dr.whois_query('127.0.0.1', 'nic.it', timeout=5, allow_private=True)
    assert 'Expire Date:        2026-12-31' in answer
    assert received == [b'nic.it\r\n']


def test_whois_transport_caps_the_answer(monkeypatch):
    port, _ = _whois_server(b'x' * (dr.MAX_WHOIS_BYTES + 10))
    real_connect = socket.socket.connect
    monkeypatch.setattr(socket.socket, 'connect',
                        lambda self, addr: real_connect(self, (addr[0], port)))
    with pytest.raises(LookupError_, match='more than'):
        dr.whois_query('127.0.0.1', 'x.it', timeout=5, allow_private=True)


# --------------------------------------------------------------------------- #
# Storage (inventory schema v3)
# --------------------------------------------------------------------------- #

def _result(domain, status=STATUS_OK, expires='2027-01-01T00:00:00Z', **kw):
    base = {'domain': domain, 'status': status, 'expires_at': expires,
            'registrar': 'Reg', 'registry_status': ['ok'], 'source': 'rdap',
            'error': None, 'checked_at': '2026-09-22T00:00:00Z'}
    base.update(kw)
    return base


def test_registration_round_trip(tmp_path):
    inv = CertInventory(tmp_path / 'data')
    inv.record_registration(_result('Example.COM'))
    stored = inv.get_registration('example.com')
    assert stored['expires_at'] == '2027-01-01T00:00:00Z'
    assert stored['registry_status'] == ['ok']


def test_a_failed_lookup_keeps_the_known_expiry(tmp_path):
    inv = CertInventory(tmp_path / 'data')
    inv.record_registration(_result('example.com'))
    inv.record_registration(_result('example.com', status=STATUS_UNAVAILABLE, expires=None,
                                    registrar=None, error='timed out',
                                    checked_at='2026-09-23T00:00:00Z'))
    stored = inv.get_registration('example.com')
    assert stored['status'] == STATUS_UNAVAILABLE
    assert stored['error'] == 'timed out'
    assert stored['expires_at'] == '2027-01-01T00:00:00Z'
    assert stored['registrar'] == 'Reg'
    assert stored['checked_at'] == '2026-09-23T00:00:00Z'


def test_a_renewed_registration_replaces_the_old_date(tmp_path):
    inv = CertInventory(tmp_path / 'data')
    inv.record_registration(_result('example.com'))
    inv.record_registration(_result('example.com', expires='2028-01-01T00:00:00Z'))
    assert inv.get_registration('example.com')['expires_at'] == '2028-01-01T00:00:00Z'


def test_list_is_soonest_first_and_unknown_last(tmp_path):
    inv = CertInventory(tmp_path / 'data')
    inv.record_registration(_result('late.com', expires='2030-01-01T00:00:00Z'))
    inv.record_registration(_result('unknown.de', status=STATUS_NOT_PUBLISHED, expires=None))
    inv.record_registration(_result('soon.com', expires='2026-10-01T00:00:00Z'))
    assert [r['domain'] for r in inv.list_registrations()] == ['soon.com', 'late.com', 'unknown.de']


def test_prune_forgets_untracked_domains(tmp_path):
    inv = CertInventory(tmp_path / 'data')
    for d in ('a.com', 'b.com', 'c.com'):
        inv.record_registration(_result(d))
    assert inv.prune_registrations(['a.com', 'C.com']) == 1
    assert [r['domain'] for r in inv.list_registrations()] == ['a.com', 'c.com']


def test_v2_database_gains_the_registrations_table(tmp_path):
    import sqlite3
    from modules.core import cert_inventory
    inv_dir = tmp_path / 'data' / 'inventory'
    inv_dir.mkdir(parents=True)
    conn = sqlite3.connect(str(inv_dir / 'inventory.db'))
    conn.executescript(cert_inventory._SCHEMA)
    for name, sql_type in cert_inventory._REVOCATION_COLUMNS:
        conn.execute(f'ALTER TABLE certificates ADD COLUMN {name} {sql_type}')
    conn.execute('PRAGMA user_version = 2')
    conn.commit()
    conn.close()
    inv = CertInventory(tmp_path / 'data')
    inv.record_registration(_result('example.com'))
    assert inv.get_registration('example.com') is not None
    CertInventory(tmp_path / 'data')  # reopening is harmless


# --------------------------------------------------------------------------- #
# When to ask again
# --------------------------------------------------------------------------- #

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=timezone.utc)


def _stored(checked_hours_ago, status=STATUS_OK, expires_in_days=365):
    return {'status': status,
            'checked_at': (NOW - timedelta(hours=checked_hours_ago)).isoformat(),
            'expires_at': (NOW + timedelta(days=expires_in_days)).isoformat()
            if expires_in_days is not None else None}


def test_is_due_rules():
    assert is_due(None, NOW)
    assert not is_due(_stored(24 * 6), NOW)                 # far expiry: weekly
    assert is_due(_stored(24 * 7), NOW)
    assert not is_due(_stored(20, expires_in_days=40), NOW)  # expiring: daily
    assert is_due(_stored(24, expires_in_days=40), NOW)
    assert not is_due(_stored(5, status=STATUS_UNAVAILABLE), NOW)
    assert is_due(_stored(6, status=STATUS_UNAVAILABLE), NOW)
    assert not is_due(_stored(24, status=STATUS_NOT_PUBLISHED, expires_in_days=None), NOW)


# --------------------------------------------------------------------------- #
# The sweep
# --------------------------------------------------------------------------- #

class _Settings:
    def __init__(self, data):
        self.data = data

    def load_settings(self):
        return self.data

    def update(self, fn, _reason):
        fn(self.data)


class _Client:
    def __init__(self):
        self.asked = []

    def lookup(self, domain):
        self.asked.append(domain)
        return _result(domain, checked_at=NOW.isoformat().replace('+00:00', 'Z'))


def _manager(tmp_path, settings, client=None):
    inv = CertInventory(tmp_path / 'data')
    sleeps = []
    mgr = DomainRegistrationManager(_Settings(settings), inv, tmp_path / 'certs',
                                    client=client or _Client(), sleep=sleeps.append,
                                    now=lambda: NOW)
    mgr.sleeps = sleeps
    return mgr, inv


def test_tracked_set_reduces_every_source_to_registrable_domains(tmp_path):
    certs = tmp_path / 'certs'
    (certs / 'app.example.com').mkdir(parents=True)
    (certs / 'app.example.com' / 'cert.pem').write_text('x')  # what marks a real cert dir (#99)
    (certs / 'app.example.com' / 'metadata.json').write_text(json.dumps(
        {'san_domains': ['www.example.com', 'shop.example.org']}))
    settings = {'domains': ['api.example.com', {'domain': 'b.example.co.uk'}],
                'domain_registration': {'enabled': True, 'extra_domains': ['brand.it']}}
    mgr, inv = _manager(tmp_path, settings)
    inv.record_certificate({'fingerprint_sha256': 'f', 'subject_cn': 'cdn.partner.net',
                            'san_dns': ['*.partner.net', '10.0.0.1']}, source='probed')
    assert mgr.tracked_domains() == ['brand.it', 'example.co.uk', 'example.com',
                                     'example.org', 'partner.net']
    mgr.save_config({'enabled': True, 'include_inventory': False, 'extra_domains': []})
    assert 'partner.net' not in mgr.tracked_domains()


def test_disabled_sweep_asks_nothing(tmp_path):
    client = _Client()
    mgr, _ = _manager(tmp_path, {'domains': ['a.example.com']}, client)
    assert mgr.run_check()['skipped'] is True
    assert client.asked == []


def test_sweep_asks_only_what_is_due_and_paces_itself(tmp_path):
    client = _Client()
    settings = {'domains': ['a.one.com', 'b.two.com', 'c.three.com'],
                'domain_registration': {'enabled': True}}
    mgr, inv = _manager(tmp_path, settings, client)
    inv.record_registration(_result('two.com', checked_at=NOW.isoformat()))  # fresh
    out = mgr.run_check()
    assert sorted(client.asked) == ['one.com', 'three.com']
    assert mgr.sleeps == [dr.LOOKUP_INTERVAL_SECONDS]  # between lookups, not before the first
    assert out['summary'] == {'tracked': 3, 'looked_up': 2, 'deferred': 0, 'forgotten': 0}


def test_sweep_defers_beyond_its_budget(tmp_path):
    client = _Client()
    settings = {'domains': [f'h.d{i}.com' for i in range(5)], 'domain_registration': {'enabled': True}}
    mgr, _ = _manager(tmp_path, settings, client)
    out = mgr.run_check(max_lookups=2)
    assert len(client.asked) == 2
    assert out['summary']['deferred'] == 3


def test_sweep_forgets_domains_no_longer_tracked(tmp_path):
    settings = {'domains': ['a.keep.com'], 'domain_registration': {'enabled': True}}
    mgr, inv = _manager(tmp_path, settings)
    inv.record_registration(_result('gone.com'))
    out = mgr.run_check()
    assert out['summary']['forgotten'] == 1
    assert [r['domain'] for r in inv.list_registrations()] == ['keep.com']


def test_config_rejects_a_name_no_registry_holds(tmp_path):
    mgr, _ = _manager(tmp_path, {})
    with pytest.raises(ValueError, match='no registry holds it'):
        mgr.save_config({'extra_domains': ['intranet.corp']})


# --------------------------------------------------------------------------- #
# The view
# --------------------------------------------------------------------------- #

def test_view_counts_only_published_dates():
    now = datetime(2026, 9, 22)
    view = build_registrations_view([
        {'domain': 'a.com', 'status': 'ok', 'expires_at': '2026-10-10T00:00:00Z'},
        {'domain': 'b.com', 'status': 'ok', 'expires_at': '2026-09-01T00:00:00Z'},
        {'domain': 'c.de', 'status': 'not_published', 'expires_at': None},
        {'domain': 'd.it', 'status': 'unavailable', 'expires_at': None},
    ], now=now)
    s = view['summary']
    assert s['expiry'] == {'expired': 1, '30': 1, '60': 1, '90': 1}
    assert s['by_status'] == {'ok': 2, 'not_published': 1, 'not_registered': 0, 'unavailable': 1}
    c = next(d for d in view['domains'] if d['domain'] == 'c.de')
    assert c['days_until_expiry'] is None and c['expiry_status'] == 'unknown'


# --------------------------------------------------------------------------- #
# The API
# --------------------------------------------------------------------------- #

@pytest.fixture
def real_app(tmp_path, monkeypatch):
    from modules.core.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    application, container = create_app()
    return application, container


def test_domains_endpoint_lists_registrations(real_app):
    application, container = real_app
    inv = container.managers['cert_inventory']
    inv.record_registration(_result('example.com', expires='2026-10-01T00:00:00Z'))
    inv.record_registration(_result('example.de', status=STATUS_NOT_PUBLISHED, expires=None))
    body = application.test_client().get('/api/inventory/domains').get_json()
    assert [d['domain'] for d in body['domains']] == ['example.com', 'example.de']
    assert body['summary']['by_status']['not_published'] == 1


def test_domains_endpoint_filters_by_scope(tmp_path, monkeypatch):
    """Through the real auth stack: a viewer key scoped to one tenant sees that
    tenant's registration and not the other's.

    An operator bearer token is set first, because an instance still in setup
    mode serves every request as admin and ignores the key entirely — the scope
    would never be exercised, and the test would pass for the wrong reason.
    """
    import secrets as _secrets
    from modules.core.factory import create_app
    admin_token = _secrets.token_urlsafe(32)
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('API_BEARER_TOKEN', admin_token)
    application, container = create_app()
    assert not container.managers['auth'].is_setup_mode()

    inv = container.managers['cert_inventory']
    inv.record_registration(_result('tenant-a.example'))
    inv.record_registration(_result('tenant-b.example'))
    client = application.test_client()
    admin = {'Authorization': f'Bearer {admin_token}'}
    created = client.post('/api/keys', headers=admin, json={
        'name': 'tenant-a', 'role': 'viewer', 'allowed_domains': ['tenant-a.example']})
    assert created.status_code in (200, 201), created.get_json()
    scoped = {'Authorization': f'Bearer {created.get_json()["token"]}'}

    seen = client.get('/api/inventory/domains', headers=scoped).get_json()
    assert [d['domain'] for d in seen['domains']] == ['tenant-a.example']
    everything = client.get('/api/inventory/domains', headers=admin).get_json()
    assert [d['domain'] for d in everything['domains']] == ['tenant-a.example', 'tenant-b.example']


def test_config_round_trips_the_registration_section(real_app):
    application, _ = real_app
    client = application.test_client()
    assert client.get('/api/inventory/config').get_json()['domain_registration'] == {
        'enabled': False, 'include_inventory': True, 'extra_domains': []}
    r = client.post('/api/inventory/config', json={'domain_registration': {
        'enabled': True, 'extra_domains': ['brand.it']}})
    assert r.status_code == 200
    assert r.get_json()['domain_registration']['extra_domains'] == ['brand.it']
    bad = client.post('/api/inventory/config', json={'domain_registration': {
        'extra_domains': ['intranet.corp']}})
    assert bad.status_code == 400


def test_scan_runs_the_registration_check_last(real_app):
    application, container = real_app
    mgr = container.managers['domain_registration']
    mgr.run_check = MagicMock(return_value={'skipped': True, 'reason': 'disabled', 'results': []})
    body = application.test_client().post('/api/inventory/scan').get_json()
    # The registration check runs after discovery and the CT poll, so it sees
    # what they just added; the name-level checks follow it for the same reason.
    assert list(body) == ['discovery', 'ct_monitoring', 'domain_registration', 'domain_health']
    mgr.run_check.assert_called_once_with()


# --------------------------------------------------------------------------- #
# Real registries
# --------------------------------------------------------------------------- #

@pytest.mark.network
def test_real_registries():
    """google.com over RDAP, nic.it over WHOIS (.it has no RDAP), google.de
    not published (DENIC does not publish expiry)."""
    client = RegistrationClient()
    com = client.lookup('google.com')
    assert (com['status'], com['source']) == (STATUS_OK, 'rdap')
    it = client.lookup('nic.it')
    assert (it['status'], it['source']) == (STATUS_OK, 'whois')
    assert client.lookup('google.de')['status'] == STATUS_NOT_PUBLISHED


def test_a_scan_without_the_registration_manager_still_scans(real_app):
    application, container = real_app
    container.managers.pop('domain_registration')
    body = application.test_client().post('/api/inventory/scan').get_json()
    assert 'domain_registration' not in body
    assert 'discovery' in body


def test_a_registration_check_that_blows_up_does_not_lose_the_scan(real_app):
    application, container = real_app
    container.managers['domain_registration'].run_check = MagicMock(
        side_effect=RuntimeError('registry on fire'))
    body = application.test_client().post('/api/inventory/scan').get_json()
    assert body['domain_registration'] == {'error': 'domain registration check failed'}
    assert 'ct_monitoring' in body


def test_the_domains_endpoint_says_so_when_there_is_no_inventory(real_app):
    application, container = real_app
    container.managers['cert_inventory'] = None
    response = application.test_client().get('/api/inventory/domains')
    assert response.status_code == 503
    assert response.get_json()['code'] == 'INVENTORY_UNAVAILABLE'
