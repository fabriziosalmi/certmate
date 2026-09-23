"""Tests for the configurable resolver (``modules/core/dns_resolver.py``).

The documentation told an operator to "point CertMate at a resolver of your
own" when a blocklist refused the query, and there was no way to do it
(#881). This is that setting.

A setting like this fails in a way that looks like success: dnspython will
happily be given nameservers and then, if they are left alongside the ones
from ``resolv.conf``, answer from whichever replies first — so an operator
would configure a resolver, see answers, and still be querying the one they
were trying to replace.

The obvious test for that is to point at an unroutable address and assert the
lookup fails. It was written, and it did not fail: the network this was
developed on transparently intercepts every query to port 53, so
``dig @192.0.2.53 example.com TXT`` returns a real answer in 30ms. The premise
was false rather than the code, but a test that cannot fail proves nothing.

So the proof is positive instead: a responder is stood up on a free port, told
to answer with a string nothing else in the world would return, and the test
checks that the answer came from *it* — with a negative half asserting that
without the setting, that responder is never contacted.
"""
import ipaddress

import pytest

from modules.core import caa
from modules.core import dns_resolver as dr
from modules.core import domain_health as dh

pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------- #
# What counts as a nameserver
# --------------------------------------------------------------------------- #

def test_addresses_of_both_families_are_accepted():
    assert dr.parse_nameservers(['9.9.9.9', '2620:fe::fe']) == ['9.9.9.9', '2620:fe::fe']


def test_whitespace_is_stripped_and_blanks_dropped():
    assert dr.parse_nameservers([' 1.1.1.1 ', '', '   ']) == ['1.1.1.1']


def test_duplicates_go_and_the_order_is_kept():
    """A resolver tries them in order, so the order is the operator's
    preference and is not sorted away."""
    assert dr.parse_nameservers(['9.9.9.9', '1.1.1.1', '9.9.9.9']) == \
        ['9.9.9.9', '1.1.1.1']


def test_a_hostname_is_refused_with_the_reason():
    """Resolving it would need the resolver being replaced — so it would
    either depend on the thing the operator is trying to stop using, or fail
    in a way that looks like the new resolver being broken."""
    with pytest.raises(ValueError) as e:
        dr.parse_nameservers(['dns.example.com'])
    assert 'resolver you are replacing' in str(e.value)


@pytest.mark.parametrize('bad', ['9.9.9.9', 42, {'a': 'b'}])
def test_something_that_is_not_a_list_is_refused(bad):
    """A bare string is the likely mistake, and iterating it would read one
    character at a time."""
    with pytest.raises(ValueError):
        dr.parse_nameservers(bad)


@pytest.mark.parametrize('bad', ['9.9.9.9.9', '999.1.1.1', '1.1.1.1/24',
                                 'localhost', '1.1.1.1 9.9.9.9'])
def test_things_that_look_like_addresses_and_are_not(bad):
    with pytest.raises(ValueError):
        dr.parse_nameservers([bad])


def test_nothing_configured_is_an_empty_list_not_an_error():
    assert dr.parse_nameservers(None) == []
    assert dr.parse_nameservers([]) == []


# --------------------------------------------------------------------------- #
# Reading it out of settings
# --------------------------------------------------------------------------- #

def test_the_setting_is_read_from_where_it_is_written():
    settings = {'dns_resolver': {'nameservers': ['9.9.9.9']}}
    assert dr.configured_nameservers(settings) == ['9.9.9.9']


@pytest.mark.parametrize('settings', [
    {}, None, {'dns_resolver': None}, {'dns_resolver': {}},
    {'dns_resolver': {'nameservers': []}},
])
def test_an_instance_that_configures_nothing_uses_the_system_resolver(settings):
    assert dr.configured_nameservers(settings) == []


def test_an_unreadable_setting_falls_back_instead_of_stopping_every_lookup():
    """Saving an invalid one is refused up front, which is where the operator
    finds out. If one reaches the file anyway, falling back to the system
    resolver is better than every name-level check raising."""
    assert dr.configured_nameservers(
        {'dns_resolver': {'nameservers': ['not-an-address']}}) == []


# --------------------------------------------------------------------------- #
# Does it actually reach the resolver?
# --------------------------------------------------------------------------- #

def test_the_resolver_is_pointed_at_what_was_configured():
    resolver = dr.build(3.0, ['9.9.9.9', '1.1.1.1'])
    assert resolver.nameservers == ['9.9.9.9', '1.1.1.1']
    assert resolver.lifetime == 3.0


def test_the_configured_servers_replace_the_system_ones_rather_than_joining_them():
    """Left alongside, a query the chosen resolver refuses would be answered
    by the one it replaced — silently, and differently from run to run."""
    system = dr.build(3.0).nameservers
    configured = dr.build(3.0, ['192.0.2.53']).nameservers
    assert configured == ['192.0.2.53']
    assert not set(configured) & set(system or [])


def test_configuring_nothing_leaves_the_system_resolver_untouched():
    assert dr.build(3.0).nameservers == dr.build(3.0, []).nameservers


def _captured_resolver(monkeypatch):
    """Capture the resolver each code path builds, without resolving."""
    import dns.resolver
    built = []
    real = dns.resolver.Resolver

    class Recording(real):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            built.append(self)

    monkeypatch.setattr(dns.resolver, 'Resolver', Recording)
    return built


def test_domain_health_lookups_use_the_configured_servers(monkeypatch):
    built = _captured_resolver(monkeypatch)
    dh.dns_lookups(4.0, ['9.9.9.9'])
    assert built[-1].nameservers == ['9.9.9.9']
    assert built[-1].lifetime == 4.0


def test_the_caa_check_uses_them_too(monkeypatch):
    """CAA resolves names itself as well. A setting that covered one of the
    two would leave an operator wondering which lookups it applied to."""
    built = _captured_resolver(monkeypatch)
    caa._dnspython_resolver(4.0, ['9.9.9.9'])
    assert built[-1].nameservers == ['9.9.9.9']


def test_the_sweep_reads_the_setting_rather_than_holding_it(monkeypatch, tmp_path):
    """Built per sweep, so changing the setting takes effect on the next run
    instead of on the next restart."""
    from unittest.mock import MagicMock

    from modules.core.cert_inventory import CertInventory

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'dns_resolver': {'nameservers': ['9.9.9.9']}}
    manager = dh.DomainHealthManager(settings_manager, CertInventory(tmp_path),
                                     tmp_path)
    built = _captured_resolver(monkeypatch)
    manager._configured_lookups()
    assert built[-1].nameservers == ['9.9.9.9']

    settings_manager.load_settings.return_value = {
        'dns_resolver': {'nameservers': ['1.1.1.1']}}
    manager._configured_lookups()
    assert built[-1].nameservers == ['1.1.1.1']


def test_an_injected_lookup_still_wins_over_the_setting(monkeypatch, tmp_path):
    """The tests inject their own lookups; the setting must not override
    them, or every offline test would start resolving for real."""
    from unittest.mock import MagicMock

    from modules.core.cert_inventory import CertInventory

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'domain_health': {'enabled': True, 'include_inventory': False},
        'dns_resolver': {'nameservers': ['9.9.9.9']}}
    injected = (lambda n: [],) * 4
    manager = dh.DomainHealthManager(settings_manager, CertInventory(tmp_path),
                                     tmp_path, lookups=injected,
                                     headers_fetcher=lambda h: None)
    built = _captured_resolver(monkeypatch)
    manager.check_one('example.com', True, manager.get_config())
    assert built == []


# --------------------------------------------------------------------------- #
# Through the API
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
    return create_app()


def test_the_config_endpoint_reports_the_system_resolver_as_empty(real_app):
    application, _ = real_app
    body = application.test_client().get('/api/inventory/config').get_json()
    assert body['dns_resolver'] == {'nameservers': []}


def test_the_setting_round_trips_and_persists(real_app):
    application, container = real_app
    client = application.test_client()
    saved = client.post('/api/inventory/config',
                        json={'dns_resolver': {'nameservers': ['9.9.9.9', '1.1.1.1']}})
    assert saved.status_code == 200
    assert saved.get_json()['dns_resolver']['nameservers'] == ['9.9.9.9', '1.1.1.1']
    again = client.get('/api/inventory/config').get_json()
    assert again['dns_resolver']['nameservers'] == ['9.9.9.9', '1.1.1.1']
    stored = container.managers['settings'].load_settings()['dns_resolver']
    assert stored == {'nameservers': ['9.9.9.9', '1.1.1.1']}


def test_a_hostname_is_refused_by_the_endpoint(real_app):
    application, _ = real_app
    bad = application.test_client().post(
        '/api/inventory/config', json={'dns_resolver': {'nameservers': ['dns.quad9.net']}})
    assert bad.status_code == 400
    assert 'resolver you are replacing' in bad.get_json()['error']


def test_a_refused_setting_leaves_the_previous_one_in_place(real_app):
    application, container = real_app
    client = application.test_client()
    client.post('/api/inventory/config', json={'dns_resolver': {'nameservers': ['9.9.9.9']}})
    client.post('/api/inventory/config', json={'dns_resolver': {'nameservers': ['nope']}})
    assert container.managers['settings'].load_settings()['dns_resolver'] == \
        {'nameservers': ['9.9.9.9']}


def test_clearing_it_goes_back_to_the_system_resolver(real_app):
    application, container = real_app
    client = application.test_client()
    client.post('/api/inventory/config', json={'dns_resolver': {'nameservers': ['9.9.9.9']}})
    client.post('/api/inventory/config', json={'dns_resolver': {'nameservers': []}})
    assert container.managers['settings'].load_settings()['dns_resolver'] == \
        {'nameservers': []}


# --------------------------------------------------------------------------- #
# Ports
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('entry,host,port', [
    ('9.9.9.9', '9.9.9.9', None),
    ('10.0.0.53:5353', '10.0.0.53', 5353),
    ('2001:db8::1', '2001:db8::1', None),
    ('[2001:db8::1]:5353', '2001:db8::1', 5353),
])
def test_an_address_may_carry_a_port(entry, host, port):
    assert dr.split_address(entry) == (host, port)


@pytest.mark.parametrize('bad', ['1.2.3.4:0', '1.2.3.4:99999', '1.2.3.4:abc',
                                 '[2001:db8::1', '[2001:db8::1]x'])
def test_a_malformed_port_or_bracket_is_refused(bad):
    with pytest.raises(ValueError):
        dr.split_address(bad)


def test_an_ipv6_address_with_a_port_keeps_its_brackets():
    assert dr.parse_nameservers(['[2001:db8::1]:5353']) == ['[2001:db8::1]:5353']


# --------------------------------------------------------------------------- #
# The one that proves the setting is real
# --------------------------------------------------------------------------- #
#
# This started as "point at an unroutable address and assert the lookup
# fails". It does not fail: the network this was written on transparently
# intercepts every query to port 53, so `dig @192.0.2.53 example.com TXT`
# returns a real answer in 30ms. The premise was false, not the code — but a
# test that cannot fail proves nothing, and neither does one that passes
# because the network answered on someone else's behalf.
#
# So the proof is positive instead: stand up a resolver of our own, give it an
# answer nothing else in the world would give, and check we got that one.

class _Responder:
    """A DNS server that answers every TXT query with one distinctive string."""

    def __init__(self, answer):
        import socket
        import threading
        self.answer = answer
        self.queries = []
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(('127.0.0.1', 0))
        self.port = self._sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        import dns.message
        import dns.rdataclass
        import dns.rdatatype
        self._sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(4096)
            except OSError:
                continue
            try:
                query = dns.message.from_wire(data)
                self.queries.append(str(query.question[0].name))
                reply = dns.message.make_response(query)
                reply.answer.append(dns.rrset.from_text(
                    query.question[0].name, 60, dns.rdataclass.IN,
                    dns.rdatatype.TXT, f'"{self.answer}"'))
                self._sock.sendto(reply.to_wire(), addr)
            except Exception:  # noqa: BLE001 - a test double, not shipped code
                continue

    def close(self):
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()


@pytest.fixture
def responder():
    import dns.rrset  # noqa: F401 - imported for the thread's use
    r = _Responder('answered-by-the-configured-resolver')
    try:
        yield r
    finally:
        r.close()


def test_the_answer_comes_from_the_resolver_that_was_configured(responder):
    """The test this file exists for.

    Nothing else on the internet answers example.com's TXT with this string,
    so receiving it proves the query reached the server named in the setting
    — and reached only it, because that is the only place the string exists.
    """
    txt, _, _, _ = dh.dns_lookups(timeout=3.0,
                                  nameservers=[f'127.0.0.1:{responder.port}'])
    assert txt('example.com') == ['answered-by-the-configured-resolver']
    assert responder.queries == ['example.com.']


def test_the_caa_lookup_reaches_it_too(responder):
    """Both resolvers in the tree honour the setting, not just one."""
    resolve = caa._dnspython_resolver(3.0, [f'127.0.0.1:{responder.port}'])
    resolve('example.com')          # TXT is the wrong type; the point is the hop
    assert responder.queries == ['example.com.']


def test_the_sweep_sends_its_lookups_there(responder, tmp_path):
    """End to end from the setting as an operator writes it, through the
    sweep itself rather than through the helper it calls — otherwise removing
    the call site would leave every other test in this file passing."""
    from unittest.mock import MagicMock

    from modules.core.cert_inventory import CertInventory

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'domain_health': {'enabled': True, 'include_inventory': False,
                          'check_blocklists': False, 'check_headers': False},
        'domains': {'example.com': {}},
        'dns_resolver': {'nameservers': [f'127.0.0.1:{responder.port}']}}
    manager = dh.DomainHealthManager(settings_manager, CertInventory(tmp_path),
                                     tmp_path)
    result = manager.run_check()

    assert result['skipped'] is False
    assert 'example.com.' in responder.queries
    stored = manager.inventory.get_domain_health('example.com')
    # The responder answers every TXT query with a string that is not an SPF
    # record, so the check judges an answer it received rather than reporting
    # `unknown`, which is what a lookup that never completed would give.
    assert stored['checks']['spf']['status'] == dh.FAILING
    assert stored['checks']['spf']['status'] != dh.UNKNOWN


def test_without_the_setting_the_lookup_does_not_go_there(responder):
    """The negative half: with nothing configured, this responder sees
    nothing. Without it, the test above would pass even if the setting were
    ignored and some other resolver happened to answer."""
    txt, _, _, _ = dh.dns_lookups(timeout=3.0)
    result = txt('example.com')
    assert responder.queries == []
    assert result != ['answered-by-the-configured-resolver']


@pytest.mark.network
def test_a_blocklist_answers_through_a_resolver_of_our_own():
    """The reason the setting exists: on a machine whose system resolver is
    refused by Spamhaus, naming one that is not makes the check work.

    Skipped rather than failed when the chosen resolver is also refused —
    that is a property of where this runs, not of the code.
    """
    _, _, _, rbl = dh.dns_lookups(timeout=5.0, nameservers=['9.9.9.9'])
    answer = rbl(f'{dh.RBL_SELFTEST_LISTED}.zen.spamhaus.org')
    if answer is None or any(str(a).startswith(dh.RBL_REFUSED_PREFIX)
                             for a in answer):
        pytest.skip('this resolver is refused by Spamhaus too')
    assert dh.classify_rbl_answer(answer) in ('listed', 'policy')


def test_the_reserved_address_used_above_really_is_unroutable():
    """Pins the premise of the network test rather than trusting the comment:
    192.0.2.0/24 is TEST-NET-1, reserved by RFC 5737 for documentation."""
    assert ipaddress.ip_address('192.0.2.53') in ipaddress.ip_network('192.0.2.0/24')
    assert not ipaddress.ip_address('192.0.2.53').is_global


# --------------------------------------------------------------------------- #
# The environment, for the deployments where this problem lives
# --------------------------------------------------------------------------- #

def test_the_environment_can_name_the_resolvers():
    assert dr.env_nameservers({dr.ENV_VAR: '9.9.9.9,1.1.1.1'}) == ['9.9.9.9', '1.1.1.1']


def test_spaces_around_the_commas_are_tolerated():
    assert dr.env_nameservers({dr.ENV_VAR: ' 9.9.9.9 , 1.1.1.1 '}) == ['9.9.9.9', '1.1.1.1']


@pytest.mark.parametrize('raw', ['', '   ', ',,,'])
def test_an_empty_environment_variable_is_nothing_configured(raw):
    assert dr.env_nameservers({dr.ENV_VAR: raw}) == []


def test_a_bad_environment_variable_does_not_stop_the_instance_starting():
    """A settings file is edited by someone looking at the interface; an
    environment variable is edited by someone editing a compose file, often
    without a way to see the error. Falling back is better than refusing to
    start."""
    assert dr.env_nameservers({dr.ENV_VAR: 'dns.example.com'}) == []


def test_the_environment_is_used_when_nothing_is_stored():
    assert dr.configured_nameservers({}, {dr.ENV_VAR: '9.9.9.9'}) == ['9.9.9.9']


def test_a_stored_setting_wins_over_the_environment():
    """That way round on purpose: the setting is the one an operator can see
    and change. If the environment overrode it, saving a resolver would appear
    to work and change nothing, which is the worse surprise."""
    stored = {'dns_resolver': {'nameservers': ['8.8.8.8']}}
    assert dr.configured_nameservers(stored, {dr.ENV_VAR: '9.9.9.9'}) == ['8.8.8.8']


def test_clearing_the_setting_falls_back_to_the_environment_not_to_nothing():
    stored = {'dns_resolver': {'nameservers': []}}
    assert dr.configured_nameservers(stored, {dr.ENV_VAR: '9.9.9.9'}) == ['9.9.9.9']


def test_the_environment_is_read_from_the_real_one_by_default(monkeypatch):
    monkeypatch.setenv(dr.ENV_VAR, '9.9.9.9')
    assert dr.configured_nameservers({}) == ['9.9.9.9']


def test_the_environment_reaches_an_actual_lookup(responder, monkeypatch, tmp_path):
    """Stored and environment both end in the same place, so both are proven
    the same way rather than one being trusted because the other works."""
    from unittest.mock import MagicMock

    from modules.core.cert_inventory import CertInventory

    monkeypatch.setenv(dr.ENV_VAR, f'127.0.0.1:{responder.port}')
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {}
    manager = dh.DomainHealthManager(settings_manager, CertInventory(tmp_path),
                                     tmp_path)
    txt, _, _, _ = manager._configured_lookups()
    assert txt('example.com') == ['answered-by-the-configured-resolver']


# --------------------------------------------------------------------------- #
# The remedy points at something that exists
# --------------------------------------------------------------------------- #

def test_the_advice_given_when_nothing_answers_names_the_setting():
    """#881: the check told operators to point CertMate at a resolver of
    their own, and there was no way to. Whatever the wording, it has to name
    something they can act on."""
    def refusing(name):
        return ['127.255.255.254']

    result = dh.check_blocklists('example.com', ['192.0.2.13'], refusing)
    assert result['status'] == dh.UNKNOWN
    assert 'dns_resolver' in result['detail'] or dr.ENV_VAR in result['detail']
