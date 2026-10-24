"""The ACME server certifies an IPv4 address (RFC 8738, #1338).

An order may name {"type": "ip", "value": "<address>"} in the address's textual
form. It is authorized over http-01 alone (dns-01 MUST NOT validate an
address, section 7), fetched from the address itself with no DNS step (section
4) and the address as the Host header (section 5), under the guards the fetch
has: private networks allowed, never loopback, link-local, multicast, reserved
or metadata, which an order is refused for at once. An EAB key allows an
address by an address or CIDR pattern, never by a name pattern, and a name
never by an address pattern. The certificate carries the address as an
iPAddress SAN; an order of addresses alone has an empty subject and a critical
SAN extension (RFC 5280 section 4.2.1.6), as Let's Encrypt issues them.
"""
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.acme_server import AcmeAdminError, identifier_pattern
from tests.acme_support import (
    ChallengeServer,
    eab_for,
    problem,
    registered_client,
    resolve_for_tests,
    served_app,
)
from tests.test_the_acme_server_issues_and_revokes import _der
from tests.test_the_acme_server_validates_orders import _serve

pytestmark = [pytest.mark.unit]

ADDRESS = '10.20.0.5'
PATTERNS = ['*.lab.internal', '10.20.0.0/16']


@pytest.fixture
def responder():
    server = ChallengeServer()
    yield server
    server.close()


@pytest.fixture
def asked():
    return []


@pytest.fixture
def app(responder, asked):
    application = served_app(responder)

    def resolve(host, port, allow_internal):
        # The address is fetched as itself: what reaches here is the address,
        # and the test's challenge server stands in for the host behind it.
        asked.append(host)
        if host in (ADDRESS, '10.20.9.9'):
            return '127.0.0.1'
        return resolve_for_tests(host, port, allow_internal)

    application.extensions['certmate_container'].managers['acme_server'].resolve = resolve
    return application


@pytest.fixture
def client(app):
    return registered_client(app, eab_for(app, PATTERNS))


def _order(client, *identifiers):
    return client.post('new-order', {'identifiers': [
        {'type': 'ip' if _is_address(v) else 'dns', 'value': v} for v in identifiers]})


def _is_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _authorizations(client, order):
    return [client.post(url, None).get_json() for url in order.get_json()['authorizations']]


def _ready(client, responder, *identifiers):
    order = _order(client, *identifiers)
    assert order.status_code == 201, order.get_json()
    for authz in _authorizations(client, order):
        challenge = next(c for c in authz['challenges'] if c['type'] == 'http-01')
        _serve(client, responder, challenge)
        assert client.post(challenge['url'], {}).get_json()['status'] == 'valid'
    return order.headers['Location']


def _csr(dns=(), addresses=(), common_name=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else [])
    san = [x509.DNSName(n) for n in dns] + [x509.IPAddress(ipaddress.ip_address(a)) for a in addresses]
    return (x509.CertificateSigningRequestBuilder().subject_name(subject)
            .add_extension(x509.SubjectAlternativeName(san), critical=False).sign(key, hashes.SHA256()))


def _leaf(client, location, csr):
    finalized = client.post(location + '/finalize', {'csr': _der(csr)})
    assert finalized.status_code == 200, finalized.get_json()
    pem = client.post(finalized.get_json()['certificate'], None).data
    return x509.load_pem_x509_certificates(pem)[0]


# --- the order ------------------------------------------------------------------

def test_an_address_is_ordered_and_authorized_over_http01_alone(client):
    order = _order(client, ADDRESS)
    assert order.status_code == 201, order.get_json()
    assert order.get_json()['identifiers'] == [{'type': 'ip', 'value': ADDRESS}]
    [authz] = _authorizations(client, order)
    assert authz['identifier'] == {'type': 'ip', 'value': ADDRESS}
    assert [c['type'] for c in authz['challenges']] == ['http-01']


def test_http01_is_fetched_from_the_address_with_it_as_the_host(client, responder, asked):
    _ready(client, responder, ADDRESS)
    assert asked == [ADDRESS], 'the address is the destination, with no DNS step (RFC 8738 section 4)'
    # The test serves on a port of its own, which the Host header then names.
    assert responder.hosts[-1].split(':')[0] == ADDRESS


def test_a_name_and_an_address_are_ordered_together(client):
    order = _order(client, 'web.lab.internal', ADDRESS)
    assert order.status_code == 201
    kinds = {a['identifier']['value']: [c['type'] for c in a['challenges']] for a in _authorizations(client, order)}
    assert kinds == {'web.lab.internal': ['http-01', 'dns-01'], ADDRESS: ['http-01']}


# --- refused at the order, before any fetch ---------------------------------------

@pytest.mark.parametrize('value,kind,because', [
    ('2001:db8::1', 'unsupportedIdentifier', 'IPv4 addresses only'),
    ('010.20.0.5', 'rejectedIdentifier', 'textual form'),
    (' 10.20.0.5', 'rejectedIdentifier', 'textual form'),
    ('web.lab.internal', 'rejectedIdentifier', 'textual form'),
    ('127.0.0.1', 'rejectedIdentifier', 'can never reach'),
    ('169.254.169.254', 'rejectedIdentifier', 'can never reach'),
    ('224.0.0.1', 'rejectedIdentifier', 'can never reach'),
    ('0.0.0.0', 'rejectedIdentifier', 'can never reach'),
    ('240.0.0.1', 'rejectedIdentifier', 'can never reach'),
    ('100.100.100.200', 'rejectedIdentifier', 'can never reach'),
])
def test_an_address_this_server_cannot_certify_is_refused(client, responder, value, kind, because):
    response = client.post('new-order', {'identifiers': [{'type': 'ip', 'value': value}]})
    assert problem(response, because) == kind
    assert responder.hosts == []


def test_an_address_outside_the_keys_patterns_is_refused(client, responder):
    response = _order(client, ADDRESS, '10.30.0.5')
    assert problem(response, 'may not order') == 'rejectedIdentifier'
    assert [s['identifier'] for s in response.get_json()['subproblems']] == [{'type': 'ip', 'value': '10.30.0.5'}]
    assert responder.hosts == []


def test_a_name_pattern_never_allows_an_address(app):
    client = registered_client(app, eab_for(app, ['*.lab.internal']))
    assert problem(_order(client, ADDRESS), 'may not order') == 'rejectedIdentifier'


def test_an_address_pattern_never_allows_a_name(app):
    client = registered_client(app, eab_for(app, ['10.20.0.0/16']))
    assert problem(_order(client, 'web.lab.internal'), 'may not order') == 'rejectedIdentifier'


@pytest.mark.parametrize('written', ['0.0.0.0/0', '::/0', '2001:db8::/32'])
def test_a_pattern_written_into_the_settings_by_hand_that_no_admin_call_accepts_allows_nothing(app, written):
    client = registered_client(app, eab_for(app, [written]))
    assert problem(_order(client, ADDRESS), 'may not order') == 'rejectedIdentifier'


def test_an_address_stored_before_as_a_name_allows_that_address(app):
    """Before #1338 name_pattern kept "10.20.0.5" as a name; eab_for writes the
    settings directly, as such a key is stored."""
    client = registered_client(app, eab_for(app, [ADDRESS]))
    assert _order(client, ADDRESS).status_code == 201
    assert problem(_order(client, '10.20.0.6'), 'may not order') == 'rejectedIdentifier'


# --- the certificate --------------------------------------------------------------

def test_an_address_is_certified_as_an_ip_address_with_an_empty_subject(client, responder):
    leaf = _leaf(client, _ready(client, responder, ADDRESS), _csr(addresses=[ADDRESS]))
    extension = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert extension.value.get_values_for_type(x509.IPAddress) == [ipaddress.ip_address(ADDRESS)]
    assert extension.value.get_values_for_type(x509.DNSName) == []
    assert list(leaf.subject) == []
    assert extension.critical is True, 'an empty subject needs a critical SAN (RFC 5280 4.2.1.6)'


def test_a_name_and_an_address_are_certified_together_under_the_name(client, responder):
    location = _ready(client, responder, 'web.lab.internal', ADDRESS)
    leaf = _leaf(client, location, _csr(dns=['web.lab.internal'], addresses=[ADDRESS]))
    extension = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    assert list(extension.value) == [x509.DNSName('web.lab.internal'),
                                     x509.IPAddress(ipaddress.ip_address(ADDRESS))]
    assert leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'web.lab.internal'
    assert extension.critical is False


def test_a_csr_may_repeat_the_address_as_its_common_name(client, responder):
    leaf = _leaf(client, _ready(client, responder, ADDRESS), _csr(addresses=[ADDRESS], common_name=ADDRESS))
    assert list(leaf.subject) == []


@pytest.mark.parametrize('csr', [
    lambda: _csr(dns=[ADDRESS]),                       # the address as a name
    lambda: _csr(addresses=['10.20.9.9']),             # another address
    lambda: _csr(addresses=[ADDRESS, '10.20.9.9']),    # one more
    lambda: _csr(addresses=[ADDRESS], common_name='10.20.9.9'),
])
def test_a_csr_that_does_not_name_the_orders_address_is_refused(client, responder, csr):
    location = _ready(client, responder, ADDRESS)
    response = client.post(location + '/finalize', {'csr': _der(csr())})
    assert problem(response, 'must be the same') == 'badCSR'


# --- the patterns an administrator writes ---------------------------------------------

@pytest.mark.parametrize('written,stored', [
    ('10.20.0.0/16', '10.20.0.0/16'),
    (' 192.168.1.20 ', '192.168.1.20'),
    ('192.168.1.20/32', '192.168.1.20'),
    ('*.lab.internal', '*.lab.internal'),
])
def test_an_address_or_a_network_is_a_pattern(written, stored):
    assert identifier_pattern(written) == stored


@pytest.mark.parametrize('written,because', [
    ('10.20.0.1/16', 'host bits set'),
    ('10.0.0.0/33', 'CIDR'),
    ('0.0.0.0/0', 'every address'),
    ('fe80::1', 'IPv6'),
    ('2001:db8::/32', 'IPv6'),
    ('010.0.0.1', 'no top-level domain is all digits'),
    ('*.1.168.192', 'no top-level domain is all digits'),
    ('*', 'not a DNS name'),
])
def test_a_pattern_that_is_neither_is_refused(written, because):
    with pytest.raises(AcmeAdminError, match=because):
        identifier_pattern(written)


def test_the_admin_api_takes_addresses_and_networks(app):
    server = app.extensions['certmate_container'].managers['acme_server']
    created = server.create_eab_key(allowed_identifiers=['10.20.0.0/16', '192.168.1.20', '*.lab.internal'])
    assert created['allowed_identifiers'] == ['10.20.0.0/16', '192.168.1.20', '*.lab.internal']
    assert server.set_options({'allowed_identifiers': ['10.30.0.0/24']})['allowed_identifiers'] == ['10.30.0.0/24']
    with pytest.raises(AcmeAdminError, match='host bits set'):
        server.set_options({'allowed_identifiers': ['10.30.0.1/24']})

