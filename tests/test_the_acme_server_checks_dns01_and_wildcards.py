"""dns-01 and wildcards on CertMate's ACME server (#476, I1 and I2).

The server looks up the TXT record at _acme-challenge.<name> through the
resolver the instance is configured with, CNAMEs followed, and compares it
with the digest of the key authorization (RFC 8555 section 8.4). A wildcard
order is authorized on its base name with dns-01 alone (section 7.1.3), and
only an EAB key with a "*." pattern at or above that base allows one.

The DNS here is a real UDP server on 127.0.0.1, which the instance's settings
point at, so the path is the one production takes.
"""
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.acme_validation import dns01_digest
from tests.acme_support import (
    ChallengeServer,
    DnsResponder,
    b64s,
    eab_for,
    point_dns_at,
    problem,
    registered_client,
    served_app,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture
def responder():
    server = ChallengeServer()
    yield server
    server.close()


@pytest.fixture
def dns():
    server = DnsResponder()
    yield server
    server.close()


@pytest.fixture
def app(responder, dns):
    application = served_app(responder)
    point_dns_at(application, dns)
    return application


@pytest.fixture
def client(app):
    return registered_client(app, eab_for(app, ['*.lab.internal', 'nas.office.internal']))


def _order(client, *names):
    return client.post('new-order', {'identifiers': [{'type': 'dns', 'value': n} for n in names]})


def _authz(client, order):
    return client.post(order.get_json()['authorizations'][0], None).get_json()


def _dns_challenge(authz):
    return next(c for c in authz['challenges'] if c['type'] == 'dns-01')


def _publish(client, dns, name, challenge, at=None):
    key_authorization = f"{challenge['token']}.{b64s(client.key.thumbprint())}"
    dns.txt[at or f'_acme-challenge.{name}'] = [dns01_digest(key_authorization)]


def test_a_name_is_offered_http01_dns01_and_tls_alpn01_with_tokens_of_their_own(client):
    authz = _authz(client, _order(client, 'web.lab.internal'))
    assert [c['type'] for c in authz['challenges']] == ['http-01', 'dns-01', 'tls-alpn-01']
    assert len({c['token'] for c in authz['challenges']}) == 3
    assert 'wildcard' not in authz


def test_a_published_digest_makes_the_authorization_valid(client, dns):
    order = _order(client, 'web.lab.internal')
    authz = _authz(client, order)
    challenge = _dns_challenge(authz)
    _publish(client, dns, 'web.lab.internal', challenge)
    answered = client.post(challenge['url'], {}).get_json()
    assert answered['status'] == 'valid'
    assert dns.asked == ['_acme-challenge.web.lab.internal']
    assert client.post(order.headers['Location'], None).get_json()['status'] == 'ready'


def test_a_cname_is_followed_to_where_the_record_is(client, dns):
    """A DNS alias: the client can write only the zone the CNAME points into."""
    order = _order(client, 'web.lab.internal')
    challenge = _dns_challenge(_authz(client, order))
    dns.cname['_acme-challenge.web.lab.internal'] = 'web.acme-delegated.example'
    _publish(client, dns, 'web.lab.internal', challenge, at='web.acme-delegated.example')
    assert client.post(challenge['url'], {}).get_json()['status'] == 'valid'


def test_the_digest_may_sit_among_other_records(client, dns):
    order = _order(client, 'web.lab.internal')
    challenge = _dns_challenge(_authz(client, order))
    _publish(client, dns, 'web.lab.internal', challenge)
    dns.txt['_acme-challenge.web.lab.internal'].insert(0, 'an-older-digest')
    assert client.post(challenge['url'], {}).get_json()['status'] == 'valid'


@pytest.mark.parametrize('setup,kind,because', [
    (lambda dns: dns.txt.update({'_acme-challenge.web.lab.internal': ['not-the-digest']}),
     'incorrectResponse', 'not the digest'),
    (lambda dns: None, 'dns', 'does not exist'),
])
def test_a_missing_or_wrong_record_makes_the_authorization_invalid(client, dns, setup, kind, because):
    order = _order(client, 'web.lab.internal')
    challenge = _dns_challenge(_authz(client, order))
    setup(dns)
    error = client.post(challenge['url'], {}).get_json()['error']
    assert error['type'].endswith(':' + kind) and because in error['detail']
    assert client.post(order.headers['Location'], None).get_json()['status'] == 'invalid'


def test_the_configured_resolver_is_the_one_asked(app, client, dns):
    """With no resolver configured the system's would be asked, and it knows nothing of these names."""
    order = _order(client, 'web.lab.internal')
    challenge = _dns_challenge(_authz(client, order))
    _publish(client, dns, 'web.lab.internal', challenge)
    client.post(challenge['url'], {})
    assert dns.asked, 'the configured nameserver was never asked'


# --- wildcards (decision I2) ------------------------------------------------------

@pytest.mark.parametrize('wildcard', ['*.lab.internal', '*.team.lab.internal'])
def test_a_wildcard_under_a_star_pattern_is_authorized_on_its_base_with_dns01_alone(client, wildcard):
    order = _order(client, wildcard)
    assert order.status_code == 201
    assert order.get_json()['identifiers'] == [{'type': 'dns', 'value': wildcard}]
    authz = _authz(client, order)
    assert authz['identifier'] == {'type': 'dns', 'value': wildcard[2:]}
    assert authz['wildcard'] is True
    assert [c['type'] for c in authz['challenges']] == ['dns-01']


@pytest.mark.parametrize('wildcard', ['*.office.internal', '*.nas.office.internal', '*.evil-lab.internal',
                                      '*.internal'])
def test_a_wildcard_no_star_pattern_covers_is_refused(client, wildcard):
    assert problem(_order(client, wildcard), 'may not order') == 'rejectedIdentifier'


def test_a_wildcard_certificate_is_issued_after_dns01(client, dns, responder):
    order = _order(client, '*.team.lab.internal')
    authz = _authz(client, order)
    challenge = _dns_challenge(authz)
    _publish(client, dns, 'team.lab.internal', challenge)
    assert client.post(challenge['url'], {}).get_json()['status'] == 'valid'
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder().subject_name(x509.Name([]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName('*.team.lab.internal')]), critical=False)
           .sign(key, hashes.SHA256()))
    finalized = client.post(order.headers['Location'] + '/finalize',
                            {'csr': b64s(csr.public_bytes(serialization.Encoding.DER))})
    assert finalized.status_code == 200, finalized.get_data(as_text=True)
    pem = client.post(finalized.get_json()['certificate'], None)
    cert = x509.load_pem_x509_certificate(pem.data)
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ['*.team.lab.internal']
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == '*.team.lab.internal'
    assert responder.hosts == []  # nothing was fetched over HTTP
