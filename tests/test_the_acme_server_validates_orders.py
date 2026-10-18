"""Orders, the name policy and the http-01 check of the ACME server (#476).

An order asks for names; each name must be one the account's EAB key allows
(decision D2), or, for an account enrolled without one, one the server-wide
list allows (F1). Each name gets an authorization with an http-01 challenge,
and the server fetches the client's answer itself (F3), through a guard that
reaches private networks but never loopback, link-local or a metadata
address, follows at most 5 redirects and only to ports 80 and 443 (F2), and
gives up after 10 seconds.

The challenge server here is a real HTTP server on 127.0.0.1, which the
guard would refuse; the tests point their names at it through the server's
resolver, as Pebble lets its tests do, and the guard itself is tested with
the real resolver.
"""
import time

import pytest

from modules.core import acme_validation
from tests.acme_support import (
    AcmeTestClient,
    ChallengeServer,
    eab_for,
    enable,
    problem,
    registered_client,
    resolve_for_tests,
    served_app,
)

pytestmark = [pytest.mark.unit]

@pytest.fixture
def responder():
    server = ChallengeServer()
    yield server
    server.close()


@pytest.fixture
def app(responder):
    return served_app(responder)


@pytest.fixture
def eab(app):
    return eab_for(app)


@pytest.fixture
def client(app, eab):
    return registered_client(app, eab)


def _order(client, *names, **extra):
    payload = {'identifiers': [{'type': 'dns', 'value': n} for n in names]}
    payload.update(extra)
    return client.post('new-order', payload)


def _first_challenge(client, order_response):
    authz_url = order_response.get_json()['authorizations'][0]
    authz = client.post(authz_url, None).get_json()
    return authz_url, authz['challenges'][0]


def _serve(client, responder, challenge):
    from tests.acme_support import b64s
    key_authorization = f'{challenge["token"]}.{b64s(client.key.thumbprint())}'
    responder.answers[challenge['token']] = ('body', key_authorization.encode())
    return key_authorization


# --- orders and the name policy -------------------------------------------------

def test_an_order_names_its_authorizations_and_where_to_finalize(client):
    response = _order(client, 'web.lab.internal', 'nas.office.internal')
    assert response.status_code == 201
    body = response.get_json()
    assert body['status'] == 'pending'
    assert body['identifiers'] == [{'type': 'dns', 'value': 'web.lab.internal'},
                                   {'type': 'dns', 'value': 'nas.office.internal'}]
    assert len(body['authorizations']) == 2
    assert body['finalize'] == response.headers['Location'] + '/finalize'
    assert body['expires'].endswith('Z')
    listed = client.post(client.account_url + '/orders', None).get_json()
    assert listed == {'orders': [response.headers['Location']]}


def test_names_are_normalised_and_counted_once(client):
    body = _order(client, 'Web.Lab.Internal.', 'web.lab.internal').get_json()
    assert body['identifiers'] == [{'type': 'dns', 'value': 'web.lab.internal'}]
    assert len(body['authorizations']) == 1


@pytest.mark.parametrize('name', ['lab.internal', 'evil-lab.internal', 'nas2.office.internal', 'x.office.internal'])
def test_a_name_outside_the_keys_patterns_is_refused_before_any_check(client, responder, name):
    response = _order(client, 'ok.lab.internal', name)
    assert problem(response, 'may not order') == 'rejectedIdentifier'
    assert [s['identifier']['value'] for s in response.get_json()['subproblems']] == [name]
    assert responder.hosts == []


@pytest.mark.parametrize('identifier,kind,because', [
    ({'type': 'dns', 'value': '*.lab.internal'}, 'rejectedIdentifier', 'needs dns-01'),
    ({'type': 'ip', 'value': '10.0.0.1'}, 'unsupportedIdentifier', 'Only dns'),
    ({'type': 'dns', 'value': 'not_a.lab.internal'}, 'rejectedIdentifier', 'not a DNS name'),
    ({'value': 'web.lab.internal'}, 'unsupportedIdentifier', 'Only dns'),
    ('web.lab.internal', 'malformed', 'an object with a type and a value'),
])
def test_an_identifier_this_server_cannot_certify_is_refused(client, identifier, kind, because):
    response = client.post('new-order', {'identifiers': [identifier]})
    assert problem(response, because) == kind


@pytest.mark.parametrize('payload,kind,because', [
    ({'identifiers': []}, 'malformed', 'non-empty list'),
    ({}, 'malformed', 'non-empty list'),
    ({'identifiers': [{'type': 'dns', 'value': f'h{i}.lab.internal'} for i in range(101)]},
     'rejectedIdentifier', 'At most 100'),
    ({'identifiers': [{'type': 'dns', 'value': 'web.lab.internal'}], 'notAfter': '2030-01-01T00:00:00Z'},
     'malformed', 'sets the validity'),
])
def test_an_order_must_be_well_formed(client, payload, kind, because):
    assert problem(client.post('new-order', payload), because) == kind


def test_an_account_without_an_eab_key_orders_only_the_server_wide_names(app):
    enable(app, eab_required=False)
    client = AcmeTestClient(app)
    assert client.new_account(None).status_code == 201
    assert problem(_order(client, 'web.lab.internal'), 'may not order') == 'rejectedIdentifier'
    enable(app, eab_required=False, allowed_identifiers=['*.lab.internal'])
    assert _order(client, 'web.lab.internal').status_code == 201


def test_a_disabled_keys_accounts_keep_their_names(app, eab, client):
    enable(app, eab_keys=[dict(eab, disabled=True)])
    assert _order(client, 'web.lab.internal').status_code == 201
    assert problem(_order(client, 'web.other.internal'), 'may not order') == 'rejectedIdentifier'


def test_an_account_reaches_only_its_own_orders(app, eab, client):
    order = _order(client, 'web.lab.internal')
    authz_url, challenge = _first_challenge(client, order)
    other = AcmeTestClient(app)
    assert other.new_account(eab).status_code == 201
    for url in (order.headers['Location'], authz_url, challenge['url']):
        assert problem(other.post(url, None), 'No ') == 'unauthorized', url


def test_an_order_is_read_with_post_as_get(client):
    location = _order(client, 'web.lab.internal').headers['Location']
    assert client.post(location, None).get_json()['status'] == 'pending'
    assert problem(client.post(location, {}), 'POST-as-GET') == 'malformed'


# --- http-01 -----------------------------------------------------------------------

def test_a_served_key_authorization_makes_the_order_ready(client, responder):
    order = _order(client, 'web.lab.internal')
    authz_url, challenge = _first_challenge(client, order)
    _serve(client, responder, challenge)
    answered = client.post(challenge['url'], {})
    assert answered.status_code == 200
    assert answered.get_json()['status'] == 'valid' and answered.get_json()['validated'].endswith('Z')
    assert f'<{authz_url}>;rel="up"' in answered.headers.getlist('Link')
    assert client.post(authz_url, None).get_json()['status'] == 'valid'
    assert client.post(order.headers['Location'], None).get_json()['status'] == 'ready'
    assert responder.hosts == [f'web.lab.internal:{responder.port}']


def test_whitespace_after_the_key_authorization_is_ignored(client, responder):
    order = _order(client, 'web.lab.internal')
    _authz_url, challenge = _first_challenge(client, order)
    key_authorization = _serve(client, responder, challenge)
    responder.answers[challenge['token']] = ('body', (key_authorization + '\r\n\t ').encode())
    assert client.post(challenge['url'], {}).get_json()['status'] == 'valid'


@pytest.mark.parametrize('answer,because', [
    (('body', b'not.the.key.authorization'), 'not the key authorization'),
    (('status', 404), 'answered HTTP 404'),
    (('status', 500), 'answered HTTP 500'),
])
def test_a_wrong_answer_makes_the_challenge_its_authorization_and_order_invalid(client, responder, answer, because):
    order = _order(client, 'web.lab.internal')
    authz_url, challenge = _first_challenge(client, order)
    responder.answers[challenge['token']] = answer
    body = client.post(challenge['url'], {}).get_json()
    assert body['status'] == 'invalid'
    assert body['error']['type'].endswith(':incorrectResponse') and because in body['error']['detail']
    assert client.post(authz_url, None).get_json()['status'] == 'invalid'
    assert client.post(order.headers['Location'], None).get_json()['status'] == 'invalid'


def test_a_challenge_is_checked_once(client, responder):
    order = _order(client, 'web.lab.internal')
    _authz_url, challenge = _first_challenge(client, order)
    _serve(client, responder, challenge)
    assert client.post(challenge['url'], None).get_json()['status'] == 'pending'  # POST-as-GET checks nothing
    assert responder.hosts == []
    first = client.post(challenge['url'], {})
    again = client.post(challenge['url'], {})
    assert first.get_json()['status'] == 'valid'
    # A client that retries its answer gets the challenge as it stands, not a refusal.
    assert again.status_code == 200 and again.get_json() == first.get_json()
    assert len(responder.hosts) == 1


def test_a_redirect_on_the_same_port_is_followed(client, responder):
    order = _order(client, 'web.lab.internal')
    _authz_url, challenge = _first_challenge(client, order)
    key_authorization = _serve(client, responder, challenge)
    responder.answers['moved'] = ('body', key_authorization.encode())
    responder.answers[challenge['token']] = ('redirect', f'http://other.lab.internal:{responder.port}/x/moved')
    assert client.post(challenge['url'], {}).get_json()['status'] == 'valid'
    assert responder.hosts[-1] == f'other.lab.internal:{responder.port}'


@pytest.mark.parametrize('location,because', [
    ('http://web.lab.internal:1/x', 'port 1 is not followed'),
    ('ftp://web.lab.internal/x', 'ftp'),
    ('http://169.254.169.254:{port}/latest/meta-data', 'never a valid destination'),
    ('http://127.0.0.1:{port}/x', 'never a valid destination'),
])
def test_a_redirect_the_guard_does_not_allow_is_not_followed(client, responder, location, because):
    order = _order(client, 'web.lab.internal')
    _authz_url, challenge = _first_challenge(client, order)
    responder.answers[challenge['token']] = ('redirect', location.format(port=responder.port))
    error = client.post(challenge['url'], {}).get_json()['error']
    assert error['type'].endswith(':connection') and because in error['detail'], error


def test_more_than_five_redirects_are_not_followed(client, responder):
    order = _order(client, 'web.lab.internal')
    _authz_url, challenge = _first_challenge(client, order)
    responder.answers[challenge['token']] = ('redirect', f'http://web.lab.internal:{responder.port}/x/loop')
    responder.answers['loop'] = ('redirect', f'http://web.lab.internal:{responder.port}/x/loop')
    error = client.post(challenge['url'], {}).get_json()['error']
    assert 'More than 5 redirects' in error['detail']
    assert len(responder.hosts) == 6


def test_a_name_that_resolves_to_loopback_is_never_fetched(app, client, responder):
    """The real guard, not the test resolver: localhost is 127.0.0.1."""
    eab = app.extensions['certmate_container'].managers['acme_server'].config()['eab_keys'][0]
    enable(app, eab_keys=[dict(eab, allowed_identifiers=['localhost'])])
    order = _order(client, 'localhost')
    _authz_url, challenge = _first_challenge(client, order)
    error = client.post(challenge['url'], {}).get_json()['error']
    assert error['type'].endswith(':connection') and 'never a valid destination' in error['detail']
    assert responder.hosts == []


def test_a_name_that_does_not_resolve_is_a_dns_error(app, client):
    eab = app.extensions['certmate_container'].managers['acme_server'].config()['eab_keys'][0]
    enable(app, eab_keys=[dict(eab, allowed_identifiers=['*.lab.internal', 'nx.example.internal'])])
    order = _order(client, 'nx.example.internal')
    _authz_url, challenge = _first_challenge(client, order)
    assert client.post(challenge['url'], {}).get_json()['error']['type'].endswith(':dns')


def test_the_check_gives_up_at_its_budget(responder):
    responder.answers['slow'] = ('sleep', 3)
    started = time.monotonic()
    with pytest.raises(acme_validation.ValidationFailed) as failed:
        acme_validation.http01('web.lab.internal', 'slow', 'x', port=responder.port,
                               resolve=resolve_for_tests, budget=1)
    assert failed.value.kind == 'connection'
    assert time.monotonic() - started < 2.5


def test_a_body_is_read_no_further_than_8_kib(responder):
    responder.answers['big'] = ('body', b'x' * 20000)
    with pytest.raises(acme_validation.ValidationFailed) as failed:
        acme_validation.http01('web.lab.internal', 'big', 'x' * 20000, port=responder.port, resolve=resolve_for_tests)
    assert failed.value.kind == 'incorrectResponse'


# --- authorizations ---------------------------------------------------------------

def test_a_client_deactivates_its_authorization_and_the_order_fails(client):
    order = _order(client, 'web.lab.internal')
    authz_url, _challenge = _first_challenge(client, order)
    assert client.post(authz_url, {'status': 'deactivated'}).get_json()['status'] == 'deactivated'
    assert client.post(order.headers['Location'], None).get_json()['status'] == 'invalid'
    assert problem(client.post(authz_url, {'status': 'deactivated'}), 'cannot be deactivated') == 'malformed'


def test_an_expired_order_is_invalid_and_its_challenge_cannot_be_answered(app, client, responder):
    order = _order(client, 'web.lab.internal')
    authz_url, challenge = _first_challenge(client, order)
    store = app.extensions['certmate_container'].managers['acme_server'].store
    import sqlite3
    with sqlite3.connect(store.path) as con:
        con.execute("UPDATE orders SET expires = '2020-01-01T00:00:00'")
        con.execute("UPDATE authorizations SET expires = '2020-01-01T00:00:00'")
    assert client.post(order.headers['Location'], None).get_json()['status'] == 'invalid'
    assert client.post(authz_url, None).get_json()['status'] == 'expired'
    _serve(client, responder, challenge)
    assert problem(client.post(challenge['url'], {}), 'no longer pending') == 'malformed'
    assert responder.hosts == []


@pytest.fixture
def tls_responder(tmp_path):
    """An https server with a self-signed certificate that records the SNI it was asked for."""
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'self-signed.invalid')])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    (tmp_path / 'c.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / 'k.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    server = ChallengeServer()
    server.sni = []
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(tmp_path / 'c.pem', tmp_path / 'k.pem')
    context.sni_callback = lambda sock, server_name, ctx: server.sni.append(server_name)
    server.httpd.socket = context.wrap_socket(server.httpd.socket, server_side=True)
    yield server
    server.close()


def test_an_https_redirect_is_followed_to_the_pinned_address_with_the_name_as_sni(responder, tls_responder):
    """The certificate is self-signed and for another name: http-01 does not
    verify it, and the name still reaches the server, in SNI and Host."""
    tls_responder.answers['tok'] = ('body', b'tok.key-authorization')
    responder.answers['tok'] = ('redirect', f'https://web.lab.internal:{tls_responder.port}'
                                            '/.well-known/acme-challenge/tok')
    acme_validation.http01('web.lab.internal', 'tok', 'tok.key-authorization', port=responder.port,
                           https_port=tls_responder.port, resolve=resolve_for_tests)
    assert tls_responder.sni == ['web.lab.internal']
    assert tls_responder.hosts == [f'web.lab.internal:{tls_responder.port}']


def test_an_https_redirect_to_another_port_is_not_followed(responder, tls_responder):
    responder.answers['tok'] = ('redirect', f'https://web.lab.internal:{tls_responder.port}/x/tok')
    with pytest.raises(acme_validation.ValidationFailed) as failed:
        acme_validation.http01('web.lab.internal', 'tok', 'x', port=responder.port, resolve=resolve_for_tests)
    assert failed.value.kind == 'connection' and 'only 80 for http and 443 for https' in failed.value.detail
    assert tls_responder.hosts == []

