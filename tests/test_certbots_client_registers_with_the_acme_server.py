"""certbot's own ACME client registers an account with CertMate's ACME server (#476).

The other tests sign requests by hand to break one rule at a time; this one
lets a real client do it. `acme.client.ClientV2` is the protocol client inside
certbot, pinned in requirements.txt, and it talks to the server over a real
socket: if the directory, the nonces, the JWS checks or the account answers
differ from what a client expects, this is where it shows.

Over plain HTTP on 127.0.0.1, which needs `allow_http`: the test has no TLS in
front of the server. The HTTPS refusal has its own test.
"""
import threading

import josepy
import pytest
from acme import client as acme_client
from acme import errors, messages
from werkzeug.serving import make_server

from modules.core.acme_nonces import NonceStore
from tests import contract_support
from tests.acme_support import ec_key, enable

pytestmark = [pytest.mark.unit]


@pytest.fixture
def served():
    app, _token = contract_support.build_app()
    entry = enable(app, allow_http=True)
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield app, entry, f'http://127.0.0.1:{server.server_port}/acme/directory'
    finally:
        server.shutdown()
        thread.join(timeout=10)


def _client(directory_url, key):
    net = acme_client.ClientNetwork(key, alg=josepy.ES256, user_agent='certmate-tests')
    directory = acme_client.ClientV2.get_directory(directory_url, net)
    return acme_client.ClientV2(directory, net), directory


def test_certbots_client_registers_reads_updates_and_deactivates(served):
    _app, entry, directory_url = served
    key = ec_key()
    client, directory = _client(directory_url, key)
    assert client.external_account_required()

    eab = messages.ExternalAccountBinding.from_data(key.public_key(), entry['kid'], entry['hmac_key'], directory)
    regr = client.new_account(messages.NewRegistration.from_data(
        email='ops@lab.internal', terms_of_service_agreed=True, external_account_binding=eab))
    assert regr.body.status == 'valid'
    assert regr.uri.startswith(directory_url.replace('/directory', '/account/'))
    assert client.query_registration(regr).body.contact == ('mailto:ops@lab.internal',)

    updated = client.update_registration(regr, regr.body.update(contact=('mailto:pki@lab.internal',)))
    assert updated.body.contact == ('mailto:pki@lab.internal',)

    # A client that lost its account URL registers again with the same key and
    # is pointed at the account it has. A fresh ClientNetwork, because one that
    # knows its account signs with kid, and new-account takes jwk (section 6.2).
    again, _ = _client(directory_url, key)
    with pytest.raises(errors.ConflictError) as found:
        again.new_account(messages.NewRegistration.from_data(
            email='ops@lab.internal', terms_of_service_agreed=True, external_account_binding=eab))
    assert found.value.location == regr.uri

    assert client.deactivate_registration(updated).body.status == 'deactivated'


def test_certbots_client_recovers_from_a_restart_that_forgot_its_nonce(served):
    """A restart forgets every nonce. The client's next POST gets badNonce
    with a fresh one in Replay-Nonce, and certbot's client retries with it."""
    app, entry, directory_url = served
    key = ec_key()
    client, directory = _client(directory_url, key)
    eab = messages.ExternalAccountBinding.from_data(key.public_key(), entry['kid'], entry['hmac_key'], directory)
    regr = client.new_account(messages.NewRegistration.from_data(
        email='ops@lab.internal', terms_of_service_agreed=True, external_account_binding=eab))

    app.extensions['certmate_container'].managers['acme_server'].nonces = NonceStore()
    assert client.query_registration(regr).body.status == 'valid'


def test_certbots_client_is_told_without_an_eab(served):
    _app, _entry, directory_url = served
    client, _directory = _client(directory_url, ec_key())
    with pytest.raises(messages.Error) as refused:
        client.new_account(messages.NewRegistration.from_data(
            email='ops@lab.internal', terms_of_service_agreed=True))
    assert refused.value.code == 'externalAccountRequired'


def test_certbots_client_orders_and_proves_its_names_with_http01(served):
    """The order half, as certbot runs it: an order from a CSR, one http-01
    answer per authorization, then polling until every one is valid."""
    import datetime

    from acme import challenges, crypto_util
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from tests.test_the_acme_server_validates_orders import ChallengeServer, _test_resolver

    app, entry, directory_url = served
    responder = ChallengeServer()
    try:
        server = app.extensions['certmate_container'].managers['acme_server']
        server.http01_port = responder.port
        server.resolve = _test_resolver
        key = ec_key()
        client, directory = _client(directory_url, key)
        eab = messages.ExternalAccountBinding.from_data(key.public_key(), entry['kid'], entry['hmac_key'], directory)
        client.new_account(messages.NewRegistration.from_data(
            email='ops@lab.internal', terms_of_service_agreed=True, external_account_binding=eab))

        names = ['web.lab.internal', 'api.lab.internal']
        cert_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        orderr = client.new_order(crypto_util.make_csr(cert_key, names))
        assert sorted(a.body.identifier.value for a in orderr.authorizations) == sorted(names)

        for authzr in orderr.authorizations:
            challb = next(c for c in authzr.body.challenges if isinstance(c.chall, challenges.HTTP01))
            response, validation = challb.chall.response_and_validation(key)
            responder.answers[challb.chall.encode('token')] = ('body', validation.encode())
            client.answer_challenge(challb, response)

        deadline = datetime.datetime.now() + datetime.timedelta(seconds=30)
        orderr = client.poll_authorizations(orderr, deadline)
        assert [a.body.status for a in orderr.authorizations] == [messages.STATUS_VALID] * 2
        assert sorted(responder.hosts) == sorted(f'{n}:{responder.port}' for n in names)
    finally:
        responder.close()
