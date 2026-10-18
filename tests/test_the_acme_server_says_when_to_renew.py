"""ACME Renewal Information on CertMate's ACME server (RFC 9773, #476 decision I3).

The server tells a client when to renew each certificate: between two thirds
and five sixths of its lifetime, and at once when it was revoked, so a client
that asks (certbot and lego do) replaces a revoked certificate on its next
run with nobody touching it. A new order can say which certificate it
replaces; that one must be the account's own and not replaced already.

The identifier is computed the way certbot's client computes it, by its own
function, so the two cannot drift apart unnoticed.
"""
import datetime
import json
import sqlite3
import threading

import josepy
import pytest
from acme import client as acme_client
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from werkzeug.serving import make_server

from tests.acme_support import (
    AcmeTestClient,
    ChallengeServer,
    b64s,
    eab_for,
    enable,
    problem,
    registered_client,
    served_app,
)
from tests.test_the_acme_server_issues_and_revokes import _issue

pytestmark = [pytest.mark.unit]


def _ari_id(cert):
    return acme_client._renewal_info_path_component(cert)


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


def _leaf(pem_response):
    return x509.load_pem_x509_certificate(pem_response.data)


def _window(client, cert):
    response = client.http.get(client.url('renewal-info/' + _ari_id(cert)))
    assert response.status_code == 200, response.get_data(as_text=True)
    window = response.get_json()['suggestedWindow']
    parse = lambda s: datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))  # noqa: E731
    return parse(window['start']), parse(window['end']), response


def test_the_directory_names_renewal_info(client):
    assert client.http.get(client.url('directory')).get_json()['renewalInfo'] == client.url('renewal-info')


def test_the_window_runs_from_two_thirds_to_five_sixths_of_the_lifetime(client, responder):
    _, _, pem, _ = _issue(client, responder, ('web.lab.internal',))
    cert = _leaf(pem)
    start, end, response = _window(client, cert)
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert abs(start - (cert.not_valid_before_utc + lifetime * 2 / 3)) < datetime.timedelta(seconds=1)
    assert abs(end - (cert.not_valid_before_utc + lifetime * 5 / 6)) < datetime.timedelta(seconds=1)
    assert cert.not_valid_after_utc - end >= datetime.timedelta(days=7)  # a week or more still left at 45 days
    assert response.headers['Retry-After'] == str(6 * 3600)


def test_a_revoked_certificate_is_to_be_renewed_now(client, responder):
    _, _, pem, _ = _issue(client, responder, ('web.lab.internal',))
    cert = _leaf(pem)
    revoked = client.post('revoke-cert', {'certificate': b64s(cert.public_bytes(serialization.Encoding.DER))})
    assert revoked.status_code == 200
    start, end, _ = _window(client, cert)
    now = datetime.datetime.now(datetime.UTC)
    # Wholly in the past: a client picks a moment inside it, and every one has passed.
    assert start < end <= now
    assert now - end < datetime.timedelta(minutes=1)


@pytest.mark.parametrize('cert_id,status', [
    ('not-an-identifier', 400),
    ('AAAA.AQ', 404),
])
def test_an_identifier_that_names_nothing_here_is_refused(client, responder, cert_id, status):
    _issue(client, responder, ('web.lab.internal',))
    response = client.http.get(client.url('renewal-info/' + cert_id))
    assert response.status_code == status and problem(response) == 'malformed'


def test_a_server_that_issued_nothing_answers_404_and_makes_no_root(app, client):
    response = client.http.get(client.url('renewal-info/AAAA.AQ'))
    assert response.status_code == 404
    assert not app.extensions['certmate_container'].managers['acme_server'].ca.generator.ca_key_path.exists()


# --- certbot's client, with its own identifier and its own choice of moment ------------

@pytest.fixture
def served(app, eab, responder):
    enable(app, allow_http=True, eab_keys=[eab])
    server = make_server('127.0.0.1', 0, app, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}/acme/directory'
    finally:
        server.shutdown()
        thread.join(timeout=10)


def test_certbots_client_picks_a_moment_inside_the_window(app, eab, responder, served):
    acme = AcmeTestClient(app, base=served.rsplit('/acme/', 1)[0])
    assert acme.new_account(eab).status_code == 201
    _, _, pem, _ = _issue(acme, responder, ('web.lab.internal',))
    cert = _leaf(pem)
    net = acme_client.ClientNetwork(acme.key, alg=josepy.ES256, user_agent='certmate-tests')
    certbot = acme_client.ClientV2(acme_client.ClientV2.get_directory(served, net), net)
    when, ask_again = certbot.renewal_time(pem.data)
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert cert.not_valid_before_utc + lifetime * 2 / 3 - datetime.timedelta(seconds=1) <= when
    assert when <= cert.not_valid_before_utc + lifetime * 5 / 6 + datetime.timedelta(seconds=1)
    assert ask_again - datetime.datetime.now() > datetime.timedelta(hours=5)


def test_certbots_client_renews_a_revoked_certificate_at_once(app, eab, responder, served):
    """It picks a moment inside the window; inside a window that is still open,
    that moment was most often a few seconds ahead, and a run by cron skipped."""
    acme = AcmeTestClient(app, base=served.rsplit('/acme/', 1)[0])
    assert acme.new_account(eab).status_code == 201
    _, _, pem, _ = _issue(acme, responder, ('web.lab.internal',))
    cert = _leaf(pem)
    assert acme.post('revoke-cert', {'certificate': b64s(cert.public_bytes(serialization.Encoding.DER))}).status_code == 200
    net = acme_client.ClientNetwork(acme.key, alg=josepy.ES256, user_agent='certmate-tests')
    certbot = acme_client.ClientV2(acme_client.ClientV2.get_directory(served, net), net)
    for _ in range(5):  # a random moment each time
        when, _ask_again = certbot.renewal_time(pem.data)
        assert when <= datetime.datetime.now(datetime.UTC)


# --- replaces (RFC 9773 section 5) --------------------------------------------------------

def _replacing_order(client, cert, name='web.lab.internal'):
    return client.post('new-order', {'identifiers': [{'type': 'dns', 'value': name}], 'replaces': _ari_id(cert)})


def test_an_order_says_which_certificate_it_replaces_once(client, responder):
    _, _, pem, _ = _issue(client, responder, ('web.lab.internal',))
    cert = _leaf(pem)
    first = _replacing_order(client, cert)
    assert first.status_code == 201 and first.get_json()['replaces'] == _ari_id(cert)
    assert problem(_replacing_order(client, cert), 'replaces that certificate already') == 'alreadyReplaced'


def test_a_failed_replacement_leaves_the_certificate_to_replace_again(client, responder):
    _, _, pem, _ = _issue(client, responder, ('web.lab.internal',))
    cert = _leaf(pem)
    first = _replacing_order(client, cert)
    authz = client.post(first.get_json()['authorizations'][0], None).get_json()
    client.post(authz['challenges'][0]['url'], {})  # nothing served: the challenge fails
    assert client.post(first.headers['Location'], None).get_json()['status'] == 'invalid'
    assert _replacing_order(client, cert).status_code == 201


def test_another_accounts_certificate_is_not_replaced(app, eab, client, responder):
    _, _, pem, _ = _issue(client, responder, ('web.lab.internal',))
    other = registered_client(app, eab)
    assert problem(_replacing_order(other, _leaf(pem)), 'another account') == 'unauthorized'


def test_replaces_must_name_a_certificate_of_this_server(client):
    response = client.post('new-order', {'identifiers': [{'type': 'dns', 'value': 'web.lab.internal'}],
                                         'replaces': 'AAAA.AQ'})
    assert problem(response, 'no certificate this server issued') == 'malformed'


def test_a_database_from_before_replaces_gets_the_column(tmp_path):
    from modules.core.acme_store import AcmeStore
    path = tmp_path / 'acme.db'
    with sqlite3.connect(path) as con:
        con.execute('CREATE TABLE orders (id TEXT PRIMARY KEY, account_id TEXT NOT NULL, status TEXT NOT NULL, '
                    'expires TEXT NOT NULL, identifiers TEXT NOT NULL, error TEXT, created_at TEXT NOT NULL)')
    store = AcmeStore(path)
    order = store.create_order('acct', [{'type': 'dns', 'value': 'web.lab.internal'}], '2099-01-01T00:00:00',
                               replaces='cert-id')
    assert order['replaces'] == 'cert-id'
    assert json.loads(json.dumps(order['identifiers'])) == [{'type': 'dns', 'value': 'web.lab.internal'}]


def test_a_serial_of_ours_under_another_cas_key_identifier_is_not_ours(client, responder):
    _, _, pem, _ = _issue(client, responder, ('web.lab.internal',))
    own = _ari_id(_leaf(pem))
    foreign = 'AAAAAAAAAAAAAAAAAAAAAAAAAAA.' + own.split('.')[1]
    assert client.http.get(client.url('renewal-info/' + own)).status_code == 200
    assert client.http.get(client.url('renewal-info/' + foreign)).status_code == 404
