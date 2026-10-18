"""The ACME server limits the requests one address makes (#476).

Up to the account, /acme/ answers without authentication: the directory,
nonces, the root, the CRL, renewal information. Every answer carries a fresh
nonce, so an address with no limit could fill the nonce store and push out
the nonces of clients in the middle of an order. The /api/ limiter's switch
and table cover /acme/ too, in a bucket of its own per address, `acme`, 300
requests a minute by default: lego registered and got a certificate in 8
requests and acme.sh in 11 (tests/interop/run.sh).
"""
import pytest

from tests import contract_support
from tests.acme_support import BASE, enable, problem

pytestmark = [pytest.mark.unit]


@pytest.fixture
def app():
    application, token = contract_support.build_app()
    application.extensions['certmate_test_token'] = token
    enable(application)
    return application


def _limit(app, limit, enabled=True):
    app.extensions['certmate_container'].managers['settings'].update(
        lambda s: s.__setitem__('rate_limits', {'enabled': enabled, 'limits': {'acme': limit}}))


def _directory(app, address='127.0.0.1'):
    return app.test_client().get(BASE + '/acme/directory', environ_base={'REMOTE_ADDR': address})


def _nonces(app):
    return len(app.extensions['certmate_container'].managers['acme_server'].nonces._issued)


def test_an_address_over_the_limit_is_told_rate_limited_and_when_to_retry(app):
    _limit(app, 3)
    assert [_directory(app).status_code for _ in range(3)] == [200, 200, 200]
    issued = _nonces(app)
    refused = _directory(app)
    assert refused.status_code == 429
    assert problem(refused, 'More than 3 requests a minute') == 'rateLimited'
    assert refused.headers['Retry-After'] == '60'
    # A refusal for the limit mints no nonce: the store is what the limit protects.
    assert 'Replay-Nonce' not in refused.headers and _nonces(app) == issued


def test_every_acme_route_counts_against_the_same_bucket(app):
    _limit(app, 2)
    client = app.test_client()
    assert client.head(BASE + '/acme/new-nonce').status_code == 200
    assert client.get(BASE + '/acme/root').status_code == 200
    assert client.get(BASE + '/acme/crl').status_code == 429


def test_another_address_has_a_bucket_of_its_own(app):
    _limit(app, 1)
    assert _directory(app).status_code == 200
    assert _directory(app).status_code == 429
    assert _directory(app, '10.0.0.7').status_code == 200


def test_the_rate_limit_switch_turns_it_off(app):
    _limit(app, 1, enabled=False)
    assert {_directory(app).status_code for _ in range(5)} == {200}


def test_the_default_is_300_a_minute_and_an_admin_sees_it(app):
    token = app.extensions['certmate_test_token']
    answer = app.test_client().get('/api/settings/rate-limits', headers={'Authorization': f'Bearer {token}'})
    assert answer.status_code == 200
    assert answer.get_json()['defaults']['acme'] == 300 and answer.get_json()['limits']['acme'] == 300
