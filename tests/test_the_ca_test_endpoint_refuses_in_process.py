"""`POST /api/settings/test-ca-provider` refusals, exercised without Docker.

`tests/test_ca_provider_test_endpoint.py` covers this endpoint well, and every
test in it is marked `e2e` — it drives a running container through the `api`
fixture. The coverage gate runs `-m unit`, so none of that reaches the
per-module floor, and a branch can be thoroughly tested and still read as
uncovered.

That is how adding Sectigo took `modules/api/resources_ca.py` from 85% to
84.3% and failed the build with every one of its own tests passing.

So this file drives the same endpoint in-process. It is not a replacement for
the e2e file — that one proves the endpoint works in the image, which no
in-process client can — it covers the *refusal* paths, which need no network
and no container, and which are the ones a floor is most likely to catch
falling.
"""
import secrets

import pytest

pytestmark = [pytest.mark.unit]

TOKEN = secrets.token_urlsafe(32)


@pytest.fixture(scope='module')
def client(tmp_path_factory):
    """The real app with a bearer token, so the instance is not in setup mode
    and the endpoint is reached through its actual auth path."""
    import os

    tmp_path = tmp_path_factory.mktemp('ca-endpoint')
    with pytest.MonkeyPatch.context() as patch:
        for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                         ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
            (tmp_path / sub).mkdir(exist_ok=True)
            patch.setenv(var, str(tmp_path / sub))
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('TESTING', 'true')
        patch.setenv('API_BEARER_TOKEN', TOKEN)
        os.environ['API_BEARER_TOKEN'] = TOKEN
        from modules.core.factory import create_app
        application, _ = create_app()
        yield application.test_client()


def _test_ca(client, ca_provider, config):
    return client.post('/api/settings/test-ca-provider',
                       json={'ca_provider': ca_provider, 'config': config},
                       headers={'Authorization': f'Bearer {TOKEN}',
                                'Origin': 'http://localhost'})


SECTIGO_OK = {'acme_url': 'https://acme.sectigo.com/v2/OV',
              'eab_kid': 'example-kid', 'eab_hmac': 'example-secret',
              'email': 'ops@example.com'}


def test_the_endpoint_is_reachable_at_all(client):
    """Guard the guard: a 401 or a 404 here would make every refusal below
    pass for the wrong reason."""
    response = _test_ca(client, 'sectigo', dict(SECTIGO_OK))
    assert response.status_code not in (401, 403, 404), response.get_data(as_text=True)


@pytest.mark.parametrize('bad_url', [
    'http://acme.sectigo.com/v2/OV',     # plain HTTP
    'HTTP://acme.sectigo.com/v2/OV',     # and it is still HTTP in capitals
])
def test_plain_http_is_refused_as_plain_http(client, bad_url):
    """The branch this PR added: a provider whose directory comes from the
    account validates it before claiming the connection is fine."""
    body = _test_ca(client, 'sectigo', {**SECTIGO_OK, 'acme_url': bad_url}).get_json()
    assert body.get('success') is False, body
    assert body.get('ca_provider') == 'sectigo'
    assert 'https' in (body.get('message') or '').lower()


def test_something_that_is_not_a_url_is_refused_as_malformed(client):
    """Separate from the case above on purpose. An operator whose URL is
    plain HTTP must be told to use https; one who typed nonsense must be told
    the format is wrong. The first version of this test lumped the two
    together and demanded the https wording for both, which would have
    accepted a validator that could no longer tell them apart."""
    body = _test_ca(client, 'sectigo', {**SECTIGO_OK, 'acme_url': 'not-a-url'}).get_json()
    assert body.get('success') is False, body
    assert 'format' in (body.get('message') or '').lower()
    assert 'https' not in (body.get('message') or '').lower()


@pytest.mark.parametrize('missing', ['acme_url', 'eab_kid', 'eab_hmac'])
def test_a_missing_field_is_named(client, missing):
    config = {k: v for k, v in SECTIGO_OK.items() if k != missing}
    body = _test_ca(client, 'sectigo', config).get_json()
    assert body.get('success') is False, body
    assert body.get('message')


def test_an_unknown_provider_is_refused(client):
    """The `else` at the end of the dispatch. Reached by nothing else in the
    unit suite, and it is the branch that decides whether a typo in the UI
    reads as a failed connection or as a bad request."""
    response = _test_ca(client, 'not-a-real-ca', dict(SECTIGO_OK))
    assert response.status_code == 400
    assert 'Invalid CA provider type' in response.get_data(as_text=True)


def test_the_hmac_never_comes_back(client):
    """Stated here as well as in the e2e file, because this is the assertion
    that must hold on every path, including the refusals above."""
    for config in (dict(SECTIGO_OK),
                   {**SECTIGO_OK, 'acme_url': 'http://acme.sectigo.com/v2/OV'}):
        text = _test_ca(client, 'sectigo', config).get_data(as_text=True)
        assert 'example-secret' not in text
