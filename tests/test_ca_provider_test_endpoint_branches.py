"""What `POST /api/ca/test` actually answers, per provider (#662).

This endpoint was the least-covered code in the project — 11%, 99 of its 111
statements never executed by the gated suite. It is the button an operator
presses before trusting a certificate authority with their issuance, so what it
says matters: a "configuration appears valid" that is not, or a refusal that
does not name what is missing, both cost an operator a failed issuance and a
confusing log.

Every branch is exercised through the built resource rather than through the
helper functions, because the branch structure IS the behaviour here — the
endpoint is almost entirely a decision tree over provider and config shape.

Reaching it needed the whole manager graph until #667; it is now one factory
call.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api

from modules.api.resource_context import ApiContext
from modules.api.resources_ca import create_ca_resources

pytestmark = [pytest.mark.unit]

CA_PROVIDERS = {
    'letsencrypt': {'name': "Let's Encrypt",
                    'production_url': 'https://acme-v02.api.letsencrypt.org/directory'},
    'letsencrypt_staging': {'name': "Let's Encrypt Staging",
                            'production_url': 'https://acme-staging-v02.api.letsencrypt.org/directory'},
    'zerossl': {'name': 'ZeroSSL', 'production_url': 'https://acme.zerossl.com/v2/DV90'},
    'google': {'name': 'Google Trust Services',
               'production_url': 'https://dv.acme-v02.api.pki.goog/directory'},
    'sslcom': {'name': 'SSL.com', 'production_url': 'https://acme.ssl.com/sslcom-dv-rsa'},
    'actalis': {'name': 'Actalis', 'production_url': 'https://acme-api.actalis.com/acme/directory'},
}

VALID_EAB = {'eab_kid': 'a-key-id-long-enough',
             'eab_hmac': 'a' * 40,
             'email': 'ops@example.com'}


@pytest.fixture
def endpoint():
    """The CA test resource, built with a stub CA manager and nothing else."""
    ca_manager = MagicMock()
    ca_manager.ca_providers = CA_PROVIDERS

    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    ctx = ApiContext(
        auth=auth, settings=MagicMock(), certificates=None, file_ops=None,
        cache=None, dns=None, deployer=None, audit=None, cert_service=None,
        cert_executor=None, managers={'ca': ca_manager})

    app = Flask(__name__)
    api = Api(app, prefix='/api')
    resource = create_ca_resources(
        api, {'ca_test_config_model': MagicMock()}, ctx)['CAProviderTest']
    return app, resource


def _post(endpoint, payload):
    app, resource = endpoint
    with app.test_request_context('/', json=payload):
        return resource().post()


def _body(result):
    return result[0] if isinstance(result, tuple) else result


# ---------------------------------------------------------------------------
# Let's Encrypt: email only, because the directory is pinned per entry
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('provider', ['letsencrypt', 'letsencrypt_staging'])
def test_lets_encrypt_accepts_an_email(endpoint, provider):
    body = _body(_post(endpoint, {'ca_provider': provider,
                                  'config': {'email': 'ops@example.com'}}))
    assert body['success'] is True
    assert body['ca_provider'] == provider
    assert body['directory_url'] == CA_PROVIDERS[provider]['production_url'], (
        'staging and production must not report the same directory — they are '
        'separate CAs, and issuing against the wrong one is a wasted rate limit '
        'or an untrusted certificate'
    )


@pytest.mark.parametrize('provider', ['letsencrypt', 'letsencrypt_staging'])
def test_lets_encrypt_without_an_email_says_so(endpoint, provider):
    body = _body(_post(endpoint, {'ca_provider': provider, 'config': {}}))
    assert body['success'] is False
    assert 'email' in body['message'].lower()


# ---------------------------------------------------------------------------
# DigiCert: ACME URL + EAB + email, and the EAB has to look like one
# ---------------------------------------------------------------------------

DIGICERT_OK = {'acme_url': 'https://acme.digicert.com/v2/acme/directory',
               **VALID_EAB}


def test_digicert_accepts_a_complete_configuration(endpoint):
    body = _body(_post(endpoint, {'ca_provider': 'digicert',
                                  'config': dict(DIGICERT_OK)}))
    assert body['success'] is True
    assert body['acme_url'] == DIGICERT_OK['acme_url']


@pytest.mark.parametrize('missing,expected', [
    ('acme_url', 'acme url'),
    ('eab_kid', 'eab'),
    ('eab_hmac', 'eab'),
    ('email', 'email'),
])
def test_digicert_names_the_missing_field(endpoint, missing, expected):
    """A refusal that does not say what is missing sends the operator hunting."""
    config = dict(DIGICERT_OK)
    config.pop(missing)
    body = _body(_post(endpoint, {'ca_provider': 'digicert', 'config': config}))

    assert body['success'] is False
    assert expected in body['message'].lower(), (
        f'removing {missing} produced {body["message"]!r}, which does not name it'
    )


@pytest.mark.parametrize('field,value', [
    ('eab_kid', 'short'),
    ('eab_hmac', 'a' * 31),
])
def test_digicert_rejects_eab_credentials_that_are_too_short(
        endpoint, field, value):
    config = dict(DIGICERT_OK)
    config[field] = value
    body = _body(_post(endpoint, {'ca_provider': 'digicert', 'config': config}))
    assert body['success'] is False
    assert 'short' in body['message'].lower()


def test_digicert_accepts_the_other_eab_field_spelling(endpoint):
    """The settings form posts eab_key_id/eab_hmac_key here and eab_kid/eab_hmac
    elsewhere; both are accepted on purpose, so both are pinned."""
    body = _body(_post(endpoint, {'ca_provider': 'digicert', 'config': {
        'acme_url': DIGICERT_OK['acme_url'],
        'eab_key_id': 'a-key-id-long-enough',
        'eab_hmac_key': 'a' * 40,
        'email': 'ops@example.com',
    }}))
    assert body['success'] is True


# ---------------------------------------------------------------------------
# The fixed-directory EAB CAs, which share one shape
# ---------------------------------------------------------------------------

EAB_PROVIDERS = ['zerossl', 'google', 'sslcom', 'actalis']


@pytest.mark.parametrize('provider', EAB_PROVIDERS)
def test_a_fixed_directory_ca_accepts_eab_and_email(endpoint, provider):
    body = _body(_post(endpoint, {'ca_provider': provider,
                                  'config': dict(VALID_EAB)}))
    assert body['success'] is True
    assert body['acme_url'] == CA_PROVIDERS[provider]['production_url'], (
        'the ACME URL is pinned per CA; reporting the wrong one would send '
        'issuance to a different authority than the operator tested'
    )
    assert CA_PROVIDERS[provider]['name'] in body['message']


@pytest.mark.parametrize('provider', EAB_PROVIDERS)
@pytest.mark.parametrize('missing', ['eab_kid', 'email'])
def test_a_fixed_directory_ca_names_what_is_missing(endpoint, provider, missing):
    config = dict(VALID_EAB)
    config.pop(missing)
    body = _body(_post(endpoint, {'ca_provider': provider, 'config': config}))

    assert body['success'] is False
    assert CA_PROVIDERS[provider]['name'] in body['message'], (
        'the refusal must name the provider it is about — these four share a '
        'code path and an operator has usually configured more than one'
    )


# ---------------------------------------------------------------------------
# Private CA: the only branch that actually reaches the network
# ---------------------------------------------------------------------------

PRIVATE_OK = {'acme_url': 'https://ca.internal/acme/directory',
              'email': 'ops@example.com'}
PEM = ('-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----')


def _directory_response(status=200, payload=None, raises_json=False):
    response = MagicMock()
    response.status_code = status
    if raises_json:
        response.json.side_effect = ValueError('not json')
    else:
        response.json.return_value = payload if payload is not None else {
            'newAccount': 'https://ca.internal/acme/new-acct',
            'keyChange': 'https://ca.internal/acme/key-change',
        }
    return response


@pytest.mark.parametrize('missing,expected', [
    ('acme_url', 'acme url'),
    ('email', 'email'),
])
def test_private_ca_names_the_missing_field(endpoint, missing, expected):
    config = dict(PRIVATE_OK)
    config.pop(missing)
    body = _body(_post(endpoint, {'ca_provider': 'private_ca', 'config': config}))
    assert body['success'] is False
    assert expected in body['message'].lower()


def test_private_ca_requires_an_http_url(endpoint):
    """A bare hostname would be handed straight to requests and fail obscurely."""
    body = _body(_post(endpoint, {'ca_provider': 'private_ca', 'config': {
        **PRIVATE_OK, 'acme_url': 'ca.internal/acme/directory'}}))
    assert body['success'] is False
    assert 'http' in body['message'].lower()


def test_private_ca_rejects_a_ca_cert_that_is_not_pem(endpoint):
    body = _body(_post(endpoint, {'ca_provider': 'private_ca', 'config': {
        **PRIVATE_OK, 'ca_cert': 'this is not a certificate'}}))
    assert body['success'] is False
    assert 'pem' in body['message'].lower()


def test_private_ca_accepts_a_real_acme_directory(endpoint, monkeypatch):
    import requests

    monkeypatch.setattr(requests, 'get',
                        lambda *a, **k: _directory_response())
    body = _body(_post(endpoint, {'ca_provider': 'private_ca',
                                  'config': dict(PRIVATE_OK)}))
    assert body['success'] is True
    assert body['has_ca_cert'] is False
    assert 'newAccount' in body['urls']


def test_private_ca_refuses_a_url_that_is_not_an_acme_directory(
        endpoint, monkeypatch):
    """Reachable is not the same as correct: pointing this at a web server
    returns 200 and no ACME keys, and calling that valid would send issuance
    somewhere that cannot answer."""
    import requests

    monkeypatch.setattr(requests, 'get',
                        lambda *a, **k: _directory_response(payload={'hello': 'world'}))
    body = _body(_post(endpoint, {'ca_provider': 'private_ca',
                                  'config': dict(PRIVATE_OK)}))
    assert body['success'] is False
    assert 'acme directory' in body['message'].lower()


def test_private_ca_reports_a_non_json_body(endpoint, monkeypatch):
    import requests

    monkeypatch.setattr(requests, 'get',
                        lambda *a, **k: _directory_response(raises_json=True))
    body = _body(_post(endpoint, {'ca_provider': 'private_ca',
                                  'config': dict(PRIVATE_OK)}))
    assert body['success'] is False
    assert 'json' in body['message'].lower()


def test_private_ca_reports_the_http_status(endpoint, monkeypatch):
    import requests

    monkeypatch.setattr(requests, 'get',
                        lambda *a, **k: _directory_response(status=404))
    body = _body(_post(endpoint, {'ca_provider': 'private_ca',
                                  'config': dict(PRIVATE_OK)}))
    assert body['success'] is False
    assert '404' in body['message']


@pytest.mark.parametrize('failure,expected', [
    ('Timeout', 'timeout'),
    ('ConnectionError', 'not accessible'),
])
def test_private_ca_translates_a_network_failure(
        endpoint, monkeypatch, failure, expected):
    """These messages are the whole value of the button: an operator needs to
    know whether the host is unreachable, slow, or presenting a bad chain."""
    import requests

    def _raise(*_a, **_k):
        raise getattr(requests.exceptions, failure)()

    monkeypatch.setattr(requests, 'get', _raise)
    body = _body(_post(endpoint, {'ca_provider': 'private_ca',
                                  'config': dict(PRIVATE_OK)}))
    assert body['success'] is False
    assert expected in body['message'].lower()


@pytest.mark.parametrize('ca_cert,hint', [
    ('', 'provide ca cert'),
    (PEM, 'could not verify'),
])
def test_an_ssl_failure_hint_depends_on_whether_a_ca_cert_was_given(
        endpoint, monkeypatch, ca_cert, hint):
    """Two different problems that look identical without the distinction:
    no trust anchor supplied, versus one supplied that does not verify."""
    import requests

    def _raise(*_a, **_k):
        raise requests.exceptions.SSLError()

    monkeypatch.setattr(requests, 'get', _raise)
    config = dict(PRIVATE_OK)
    if ca_cert:
        config['ca_cert'] = ca_cert
    body = _body(_post(endpoint, {'ca_provider': 'private_ca', 'config': config}))

    assert body['success'] is False
    assert hint in body['message'].lower()


def test_a_missing_ca_manager_is_a_503_not_a_crash(endpoint):
    """The manager is optional in the context; the endpoint must degrade."""
    app, resource = endpoint
    # Rebuild with no CA manager at all.
    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    ctx = ApiContext(
        auth=auth, settings=MagicMock(), certificates=None, file_ops=None,
        cache=None, dns=None, deployer=None, audit=None, cert_service=None,
        cert_executor=None, managers={})
    api = Api(Flask(__name__), prefix='/api')
    bare = create_ca_resources(
        api, {'ca_test_config_model': MagicMock()}, ctx)['CAProviderTest']

    with app.test_request_context('/', json={'ca_provider': 'letsencrypt',
                                             'config': {}}):
        result = bare().post()
    assert result[1] == 503
