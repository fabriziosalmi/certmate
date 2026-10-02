"""`/api/dns-providers/accounts/<id>` has no provider in it, and must not guess one (#1088).

Two paths reach the same handler without a provider in the URL: the deprecated
`/api/dns-providers/accounts/<account_id>` that docs/api.md says keeps answering until
its sunset, and the dashboard's `/api/web/settings/accounts/<account_id>`. The handler
ran with `provider=None`:

  * DELETE answered 500 for an account that exists, and left it there;
  * PUT answered 200 "Account updated" without touching the account. It created a new
    one under a provider called `null` (a `None` key, which JSON writes as "null"),
    holding whatever the caller sent, for an id that did not exist too; and the
    pre-save backup failed on the same `None`.

The id alone names an account only when exactly one provider has it. These tests pin
that: the provider is found when it is unambiguous, a request that names nothing is a
404, one that names several is a 409 that says which path is not ambiguous, and
NOTHING is written in either refusal. The provider-qualified forms, which the
dashboard, the SDK and the MCP server use, are unchanged.
"""
import copy
import pathlib
import secrets
import tempfile
from types import SimpleNamespace

import pytest

pytestmark = [pytest.mark.unit]

ALIAS = '/api/dns-providers/accounts'
DASHBOARD = '/api/web/settings/accounts'


@pytest.fixture(scope='module')
def instance():
    root = pathlib.Path(tempfile.mkdtemp()) / 'certmate'
    module_dir = root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    anchor = module_dir / 'factory.py'
    anchor.write_text('# test path anchor\n', encoding='utf-8')
    token = secrets.token_urlsafe(32)

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv('TESTING', 'true')
        patch.setenv('FLASK_ENV', 'testing')
        patch.setenv('API_BEARER_TOKEN', token)
        from modules.factory import create_app
        patch.setattr('modules.factory.__file__', str(anchor))
        result = create_app()
    app, container = result[0], result[1]
    return SimpleNamespace(client=app.test_client(), settings=container.managers['settings'],
                           headers={'Authorization': f'Bearer {token}'})


def _create(instance, provider, name, secret):
    response = instance.client.post(
        ALIAS, headers=instance.headers,
        json={'name': name, 'provider': provider, 'config': {'api_token': secret}})
    assert response.status_code == 200, response.get_json()


def _owners(instance, account_id):
    listed = instance.client.get('/api/dns/accounts', headers=instance.headers).get_json()
    return sorted(a['provider'] for a in listed if a['account_id'] == account_id)


def _stored(instance):
    """Every provider's accounts as they sit in settings, which is where a write under a
    provider that does not exist would be found."""
    return copy.deepcopy(instance.settings.load_settings().get('dns_providers', {}))


def _token(instance, provider, name):
    return _stored(instance)[provider]['accounts'][name]['api_token']


def _unique(prefix):
    return f'{prefix}-{secrets.token_hex(4)}'


# --------------------------------------------------------------------------
# What works: the id names one account, so the provider is known.
# --------------------------------------------------------------------------

@pytest.mark.parametrize('base', [ALIAS, DASHBOARD], ids=['deprecated-alias', 'dashboard-path'])
def test_a_delete_finds_the_account_and_removes_only_it(instance, base):
    name = _unique('del')
    keep = _unique('keep')
    _create(instance, 'cloudflare', name, 'x' * 24)
    _create(instance, 'cloudflare', keep, 'x' * 24)

    response = instance.client.delete(f'{base}/{name}', headers=instance.headers)

    assert response.status_code == 200, response.get_json()
    assert _owners(instance, name) == []
    assert _owners(instance, keep) == ['cloudflare']


@pytest.mark.parametrize('base', [ALIAS, DASHBOARD], ids=['deprecated-alias', 'dashboard-path'])
def test_a_put_updates_the_account_where_it_lives(instance, base):
    name = _unique('put')
    _create(instance, 'cloudflare', name, 'a' * 24)

    response = instance.client.put(f'{base}/{name}', headers=instance.headers,
                                   json={'api_token': 'b' * 24})

    assert response.status_code == 200, response.get_json()
    assert response.get_json()['id'] == name
    assert _owners(instance, name) == ['cloudflare']
    assert _token(instance, 'cloudflare', name) == 'b' * 24
    assert set(_stored(instance)) <= {'cloudflare', 'route53', 'azure', 'google', 'powerdns',
                                      'digitalocean', 'linode', 'edgedns', 'gandi', 'ovh',
                                      'namecheap', 'arvancloud', 'infomaniak', 'acme-dns',
                                      'duckdns', 'hetzner-cloud', 'hetzner', 'multi',
                                      'dnsmadeeasy', 'dynudns', 'godaddy', 'he-ddns', 'nsone',
                                      'porkbun', 'rfc2136', 'vultr'}, 'a provider that is not one appeared'


# --------------------------------------------------------------------------
# What is refused: and nothing is written.
# --------------------------------------------------------------------------

@pytest.mark.parametrize('base', [ALIAS, DASHBOARD], ids=['deprecated-alias', 'dashboard-path'])
@pytest.mark.parametrize('verb', ['put', 'delete'])
def test_an_id_that_names_nothing_is_a_404_and_writes_nothing(instance, base, verb):
    ghost = _unique('ghost')
    before = _stored(instance)

    kwargs = {'json': {'api_token': 'c' * 24}} if verb == 'put' else {}
    response = getattr(instance.client, verb)(f'{base}/{ghost}', headers=instance.headers, **kwargs)

    assert response.status_code == 404, response.get_json()
    assert ghost in response.get_json()['error']
    assert _stored(instance) == before
    assert _owners(instance, ghost) == []
    assert 'null' not in _stored(instance) and 'None' not in _stored(instance)


@pytest.mark.parametrize('base', [ALIAS, DASHBOARD], ids=['deprecated-alias', 'dashboard-path'])
@pytest.mark.parametrize('verb', ['put', 'delete'])
def test_an_id_two_providers_have_is_a_409_that_names_the_unambiguous_path(instance, base, verb):
    shared = _unique('shared')
    _create(instance, 'cloudflare', shared, 'd' * 24)
    _create(instance, 'digitalocean', shared, 'e' * 24)
    before = _stored(instance)

    kwargs = {'json': {'api_token': 'f' * 24}} if verb == 'put' else {}
    response = getattr(instance.client, verb)(f'{base}/{shared}', headers=instance.headers, **kwargs)

    body = response.get_json()
    assert response.status_code == 409, body
    assert body['providers'] == ['cloudflare', 'digitalocean']
    assert f'/api/dns/<provider>/accounts/{shared}' in body['error']
    assert _stored(instance) == before, 'a refusal wrote something'
    assert _owners(instance, shared) == ['cloudflare', 'digitalocean']


@pytest.mark.parametrize('verb', ['put', 'delete'])
def test_default_is_always_ambiguous_because_every_provider_has_one(instance, verb):
    before = _stored(instance)
    kwargs = {'json': {'api_token': 'g' * 24}} if verb == 'put' else {}

    response = getattr(instance.client, verb)(f'{ALIAS}/default', headers=instance.headers, **kwargs)

    assert response.status_code == 409, response.get_json()
    assert len(response.get_json()['providers']) > 1
    assert _stored(instance) == before


# --------------------------------------------------------------------------
# What did not change: the forms that name their provider.
# --------------------------------------------------------------------------

def test_the_provider_qualified_forms_are_what_they_were(instance):
    name = _unique('qual')
    _create(instance, 'cloudflare', name, 'h' * 24)

    put = instance.client.put(f'/api/dns/cloudflare/accounts/{name}', headers=instance.headers,
                              json={'api_token': 'i' * 24})
    assert put.status_code == 200, put.get_json()
    assert _token(instance, 'cloudflare', name) == 'i' * 24

    delete = instance.client.delete(f'/api/dns/cloudflare/accounts/{name}', headers=instance.headers)
    assert delete.status_code == 200, delete.get_json()
    assert _owners(instance, name) == []


def test_a_provider_qualified_delete_of_the_ambiguous_one_still_works(instance):
    """The long form is the way out of the 409, so it has to work for exactly that case."""
    shared = _unique('both')
    _create(instance, 'cloudflare', shared, 'j' * 24)
    _create(instance, 'digitalocean', shared, 'k' * 24)

    response = instance.client.delete(f'/api/dns/digitalocean/accounts/{shared}', headers=instance.headers)

    assert response.status_code == 200, response.get_json()
    assert _owners(instance, shared) == ['cloudflare']
