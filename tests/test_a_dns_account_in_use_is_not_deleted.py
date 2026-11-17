"""A DNS account that certificates renew through is not deleted.

Found by the UX audit of 2026-11-17: `bound.example.test` was issued with
cloudflare:production and due for renewal; deleting that account answered 200,
nothing warned, and the next renewal would have failed. CA accounts already
refused this (modules/web/settings_routes.py, _ca_account_in_use).

Now the delete answers 409 DNS_ACCOUNT_IN_USE and names the certificates. A
certificate with no account recorded renews through the provider's default, so
it holds the default. Driven through the real application.
"""
import json

import pytest

from tests import contract_support

pytestmark = [pytest.mark.unit]

TOKEN = 'p' * 40
DETAIL_PATHS = ['/api/dns/cloudflare/accounts/{id}', '/api/web/settings/accounts/{id}']


@pytest.fixture
def instance():
    app, token = contract_support.build_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    managers = app.extensions['certmate_container'].managers
    return client, managers


def _account(client, account_id):
    created = client.post('/api/dns/cloudflare/accounts', json={
        'account_id': account_id, 'config': {'name': account_id, 'api_token': TOKEN}})
    assert created.status_code in (200, 201), created.get_json()


def _certificate(managers, domain, **metadata):
    directory = managers['certificates'].cert_dir / domain
    directory.mkdir(parents=True)
    (directory / 'cert.pem').write_text('placeholder\n')
    (directory / 'metadata.json').write_text(json.dumps(
        {'domain': domain, 'dns_provider': 'cloudflare', 'challenge_type': 'dns-01', **metadata}))


def _exists(managers, account_id):
    return any(a.get('account_id') == account_id and a.get('provider') == 'cloudflare'
               for a in managers['dns'].list_accounts())


@pytest.mark.parametrize('path', DETAIL_PATHS)
def test_an_account_a_certificate_renews_through_is_refused(instance, path):
    client, managers = instance
    _account(client, 'production')
    _account(client, 'staging')
    _certificate(managers, 'bound.example.test', account_id='production')

    answer = client.delete(path.format(id='production'))

    assert answer.status_code == 409, (answer.status_code, answer.get_json())
    body = answer.get_json()
    assert body['code'] == 'DNS_ACCOUNT_IN_USE'
    assert body['certificates'] == ['bound.example.test']
    assert 'bound.example.test' in body['error']
    assert _exists(managers, 'production')


def test_a_certificate_with_no_account_recorded_holds_the_default(instance):
    client, managers = instance
    _account(client, 'production')          # the first real account becomes the default
    default = managers['settings'].load_settings()['default_accounts']['cloudflare']
    assert default == 'production'
    _certificate(managers, 'implicit.example.test', account_id=None)

    answer = client.delete('/api/dns/cloudflare/accounts/production')

    assert answer.status_code == 409, answer.get_json()
    assert answer.get_json()['certificates'] == ['implicit.example.test']


def test_an_account_no_certificate_uses_is_deleted(instance):
    """CONTROL: the guard is about use, not about having certificates at all."""
    client, managers = instance
    _account(client, 'production')
    _account(client, 'spare')
    _certificate(managers, 'bound.example.test', account_id='production')

    answer = client.delete('/api/dns/cloudflare/accounts/spare')

    assert answer.status_code == 200, answer.get_json()
    assert not _exists(managers, 'spare')


def test_an_alias_account_counts_as_use(instance):
    client, managers = instance
    _account(client, 'production')
    _account(client, 'aliases')
    _certificate(managers, 'aliased.example.test', dns_provider='route53',
                 alias_dns_provider='cloudflare', account_id='aliases')

    answer = client.delete('/api/dns/cloudflare/accounts/aliases')

    assert answer.status_code == 409, answer.get_json()
