"""Creating a DNS account under a name in use does not replace that account.

Found by the UX audit of 2026-11-17: "Production" with token B, then
"Production" again with token C. Both answered "created successfully", and
settings.json held only token C; the audit log showed "Account added" twice.
The settings page makes the id from the name (lowercased), and the create path
assigned the new config over whatever was there. Editing has its own route.

Now a create whose name is an account that already has credentials is refused
with 409, on every path the create is served at, and the account is left as it
was. An account without credentials, such as the empty "default" a fresh
instance carries, can still be filled in by a create.

Driven through the real application with its bearer token.
"""
import pytest

from modules.core.dns_providers import DNSAccountTaken, DNSManager
from tests import contract_support

pytestmark = [pytest.mark.unit]

TOKEN_B = 'b' * 40
TOKEN_C = 'c' * 40
CREATE_PATHS = ['/api/dns/cloudflare/accounts', '/api/web/settings/accounts']


@pytest.fixture
def instance():
    app, token = contract_support.build_app()
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f'Bearer {token}'
    return client, app.extensions['certmate_container'].managers['dns']


def _create(client, path, token, name='Production'):
    body = {'account_id': name.lower(), 'config': {'name': name, 'api_token': token}}
    if path.startswith('/api/web/'):
        body['provider'] = 'cloudflare'
    return client.post(path, json=body)


def _stored(dns, account_id='production'):
    for account in dns.list_accounts():
        if account.get('provider') == 'cloudflare' and account.get('account_id') == account_id:
            return dns.settings_manager.load_settings()['dns_providers']['cloudflare']['accounts'][account_id]
    return None


@pytest.mark.parametrize('path', CREATE_PATHS)
def test_a_second_create_with_the_same_name_is_refused(instance, path):
    client, dns = instance
    first = _create(client, path, TOKEN_B)
    assert first.status_code in (200, 201), first.get_json()

    second = _create(client, path, TOKEN_C)

    assert second.status_code == 409, (second.status_code, second.get_json())
    assert second.get_json()['code'] == 'DNS_ACCOUNT_EXISTS'
    assert 'already exists' in second.get_json()['error']
    assert _stored(dns)['api_token'] == TOKEN_B


def test_editing_the_account_still_replaces_its_token(instance):
    """CONTROL: the edit route is how a token is changed, and it still is."""
    client, dns = instance
    assert _create(client, CREATE_PATHS[0], TOKEN_B).status_code in (200, 201)
    edited = client.put('/api/dns/cloudflare/accounts/production', json={'api_token': TOKEN_C})
    assert edited.status_code == 200, edited.get_json()
    assert _stored(dns)['api_token'] == TOKEN_C


def test_the_empty_default_of_a_fresh_instance_can_be_filled_in_by_a_create(instance):
    """The first-run settings carry an empty "default" Cloudflare account. An
    operator who names their first account "Default" fills it in."""
    client, dns = instance
    assert not dns.account_with_credentials('cloudflare', 'default')
    created = _create(client, CREATE_PATHS[0], TOKEN_B, name='Default')
    assert created.status_code in (200, 201), created.get_json()
    assert _stored(dns, 'default')['api_token'] == TOKEN_B


class _Settings:
    def __init__(self, data):
        self.data = data

    def load_settings(self):
        import copy
        return copy.deepcopy(self.data)

    def migrate_dns_providers_to_multi_account(self, settings):
        return settings

    def update(self, mutate, reason):
        mutate(self.data)
        return True


def test_the_manager_refuses_under_the_lock_too():
    """Two creates of one name at once: the route's check can pass for both,
    so the write itself refuses when the account has credentials by then."""
    data = {'dns_providers': {'cloudflare': {'accounts': {
        'production': {'name': 'Production', 'api_token': TOKEN_B}}}}}
    manager = DNSManager(_Settings(data))
    with pytest.raises(DNSAccountTaken):
        manager.add_account('production', 'cloudflare',
                            {'name': 'Production', 'api_token': TOKEN_C}, refuse_taken=True)
    assert data['dns_providers']['cloudflare']['accounts']['production']['api_token'] == TOKEN_B
