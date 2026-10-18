"""A viewer reads the settings, and no credential in them.

GET /api/settings and GET /api/settings/dns-providers are open to a viewer and
answered through the API models. Most secret fields there are MaskedString,
but the acme-dns username and subdomain (which settings.py counts as secrets)
were plain strings, and `multi` was a raw dict, so a read-only key saw them in
clear. The answers now go through mask_secrets_in_settings first, the same
helper /api/web/settings and share-safe backups use.
"""
import pytest

from tests import contract_support

pytestmark = [pytest.mark.unit]

SECRETS = {
    'acme-dns username': 'acmedns-user-5f2c9e',
    'acme-dns subdomain': 'acmedns-sub-77d01a',
    'acme-dns password': 'acmedns-pass-0c41be',
    'multi token': 'multi-token-9ab3d2',
    'cloudflare token': 'cf-token-3e8f60',
}


@pytest.fixture
def viewer():
    app, _token = contract_support.build_app()
    managers = app.extensions['certmate_container'].managers

    def seed(settings):
        providers = settings.setdefault('dns_providers', {})
        providers['acme-dns'] = {'api_url': 'https://acme-dns.example.internal',
                                 'username': SECRETS['acme-dns username'],
                                 'subdomain': SECRETS['acme-dns subdomain'],
                                 'password': SECRETS['acme-dns password']}
        providers['multi'] = {'provider': 'example', 'api_token': SECRETS['multi token']}
        providers['cloudflare'] = {'api_token': SECRETS['cloudflare token']}
    managers['settings'].update(seed, 'test')
    ok, key = managers['auth'].create_api_key('reader', role='viewer')
    assert ok
    client = app.test_client()
    client.environ_base['HTTP_AUTHORIZATION'] = f"Bearer {key['token']}"
    return client


@pytest.mark.parametrize('path', ['/api/settings', '/api/settings/dns-providers'])
def test_no_credential_reaches_a_viewer(viewer, path):
    answer = viewer.get(path)
    assert answer.status_code == 200, answer.get_data(as_text=True)[:200]
    body = answer.get_data(as_text=True)
    leaked = [name for name, value in SECRETS.items() if value in body]
    assert leaked == [], f'{path} shows a viewer: {leaked}'
