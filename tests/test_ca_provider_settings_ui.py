"""CA account changes preserve other accounts and the active default."""

import shlex
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask

from modules.core.ca_manager import CAManager
from modules.core.certificates import CertificateManager
from modules.core.shell import MockShellExecutor
from modules.web.settings_routes import register_settings_routes


pytestmark = pytest.mark.unit


def test_ca_account_crud_migrates_legacy_settings_and_preserves_secrets():
    app = Flask(__name__)
    settings = {'default_ca': 'letsencrypt', 'ca_providers': {
        'letsencrypt': {'email': 'dns@quentin.fr'},
        'sectigo': {'accounts': {'Quentin': {
            'email': 'q@example.com', 'acme_url': 'https://acme.example.com',
            'eab_kid': 'q-kid', 'eab_hmac': 'q-secret'}}},
    }, 'default_ca_accounts': {'sectigo': 'Quentin'}, 'domains': []}
    store = MagicMock()
    store.load_settings.side_effect = lambda: settings
    store.update.side_effect = lambda mutate, reason: (mutate(settings) or True)
    auth = MagicMock()
    auth.require_role.side_effect = lambda role: lambda fn: fn
    cert_service = MagicMock()
    register_settings_routes(app, {'cert_service': cert_service}, None, auth, store, MagicMock())
    client = app.test_client()
    url = '/api/web/settings/ca-providers/'

    response = client.post(url + 'letsencrypt/accounts/Bertrand', json={'email': 'dns@bertrand.fr'})
    assert response.status_code == 200, response.get_json()
    assert settings['ca_providers']['letsencrypt']['accounts']['default']['email'] == 'dns@quentin.fr'
    assert settings['ca_providers']['letsencrypt']['accounts']['Bertrand']['email'] == 'dns@bertrand.fr'
    assert CAManager(store).get_ca_config('letsencrypt', 'Bertrand')[0]['email'] == 'dns@bertrand.fr'

    response = client.post(url + 'sectigo/accounts/Bertrand', json={
        'name': 'Bertrand', 'email': 'b@example.com',
        'acme_url': 'https://acme.example.com', 'eab_kid': 'b-kid', 'eab_hmac': 'b-secret'})
    assert response.status_code == 200, response.get_json()
    response = client.post(url + 'sectigo/accounts/Bertrand', json={
        'email': 'new@example.com', 'eab_hmac': ''})
    assert response.status_code == 200, response.get_json()
    assert settings['ca_providers']['sectigo']['accounts']['Bertrand']['eab_hmac'] == 'b-secret'
    assert settings['ca_providers']['sectigo']['accounts']['Bertrand']['email'] == 'new@example.com'
    assert settings['ca_providers']['sectigo']['accounts']['Quentin']['eab_hmac'] == 'q-secret'
    assert client.post(url + 'sectigo/accounts/Quentin?create=1', json={
        'email': 'overwritten@example.com'}).status_code == 409
    assert settings['ca_providers']['sectigo']['accounts']['Quentin']['email'] == 'q@example.com'
    settings['domains'] = [{'domain': 'issued.example.com'}]
    cert_service.read_metadata.return_value = {'ca_provider': 'sectigo', 'ca_account_id': 'Bertrand'}
    assert client.delete(url + 'sectigo/accounts/Bertrand').status_code == 409
    settings['domains'] = []
    assert client.delete(url + 'sectigo/accounts/Quentin').status_code == 200
    assert settings['default_ca_accounts']['sectigo'] == 'Bertrand'
    assert client.delete(url + 'sectigo/accounts/Bertrand').status_code == 200
    assert 'sectigo' not in settings['ca_providers']


def test_first_lets_encrypt_account_keeps_existing_global_email():
    app = Flask(__name__)
    settings = {'email': 'dns@quentin.fr', 'default_ca': 'letsencrypt'}
    store = MagicMock()
    store.load_settings.side_effect = lambda: settings
    store.update.side_effect = lambda mutate, reason: (mutate(settings) or True)
    auth = MagicMock()
    auth.require_role.side_effect = lambda role: lambda fn: fn
    register_settings_routes(app, {}, None, auth, store, MagicMock())

    response = app.test_client().post(
        '/api/web/settings/ca-providers/letsencrypt/accounts/Bertrand',
        json={'email': 'dns@bertrand.fr'})
    assert response.status_code == 200, response.get_json()
    accounts = settings['ca_providers']['letsencrypt']['accounts']
    assert accounts['default']['email'] == 'dns@quentin.fr'
    assert accounts['Bertrand']['email'] == 'dns@bertrand.fr'


def test_selected_ca_account_supplies_issuance_email(tmp_path):
    store = MagicMock()
    store.load_settings.return_value = {
        'email': 'dns@quentin.fr', 'default_ca': 'letsencrypt',
        'ca_providers': {'letsencrypt': {'accounts': {
            'Quentin': {'email': 'dns@quentin.fr'},
            'Bertrand': {'email': 'dns@bertrand.fr'},
        }}},
    }
    shell = MockShellExecutor()
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=store,
                                 dns_manager=MagicMock(), ca_manager=CAManager(store),
                                 shell_executor=shell)
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        manager.create_certificate('test.example.com', 'dns@quentin.fr',
                                   ca_provider='letsencrypt', ca_account_id='Bertrand',
                                   dns_provider='cloudflare', dns_config={'api_token': 'test'})
    args = shlex.split(shell.commands_executed[0])
    assert args[args.index('--email') + 1] == 'dns@bertrand.fr'
    assert manager._load_metadata('test.example.com')['email'] == 'dns@bertrand.fr'
