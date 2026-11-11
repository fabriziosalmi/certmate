"""Test Connection and Migrate use the saved secret when the form leaves it empty (#1424).

The settings page never sends a saved secret back to the browser, so after a reload the
Vault token field is empty. Saving reads an empty or masked secret as "keep the stored one"
(_strip_masked_values), but Test Connection built the backend from the request alone and
Migrate fell back to the saved settings for the source only. Both refused until the token
was typed again, which is the one thing masking exists to avoid.

They now merge the saved configuration under the form, as saving does, with one limit: the
Vault token and Infisical's client credentials are sent to an address the operator types
(vault_url, site_url), so a saved one is reused only for the address it was saved for.
Saving can still move it to a new address, which is visible and audited; a test is neither.
"""
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask_restx import Api

from modules.api.resource_context import ApiContext
from modules.api.resources_storage import create_storage_resources
from modules.core.storage_backends import HashiCorpVaultBackend, InfisicalBackend

pytestmark = pytest.mark.unit

VAULT = {'vault_url': 'https://vault.example:8200', 'vault_token': 'hvs.saved', 'mount_point': 'secret',
         'engine_version': 'v2'}


def _resources(stored):
    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    settings = MagicMock()
    settings.load_settings.return_value = {'certificate_storage': stored}
    storage = MagicMock()
    storage.migrate_certificates.return_value = {'a.example': True}
    ctx = ApiContext(auth=auth, settings=settings, certificates=None, file_ops=None, cache=None,
                     dns=None, deployer=None, audit=None, cert_service=None, cert_executor=None,
                     managers={'storage': storage})
    app = Flask(__name__)
    api = Api(app, prefix='/api')
    models = {key: MagicMock() for key in ('storage_config_model', 'storage_test_config_model',
                                          'storage_migration_config_model')}
    return app, create_storage_resources(api, models, ctx), storage


def _test(stored, backend, form, backend_class=HashiCorpVaultBackend):
    """Run Test Connection; return its answer and the backends it built."""
    built = []

    def attempt(self):
        built.append(self)
        return []

    app, resources, _ = _resources(stored)
    with app.test_request_context('/', json={'backend': backend, 'config': form}), \
            patch.object(backend_class, '_list_certificates_attempt', attempt):
        return resources['StorageBackendTest']().post(), built


def _form(**changes):
    return {**VAULT, 'vault_token': '', **changes}


SAVED = {'backend': 'hashicorp_vault', 'hashicorp_vault': VAULT}


@pytest.mark.parametrize('token', ['', '********'])
def test_an_empty_or_masked_token_is_the_saved_one(token):
    answer, built = _test(SAVED, 'hashicorp_vault', _form(vault_token=token))

    assert answer['success'] is True, answer
    assert built[0].vault_token == 'hvs.saved'


def test_a_typed_token_wins_over_the_saved_one():
    _, built = _test(SAVED, 'hashicorp_vault', _form(vault_token='hvs.typed'))

    assert built[0].vault_token == 'hvs.typed'


def test_the_saved_token_does_not_go_to_another_address():
    answer, built = _test(SAVED, 'hashicorp_vault', _form(vault_url='https://elsewhere.example:8200'))

    assert answer['success'] is False
    assert 'vault_token' in answer['message'] and 'vault_url' in answer['message']
    assert 'hvs.saved' not in answer['message']
    assert built == [], 'a backend was built with the saved token for another address'


def test_another_address_with_a_typed_token_is_tested_with_it():
    answer, built = _test(SAVED, 'hashicorp_vault',
                          _form(vault_url='https://elsewhere.example:8200', vault_token='hvs.typed'))

    assert answer['success'] is True
    assert built[0].vault_token == 'hvs.typed'


def test_the_legacy_flat_shape_is_read_too():
    flat = {'backend': 'hashicorp_vault', **VAULT, 'azure_keyvault': {'client_secret': 'other'}}
    _, built = _test(flat, 'hashicorp_vault', _form())

    assert built[0].vault_token == 'hvs.saved'


def test_infisical_with_the_default_address_uses_the_saved_secret():
    """The form sends the default site_url; the saved block may have none."""
    stored = {'backend': 'infisical',
              'infisical': {'client_id': 'cid', 'client_secret': 'cs.saved', 'project_id': 'p'}}
    form = {'site_url': 'https://app.infisical.com', 'client_id': 'cid', 'client_secret': '',
            'project_id': 'p', 'environment': 'prod'}
    answer, built = _test(stored, 'infisical', form, backend_class=InfisicalBackend)

    assert answer['success'] is True, answer
    assert built[0].client_secret == 'cs.saved'


def test_migrate_builds_the_target_with_the_saved_token():
    app, resources, storage = _resources(SAVED)
    payload = {'source_backend': 'local_filesystem', 'source_config': {'cert_dir': '/tmp/none'},
               'target_backend': 'hashicorp_vault',
               'target_config': {'backend': 'hashicorp_vault', 'hashicorp_vault': _form()}}
    with app.test_request_context('/', json=payload):
        answer = resources['StorageBackendMigrate']().post()

    assert answer['success'] is True, answer
    target = storage.migrate_certificates.call_args.args[1]
    assert target.vault_token == 'hvs.saved'


def test_migrate_does_not_send_the_saved_token_to_another_address():
    app, resources, storage = _resources(SAVED)
    payload = {'source_backend': 'local_filesystem', 'source_config': {'cert_dir': '/tmp/none'},
               'target_backend': 'hashicorp_vault',
               'target_config': {'backend': 'hashicorp_vault',
                                 'hashicorp_vault': _form(vault_url='https://elsewhere.example:8200')}}
    with app.test_request_context('/', json=payload):
        answer, status = resources['StorageBackendMigrate']().post()

    assert status == 500 and 'vault_token' in answer['message']
    storage.migrate_certificates.assert_not_called()


# --- the page ------------------------------------------------------------

def test_the_page_fills_in_the_infisical_client_id():
    """The client ID is not secret-named, so a Save of any setting after a reload wrote ''
    over the stored one: _strip_masked_values keeps only secret-named fields."""
    from pathlib import Path
    js = (Path(__file__).resolve().parent.parent / 'static' / 'js' / 'settings.js').read_text()

    assert "getElementById('infisical-client-id').value = infisicalConfig.client_id" in js


def _settings_js_run(body):
    """Run settings.js's own storage functions in node against a fake page."""
    import json
    import re
    import shutil
    import subprocess
    from pathlib import Path

    node = shutil.which('node')
    if not node:
        pytest.skip('node is not available')
    js = (Path(__file__).resolve().parent.parent / 'static' / 'js' / 'settings.js').read_text()

    def function(name):
        found = re.search(r'\n    function ' + name + r'\(.*?\n    \}\n', js, re.S)
        assert found, f'{name} not found in settings.js'
        return found.group(0)

    script = (
        "var fields = {};\n"
        "var document = {getElementById: function (id) {"
        " return fields[id] = fields[id] || {value: '', style: {}, classList: {toggle: function () {}}}; }};\n"
        "function toggleStorageBackendConfig() {} function toggleAzureBackfillRow() {}\n"
        "function toggleAWSAuthMode() {} function toggleS3AuthMode() {}\n"
        "var savedStorageConfig = {};\n"
        + ''.join(function(n) for n in ('savedSecret', 'hasSecret', 'validateStorageConfig',
                                        'loadStorageBackendSettings'))
        + body)
    result = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


MASKED_VAULT = {'certificate_storage': {'backend': 'hashicorp_vault', 'hashicorp_vault': {
    'vault_url': 'https://vault.example:8200', 'vault_token': '********'}}}


def test_the_page_accepts_a_saved_token_it_cannot_show():
    out = _settings_js_run(
        'loadStorageBackendSettings(' + __import__('json').dumps(MASKED_VAULT) + ');\n'
        "console.log(JSON.stringify({saved: !!validateStorageConfig('hashicorp_vault',"
        " {vault_url: 'https://vault.example:8200', vault_token: ''}),"
        " other: !!validateStorageConfig('infisical', {client_id: 'c', client_secret: '', project_id: 'p'})}));")

    assert out['saved'] is True, 'a saved token still has to be typed again'
    assert out['other'] is False, 'a secret saved for one backend counted for another'


def test_the_page_shows_the_saved_infisical_client_id():
    settings = {'certificate_storage': {'backend': 'infisical', 'infisical': {
        'client_id': 'cid-saved', 'client_secret': '********', 'project_id': 'p'}}}
    out = _settings_js_run(
        'loadStorageBackendSettings(' + __import__('json').dumps(settings) + ');\n'
        "console.log(JSON.stringify({id: fields['infisical-client-id'].value,"
        " secret: fields['infisical-client-secret'] ? fields['infisical-client-secret'].value : ''}));")

    assert out['id'] == 'cid-saved'
    assert out['secret'] == '', 'the secret itself must never be put back in the page'
