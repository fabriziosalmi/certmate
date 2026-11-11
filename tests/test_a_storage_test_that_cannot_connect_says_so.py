"""Test Connection says why it could not connect, and a migration that moved nothing is not a success (#1422).

With the HashiCorp Vault backend, "Test Connection" answered "Successfully connected to
hashicorp_vault" for a host that does not exist, a token of `x`, and an image without
hvac. Every remote backend's public ``list_certificates()`` turns a failure into ``[]``,
because the callers that read it must keep going. The Test endpoint asked
``_list_certificates_attempt()`` instead, which raises, but only for S3 and Secrets
Manager. Vault, Azure Key Vault and Infisical took the forgiving path, where nothing
could fail.

The migration then failed for every certificate, and the audit trail recorded
``status: success`` with ``successful: 0, failed: 3``.
"""
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask_restx import Api

from modules.api.resource_context import ApiContext
from modules.api.resources_storage import create_storage_resources
from modules.core.storage_backends import (
    AzureKeyVaultBackend,
    HashiCorpVaultBackend,
    InfisicalBackend,
)

pytestmark = pytest.mark.unit

CONFIGS = {
    'hashicorp_vault': (HashiCorpVaultBackend, {
        'vault_url': 'https://does-not-exist.example:8200', 'vault_token': 'x', 'mount_point': 'test'}),
    'azure_keyvault': (AzureKeyVaultBackend, {
        'vault_url': 'https://kv.example.vault.azure.net', 'client_id': 'c',
        'client_secret': 's', 'tenant_id': 't'}),
    'infisical': (InfisicalBackend, {'client_id': 'c', 'client_secret': 's', 'project_id': 'p'}),
}


def _resources(audit=None, storage=None):
    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    ctx = ApiContext(auth=auth, settings=MagicMock(), certificates=None,
                     file_ops=None, cache=None, dns=None, deployer=None,
                     audit=audit, cert_service=None, cert_executor=None,
                     managers={'storage': storage} if storage else {})
    app = Flask(__name__)
    api = Api(app, prefix='/api')
    models = {key: MagicMock() for key in ('storage_config_model',
                                          'storage_test_config_model',
                                          'storage_migration_config_model')}
    return app, create_storage_resources(api, models, ctx)


def _test_connection(backend_type, **patches):
    backend_class, config = CONFIGS[backend_type]
    app, resources = _resources()
    with app.test_request_context('/', json={'backend': backend_type, 'config': config}), \
            patch.multiple(backend_class, **patches):
        return resources['StorageBackendTest']().post()


@pytest.mark.parametrize('backend_type', sorted(CONFIGS))
def test_a_backend_that_cannot_list_fails_the_test(backend_type):
    result = _test_connection(
        backend_type, _list_certificates_attempt=MagicMock(side_effect=ConnectionError('no route to host')))

    assert result['success'] is False, f'{backend_type}: "{result["message"]}"'
    assert result['backend'] == backend_type


def test_a_missing_sdk_is_named_with_the_file_that_installs_it():
    result = _test_connection(
        'hashicorp_vault',
        _get_client=MagicMock(side_effect=ImportError("HashiCorp Vault backend requires 'hvac' package")))

    assert result['success'] is False
    assert 'requirements-vault-storage.txt' in result['message']


class InvalidPath(Exception):
    """hvac's exception for a path with nothing under it, matched by name in the backend."""


def test_an_empty_vault_is_a_store_with_no_certificate_not_a_failure():
    """The other side of asking the attempt: Vault answers 404 for a path nothing has
    been written under, so a new, healthy Vault would fail the test if that were an error."""
    client = MagicMock()
    client.secrets.kv.v2.list_secrets.side_effect = InvalidPath('no secrets at certmate/certificates')

    result = _test_connection('hashicorp_vault', _get_client=MagicMock(return_value=client))

    assert result['success'] is True
    assert result['certificate_count'] == 0


def test_a_vault_that_refuses_the_token_fails_the_test():
    client = MagicMock()
    client.secrets.kv.v2.list_secrets.side_effect = PermissionError('permission denied')

    result = _test_connection('hashicorp_vault', _get_client=MagicMock(return_value=client))

    assert result['success'] is False


def _migrate(results):
    audit, storage = MagicMock(), MagicMock()
    storage.migrate_certificates.return_value = results
    app, resources = _resources(audit=audit, storage=storage)
    payload = {'source_backend': 'local_filesystem', 'source_config': {'cert_dir': '/tmp/none'},
               'target_backend': 'hashicorp_vault', 'target_config': CONFIGS['hashicorp_vault'][1]}
    with app.test_request_context('/', json=payload):
        resources['StorageBackendMigrate']().post()
    return audit.log_operation.call_args.kwargs


def test_a_migration_that_moved_nothing_is_recorded_as_a_failure():
    entry = _migrate({'a.example': False, 'b.example': False, 'c.example': False})

    assert entry['status'] == 'failure'
    assert entry['details']['successful'] == 0 and entry['details']['failed'] == 3
    assert entry['error'] == '3 of 3 certificates were not migrated'


def test_a_migration_that_left_one_behind_is_recorded_as_a_failure():
    entry = _migrate({'a.example': True, 'b.example': False})

    assert entry['status'] == 'failure'


def test_a_complete_migration_is_recorded_as_a_success():
    entry = _migrate({'a.example': True, 'b.example': True})

    assert entry['status'] == 'success'
    assert entry['error'] is None
