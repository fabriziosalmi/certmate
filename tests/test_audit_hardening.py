"""
Unit tests for scoped security hardening and audit log additions.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, request
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
from modules.web.settings_routes import register_settings_routes


pytestmark = [pytest.mark.unit]


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


@pytest.fixture
def audit_test_app(tmp_path):
    """
    Setup a Flask app with mock managers to test audit logging on API
    and settings endpoints.
    """
    # Create mock/stub managers
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    settings_manager = MagicMock()
    # default load_settings
    settings_manager.load_settings.return_value = {
        'certificate_storage': {
            'backend': 'local_filesystem',
            'azure_keyvault': {
                'vault_url': 'https://x.vault.azure.net/',
                'client_id': 'azure-client-id-uuid',
                'client_secret': 'AZURE-PLAINTEXT-CLIENT-SECRET',
                'tenant_id': 'azure-tenant-uuid',
            }
        }
    }
    settings_manager.atomic_update.return_value = True
    settings_manager.update.return_value = True
    settings_manager.migrate_dns_providers_to_multi_account.side_effect = lambda s: s

    file_ops = MagicMock()
    file_ops.backup_dir = tmp_path / 'backups'
    # Ensure backup_dir exists
    file_ops.backup_dir.mkdir(parents=True, exist_ok=True)
    (file_ops.backup_dir / 'unified').mkdir(parents=True, exist_ok=True)

    cache_manager = MagicMock()
    cache_manager.clear_cache.return_value = 42

    storage_manager = MagicMock()
    mock_backend = MagicMock()
    mock_backend.get_backend_name.return_value = 'azure_keyvault'
    mock_backend.storage_mode = 'both'
    mock_backend.list_certificates.return_value = ['example.com']
    mock_backend.has_certificate_object.return_value = False
    mock_backend.retrieve_certificate.return_value = ({'cert.pem': 'dummy'}, {'domain': 'example.com'})
    mock_backend.import_certificate_object.return_value = True
    storage_manager.get_backend.return_value = mock_backend

    dns_manager = MagicMock()
    dns_manager.list_accounts.return_value = []
    dns_manager.add_account.return_value = True
    dns_manager.delete_account.return_value = True

    audit_logger = MagicMock()

    managers = {
        'auth': auth_manager,
        'settings': settings_manager,
        'storage': storage_manager,
        'certificates': MagicMock(),
        'file_ops': file_ops,
        'cache': cache_manager,
        'dns': dns_manager,
        'audit': audit_logger,
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    api_resources = create_api_resources(api, models, managers)

    # Register backups and cache namespaces like factory.py does
    ns_backups = Namespace('backups', description='Backup and restore')
    ns_backups.add_resource(api_resources['BackupDownload'], '/download/<backup_type>/<filename>')
    api.add_namespace(ns_backups)

    ns_cache = Namespace('cache', description='Cache management operations')
    ns_cache.add_resource(api_resources['CacheClear'], '/clear')
    api.add_namespace(ns_cache)

    # Inject username for audit logs
    @app.before_request
    def set_dummy_user():
        request.current_user = {'username': 'test_admin'}

    # Register settings web routes
    register_settings_routes(
        app,
        managers=managers,
        require_web_auth=lambda f: f,
        auth_manager=auth_manager,
        settings_manager=settings_manager,
        dns_manager=dns_manager,
    )

    return app, managers


class TestBackupDownloadAudit:
    """Tests audit logging for unified backup downloads and traversal checks."""

    def test_backup_download_success(self, audit_test_app, tmp_path):
        app, managers = audit_test_app
        client = app.test_client()

        # Create dummy file to bypass the exists check
        backup_file = managers['file_ops'].backup_dir / 'unified' / 'backup_123.zip'
        backup_file.write_text('dummy zip content')

        response = client.get('/api/backups/download/unified/backup_123.zip')
        assert response.status_code == 200

        # Assert audit log was recorded correctly
        managers['audit'].log_operation.assert_called_with(
            operation='download',
            resource_type='backup',
            resource_id='backup_123.zip',
            status='success',
            details={'backup_type': 'unified'},
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_backup_download_path_traversal_denied(self, audit_test_app, tmp_path):
        app, managers = audit_test_app
        client = app.test_client()

        # Create a dummy file that passes the exists check but resolves outside the backup_dir
        # We achieve this by creating a mock file "backup_outside.zip" in unified directory,
        # but mocking resolve() to return a path outside backup_dir.
        backup_file = managers['file_ops'].backup_dir / 'unified' / 'backup_outside.zip'
        backup_file.write_text('dummy zip content')

        real_resolve = Path.resolve
        def fake_resolve(self, *args, **kwargs):
            if 'backup_outside.zip' in str(self):
                return Path('/outside/directory/backup_outside.zip')
            return real_resolve(self, *args, **kwargs)

        with patch('modules.api.resources.Path.resolve', fake_resolve):
            response = client.get('/api/backups/download/unified/backup_outside.zip')
            assert response.status_code == 403

        # Assert path traversal attempt was logged as denied
        managers['audit'].log_operation.assert_called_with(
            operation='download',
            resource_type='backup',
            resource_id='backup_outside.zip',
            status='denied',
            details={
                'backup_type': 'unified',
                'reason': 'Path traversal attempt'
            },
            user='test_admin',
            ip_address='127.0.0.1'
        )


class TestStorageConfigAudit:
    """Tests audit logging for storage backend configuration updates."""

    def test_storage_config_success(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['settings'].atomic_update.return_value = True

        response = client.post('/api/storage/config', json={
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://x.vault.azure.net/'
            }
        })
        assert response.status_code == 200

        managers['audit'].log_operation.assert_called_with(
            operation='update_config',
            resource_type='storage_backend',
            resource_id='azure_keyvault',
            status='success',
            details={'backend_type': 'azure_keyvault'},
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_storage_config_failure(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['settings'].atomic_update.return_value = False

        response = client.post('/api/storage/config', json={
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://x.vault.azure.net/'
            }
        })
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='update_config',
            resource_type='storage_backend',
            resource_id='azure_keyvault',
            status='failure',
            details={
                'backend_type': 'azure_keyvault',
                'reason': 'Atomic update failed'
            },
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_storage_config_exception(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['settings'].atomic_update.side_effect = Exception("Atomic crash")

        response = client.post('/api/storage/config', json={
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://x.vault.azure.net/'
            }
        })
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='update_config',
            resource_type='storage_backend',
            resource_id='azure_keyvault',
            status='failure',
            details={'error': 'Atomic crash'},
            user='test_admin',
            ip_address='127.0.0.1'
        )


class TestStorageMigrateAudit:
    """Tests audit logging for storage migration."""

    def test_storage_migrate_success(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        # Mock the migrate_certificates method on storage manager
        managers['storage'].migrate_certificates.return_value = {
            'domain1.com': True,
            'domain2.com': False
        }

        response = client.post('/api/storage/migrate', json={
            'source_backend': 'local_filesystem',
            'target_backend': 'azure_keyvault',
            'target_config': {
                'azure_keyvault': {
                    'vault_url': 'https://x.vault.azure.net/',
                    'client_id': 'azure-id',
                    'client_secret': 'azure-secret',
                    'tenant_id': 'azure-tenant'
                }
            }
        })
        assert response.status_code == 200

        managers['audit'].log_operation.assert_called_with(
            operation='migrate',
            resource_type='storage',
            resource_id='local_filesystem_to_azure_keyvault',
            status='success',
            details={
                'source_backend': 'local_filesystem',
                'target_backend': 'azure_keyvault',
                'total_certificates': 2,
                'successful': 1,
                'failed': 1
            },
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_storage_migrate_failure(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['storage'].migrate_certificates.side_effect = Exception("Migration crashed")

        response = client.post('/api/storage/migrate', json={
            'source_backend': 'local_filesystem',
            'target_backend': 'azure_keyvault',
            'target_config': {
                'azure_keyvault': {
                    'vault_url': 'https://x.vault.azure.net/',
                    'client_id': 'azure-id',
                    'client_secret': 'azure-secret',
                    'tenant_id': 'azure-tenant'
                }
            }
        })
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='migrate',
            resource_type='storage',
            resource_id='local_filesystem_to_azure_keyvault',
            status='failure',
            details={
                'source_backend': 'local_filesystem',
                'target_backend': 'azure_keyvault',
            },
            error='Migration crashed',
            user='test_admin',
            ip_address='127.0.0.1'
        )


class TestStorageKeyVaultBackfillAudit:
    """Tests audit logging for Azure Key Vault certificate backfill."""

    def test_backfill_success(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        # Mock backend methods
        backend = managers['storage'].get_backend()
        backend.list_certificates.return_value = ['d1.com', 'd2.com']
        backend.has_certificate_object.side_effect = [False, True]
        backend.retrieve_certificate.return_value = ({'cert': 'data'}, {'meta': 'data'})
        backend.import_certificate_object.return_value = True

        response = client.post('/api/storage/azure-keyvault/backfill-certificates')
        assert response.status_code == 200

        managers['audit'].log_operation.assert_called_with(
            operation='backfill',
            resource_type='storage_azure_keyvault',
            resource_id='certificates',
            status='success',
            details={
                'imported': 1,
                'skipped': 1,
                'errors': 0,
                'remaining': 0
            },
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_backfill_failure(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        # Mock backend methods to fail on import
        backend = managers['storage'].get_backend()
        backend.list_certificates.return_value = ['d1.com']
        backend.has_certificate_object.return_value = False
        backend.retrieve_certificate.return_value = ({'cert': 'data'}, {'meta': 'data'})
        backend.import_certificate_object.return_value = False

        response = client.post('/api/storage/azure-keyvault/backfill-certificates')
        assert response.status_code == 200

        managers['audit'].log_operation.assert_called_with(
            operation='backfill',
            resource_type='storage_azure_keyvault',
            resource_id='certificates',
            status='failure',
            details={
                'imported': 0,
                'skipped': 0,
                'errors': 1,
                'remaining': 0
            },
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_backfill_exception(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['storage'].get_backend.side_effect = Exception("Vault unavailable")

        response = client.post('/api/storage/azure-keyvault/backfill-certificates')
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='backfill',
            resource_type='storage_azure_keyvault',
            resource_id='certificates',
            status='failure',
            user='test_admin',
            ip_address='127.0.0.1',
            error='Vault unavailable'
        )


class TestCacheClearAudit:
    """Tests audit logging for cache clear operations."""

    def test_cache_clear_success(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        response = client.post('/api/cache/clear')
        assert response.status_code == 200

        managers['audit'].log_operation.assert_called_with(
            operation='clear',
            resource_type='cache',
            resource_id='deployment_cache',
            status='success',
            details={'cleared_entries': 42},
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_cache_clear_failure(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['cache'].clear_cache.side_effect = Exception("Cache error")

        response = client.post('/api/cache/clear')
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='clear',
            resource_type='cache',
            resource_id='deployment_cache',
            status='failure',
            user='test_admin',
            ip_address='127.0.0.1',
            error='Cache error'
        )


class TestDnsAccountAudit:
    """Tests audit logging for DNS provider accounts creation, update, and deletion."""

    def test_dns_account_create_success(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['dns'].add_account.return_value = True

        response = client.post('/api/web/settings/accounts', json={
            'name': 'test_account',
            'provider': 'cloudflare',
            'config': {}
        })
        assert response.status_code == 200

        managers['audit'].log_operation.assert_called_with(
            operation='create_account',
            resource_type='dns_provider',
            resource_id='cloudflare:test_account',
            status='success',
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_dns_account_create_failure(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['dns'].add_account.return_value = False

        response = client.post('/api/web/settings/accounts', json={
            'name': 'test_account',
            'provider': 'cloudflare',
            'config': {}
        })
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='create_account',
            resource_type='dns_provider',
            resource_id='cloudflare:test_account',
            status='failure',
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_dns_account_create_exception(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['dns'].add_account.side_effect = Exception("Creation crash")

        response = client.post('/api/web/settings/accounts', json={
            'name': 'test_account',
            'provider': 'cloudflare',
            'config': {}
        })
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='create_account',
            resource_type='dns_provider',
            resource_id='cloudflare:test_account',
            status='failure',
            user='test_admin',
            ip_address='127.0.0.1',
            error='Creation crash'
        )

    def test_dns_account_update_success(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['dns'].add_account.return_value = True

        response = client.put('/api/dns/cloudflare/accounts/test_account', json={
            'set_as_default': True,
            'api_token': 'new_token'
        })
        assert response.status_code == 200

        managers['audit'].log_operation.assert_called_with(
            operation='update_account',
            resource_type='dns_provider',
            resource_id='cloudflare:test_account',
            status='success',
            details={'set_as_default': True},
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_dns_account_update_failure(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['dns'].add_account.return_value = False

        response = client.put('/api/dns/cloudflare/accounts/test_account', json={
            'api_token': 'new_token'
        })
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='update_account',
            resource_type='dns_provider',
            resource_id='cloudflare:test_account',
            status='failure',
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_dns_account_update_exception(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['dns'].add_account.side_effect = Exception("Update crash")

        response = client.put('/api/dns/cloudflare/accounts/test_account', json={
            'api_token': 'new_token'
        })
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='update_account',
            resource_type='dns_provider',
            resource_id='cloudflare:test_account',
            status='failure',
            user='test_admin',
            ip_address='127.0.0.1',
            error='Update crash'
        )

    def test_dns_account_delete_success(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['dns'].delete_account.return_value = True

        response = client.delete('/api/dns/cloudflare/accounts/test_account')
        assert response.status_code == 200

        managers['audit'].log_operation.assert_called_with(
            operation='delete_account',
            resource_type='dns_provider',
            resource_id='cloudflare:test_account',
            status='success',
            user='test_admin',
            ip_address='127.0.0.1'
        )

    def test_dns_account_delete_failure(self, audit_test_app):
        app, managers = audit_test_app
        client = app.test_client()

        managers['dns'].delete_account.return_value = False

        response = client.delete('/api/dns/cloudflare/accounts/test_account')
        assert response.status_code == 500

        managers['audit'].log_operation.assert_called_with(
            operation='delete_account',
            resource_type='dns_provider',
            resource_id='cloudflare:test_account',
            status='failure',
            user='test_admin',
            ip_address='127.0.0.1'
        )
