"""
Tests for certificate storage backends
"""

import pytest
import tempfile
import shutil
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
import sys
import os

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.core.storage_backends import (
    LocalFileSystemBackend, 
    AzureKeyVaultBackend, 
    AWSSecretsManagerBackend, 
    HashiCorpVaultBackend, 
    InfisicalBackend, 
    StorageManager
)


class TestLocalFileSystemBackend:
    """Test cases for LocalFileSystemBackend"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        self.backend = LocalFileSystemBackend(self.temp_dir)
        
        # Sample certificate files
        self.cert_files = {
            'cert.pem': b'-----BEGIN CERTIFICATE-----\ntest cert content\n-----END CERTIFICATE-----',
            'chain.pem': b'-----BEGIN CERTIFICATE-----\ntest chain content\n-----END CERTIFICATE-----',
            'fullchain.pem': b'-----BEGIN CERTIFICATE-----\ntest fullchain content\n-----END CERTIFICATE-----',
            'privkey.pem': b'-----BEGIN PRIVATE KEY-----\ntest key content\n-----END PRIVATE KEY-----'
        }
        
        self.metadata = {
            'domain': 'example.com',
            'dns_provider': 'cloudflare',
            'created_at': '2024-01-01T00:00:00Z',
            'expires_at': '2024-04-01T00:00:00Z'
        }
    
    def teardown_method(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_backend_name(self):
        """Test backend name is correct"""
        assert self.backend.get_backend_name() == "local_filesystem"
    
    def test_store_certificate_success(self):
        """Test successful certificate storage"""
        domain = "example.com"
        
        result = self.backend.store_certificate(domain, self.cert_files, self.metadata)
        
        assert result is True
        
        # Verify files were created
        domain_dir = Path(self.temp_dir) / domain
        assert domain_dir.exists()
        
        for filename in self.cert_files.keys():
            file_path = domain_dir / filename
            assert file_path.exists()
            with open(file_path, 'rb') as f:
                assert f.read() == self.cert_files[filename]
        
        # Verify metadata was created
        metadata_file = domain_dir / 'metadata.json'
        assert metadata_file.exists()
        with open(metadata_file, 'r') as f:
            stored_metadata = json.load(f)
            assert stored_metadata == self.metadata
        
        # Verify file permissions
        privkey_path = domain_dir / 'privkey.pem'
        assert oct(privkey_path.stat().st_mode)[-3:] == '600'
    
    def test_retrieve_certificate_success(self):
        """Test successful certificate retrieval"""
        domain = "example.com"
        
        # Store certificate first
        self.backend.store_certificate(domain, self.cert_files, self.metadata)
        
        # Retrieve certificate
        result = self.backend.retrieve_certificate(domain)
        
        assert result is not None
        cert_files, metadata = result
        
        assert cert_files == self.cert_files
        assert metadata == self.metadata
    
    def test_retrieve_certificate_not_exists(self):
        """Test certificate retrieval when certificate doesn't exist"""
        result = self.backend.retrieve_certificate("nonexistent.com")
        assert result is None
    
    def test_list_certificates(self):
        """Test listing certificates"""
        domains = ["example.com", "test.org", "another.net"]
        
        # Store multiple certificates
        for domain in domains:
            self.backend.store_certificate(domain, self.cert_files, self.metadata)
        
        # List certificates
        result = self.backend.list_certificates()
        
        assert sorted(result) == sorted(domains)
    
    def test_delete_certificate_success(self):
        """Test successful certificate deletion"""
        domain = "example.com"
        
        # Store certificate first
        self.backend.store_certificate(domain, self.cert_files, self.metadata)
        assert self.backend.certificate_exists(domain)
        
        # Delete certificate
        result = self.backend.delete_certificate(domain)
        
        assert result is True
        assert not self.backend.certificate_exists(domain)
    
    def test_delete_certificate_not_exists(self):
        """Test deleting a certificate that doesn't exist"""
        result = self.backend.delete_certificate("nonexistent.com")
        assert result is False
    
    def test_certificate_exists(self):
        """Test certificate existence check"""
        domain = "example.com"
        
        # Should not exist initially
        assert not self.backend.certificate_exists(domain)
        
        # Store certificate
        self.backend.store_certificate(domain, self.cert_files, self.metadata)
        
        # Should exist now
        assert self.backend.certificate_exists(domain)


class TestAzureKeyVaultBackend:
    """Test cases for AzureKeyVaultBackend"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.config = {
            'vault_url': 'https://test-vault.vault.azure.net/',
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret',
            'tenant_id': 'test-tenant-id'
        }
        
        self.cert_files = {
            'cert.pem': b'test cert content',
            'privkey.pem': b'test key content'
        }
        
        self.metadata = {'test': 'metadata'}
    
    def test_backend_name(self):
        """Test backend name is correct"""
        backend = AzureKeyVaultBackend(self.config)
        assert backend.get_backend_name() == "azure_keyvault"
    
    def test_invalid_config(self):
        """Test that invalid config raises ValueError"""
        with pytest.raises(ValueError, match="Azure Key Vault backend requires"):
            AzureKeyVaultBackend({'vault_url': 'test'})  # Missing required fields
    
    def test_sanitize_secret_name(self):
        """Test secret name sanitization"""
        backend = AzureKeyVaultBackend(self.config)
        
        # Test normal domain
        assert backend._sanitize_secret_name("example.com") == "example-com"
        
        # Test domain with special characters
        assert backend._sanitize_secret_name("sub.domain.com") == "sub-domain-com"
        
        # Test already sanitized name
        assert backend._sanitize_secret_name("already-sanitized") == "already-sanitized"
    
    @patch('modules.core.storage_backends.AzureKeyVaultBackend._get_client')
    def test_store_certificate_success(self, mock_get_client):
        """Test successful certificate storage"""
        # Mock Azure client
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        backend = AzureKeyVaultBackend(self.config)
        domain = "example.com"
        
        result = backend.store_certificate(domain, self.cert_files, self.metadata)
        
        assert result is True
        # Verify client methods were called
        assert mock_client.set_secret.call_count == len(self.cert_files) + 1  # +1 for metadata
    
    def test_import_error_handling(self):
        """Test handling of import errors"""
        backend = AzureKeyVaultBackend(self.config)
        
        # Mock ImportError in _get_client
        with patch.object(backend, '_get_client', side_effect=ImportError("Azure Key Vault backend requires")):
            with pytest.raises(ImportError, match="Azure Key Vault backend requires"):
                backend._get_client()


class TestAWSSecretsManagerBackend:
    """Test cases for AWSSecretsManagerBackend"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.config = {
            'region': 'us-east-1',
            'access_key_id': 'test-access-key',
            'secret_access_key': 'test-secret-key'
        }
        
        self.cert_files = {
            'cert.pem': b'test cert content',
            'privkey.pem': b'test key content'
        }
        
        self.metadata = {'test': 'metadata'}
    
    def test_backend_name(self):
        """Test backend name is correct"""
        backend = AWSSecretsManagerBackend(self.config)
        assert backend.get_backend_name() == "aws_secrets_manager"
    
    def test_invalid_config(self):
        """Test that invalid config raises ValueError"""
        with pytest.raises(ValueError, match="AWS Secrets Manager backend requires"):
            AWSSecretsManagerBackend({'region': 'us-east-1'})  # Missing required fields
    
    @patch('modules.core.storage_backends.AWSSecretsManagerBackend._get_client')
    def test_store_certificate_success(self, mock_get_client):
        """Test successful certificate storage"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        # Mock successful secret creation (no existing secret)
        mock_client.update_secret.side_effect = Exception("ResourceNotFoundException")
        mock_client.exceptions.ResourceNotFoundException = Exception
        
        backend = AWSSecretsManagerBackend(self.config)
        domain = "example.com"
        
        result = backend.store_certificate(domain, self.cert_files, self.metadata)
        
        assert result is True
        mock_client.create_secret.assert_called_once()
    
    @patch('modules.core.storage_backends.AWSSecretsManagerBackend._get_client')
    def test_store_certificate_update_existing(self, mock_get_client):
        """Test updating existing certificate"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        backend = AWSSecretsManagerBackend(self.config)
        domain = "example.com"
        
        result = backend.store_certificate(domain, self.cert_files, self.metadata)
        
        assert result is True
        mock_client.update_secret.assert_called_once()


class TestHashiCorpVaultBackend:
    """Test cases for HashiCorpVaultBackend"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.config = {
            'vault_url': 'https://vault.example.com:8200',
            'vault_token': 'test-token',
            'mount_point': 'secret',
            'engine_version': 'v2'
        }
        
        self.cert_files = {
            'cert.pem': b'test cert content',
            'privkey.pem': b'test key content'
        }
        
        self.metadata = {'test': 'metadata'}
    
    def test_backend_name(self):
        """Test backend name is correct"""
        backend = HashiCorpVaultBackend(self.config)
        assert backend.get_backend_name() == "hashicorp_vault"
    
    def test_invalid_config(self):
        """Test that invalid config raises ValueError"""
        with pytest.raises(ValueError, match="HashiCorp Vault backend requires"):
            HashiCorpVaultBackend({'vault_url': 'test'})  # Missing token
    
    @patch('modules.core.storage_backends.HashiCorpVaultBackend._get_client')
    def test_store_certificate_v2(self, mock_get_client):
        """Test certificate storage with KV v2 engine"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        backend = HashiCorpVaultBackend(self.config)
        domain = "example.com"
        
        result = backend.store_certificate(domain, self.cert_files, self.metadata)
        
        assert result is True
        mock_client.secrets.kv.v2.create_or_update_secret.assert_called_once()
    
    @patch('modules.core.storage_backends.HashiCorpVaultBackend._get_client')
    def test_store_certificate_v1(self, mock_get_client):
        """Test certificate storage with KV v1 engine"""
        mock_client = Mock()
        mock_get_client.return_value = mock_client
        
        config = self.config.copy()
        config['engine_version'] = 'v1'
        backend = HashiCorpVaultBackend(config)
        domain = "example.com"
        
        result = backend.store_certificate(domain, self.cert_files, self.metadata)
        
        assert result is True
        mock_client.secrets.kv.v1.create_or_update_secret.assert_called_once()


class TestInfisicalBackend:
    """Test cases for InfisicalBackend"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.config = {
            'site_url': 'https://app.infisical.com',
            'client_id': 'test-client-id',
            'client_secret': 'test-client-secret',
            'project_id': 'test-project-id',
            'environment': 'prod'
        }
        
        self.cert_files = {
            'cert.pem': b'test cert content',
            'privkey.pem': b'test key content'
        }
        
        self.metadata = {'test': 'metadata'}
    
    def test_backend_name(self):
        """Test backend name is correct"""
        backend = InfisicalBackend(self.config)
        assert backend.get_backend_name() == "infisical"
    
    def test_invalid_config(self):
        """Test that invalid config raises ValueError"""
        with pytest.raises(ValueError, match="Infisical backend requires"):
            InfisicalBackend({'site_url': 'test'})  # Missing required fields


class TestStorageManager:
    """Test cases for StorageManager"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.mock_settings_manager = Mock()
        self.temp_dir = tempfile.mkdtemp()
    
    def teardown_method(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_default_local_filesystem_backend(self):
        """Test that default backend is local filesystem"""
        self.mock_settings_manager.load_settings.return_value = {}
        
        manager = StorageManager(self.mock_settings_manager)
        backend = manager.get_backend()
        
        assert backend.get_backend_name() == "local_filesystem"
    
    def test_azure_backend_initialization(self):
        """Test Azure backend initialization"""
        settings = {
            'certificate_storage': {
                'backend': 'azure_keyvault',
                'azure_keyvault': {
                    'vault_url': 'https://test.vault.azure.net/',
                    'client_id': 'test-id',
                    'client_secret': 'test-secret',
                    'tenant_id': 'test-tenant'
                }
            }
        }
        self.mock_settings_manager.load_settings.return_value = settings
        
        manager = StorageManager(self.mock_settings_manager)
        backend = manager.get_backend()
        
        assert backend.get_backend_name() == "azure_keyvault"
    
    def test_unknown_backend_fallback(self):
        """Test fallback to local filesystem for unknown backend"""
        settings = {
            'certificate_storage': {
                'backend': 'unknown_backend'
            }
        }
        self.mock_settings_manager.load_settings.return_value = settings
        
        manager = StorageManager(self.mock_settings_manager)
        backend = manager.get_backend()
        
        assert backend.get_backend_name() == "local_filesystem"
    
    def test_backend_initialization_error_fallback(self):
        """Test fallback to local filesystem when backend initialization fails"""
        settings = {
            'certificate_storage': {
                'backend': 'azure_keyvault',
                'azure_keyvault': {
                    'vault_url': 'invalid'  # Missing required fields
                }
            }
        }
        self.mock_settings_manager.load_settings.return_value = settings
        
        manager = StorageManager(self.mock_settings_manager)
        backend = manager.get_backend()
        
        assert backend.get_backend_name() == "local_filesystem"
    
    def test_migration_between_backends(self):
        """Test certificate migration between backends"""
        # Create source backend with test certificate
        source_backend = LocalFileSystemBackend(self.temp_dir)
        cert_files = {'cert.pem': b'test cert', 'privkey.pem': b'test key'}
        metadata = {'test': 'data'}
        
        source_backend.store_certificate('example.com', cert_files, metadata)
        
        # Create target backend
        target_temp_dir = tempfile.mkdtemp()
        target_backend = LocalFileSystemBackend(target_temp_dir)
        
        try:
            # Create manager and test migration
            manager = StorageManager(self.mock_settings_manager)
            results = manager.migrate_certificates(source_backend, target_backend)
            
            assert 'example.com' in results
            assert results['example.com'] is True
            
            # Verify certificate was copied to target
            assert target_backend.certificate_exists('example.com')
            retrieved = target_backend.retrieve_certificate('example.com')
            assert retrieved is not None
            
        finally:
            shutil.rmtree(target_temp_dir, ignore_errors=True)
    
    def test_storage_manager_methods_delegation(self):
        """Test that StorageManager properly delegates to backend"""
        self.mock_settings_manager.load_settings.return_value = {}
        
        manager = StorageManager(self.mock_settings_manager)
        
        # Test method delegation
        cert_files = {'cert.pem': b'test'}
        metadata = {'test': 'data'}
        
        # These should not raise errors and should delegate to the backend
        manager.store_certificate('test.com', cert_files, metadata)
        manager.certificate_exists('test.com')
        manager.list_certificates()
        manager.get_backend_name()


class TestStorageBackendIntegration:
    """Integration tests for storage backends"""
    
    def setup_method(self):
        """Set up test fixtures"""
        self.temp_dir = tempfile.mkdtemp()
        
    def teardown_method(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_certificate_roundtrip_local_filesystem(self):
        """Test complete certificate storage and retrieval cycle"""
        backend = LocalFileSystemBackend(self.temp_dir)
        
        # Test data
        domain = "roundtrip.test"
        cert_files = {
            'cert.pem': b'-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----',
            'chain.pem': b'-----BEGIN CERTIFICATE-----\nchain\n-----END CERTIFICATE-----',
            'fullchain.pem': b'-----BEGIN CERTIFICATE-----\nfull\n-----END CERTIFICATE-----',
            'privkey.pem': b'-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----'
        }
        metadata = {
            'domain': domain,
            'dns_provider': 'cloudflare',
            'created_at': '2024-01-01T00:00:00Z',
            'expires_at': '2024-04-01T00:00:00Z',
            'account_id': 'test-account'
        }
        
        # Store certificate
        assert backend.store_certificate(domain, cert_files, metadata)
        
        # Verify it exists
        assert backend.certificate_exists(domain)
        
        # Verify it's in the list
        certificates = backend.list_certificates()
        assert domain in certificates
        
        # Retrieve and verify content
        result = backend.retrieve_certificate(domain)
        assert result is not None
        
        retrieved_files, retrieved_metadata = result
        assert retrieved_files == cert_files
        assert retrieved_metadata == metadata
        
        # Delete and verify removal
        assert backend.delete_certificate(domain)
        assert not backend.certificate_exists(domain)
        assert domain not in backend.list_certificates()
