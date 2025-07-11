import pytest
from unittest.mock import patch, MagicMock, mock_open
import sys
import os

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.core.utils import (
    create_cloudflare_config, create_route53_config, create_azure_config,
    create_google_config, create_powerdns_config, create_digitalocean_config,
    create_linode_config, create_gandi_config, create_ovh_config,
    create_namecheap_config, create_multi_provider_config
)

class TestDNSProviderConfigs:
    """Test DNS provider configuration file creation."""
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_cloudflare_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test Cloudflare configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_cloudflare_config('test-api-token')
        
        # Should create config directory
        mock_mkdir.assert_called_once()
        
        # Should write correct format
        mock_file.write.assert_called_once_with('dns_cloudflare_api_token = test-api-token\n')
        
        # Should set proper permissions
        mock_chmod.assert_called_once_with(0o600)
        
        # Should return Path object
        assert str(result).endswith('cloudflare.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_route53_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test AWS Route53 configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_route53_config('AKIATEST', 'secret-key')
        
        # Should write both access key and secret in one call
        expected_content = (
            'dns_route53_access_key_id = AKIATEST\n'
            'dns_route53_secret_access_key = secret-key\n'
        )
        
        mock_file.write.assert_called_once_with(expected_content)
        
        # Should set proper permissions
        mock_chmod.assert_called_once_with(0o600)
        
        assert str(result).endswith('route53.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_azure_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test Azure DNS configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_azure_config(
            'subscription-id',
            'resource-group',
            'tenant-id',
            'client-id',
            'client-secret'
        )
        
        # Should write all Azure credentials in one call
        expected_content = (
            'dns_azure_subscription_id = subscription-id\n'
            'dns_azure_resource_group = resource-group\n'
            'dns_azure_tenant_id = tenant-id\n'
            'dns_azure_client_id = client-id\n'
            'dns_azure_client_secret = client-secret\n'
        )
        
        mock_file.write.assert_called_once_with(expected_content)
        
        mock_chmod.assert_called_once_with(0o600)
        assert str(result).endswith('azure.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_google_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test Google Cloud DNS configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        service_key = '{"type": "service_account", "project_id": "test"}'
        result = create_google_config('test-project', service_key)
        
        # Should write service account key to separate file and config with file reference
        write_calls = [call[0][0] for call in mock_file.write.call_args_list]
        
        # First call should write the service account key JSON
        assert service_key in write_calls
        
        # Second call should write the config content
        expected_config = (
            'dns_google_project_id = test-project\n'
            'dns_google_service_account_key = letsencrypt/config/google-service-account.json\n'
        )
        assert expected_config in write_calls
        
        # chmod should be called twice - once for service account key file, once for config file
        assert mock_chmod.call_count == 2
        mock_chmod.assert_called_with(0o600)
        assert str(result).endswith('google.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_powerdns_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test PowerDNS configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_powerdns_config('https://powerdns.example.com:8081', 'api-key-123')
        
        # Should write both API URL and key in one call
        expected_content = (
            'dns_powerdns_api_url = https://powerdns.example.com:8081\n'
            'dns_powerdns_api_key = api-key-123\n'
        )
        
        mock_file.write.assert_called_once_with(expected_content)
        
        mock_chmod.assert_called_once_with(0o600)
        assert str(result).endswith('powerdns.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_digitalocean_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test DigitalOcean DNS configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_digitalocean_config('do-api-token-123')
        
        mock_file.write.assert_called_once_with('dns_digitalocean_token = do-api-token-123\n')
        mock_chmod.assert_called_once_with(0o600)
        assert str(result).endswith('digitalocean.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_linode_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test Linode DNS configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_linode_config('linode-api-key-123')
        
        # Should write both API key and version in one call
        expected_content = (
            'dns_linode_key = linode-api-key-123\n'
            'dns_linode_version = 4\n'
        )
        
        mock_file.write.assert_called_once_with(expected_content)
        
        mock_chmod.assert_called_once_with(0o600)
        assert str(result).endswith('linode.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_gandi_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test Gandi DNS configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_gandi_config('gandi-api-token-123')
        
        mock_file.write.assert_called_once_with('dns_gandi_token = gandi-api-token-123\n')
        mock_chmod.assert_called_once_with(0o600)
        assert str(result).endswith('gandi.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_ovh_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test OVH DNS configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_ovh_config(
            'ovh-eu',
            'app-key-123',
            'app-secret-123',
            'consumer-key-123'
        )
        
        # Should write all OVH credentials in one call
        expected_content = (
            'dns_ovh_endpoint = ovh-eu\n'
            'dns_ovh_application_key = app-key-123\n'
            'dns_ovh_application_secret = app-secret-123\n'
            'dns_ovh_consumer_key = consumer-key-123\n'
        )
        
        mock_file.write.assert_called_once_with(expected_content)
        
        mock_chmod.assert_called_once_with(0o600)
        assert str(result).endswith('ovh.ini')
    
    @patch('pathlib.Path.mkdir')
    @patch('builtins.open')
    @patch('pathlib.Path.chmod')
    def test_create_namecheap_config(self, mock_chmod, mock_open, mock_mkdir):
        """Test Namecheap DNS configuration file creation."""
        mock_file = MagicMock()
        mock_open.return_value.__enter__.return_value = mock_file
        
        result = create_namecheap_config('username123', 'namecheap-api-key')
        
        # Should write both username and API key in one call
        expected_content = (
            'dns_namecheap_username = username123\n'
            'dns_namecheap_api_key = namecheap-api-key\n'
        )
        
        mock_file.write.assert_called_once_with(expected_content)
        
        mock_chmod.assert_called_once_with(0o600)
        assert str(result).endswith('namecheap.ini')
    
    def test_create_multi_provider_config_rfc2136(self):
        """Test multi-provider config creation for RFC2136."""
        config_data = {
            'nameserver': '192.168.1.1',
            'tsig_key': 'test-key',
            'tsig_secret': 'test-secret-123',
            'tsig_algorithm': 'HMAC-SHA256'
        }
        
        with patch('pathlib.Path.mkdir'), \
             patch('builtins.open', mock_open()) as mock_file_open, \
             patch('pathlib.Path.chmod') as mock_chmod:
            
            result = create_multi_provider_config('rfc2136', config_data)
            
            # Check that config file was written
            mock_file_open.assert_called_once()
            mock_file = mock_file_open.return_value.__enter__.return_value
            
            # RFC2136 writes all config in one call as a single string
            expected_content = ('dns_rfc2136_nameserver = 192.168.1.1\n'
                              'dns_rfc2136_name = test-key\n'
                              'dns_rfc2136_secret = test-secret-123\n'
                              'dns_rfc2136_algorithm = HMAC-SHA256\n')
            
            mock_file.write.assert_called_once_with(expected_content)
            
            mock_chmod.assert_called_once_with(0o600)
            assert str(result).endswith('rfc2136.ini')
    
    def test_create_multi_provider_config_vultr(self):
        """Test multi-provider config creation for Vultr."""
        config_data = {'api_key': 'vultr-api-key-123'}
        
        with patch('pathlib.Path.mkdir'), \
             patch('builtins.open', mock_open()) as mock_file_open, \
             patch('pathlib.Path.chmod') as mock_chmod:
            
            result = create_multi_provider_config('vultr', config_data)
            
            mock_file_open.assert_called_once()
            mock_file = mock_file_open.return_value.__enter__.return_value
            mock_file.write.assert_called_once_with('dns_vultr_api_key = vultr-api-key-123\n')
            
            mock_chmod.assert_called_once_with(0o600)
            assert str(result).endswith('vultr.ini')
    
    def test_create_multi_provider_config_hetzner(self):
        """Test multi-provider config creation for Hetzner."""
        config_data = {'api_token': 'hetzner-token-123'}
        
        with patch('pathlib.Path.mkdir'), \
             patch('builtins.open', mock_open()) as mock_file_open, \
             patch('pathlib.Path.chmod') as mock_chmod:
            
            result = create_multi_provider_config('hetzner', config_data)
            
            mock_file_open.assert_called_once()
            mock_file = mock_file_open.return_value.__enter__.return_value
            mock_file.write.assert_called_once_with('dns_hetzner_api_token = hetzner-token-123\n')
            
            mock_chmod.assert_called_once_with(0o600)
            assert str(result).endswith('hetzner.ini')
            
    def test_create_multi_provider_config_providers_with_dedicated_functions(self):
        """Test that providers with dedicated functions return None from multi-provider config."""
        # These providers have dedicated functions and should not be handled by create_multi_provider_config
        providers_with_dedicated_functions = [
            'cloudflare', 'route53', 'azure', 'google', 'powerdns', 
            'digitalocean', 'linode', 'gandi', 'ovh', 'namecheap'
        ]
        
        for provider in providers_with_dedicated_functions:
            config_data = {'api_token': 'test-token'}
            result = create_multi_provider_config(provider, config_data)
            assert result is None, f"Provider {provider} should return None (has dedicated function)"
    
    def test_create_multi_provider_config_unsupported(self):
        """Test multi-provider config creation for unsupported provider."""
        result = create_multi_provider_config('unsupported_provider', {'api_key': 'test'})
        assert result is None
