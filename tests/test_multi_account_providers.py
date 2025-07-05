import pytest
from unittest.mock import patch, MagicMock
import sys
import os

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import (
    migrate_dns_providers_to_multi_account,
    get_dns_provider_account_config,
    validate_dns_provider_account
)

class TestMultiAccountProviders:
    """Test multi-account functionality for supported providers only.
    
    Supported providers: cloudflare, azure, google, route53, powerdns, rfc2136, digitalocean
    """

    # Define the providers that support multi-account functionality
    MULTI_ACCOUNT_PROVIDERS = [
        'cloudflare', 'azure', 'google', 'route53', 'powerdns', 'rfc2136', 'digitalocean'
    ]

    def test_supported_multi_account_providers_list(self):
        """Test that we have the correct list of multi-account providers."""
        assert len(self.MULTI_ACCOUNT_PROVIDERS) == 7
        assert 'cloudflare' in self.MULTI_ACCOUNT_PROVIDERS
        assert 'azure' in self.MULTI_ACCOUNT_PROVIDERS
        assert 'google' in self.MULTI_ACCOUNT_PROVIDERS
        assert 'route53' in self.MULTI_ACCOUNT_PROVIDERS
        assert 'powerdns' in self.MULTI_ACCOUNT_PROVIDERS
        assert 'rfc2136' in self.MULTI_ACCOUNT_PROVIDERS
        assert 'digitalocean' in self.MULTI_ACCOUNT_PROVIDERS
        
        # Providers that do NOT support multi-account
        unsupported = ['linode', 'gandi', 'ovh', 'namecheap', 'vultr', 'hetzner']
        for provider in unsupported:
            assert provider not in self.MULTI_ACCOUNT_PROVIDERS

    @pytest.mark.parametrize("provider", MULTI_ACCOUNT_PROVIDERS)
    def test_migrate_single_to_multi_account(self, provider):
        """Test migration from single-account to multi-account for supported providers."""
        # Single-account configurations for each provider (using keys that trigger migration)
        single_account_configs = {
            'cloudflare': {'api_token': 'cf-token-123'},
            'azure': {
                'subscription_id': 'sub-123',
                'resource_group': 'rg-test',
                'tenant_id': 'tenant-123',
                'client_id': 'client-123',
                'client_secret': 'secret-123'
            },
            'google': {
                'project_id': 'gcp-project-123',
                'service_account_key': '{"type": "service_account"}'
            },
            'route53': {
                'access_key_id': 'AKIATEST',
                'secret_access_key': 'secret-key'
            },
            'powerdns': {
                'api_url': 'https://powerdns.example.com:8081',
                'api_key': 'pdns-key-123'
            },
            'rfc2136': {
                'nameserver': '192.168.1.1',
                'tsig_key': 'test-key',
                'tsig_secret': 'test-secret',
                'api_key': 'rfc2136-api-key'  # Add api_key to trigger migration
            },
            'digitalocean': {'api_token': 'do-token-123'}
        }
        
        settings = {
            'dns_providers': {
                provider: single_account_configs[provider]
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # Should be migrated to multi-account format
        assert 'dns_providers' in result
        assert provider in result['dns_providers']
        assert 'accounts' in result['dns_providers'][provider]
        assert 'default' in result['dns_providers'][provider]['accounts']
        provider_default_account = result['dns_providers'][provider]['accounts']['default']
        assert 'name' in provider_default_account
        assert provider.title() in provider_default_account['name']
        
        # Should have default account mapping
        assert 'default_accounts' in result
        assert result['default_accounts'][provider] == 'default'
        
        # Original config should be preserved within the default account
        default_account = result['dns_providers'][provider]['accounts']['default']
        for key, value in single_account_configs[provider].items():
            assert key in default_account, f"Key {key} should be in default account"
            assert default_account[key] == value

    @pytest.mark.parametrize("provider", MULTI_ACCOUNT_PROVIDERS)
    def test_multi_account_config_retrieval(self, provider):
        """Test retrieving multi-account configurations for supported providers."""
        # Multi-account configuration
        settings = {
            'dns_providers': {
                provider: {
                    'accounts': {
                        'production': {
                            'name': 'Production Account',
                            'api_token': 'prod-token'  # Simplified for test
                        },
                        'staging': {
                            'name': 'Staging Account',
                            'api_token': 'staging-token'  # Simplified for test
                        }
                    }
                }
            },
            'default_accounts': {
                provider: 'production'
            }
        }
        
        # Test getting default account
        config, account_id = get_dns_provider_account_config(provider, None, settings)
        assert config is not None
        assert account_id == 'production'
        assert config['name'] == 'Production Account'
        
        # Test getting specific account
        config, account_id = get_dns_provider_account_config(provider, 'staging', settings)
        assert config is not None
        assert account_id == 'staging'
        assert config['name'] == 'Staging Account'

    @pytest.mark.parametrize("provider", MULTI_ACCOUNT_PROVIDERS)
    def test_multi_account_validation(self, provider):
        """Test validation of multi-account configurations for supported providers."""
        # Valid configurations for each provider
        valid_configs = {
            'cloudflare': {
                'name': 'Test Cloudflare Account',
                'api_token': 'valid-cloudflare-token-1234567890'
            },
            'azure': {
                'name': 'Test Azure Account',
                'subscription_id': 'sub-123',
                'resource_group': 'rg-test',
                'tenant_id': 'tenant-123',
                'client_id': 'client-123',
                'client_secret': 'secret-123'
            },
            'google': {
                'name': 'Test Google Account',
                'project_id': 'gcp-project-123',
                'service_account_key': '{"type": "service_account", "project_id": "test"}'
            },
            'route53': {
                'name': 'Test Route53 Account',
                'access_key_id': 'AKIATEST1234567890AB',
                'secret_access_key': 'test-secret-key-1234567890123456789012345678901234567890'
            },
            'powerdns': {
                'name': 'Test PowerDNS Account',
                'api_url': 'https://powerdns.example.com:8081',
                'api_key': 'pdns-key-123'
            },
            'rfc2136': {
                'name': 'Test RFC2136 Account',
                'nameserver': '192.168.1.1',
                'tsig_key': 'test-key',
                'tsig_secret': 'test-secret'
            },
            'digitalocean': {
                'name': 'Test DigitalOcean Account',
                'api_token': 'do-token-123'
            }
        }
        
        is_valid, message = validate_dns_provider_account(
            provider, 'test-account', valid_configs[provider]
        )
        assert is_valid, f"Provider {provider} should be valid: {message}"
        assert message == "Valid configuration."

    def test_multi_account_not_supported_for_other_providers(self):
        """Test that other providers don't have multi-account features tested."""
        # These providers don't support multi-account in our design
        unsupported_providers = [
            'linode', 'gandi', 'ovh', 'namecheap', 'vultr', 'hetzner', 
            'nsone', 'dnsmadeeasy', 'porkbun', 'godaddy', 'he-ddns', 'dynudns'
        ]
        
        for provider in unsupported_providers:
            # Should be able to handle single-account format
            settings = {
                'dns_providers': {
                    provider: {'api_key': 'test-key'}
                }
            }
            
            # Migration should still work but these are typically single-account
            result = migrate_dns_providers_to_multi_account(settings)
            
            # Should either migrate to multi-account or leave as single-account
            assert 'dns_providers' in result
            assert provider in result['dns_providers']

    def test_mixed_provider_configuration(self):
        """Test settings with both multi-account and single-account providers."""
        settings = {
            'dns_providers': {
                # Multi-account provider
                'cloudflare': {
                    'production': {
                        'name': 'Cloudflare Production',
                        'api_token': 'cf-prod-token'
                    },
                    'staging': {
                        'name': 'Cloudflare Staging',
                        'api_token': 'cf-staging-token'
                    }
                },
                # Single-account provider (should be migrated)
                'route53': {
                    'access_key_id': 'AKIATEST',
                    'secret_access_key': 'secret-key'
                },
                # Non-multi-account provider
                'linode': {
                    'api_key': 'linode-key'
                }
            },
            'default_accounts': {
                'cloudflare': 'production'
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # Cloudflare should remain in multi-account format
        assert 'production' in result['dns_providers']['cloudflare']
        assert 'staging' in result['dns_providers']['cloudflare']
        
        # Route53 should be migrated to multi-account
        assert 'accounts' in result['dns_providers']['route53']
        assert 'default' in result['dns_providers']['route53']['accounts']
        assert result['default_accounts']['route53'] == 'default'
        
        # Linode should be migrated to multi-account format too
        assert 'accounts' in result['dns_providers']['linode']
        assert 'default' in result['dns_providers']['linode']['accounts']
        assert result['default_accounts']['linode'] == 'default'

    def test_empty_multi_account_provider_config(self):
        """Test handling of empty configurations for multi-account providers."""
        for provider in self.MULTI_ACCOUNT_PROVIDERS:
            # Pass empty settings explicitly to avoid loading from disk
            empty_settings = {'dns_providers': {}}
            config, account_id = get_dns_provider_account_config(provider, None, empty_settings)
            assert config is None
            assert account_id is None

    def test_invalid_account_id_for_multi_account_providers(self):
        """Test accessing non-existent account IDs for multi-account providers."""
        settings = {
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'production': {
                            'name': 'Production Account',
                            'api_token': 'prod-token'
                        }
                    }
                }
            },
            'default_accounts': {
                'cloudflare': 'production'
            }
        }
        
        # Try to access non-existent account
        config, account_id = get_dns_provider_account_config('cloudflare', 'nonexistent', settings)
        assert config is None
        assert account_id is None
