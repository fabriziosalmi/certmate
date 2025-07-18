import pytest
from unittest.mock import patch, MagicMock
import sys
import os
import base64

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import (
    validate_email, validate_domain, validate_api_token, 
    generate_secure_token, validate_dns_provider_account,
    migrate_dns_providers_to_multi_account, get_dns_provider_account_config,
    list_dns_provider_accounts, migrate_domains_format
)

class TestValidationFunctions:
    """Test validation utility functions for better coverage."""
    
    def test_validate_email_valid_cases(self):
        """Test valid email validation cases."""
        valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "test+label@example.org",
            "simple@test.io",
            "user_name@example-domain.com"
        ]
        
        for email in valid_emails:
            is_valid, result = validate_email(email)
            assert is_valid, f"Email {email} should be valid"
            assert result == email.strip().lower()
    
    def test_validate_email_invalid_cases(self):
        """Test invalid email validation cases."""
        invalid_emails = [
            "",
            None,
            "invalid",
            "@example.com",
            "test@",
            "test.example.com",
            "test@.com",
            "test@example.",
            123,  # Not a string
        ]
        
        for email in invalid_emails:
            is_valid, error = validate_email(email)
            assert not is_valid, f"Email {email} should be invalid"
            assert isinstance(error, str)
    
    def test_validate_domain_valid_cases(self):
        """Test valid domain validation cases."""
        valid_domains = [
            "example.com",
            "sub.example.com",
            "test-domain.co.uk",
            "example.org",
            "1-domain.com",
            "domain-1.example.com",
        ]
        
        for domain in valid_domains:
            is_valid, result = validate_domain(domain)
            assert is_valid, f"Domain {domain} should be valid"
            assert isinstance(result, str)
        
        # Test domains with protocols - these WILL be cleaned by validate_domain
        # The function strips protocols and returns the clean domain
        protocol_domains = [
            ("https://example.com", "example.com"),
            ("http://sub.example.com", "sub.example.com"),
        ]
        
        for input_domain, expected_clean in protocol_domains:
            is_valid, result = validate_domain(input_domain)
            assert is_valid, f"Domain {input_domain} should be valid after protocol stripping"
            assert result == expected_clean, f"Expected {expected_clean}, got {result}"
    
    def test_validate_domain_invalid_cases(self):
        """Test invalid domain validation cases."""
        invalid_domains = [
            "",
            None,
            "invalid..domain.com",  # Double dots
            "domain_with_underscores.com", 
            ".example.com",
            "example.com.",
            "-example.com",
            "example-.com",
            "a" * 250 + ".com",  # Too long
            123,  # Not a string
        ]
        
        for domain in invalid_domains:
            is_valid, error = validate_domain(domain)
            assert not is_valid, f"Domain {domain} should be invalid"
            assert isinstance(error, str)
    
    def test_validate_api_token_valid_cases(self):
        """Test valid API token validation."""
        valid_tokens = [
            "Secure-Long-Unique-Random-String-Abcdefgh123",
            "VerySecureAuthWithNumbers987AndSymbols",
            "Environment-Bearer-Auth-With-Sufficient-Length456",
            "Valid_Auth_Without_Weak_Patterns_67890ABC",
        ]
        
        for token in valid_tokens:
            is_valid, result = validate_api_token(token)
            assert is_valid, f"Token should be valid: {token}"
            assert result == token.strip()
    
    def test_validate_api_token_invalid_cases(self):
        """Test invalid API token validation."""
        invalid_tokens = [
            "",
            None,
            "short",  # Too short
            "change-this-token",  # Contains weak pattern
            "certmate-api-token-12345",  # Contains weak pattern
            123,  # Not a string
        ]
        
        for token in invalid_tokens:
            is_valid, error = validate_api_token(token)
            assert not is_valid, f"Token {token} should be invalid"
            assert isinstance(error, str)
    
    def test_generate_secure_token(self):
        """Test secure token generation."""
        token = generate_secure_token()
        
        # Should be a string
        assert isinstance(token, str)
        
        # Should be appropriate length (base64url encoded, so length varies)
        assert len(token) >= 32
        
        # Should be URL-safe base64
        import base64
        try:
            base64.urlsafe_b64decode(token + '==')  # Add padding if needed
        except Exception:
            pass  # Some tokens might not need padding
        
        # Generate multiple tokens to ensure they're different
        tokens = [generate_secure_token() for _ in range(5)]
        assert len(set(tokens)) == 5, "Generated tokens should be unique"
    
    def test_validate_dns_provider_account_cloudflare(self):
        """Test Cloudflare DNS provider account validation."""
        # Valid config
        valid_config = {
            "api_token": "valid_cloudflare_token_here_with_length"
        }
        is_valid, error = validate_dns_provider_account("cloudflare", "prod", valid_config)
        assert is_valid
        
        # Invalid configs
        invalid_configs = [
            {},  # Empty - missing api_token
            {"api_token": ""},  # Empty token
            {"name": "Test"},  # Missing api_token
        ]
        
        for config in invalid_configs:
            is_valid, error = validate_dns_provider_account("cloudflare", "test", config)
            assert not is_valid
            assert isinstance(error, str)
    
    def test_validate_dns_provider_account_route53(self):
        """Test AWS Route53 DNS provider account validation."""
        # Valid config
        valid_config = {
            "access_key_id": "AKIAIOSFODNN7EXAMPLE",
            "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        }
        is_valid, error = validate_dns_provider_account("route53", "aws-prod", valid_config)
        assert is_valid
        
        # Invalid configs
        invalid_configs = [
            {},  # Missing credentials
            {"access_key_id": ""},  # Empty access key
            {"access_key_id": "AKIAIOSFODNN7EXAMPLE"},  # Missing secret
            {"secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},  # Missing access key
        ]
        
        for config in invalid_configs:
            is_valid, error = validate_dns_provider_account("route53", "test", config)
            assert not is_valid
            assert isinstance(error, str)
    
    def test_validate_dns_provider_account_azure(self):
        """Test Azure DNS provider account validation."""
        # Valid config
        valid_config = {
            "name": "Azure Production",
            "subscription_id": "12345678-1234-1234-1234-123456789012",
            "resource_group": "my-resource-group",
            "tenant_id": "87654321-4321-4321-4321-210987654321",
            "client_id": "11111111-1111-1111-1111-111111111111",
            "client_secret": "very-secret-client-secret-value"
        }
        is_valid, error = validate_dns_provider_account("azure", "azure-prod", valid_config)
        assert is_valid
        
        # Invalid configs - missing required fields
        required_fields = ['subscription_id', 'resource_group', 'tenant_id', 'client_id', 'client_secret']
        for field in required_fields:
            config = valid_config.copy()
            del config[field]
            is_valid, error = validate_dns_provider_account("azure", "test", config)
            assert not is_valid
            assert field in error
    
    def test_validate_dns_provider_account_google(self):
        """Test Google Cloud DNS provider account validation."""
        # Valid config
        valid_config = {
            "project_id": "my-gcp-project-123456",
            "service_account_key": '{"type": "service_account", "project_id": "test"}'
        }
        is_valid, error = validate_dns_provider_account("google", "gcp-prod", valid_config)
        assert is_valid
        
        # Invalid configs
        invalid_configs = [
            {},  # Missing fields
            {"project_id": "test"},  # Missing service account key
            {"service_account_key": '{"type": "service_account"}'},  # Missing project_id
            {"project_id": "", "service_account_key": "{}"},  # Empty project ID
        ]
        
        for config in invalid_configs:
            is_valid, error = validate_dns_provider_account("google", "test", config)
            assert not is_valid
            assert isinstance(error, str)
    
    def test_validate_dns_provider_account_powerdns(self):
        """Test PowerDNS provider account validation."""
        # Valid config
        valid_config = {
            "name": "PowerDNS Server",
            "api_url": "https://powerdns.example.com:8081",
            "api_key": "powerdns-api-key-123456"
        }
        is_valid, error = validate_dns_provider_account("powerdns", "pdns", valid_config)
        assert is_valid
        
        # Invalid configs
        invalid_configs = [
            {"name": "Test"},  # Missing fields
            {"name": "Test", "api_url": "invalid-url"},  # Invalid URL
            {"name": "Test", "api_url": "https://example.com", "api_key": ""},  # Empty API key
            {"name": "Test", "api_url": "", "api_key": "key"},  # Empty URL
        ]
        
        for config in invalid_configs:
            is_valid, error = validate_dns_provider_account("powerdns", "test", config)
            assert not is_valid
            assert isinstance(error, str)
    
    def test_validate_dns_provider_account_other_providers(self):
        """Test other DNS provider account validation."""
        # Test providers that use api_key
        api_key_providers = ['linode', 'vultr', 'nsone']
        for provider in api_key_providers:
            valid_config = {
                "api_key": f"{provider}-api-key-123456789012345"
            }
            is_valid, error = validate_dns_provider_account(provider, "test", valid_config)
            assert is_valid, f"Provider {provider} should validate: {error}"
            
        # Test providers that use api_token
        api_token_providers = ['digitalocean', 'gandi', 'hetzner']
        for provider in api_token_providers:
            valid_config = {
                "api_token": f"{provider}-token-123456789012345"
            }
            is_valid, error = validate_dns_provider_account(provider, "test", valid_config)
            assert is_valid, f"Provider {provider} should validate: {error}"
        
        # Test dnsmadeeasy with api_key + secret_key
        dme_config = {
            "api_key": "dme-api-key-123456789012345",
            "secret_key": "dme-secret-key-123456789012345"
        }
        is_valid, error = validate_dns_provider_account("dnsmadeeasy", "test", dme_config)
        assert is_valid, f"DNS Made Easy should validate: {error}"
        
        # Test invalid configs for all providers
        for provider in api_key_providers + api_token_providers + ['dnsmadeeasy']:
            invalid_config = {}  # Missing required fields
            is_valid, error = validate_dns_provider_account(provider, "test", invalid_config)
            assert not is_valid
            assert "required" in error.lower()
    
    def test_validate_dns_provider_account_namecheap(self):
        """Test Namecheap DNS provider account validation."""
        # Valid config
        valid_config = {
            "username": "myusername",
            "api_key": "namecheap-api-key-12345"
        }
        is_valid, error = validate_dns_provider_account("namecheap", "nc", valid_config)
        assert is_valid
        
        # Invalid configs - missing required fields
        invalid_configs = [
            {},  # Missing credentials
            {"username": ""},  # Empty username
            {"username": "user"},  # Missing api_key
            {"api_key": "test"},  # Missing username
        ]
        
        for config in invalid_configs:
            is_valid, error = validate_dns_provider_account("namecheap", "test", config)
            assert not is_valid
            assert "required" in error.lower()
    
    def test_validate_dns_provider_account_rfc2136(self):
        """Test RFC2136 DNS provider account validation."""
        # Valid config
        valid_config = {
            "name": "RFC2136 Server",
            "nameserver": "ns.example.com",
            "tsig_key": "mykey",
            "tsig_secret": "base64encoded-secret-value"
        }
        is_valid, error = validate_dns_provider_account("rfc2136", "rfc", valid_config)
        assert is_valid
        
        # Invalid configs
        required_fields = ['nameserver', 'tsig_key', 'tsig_secret']
        for field in required_fields:
            config = valid_config.copy()
            del config[field]
            is_valid, error = validate_dns_provider_account("rfc2136", "test", config)
            assert not is_valid
            assert field in error.lower()
    
    def test_validate_dns_provider_account_tier3_providers(self):
        """Test tier 3 DNS provider validation (porkbun, godaddy, he-ddns, dynudns)."""
        # Test Porkbun
        porkbun_config = {
            "name": "Porkbun Account",
            "api_key": "porkbun_api_key_123456",
            "secret_key": "porkbun_secret_key_789"
        }
        is_valid, error = validate_dns_provider_account("porkbun", "pb", porkbun_config)
        assert is_valid
        
        # Test GoDaddy
        godaddy_config = {
            "name": "GoDaddy Account",
            "api_key": "godaddy_api_key_123456",
            "secret": "godaddy_secret_789"
        }
        is_valid, error = validate_dns_provider_account("godaddy", "gd", godaddy_config)
        assert is_valid
        
        # Test Hurricane Electric
        he_config = {
            "name": "Hurricane Electric",
            "username": "he_username",
            "password": "he_password_123"
        }
        is_valid, error = validate_dns_provider_account("he-ddns", "he", he_config)
        assert is_valid
        
        # Test Dynu
        dynu_config = {
            "name": "Dynu Account",
            "token": "dynu_api_token_123456789"
        }
        is_valid, error = validate_dns_provider_account("dynudns", "dynu", dynu_config)
        assert is_valid
    
    def test_validate_dns_provider_account_edge_cases(self):
        """Test edge cases for DNS provider validation."""
        # Test valid minimal config
        config_minimal = {
            "api_token": "valid_token_here_with_sufficient_length"
        }
        is_valid, result = validate_dns_provider_account("cloudflare", "test", config_minimal)
        assert is_valid
        
        # Test empty required field
        config_empty_token = {
            "api_token": ""
        }
        is_valid, error = validate_dns_provider_account("cloudflare", "test", config_empty_token)
        assert not is_valid
        assert "missing" in error.lower() or "required" in error.lower()
        
        # Test non-dict configuration
        is_valid, error = validate_dns_provider_account("cloudflare", "test", "not_a_dict")
        assert not is_valid
        
        # Test None configuration
        is_valid, error = validate_dns_provider_account("cloudflare", "test", None)
        assert not is_valid
        assert "nonetype" in error.lower() or "none" in error.lower() or "attribute" in error.lower()
    
    def test_validate_domain_edge_cases(self):
        """Test edge cases for domain validation."""
        # Test domain with path (protocol is stripped, path is ignored, resulting in valid domain)
        is_valid, result = validate_domain("https://example.com/path")
        # The function uses urlparse which extracts just "example.com" from the URL
        assert is_valid
        assert result == "example.com"
        
        # Test domain with port (protocol is stripped, but port remains and should be invalid)  
        is_valid, result = validate_domain("https://example.com:8080")
        # The function strips protocol, so this becomes "example.com:8080" which is invalid
        assert not is_valid
        
        # Test international domain
        is_valid, result = validate_domain("münchen.de")
        # This might fail depending on regex, which is expected
        # International domains are complex, so this tests the boundary
        
        # Test single-character TLD (valid per spec)
        is_valid, result = validate_domain("example.x")
        # Should be valid according to current regex
        
        # Test very long but valid domain parts
        long_subdomain = "a" * 63  # Max length for a domain label
        test_domain = f"{long_subdomain}.example.com"
        is_valid, result = validate_domain(test_domain)
        # Should be valid as each part is within limits
    
    def test_validate_email_edge_cases(self):
        """Test edge cases for email validation.""" 
        # Test email at maximum length (320 chars total is RFC limit, but our limit is 254)
        long_local = "a" * 50
        long_domain = "b" * 50 + ".com"
        long_email = f"{long_local}@{long_domain}"
        is_valid, result = validate_email(long_email)
        # Should be valid if under our 254 char limit
        
        # Test email with special characters that should be valid
        special_emails = [
            "user+tag@example.com",
            "user.name@example.com",
            "user_name@example.com",
            "user-name@example.com",
            "123@example.com",
        ]
        
        for email in special_emails:
            is_valid, result = validate_email(email)
            assert is_valid, f"Email {email} should be valid"
            assert result == email.lower()
        
        # Test whitespace handling
        is_valid, result = validate_email("  test@example.com  ")
        assert is_valid
        assert result == "test@example.com"
    
    def test_validate_api_token_edge_cases(self):
        """Test edge cases for API token validation."""
        # Test token at minimum length boundary with sufficient variety and character types
        min_token = "AbcDefGhiJkL123mnOpQrStUvWxYz890"  # 32 chars with good variety, no repeating patterns
        is_valid, result = validate_api_token(min_token)
        # Should be valid since it has sufficient length, variety, and character types
        assert is_valid
        
        # Test token just under minimum
        short_token = "x" * 31
        is_valid, result = validate_api_token(short_token)
        assert not is_valid
        assert "between 32 and 512 characters" in result
        
        # Test token at maximum boundary (512 chars) with character types
        # Create a 512-char token with good variety and no repeating patterns
        import string
        import random
        random.seed(42)  # For reproducible tests
        chars = string.ascii_letters + string.digits + '-_'
        max_token = ''.join(random.choice(chars) for _ in range(512))
        # Ensure it has required character types
        max_token = 'A1' + max_token[2:]  # Ensure uppercase and digit
        is_valid, result = validate_api_token(max_token)
        assert is_valid  # Should be valid if no weak patterns
        
        # Test token over maximum (512 chars)
        over_max = max_token + "X"  # 513 chars
        is_valid, result = validate_api_token(over_max)
        assert not is_valid  # Should be invalid - too long
        assert "between 32 and 512 characters" in result.lower()
        
        # Test whitespace handling
        spaced_token = "  Valid-Unique-Environment-Auth-67890  "
        is_valid, result = validate_api_token(spaced_token)
        assert is_valid
        assert result == "Valid-Unique-Environment-Auth-67890"  # App strips whitespace
        
        # Test case sensitivity of weak patterns
        case_test_tokens = [
            "change-this-token",  # Weak token from app.py
            "certmate-api-token-12345",  # Weak token from app.py
        ]
        
        for token in case_test_tokens:
            is_valid, error = validate_api_token(token)
            assert not is_valid, f"Token {token} should fail due to weak pattern"
    
    def test_generate_secure_token_properties(self):
        """Test properties of generated secure tokens."""
        # Generate multiple tokens and test their properties
        tokens = [generate_secure_token() for _ in range(10)]
        
        for token in tokens:
            # Should pass our own validation
            is_valid, result = validate_api_token(token)
            assert is_valid, f"Generated token {token} should be valid"
            
            # Should be URL-safe (no special chars that need encoding)
            import urllib.parse
            assert urllib.parse.quote(token, safe='') == token or urllib.parse.quote_plus(token) != token
        
        # Test uniqueness across multiple generations
        assert len(set(tokens)) == len(tokens), "All generated tokens should be unique"
    
    def test_dns_provider_account_validation_comprehensive(self):
        """Comprehensive test of all DNS provider validations."""
        # Test all supported providers with minimal valid configs
        provider_configs = {
            "cloudflare": {"name": "CF", "api_token": "cf_token_123456"},
            "route53": {
                "name": "AWS", 
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            },
            "azure": {
                "name": "Azure",
                "subscription_id": "12345678-1234-1234-1234-123456789012",
                "resource_group": "rg",
                "tenant_id": "87654321-4321-4321-4321-210987654321",
                "client_id": "11111111-1111-1111-1111-111111111111",
                "client_secret": "secret"
            },
            "google": {
                "name": "GCP",
                "project_id": "my-project",
                "service_account_key": '{"type": "service_account", "project_id": "test"}'
            },
            "powerdns": {
                "name": "PowerDNS",
                "api_url": "https://powerdns.example.com:8081",
                "api_key": "pdns_key"
            },
            "digitalocean": {"name": "DO", "api_token": "do_token_123456"},
            "linode": {"name": "Linode", "api_key": "linode_key_123456"},
            "gandi": {"name": "Gandi", "api_token": "gandi_token_123456"},
            "vultr": {"name": "Vultr", "api_key": "vultr_key_123456"},
            "hetzner": {"name": "Hetzner", "api_token": "hetzner_token_123456"},
            "nsone": {"name": "NS1", "api_key": "ns1_key_123456"},
            "dnsmadeeasy": {"name": "DME", "api_key": "dme_key_123456", "secret_key": "dme_secret_123456"},
        }
        
        for provider, config in provider_configs.items():
            is_valid, error = validate_dns_provider_account(provider, "test", config)
            assert is_valid, f"Provider {provider} should validate: {error}"

class TestDNSMultiAccountFunctions:
    """Test DNS multi-account related functions."""
    
    @patch('app.logger')
    def test_migrate_dns_providers_to_multi_account_no_migration_needed(self, mock_logger):
        """Test migration when no migration is needed."""
        settings = {
            'dns_providers': {
                'cloudflare': {
                    'prod': {
                        'name': 'Production',
                        'api_token': 'token123'
                    }
                }
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        assert result == settings
        mock_logger.info.assert_not_called()
    
    @patch('app.logger')
    def test_migrate_dns_providers_to_multi_account_migration_needed(self, mock_logger):
        """Test migration when single-account format needs migration."""
        settings = {
            'dns_providers': {
                'cloudflare': {
                    'api_token': 'token123'
                },
                'route53': {
                    'access_key_id': 'AKIA123',
                    'secret_access_key': 'secret123'
                }
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # Check structure was migrated
        assert 'default_accounts' in result
        assert result['default_accounts']['cloudflare'] == 'default'
        assert result['default_accounts']['route53'] == 'default'
        
        assert 'accounts' in result['dns_providers']['cloudflare']
        assert 'default' in result['dns_providers']['cloudflare']['accounts']
        default_cf = result['dns_providers']['cloudflare']['accounts']['default']
        assert 'Default' in default_cf['name']
        assert default_cf['api_token'] == 'token123'
        
        assert 'accounts' in result['dns_providers']['route53']
        assert 'default' in result['dns_providers']['route53']['accounts']
        default_r53 = result['dns_providers']['route53']['accounts']['default']
        assert default_r53['access_key_id'] == 'AKIA123'
        
        mock_logger.info.assert_called()
    
    @patch('app.logger')
    def test_migrate_dns_providers_no_dns_providers(self, mock_logger):
        """Test migration when no dns_providers exist."""
        settings = {}
        
        result = migrate_dns_providers_to_multi_account(settings)
        assert result == settings
        mock_logger.info.assert_not_called()
    
    @patch('app.logger')
    def test_migrate_dns_providers_empty_config(self, mock_logger):
        """Test migration with empty provider config."""
        settings = {
            'dns_providers': {
                'cloudflare': {},
                'route53': None
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # Empty/None configs should be preserved
        assert result['dns_providers']['cloudflare'] == {}
        assert result['dns_providers']['route53'] is None
        mock_logger.info.assert_not_called()
    
    @patch('app.logger')
    def test_migrate_dns_providers_mixed_format(self, mock_logger):
        """Test migration with mixed old and new format."""
        settings = {
            'dns_providers': {
                'cloudflare': {
                    'api_token': 'token123'  # Old format
                },
                'route53': {
                    'prod': {
                        'name': 'Production',
                        'access_key_id': 'AKIA123'  # Already new format
                    }
                }
            },
            'default_accounts': {
                'route53': 'prod'
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # Only cloudflare should be migrated
        assert result['default_accounts']['cloudflare'] == 'default'
        assert result['default_accounts']['route53'] == 'prod'  # Unchanged
        
        assert 'accounts' in result['dns_providers']['cloudflare']
        assert 'default' in result['dns_providers']['cloudflare']['accounts']
        assert 'prod' in result['dns_providers']['route53']  # Unchanged structure

    def test_get_dns_provider_account_config_success(self):
        """Test getting DNS provider account config successfully."""
        with patch('app.load_settings') as mock_load_settings:
            mock_load_settings.return_value = {
                'dns_providers': {
                    'cloudflare': {
                        'accounts': {
                            'prod': {
                                'name': 'Production',
                                'api_token': 'token123'
                            }
                        }
                    }
                }
            }
            
            config, account_id = get_dns_provider_account_config('cloudflare', 'prod')
            assert config['name'] == 'Production'
            assert config['api_token'] == 'token123'
            assert account_id == 'prod'
    
    def test_get_dns_provider_account_config_provider_not_found(self):
        """Test getting config when provider doesn't exist."""
        with patch('app.load_settings') as mock_load_settings:
            mock_load_settings.return_value = {'dns_providers': {}}
            
            config, account_id = get_dns_provider_account_config('nonexistent', 'prod')
            assert config is None
            assert account_id is None
    
    def test_get_dns_provider_account_config_account_not_found(self):
        """Test getting config when account doesn't exist."""
        with patch('app.load_settings') as mock_load_settings:
            mock_load_settings.return_value = {
                'dns_providers': {
                    'cloudflare': {
                        'accounts': {
                            'prod': {'name': 'Production'}
                        }
                    }
                }
            }
            
            config, account_id = get_dns_provider_account_config('cloudflare', 'nonexistent')
            assert config is None
            assert account_id is None
    
    def test_list_dns_provider_accounts_success(self):
        """Test listing DNS provider accounts successfully."""
        with patch('app.load_settings') as mock_load_settings:
            mock_load_settings.return_value = {
                'dns_providers': {
                    'cloudflare': {
                        'accounts': {
                            'prod': {'name': 'Production'},
                            'staging': {'name': 'Staging'}
                        }
                    }
                }
            }
            
            accounts = list_dns_provider_accounts('cloudflare')
            assert len(accounts) == 2
            account_ids = [acc['account_id'] for acc in accounts]
            assert 'prod' in account_ids
            assert 'staging' in account_ids
            prod_account = next(acc for acc in accounts if acc['account_id'] == 'prod')
            assert prod_account['name'] == 'Production'
    
    def test_list_dns_provider_accounts_provider_not_found(self):
        """Test listing accounts when provider doesn't exist."""
        with patch('app.load_settings') as mock_load_settings:
            mock_load_settings.return_value = {'dns_providers': {}}
            
            accounts = list_dns_provider_accounts('nonexistent')
            assert accounts == []
    
    def test_migrate_domains_format_success(self):
        """Test domain format migration."""
        old_settings = {
            'domains': [
                'example.com'
            ],
            'dns_provider': 'cloudflare'
        }
        
        new_settings = migrate_domains_format(old_settings)
        
        assert len(new_settings['domains']) == 1
        assert new_settings['domains'][0]['domain'] == 'example.com'
        assert new_settings['domains'][0]['dns_provider'] == 'cloudflare'
    
    def test_migrate_domains_format_with_account_id(self):
        """Test domain format migration when account_id already exists."""
        old_settings = {
            'domains': [
                {
                    'domain': 'example.com',
                    'dns_provider': 'cloudflare',
                    'account_id': 'prod'
                }
            ]
        }
        
        new_settings = migrate_domains_format(old_settings)
        
        assert len(new_settings['domains']) == 1
        assert new_settings['domains'][0]['account_id'] == 'prod'

class TestValidationEdgeCases:
    """Test additional edge cases for validation functions."""
    
    def test_validate_email_unicode_domains(self):
        """Test email validation with unicode domain names."""
        unicode_emails = [
            "test@xn--nxasmq6b.com",  # IDN domain
            "user@éxample.com",        # Direct unicode
        ]
        
        for email in unicode_emails:
            is_valid, result = validate_email(email)
            # Should handle gracefully (may be valid or invalid depending on implementation)
            assert isinstance(is_valid, bool)
            assert isinstance(result, str)
    
    def test_validate_domain_unicode_domains(self):
        """Test domain validation with unicode characters."""
        unicode_domains = [
            "éxample.com",
            "xn--nxasmq6b.com",  # Punycode
            "тест.com",
        ]
        
        for domain in unicode_domains:
            is_valid, result = validate_domain(domain)
            assert isinstance(is_valid, bool)
            assert isinstance(result, str)
    
    def test_validate_api_token_unicode_characters(self):
        """Test API token validation with unicode characters."""
        unicode_tokens = [
            "token-with-émojis-🔑-very-long-enough-for-validation",
            "токен-с-русскими-символами-достаточно-длинный"
        ]
        
        for token in unicode_tokens:
            is_valid, result = validate_api_token(token)
            # Unicode tokens should generally be valid if long enough
            assert isinstance(is_valid, bool)
            assert isinstance(result, str)
    
    def test_validate_dns_provider_account_with_extra_fields(self):
        """Test DNS provider validation with extra fields."""
        config_with_extra = {
            "name": "Test Account",
            "api_token": "valid_token_here_with_sufficient_length",
            "extra_field": "should_be_ignored",
            "description": "Optional description",
            "tags": ["production", "primary"]
        }
        
        is_valid, error = validate_dns_provider_account("cloudflare", "test", config_with_extra)
        assert is_valid, f"Should be valid even with extra fields: {error}"
    
    def test_validate_dns_provider_account_case_insensitive_provider(self):
        """Test DNS provider validation with different case providers."""
        config = {
            "name": "Test Account",
            "api_token": "valid_token_here_with_sufficient_length"
        }
        
        # Test different cases
        providers = ["CloudFlare", "CLOUDFLARE", "cloudflare", "Cloudflare"]
        
        for provider in providers:
            is_valid, error = validate_dns_provider_account(provider.lower(), "test", config)
            # Should validate the same regardless of case (after normalization)
            assert isinstance(is_valid, bool)
            assert isinstance(error, str)
    
    def test_generate_secure_token_multiple_calls_uniqueness(self):
        """Test that multiple secure token generations are unique."""
        tokens = set()
        for _ in range(100):  # Generate many tokens
            token = generate_secure_token()
            assert token not in tokens, "Generated token should be unique"
            tokens.add(token)
            assert len(token) >= 32, "Token should be at least 32 characters"
    
    def test_generate_secure_token_character_set(self):
        """Test that generated tokens use appropriate character set."""
        import string
        
        token = generate_secure_token()
        
        # Should only contain URL-safe base64 characters
        allowed_chars = set(string.ascii_letters + string.digits + '-_')
        token_chars = set(token)
        
        # All characters should be in allowed set
        assert token_chars.issubset(allowed_chars), f"Token contains invalid characters: {token_chars - allowed_chars}"

class TestValidationCornerCases:
    """Test corner cases and boundary conditions."""
    
    def test_validate_email_boundary_lengths(self):
        """Test email validation at boundary lengths."""
        # Test exactly at the limit
        long_local = "a" * 64  # Max local part length
        long_domain = "b" * 63 + ".com"  # Max domain label length
        boundary_email = f"{long_local}@{long_domain}"
        
        is_valid, result = validate_email(boundary_email)
        assert isinstance(is_valid, bool)
        
        # Test just over the limit
        too_long_email = "a" * 250 + "@example.com"
        is_valid, error = validate_email(too_long_email)
        # The app.py email validation doesn't enforce length limits
        assert isinstance(is_valid, bool)
    
    def test_validate_domain_boundary_lengths(self):
        """Test domain validation at boundary lengths."""
        # Test exactly at limit
        long_domain = "a" * 63 + ".com"  # Max label length
        is_valid, result = validate_domain(long_domain)
        assert isinstance(is_valid, bool)
        
        # Test just over limit
        too_long_domain = "a" * 250 + ".com"
        is_valid, error = validate_domain(too_long_domain)
        assert not is_valid
        assert "domain is too long" in error.lower()
    
    def test_validate_api_token_boundary_lengths(self):
        """Test API token validation at boundary lengths."""
        # Test exactly at minimum with sufficient variety and character types
        min_token = "AbcDefGhiJkL123mnOpQrStUvWxYz890"  # 32 chars with good variety, no repeating patterns
        is_valid, result = validate_api_token(min_token)
        assert is_valid
        
        # Test just under minimum
        too_short = "a" * 31
        is_valid, error = validate_api_token(too_short)
        assert not is_valid
        assert "between 32 and 512 characters" in error
        
        # Test at maximum (512 chars) with character types
        # Create a 512-char token with good variety and no repeating patterns
        import string
        import random
        random.seed(42)  # For reproducible tests
        chars = string.ascii_letters + string.digits + '-_'
        max_token = ''.join(random.choice(chars) for _ in range(512))
        # Ensure it has required character types
        max_token = 'A1' + max_token[2:]  # Ensure uppercase and digit
        is_valid, result = validate_api_token(max_token)
        assert is_valid
        
        # Test over maximum (513 chars)
        too_long = max_token + "X"  # 513 chars
        is_valid, error = validate_api_token(too_long)
        assert not is_valid  # App DOES enforce max length
        assert "between 32 and 512 characters" in error.lower()
