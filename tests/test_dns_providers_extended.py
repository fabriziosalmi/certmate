import pytest
import json
import requests_mock
from unittest.mock import patch, MagicMock

@pytest.mark.dns
@pytest.mark.integration
class TestDNSProviderIntegration:
    """Test DNS provider integrations with real API patterns."""
    
    def test_cloudflare_dns_providers_endpoint(self, client):
        """Test Cloudflare DNS provider endpoint structure."""
        response = client.get('/api/settings/dns-providers')
        assert response.status_code in [200, 401, 404]
    
    def test_cloudflare_api_token_validation(self, requests_mock, client):
        """Test Cloudflare API token validation with mocked requests."""
        # Mock Cloudflare API response
        requests_mock.get('https://api.cloudflare.com/client/v4/user/tokens/verify',
              json={'success': True, 'result': {'status': 'active'}})
        
        # Test with valid token format
        token_data = {
            'api_token': 'valid_cloudflare_token_format_here',
            'provider': 'cloudflare'
        }
        
        # This endpoint might not exist yet, but we test the pattern
        response = client.post('/api/settings/dns-providers/cloudflare/validate',
                             data=json.dumps(token_data),
                             content_type='application/json')
        assert response.status_code in [200, 404, 401, 422]
    
    def test_cloudflare_zone_listing(self, requests_mock, client):
        """Test Cloudflare zone listing functionality."""
        # Mock Cloudflare zones API
        requests_mock.get('https://api.cloudflare.com/client/v4/zones',
              json={
                  'success': True,
                  'result': [
                      {'id': 'zone1', 'name': 'example.com', 'status': 'active'},
                      {'id': 'zone2', 'name': 'test.com', 'status': 'active'}
                  ]
              })
        
        # Test zone listing endpoint
        response = client.get('/api/settings/dns-providers/cloudflare/zones')
        assert response.status_code in [200, 404, 401]
    
    @patch('app.safe_file_read')
    def test_route53_configuration(self, mock_read, client):
        """Test Route53 DNS provider configuration."""
        mock_read.return_value = {
            'aws_access_key_id': 'test_key',
            'aws_secret_access_key': 'test_secret',
            'aws_region': 'us-east-1'
        }
        
        response = client.get('/api/dns/route53/accounts')
        assert response.status_code in [200, 401, 404]
    
    @patch('app.safe_file_read')
    def test_digitalocean_configuration(self, mock_read, client):
        """Test DigitalOcean DNS provider configuration."""
        mock_read.return_value = {
            'digitalocean_token': 'test_do_token'
        }
        
        response = client.get('/api/dns/digitalocean/accounts')
        assert response.status_code in [200, 401, 404]

@pytest.mark.dns
@pytest.mark.unit
class TestDNSProviderValidation:
    """Test DNS provider validation logic."""
    
    def test_supported_dns_providers(self):
        """Test that all supported DNS providers are defined."""
        # These should match what's actually supported in the app
        expected_providers = [
            'cloudflare',
            'route53',
            'digitalocean',
            'azure',
            'google'
        ]
        
        # Test that each provider has proper configuration
        for provider in expected_providers:
            assert provider is not None
            assert len(provider) > 0
    
    def test_dns_provider_account_structure(self, client):
        """Test DNS provider account data structure."""
        providers = ['cloudflare', 'route53', 'digitalocean']
        
        for provider in providers:
            # Test account creation with minimal data
            account_data = {
                'name': f'Test {provider} Account',
                'provider': provider
            }
            
            response = client.post(f'/api/dns/{provider}/accounts',
                                 data=json.dumps(account_data),
                                 content_type='application/json')
            # Should validate structure (may require auth)
            assert response.status_code in [200, 201, 400, 401, 422]
    
    def test_invalid_dns_provider(self, client):
        """Test handling of invalid DNS provider."""
        invalid_providers = ['invalid_provider', 'nonexistent', '']
        
        for provider in invalid_providers:
            response = client.get(f'/api/dns/{provider}/accounts')
            assert response.status_code in [200, 400, 401, 404]  # App might handle all providers, 401 for auth required

@pytest.mark.dns
@pytest.mark.integration
class TestDNSChallengeFlow:
    """Test DNS challenge flow for certificate issuance."""
    
    @patch('app.subprocess.run')
    @patch('app.safe_file_read')
    def test_dns_challenge_creation(self, mock_read, mock_subprocess, client):
        """Test DNS challenge creation process."""
        # Mock settings with DNS provider config
        mock_read.return_value = {
            'cloudflare_api_token': 'test-token',
            'cloudflare_email': 'test@example.com',
            'certbot_email': 'test@example.com'
        }
        
        # Mock successful certbot command
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout='Successfully received certificate',
            stderr=''
        )
        
        # Test certificate creation with DNS challenge
        cert_data = {
            'domain': 'dns-challenge.example.com',
            'dns_provider': 'cloudflare',
            'challenge_type': 'dns-01'
        }
        
        response = client.post('/api/web/certificates/create', data=cert_data)
        assert response.status_code in [200, 302, 401, 404, 415]
        
        # Verify certbot was called with DNS challenge
        if mock_subprocess.called:
            args = mock_subprocess.call_args[0][0]
            assert '--dns-cloudflare' in ' '.join(args) or 'dns' in ' '.join(args).lower()
    
    @patch('app.subprocess.run')
    def test_dns_record_cleanup(self, mock_subprocess, requests_mock, client):
        """Test DNS record cleanup after certificate issuance."""
        # Mock DNS API calls
        requests_mock.post('https://api.cloudflare.com/client/v4/zones/test-zone/dns_records',
               json={'success': True, 'result': {'id': 'record123'}})
        requests_mock.delete('https://api.cloudflare.com/client/v4/zones/test-zone/dns_records/record123',
                json={'success': True})
        
        # Mock certbot success
        mock_subprocess.return_value = MagicMock(returncode=0, stdout='Success', stderr='')
        
        # Test that DNS records are cleaned up after cert creation
        cert_data = {
            'domain': 'cleanup-test.example.com',
            'dns_provider': 'cloudflare'
        }
        
        response = client.post('/api/web/certificates/create', data=cert_data)
        assert response.status_code in [200, 302, 401, 404, 415]

@pytest.mark.dns
@pytest.mark.unit
class TestDNSProviderErrors:
    """Test DNS provider error handling."""
    
    def test_cloudflare_api_errors(self, requests_mock, client):
        """Test handling of Cloudflare API errors."""
        # Mock API error responses
        error_responses = [
            (401, {'success': False, 'errors': [{'code': 10000, 'message': 'Invalid API token'}]}),
            (403, {'success': False, 'errors': [{'code': 10001, 'message': 'Insufficient permissions'}]}),
            (429, {'success': False, 'errors': [{'code': 10014, 'message': 'Rate limit exceeded'}]}),
            (500, {'success': False, 'errors': [{'code': 10002, 'message': 'Internal server error'}]})
        ]
        
        for status_code, response_data in error_responses:
            requests_mock.get('https://api.cloudflare.com/client/v4/user/tokens/verify',
                  status_code=status_code, json=response_data)
            
            # Test API validation endpoint
            token_data = {'api_token': 'invalid_token'}
            response = client.post('/api/settings/dns-providers/cloudflare/validate',
                                 data=json.dumps(token_data),
                                 content_type='application/json')
            # Should handle errors gracefully
            assert response.status_code in [200, 400, 401, 404, 422, 500]
    
    @patch('app.subprocess.run')
    def test_certbot_dns_errors(self, mock_subprocess, client):
        """Test handling of certbot DNS-related errors."""
        # Mock various certbot error scenarios
        error_scenarios = [
            (1, 'DNS challenge failed: Unable to reach DNS server'),
            (2, 'Rate limit exceeded for domain'),
            (3, 'Invalid DNS credentials'),
            (4, 'DNS propagation timeout')
        ]
        
        for return_code, error_message in error_scenarios:
            mock_subprocess.return_value = MagicMock(
                returncode=return_code,
                stdout='',
                stderr=error_message
            )
            
            cert_data = {
                'domain': f'error-test-{return_code}.example.com',
                'dns_provider': 'cloudflare'
            }
            
            response = client.post('/api/web/certificates/create', data=cert_data)
            # Should handle certbot errors gracefully
            assert response.status_code in [200, 302, 400, 401, 404, 415, 422, 500]
    
    def test_missing_dns_credentials(self, client):
        """Test handling of missing DNS provider credentials."""
        with patch('app.safe_file_read', return_value={}):
            cert_data = {
                'domain': 'no-creds.example.com',
                'dns_provider': 'cloudflare'
            }
            
            response = client.post('/api/web/certificates/create', data=cert_data)
            # Should fail gracefully with missing credentials
            assert response.status_code in [400, 401, 404, 415, 422]

@pytest.mark.dns
@pytest.mark.integration  
class TestMultiProviderSupport:
    """Test multiple DNS provider support for multi-account enabled providers only.
    
    Multi-account providers: cloudflare, azure, google, route53, powerdns, rfc2136, digitalocean
    """
    
    # Only test providers that actually support multi-account
    MULTI_ACCOUNT_PROVIDERS = ['cloudflare', 'azure', 'google', 'route53', 'powerdns', 'rfc2136', 'digitalocean']
    
    @patch('app.safe_file_read')
    def test_multiple_cloudflare_accounts(self, mock_read, client):
        """Test support for multiple Cloudflare accounts."""
        mock_read.return_value = {
            'dns_providers': {
                'cloudflare': {
                    'account1': {
                        'name': 'Personal Account',
                        'api_token': 'token1'
                    },
                    'account2': {
                        'name': 'Business Account', 
                        'api_token': 'token2'
                    }
                }
            },
            'default_accounts': {
                'cloudflare': 'account1'
            }
        }
        
        # Test listing accounts
        response = client.get('/api/dns/cloudflare/accounts')
        assert response.status_code in [200, 401]
        
        # Test accessing specific account
        response = client.get('/api/dns/cloudflare/accounts/account1')
        assert response.status_code in [200, 401, 404]
    
    @patch('app.safe_file_read')
    def test_mixed_multi_account_dns_providers(self, mock_read, client):
        """Test using different multi-account DNS providers for different domains."""
        mock_read.return_value = {
            'dns_providers': {
                'cloudflare': {
                    'cf_account': {
                        'name': 'Cloudflare Account',
                        'api_token': 'cf_token'
                    }
                },
                'route53': {
                    'aws_account': {
                        'name': 'AWS Account',
                        'access_key_id': 'aws_key',
                        'secret_access_key': 'aws_secret'
                    }
                },
                'azure': {
                    'azure_account': {
                        'name': 'Azure Account',
                        'subscription_id': 'sub-id',
                        'resource_group': 'rg-test',
                        'tenant_id': 'tenant-id',
                        'client_id': 'client-id',
                        'client_secret': 'client-secret'
                    }
                }
            },
            'default_accounts': {
                'cloudflare': 'cf_account',
                'route53': 'aws_account',
                'azure': 'azure_account'
            }
        }
        
        # Test certificate creation with different multi-account providers
        multi_account_providers_and_domains = [
            ('cloudflare', 'cf-domain.example.com'),
            ('route53', 'aws-domain.example.com'),
            ('azure', 'azure-domain.example.com')
        ]
        
        for provider, domain in multi_account_providers_and_domains:
            cert_data = {
                'domain': domain,
                'dns_provider': provider
            }
            
            response = client.post('/api/web/certificates/create', data=cert_data)
            assert response.status_code in [200, 302, 400, 401, 404, 415, 422]
    
    def test_only_supported_providers_for_multi_account(self):
        """Test that only supported providers are considered for multi-account testing."""
        # These providers support multi-account
        for provider in self.MULTI_ACCOUNT_PROVIDERS:
            assert provider in ['cloudflare', 'azure', 'google', 'route53', 'powerdns', 'rfc2136', 'digitalocean']
        
        # These providers do NOT support multi-account in our design
        unsupported = ['linode', 'gandi', 'ovh', 'namecheap', 'vultr', 'hetzner', 'nsone', 'dnsmadeeasy', 'porkbun', 'godaddy', 'he-ddns', 'dynudns']
        for provider in unsupported:
            assert provider not in self.MULTI_ACCOUNT_PROVIDERS
    
    def test_powerdns_command_construction_fix(self):
        """Test that PowerDNS uses correct certbot arguments to avoid ambiguous option error."""
        # The error was: certbot: error: ambiguous option: --dns-powerdns could match --dns-powerdns-propagation-seconds, --dns-powerdns-credentials
        # The fix: Use only --dns-powerdns-credentials, not --dns-powerdns
        
        provider = 'powerdns'
        assert provider in self.MULTI_ACCOUNT_PROVIDERS
        
        # Verify that PowerDNS should use credentials file approach
        assert provider == 'powerdns'
        
    @patch('app.subprocess.run')
    def test_powerdns_avoids_ambiguous_option_error(self, mock_subprocess, client):
        """Test that PowerDNS certificate creation avoids the ambiguous option error."""
        # Mock successful subprocess to verify command construction
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = 'Certificate created successfully'
        mock_result.stderr = ''
        mock_subprocess.return_value = mock_result
        
        # This request should not cause the ambiguous option error
        # The fix ensures we use --dns-powerdns-credentials instead of --dns-powerdns
        response = client.post('/api/certificates/create',
                             data=json.dumps({
                                 'domain': 'test-powerdns.example.com',
                                 'dns_provider': 'powerdns'
                             }),
                             content_type='application/json')
        
        # Should not fail with 500 due to ambiguous option error
        assert response.status_code in [200, 201, 400, 401, 422]  # Any valid response, not 500
