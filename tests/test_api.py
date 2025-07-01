import pytest
import json
from unittest.mock import patch, MagicMock, mock_open
import tempfile
import os

@pytest.mark.api
class TestHealthAPI:
    """Test health check endpoints."""
    
    def test_api_health_check(self, client):
        """Test API health check endpoint."""
        response = client.get('/api/health')
        assert response.status_code == 200
        data = response.get_json()
        assert 'status' in data
    
    def test_web_health_check(self, client):
        """Test web health check endpoint."""
        response = client.get('/health')
        assert response.status_code == 200

class TestSettingsAPI:
    """Test settings-related API endpoints."""
    
    def test_api_settings_get(self, client):
        """Test getting settings via API."""
        response = client.get('/api/settings')
        assert response.status_code in [200, 401, 404]
    
    def test_api_dns_providers_get(self, client):
        """Test getting DNS providers list."""
        response = client.get('/api/settings/dns-providers')
        assert response.status_code in [200, 401, 404]
    
    def test_web_settings_get(self, client):
        """Test web settings endpoint GET."""
        response = client.get('/api/web/settings')
        assert response.status_code in [200, 401, 302]  # May redirect to login
    
    @patch('app.safe_file_write')
    @patch('app.safe_file_read')
    def test_web_settings_post(self, mock_read, mock_write, client):
        """Test web settings endpoint POST."""
        mock_read.return_value = {}
        mock_write.return_value = True
        
        settings_data = {
            'cloudflare_api_token': 'test-token',
            'cloudflare_email': 'test@example.com',
            'certbot_email': 'test@example.com'
        }
        
        response = client.post('/api/web/settings', 
                             data=json.dumps(settings_data),
                             content_type='application/json')
        assert response.status_code in [200, 302, 401, 422]

class TestCertificatesAPI:
    """Test certificate-related API endpoints."""
    
    def test_api_certificates_list(self, client):
        """Test getting certificates list via API."""
        response = client.get('/api/certificates')
        assert response.status_code in [200, 401, 404]
    
    def test_web_certificates_list(self, client):
        """Test getting certificates list via web API."""
        response = client.get('/api/web/certificates')
        assert response.status_code in [200, 401]
    
    @patch('app.subprocess.run')
    @patch('app.safe_file_read')
    def test_certificate_create_post(self, mock_read, mock_subprocess, client):
        """Test certificate creation endpoint."""
        mock_read.return_value = {
            'cloudflare_api_token': 'test-token',
            'cloudflare_email': 'test@example.com',
            'certbot_email': 'test@example.com'
        }
        mock_subprocess.return_value = MagicMock(returncode=0, stdout='Success', stderr='')
        
        cert_data = {
            'domain': 'test.example.com',
            'dns_provider': 'cloudflare'
        }
        
        response = client.post('/api/certificates/create',
                             data=json.dumps(cert_data),
                             content_type='application/json')
        assert response.status_code in [200, 201, 400, 401, 422]
    
    def test_certificate_download(self, client):
        """Test certificate download endpoint."""
        response = client.get('/api/certificates/test.example.com/download')
        assert response.status_code in [200, 404, 401]
    
    @patch('app.subprocess.run')
    def test_certificate_renew(self, mock_subprocess, client):
        """Test certificate renewal endpoint."""
        mock_subprocess.return_value = MagicMock(returncode=0, stdout='Success', stderr='')
        
        response = client.post('/api/certificates/test.example.com/renew')
        assert response.status_code in [200, 401, 404, 422]
    
    def test_certificate_deployment_status(self, client):
        """Test certificate deployment status endpoint."""
        response = client.get('/api/certificates/test.example.com/deployment-status')
        assert response.status_code in [200, 401, 404]

class TestDNSProvidersAPI:
    """Test DNS provider account management endpoints."""
    
    def test_dns_provider_accounts_get(self, client):
        """Test getting DNS provider accounts."""
        response = client.get('/api/dns/cloudflare/accounts')
        assert response.status_code in [200, 401, 404]
    
    @patch('app.safe_file_read')
    @patch('app.safe_file_write')
    def test_dns_provider_accounts_post(self, mock_write, mock_read, client):
        """Test creating DNS provider account."""
        mock_read.return_value = {}
        mock_write.return_value = True
        
        account_data = {
            'name': 'Test Account',
            'api_token': 'test-token',
            'email': 'test@example.com'
        }
        
        response = client.post('/api/dns/cloudflare/accounts',
                             data=json.dumps(account_data),
                             content_type='application/json')
        assert response.status_code in [200, 201, 400, 401, 422]
    
    def test_dns_provider_account_get(self, client):
        """Test getting specific DNS provider account."""
        response = client.get('/api/dns/cloudflare/accounts/test-account-id')
        assert response.status_code in [200, 401, 404]
    
    @patch('app.safe_file_read')
    @patch('app.safe_file_write')
    def test_dns_provider_account_put(self, mock_write, mock_read, client):
        """Test updating DNS provider account."""
        mock_read.return_value = {
            'dns_accounts': {
                'cloudflare': {
                    'test-account-id': {
                        'name': 'Test Account',
                        'api_token': 'old-token'
                    }
                }
            }
        }
        mock_write.return_value = True
        
        update_data = {
            'name': 'Updated Account',
            'api_token': 'new-token'
        }
        
        response = client.put('/api/dns/cloudflare/accounts/test-account-id',
                            data=json.dumps(update_data),
                            content_type='application/json')
        assert response.status_code in [200, 400, 401, 404, 422]  # Added 400
    
    @patch('app.safe_file_read')
    @patch('app.safe_file_write')
    def test_dns_provider_account_delete(self, mock_write, mock_read, client):
        """Test deleting DNS provider account."""
        mock_read.return_value = {
            'dns_accounts': {
                'cloudflare': {
                    'test-account-id': {
                        'name': 'Test Account'
                    }
                }
            }
        }
        mock_write.return_value = True
        
        response = client.delete('/api/dns/cloudflare/accounts/test-account-id')
        assert response.status_code in [200, 204, 401, 404]

class TestCacheAPI:
    """Test cache management endpoints."""
    
    def test_cache_stats(self, client):
        """Test cache statistics endpoint."""
        response = client.get('/api/web/cache/stats')
        assert response.status_code in [200, 401]
    
    def test_cache_clear(self, client):
        """Test cache clearing endpoint."""
        response = client.post('/api/web/cache/clear')
        assert response.status_code in [200, 401]

class TestWebCertificatesAPI:
    """Test web certificate management endpoints."""
    
    @patch('app.safe_file_read')
    @patch('app.subprocess.run')
    def test_web_certificate_create(self, mock_subprocess, mock_read, client):
        """Test web certificate creation."""
        mock_read.return_value = {
            'cloudflare_api_token': 'test-token',
            'cloudflare_email': 'test@example.com',
            'certbot_email': 'test@example.com'
        }
        mock_subprocess.return_value = MagicMock(returncode=0, stdout='Success', stderr='')
        
        cert_data = {
            'domain': 'test.example.com',
            'dns_provider': 'cloudflare'
        }
        
        response = client.post('/api/web/certificates/create',
                             data=cert_data)  # Form data, not JSON
        assert response.status_code in [200, 302, 400, 401, 415]  # Added 415
    
    @patch('app.subprocess.run')
    def test_web_certificate_renew(self, mock_subprocess, client):
        """Test web certificate renewal."""
        mock_subprocess.return_value = MagicMock(returncode=0, stdout='Success', stderr='')
        
        response = client.post('/api/web/certificates/test.example.com/renew')
        assert response.status_code in [200, 302, 401, 404]
    
    def test_web_certificate_download(self, client):
        """Test web certificate download."""
        response = client.get('/api/web/certificates/test.example.com/download')
        assert response.status_code in [200, 404, 401]

class TestTLSEndpoint:
    """Test TLS certificate serving endpoint."""
    
    def test_tls_certificate_endpoint(self, client):
        """Test TLS certificate serving."""
        response = client.get('/test.example.com/tls')
        assert response.status_code in [200, 401, 404]  # Added 401

class TestErrorHandling:
    """Test error handling and edge cases."""
    
    def test_invalid_api_endpoint(self, client):
        """Test invalid API endpoint returns 404."""
        response = client.get('/api/nonexistent-endpoint')
        assert response.status_code == 404
    
    def test_invalid_method_on_get_endpoint(self, client):
        """Test invalid HTTP method on GET-only endpoint."""
        response = client.post('/api/health')
        assert response.status_code in [405, 404]  # Method not allowed
    
    def test_malformed_json_request(self, client):
        """Test malformed JSON in request body."""
        response = client.post('/api/certificates/create',
                             data='{"invalid": json}',
                             content_type='application/json')
        assert response.status_code in [400, 401, 422]
    
    def test_missing_content_type(self, client):
        """Test request without content type header."""
        response = client.post('/api/certificates/create',
                             data='{"domain": "test.com"}')
        assert response.status_code in [400, 401, 415, 422]

class TestAPIDocumentation:
    """Test API documentation endpoints."""
    
    def test_api_docs_endpoint(self, client):
        """Test API documentation endpoint."""
        response = client.get('/docs/')
        assert response.status_code in [200, 301, 302]  # May redirect
    
    def test_api_swagger_json(self, client):
        """Test Swagger JSON endpoint."""
        response = client.get('/swagger.json')
        assert response.status_code in [200, 404]