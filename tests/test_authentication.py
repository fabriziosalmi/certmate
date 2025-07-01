import pytest
from unittest.mock import patch, MagicMock
import secrets
import sys
import os

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import require_auth, app

class TestAuthenticationDecorator:
    """Test the authentication decorator functionality."""
    
    def test_require_auth_missing_header(self):
        """Test authentication when Authorization header is missing."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context():
            result, status_code = dummy_function()
            
            assert status_code == 401
            assert result['error'] == 'Authorization header required'
            assert result['code'] == 'AUTH_HEADER_MISSING'
    
    def test_require_auth_invalid_scheme(self):
        """Test authentication with invalid authorization scheme."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Basic dGVzdDp0ZXN0'}):
            result, status_code = dummy_function()
            
            assert status_code == 401
            assert result['error'] == 'Invalid authorization scheme. Use Bearer token'
            assert result['code'] == 'INVALID_AUTH_SCHEME'
    
    def test_require_auth_invalid_header_format(self):
        """Test authentication with malformed authorization header."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer'}):
            result, status_code = dummy_function()
            
            assert status_code == 401
            assert result['error'] == 'Invalid authorization header format. Use: Bearer <token>'
            assert result['code'] == 'INVALID_AUTH_FORMAT'
    
    def test_require_auth_no_server_token(self):
        """Test authentication when server has no API token configured."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer test-token'}):
            with patch('app.load_settings') as mock_load_settings:
                mock_load_settings.return_value = {}  # No api_bearer_token
                
                result, status_code = dummy_function()
                
                assert status_code == 500
                assert result['error'] == 'Server configuration error: no API token configured'
                assert result['code'] == 'SERVER_CONFIG_ERROR'
    
    def test_require_auth_weak_server_token(self):
        """Test authentication when server has weak API token."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer test-token'}):
            with patch('app.load_settings') as mock_load_settings:
                with patch('app.validate_api_token') as mock_validate:
                    with patch('app.logger') as mock_logger:
                        mock_load_settings.return_value = {'api_bearer_token': 'weak'}
                        mock_validate.return_value = (False, 'Token too short')
                        
                        result, status_code = dummy_function()
                        
                        assert status_code == 500
                        assert result['error'] == 'Server security configuration error'
                        assert result['code'] == 'WEAK_SERVER_TOKEN'
                        mock_logger.error.assert_called_once()
    
    def test_require_auth_invalid_token(self):
        """Test authentication with invalid token."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer wrong-token'}, environ_base={'REMOTE_ADDR': '127.0.0.1'}):
            with patch('app.load_settings') as mock_load_settings:
                with patch('app.validate_api_token') as mock_validate:
                    with patch('app.secrets.compare_digest') as mock_compare:
                        with patch('app.logger') as mock_logger:
                            mock_load_settings.return_value = {'api_bearer_token': 'correct-token-123456789012345678901234567890'}
                            mock_validate.return_value = (True, 'correct-token-123456789012345678901234567890')
                            mock_compare.return_value = False  # Tokens don't match
                            
                            result, status_code = dummy_function()
                            
                            assert status_code == 401
                            assert result['error'] == 'Invalid or expired token'
                            assert result['code'] == 'INVALID_TOKEN'
                            mock_logger.warning.assert_called_once()
    
    def test_require_auth_valid_token(self):
        """Test successful authentication with valid token."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer valid-token-123456789012345678901234567890'}):
            with patch('app.load_settings') as mock_load_settings:
                with patch('app.validate_api_token') as mock_validate:
                    with patch('app.secrets.compare_digest') as mock_compare:
                        mock_load_settings.return_value = {'api_bearer_token': 'valid-token-123456789012345678901234567890'}
                        mock_validate.return_value = (True, 'valid-token-123456789012345678901234567890')
                        mock_compare.return_value = True  # Tokens match
                        
                        result = dummy_function()
                        
                        assert result == {"success": True}
    
    def test_require_auth_preserves_function_args(self):
        """Test that the decorator preserves function arguments."""
        @require_auth
        def dummy_function(arg1, arg2, kwarg1=None):
            return {"arg1": arg1, "arg2": arg2, "kwarg1": kwarg1}
        
        with app.test_request_context(headers={'Authorization': 'Bearer valid-token-123456789012345678901234567890'}):
            with patch('app.load_settings') as mock_load_settings:
                with patch('app.validate_api_token') as mock_validate:
                    with patch('app.secrets.compare_digest') as mock_compare:
                        mock_load_settings.return_value = {'api_bearer_token': 'valid-token-123456789012345678901234567890'}
                        mock_validate.return_value = (True, 'valid-token-123456789012345678901234567890')
                        mock_compare.return_value = True
                        
                        result = dummy_function('test1', 'test2', kwarg1='test3')
                        
                        assert result == {"arg1": "test1", "arg2": "test2", "kwarg1": "test3"}
    
    def test_require_auth_exception_handling(self):
        """Test that unexpected exceptions are handled gracefully."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer test-token'}):
            with patch('app.load_settings') as mock_load_settings:
                mock_load_settings.side_effect = Exception("Unexpected error")
                
                # Should not raise exception, but should fail auth
                result, status_code = dummy_function()
                
                assert status_code == 401
                assert 'error' in result
                assert result['error'] == 'Authentication failed'
    
    def test_require_auth_load_settings_exception(self):
        """Test authentication when loading settings fails."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer test-token'}):
            with patch('app.load_settings') as mock_load_settings:
                mock_load_settings.side_effect = Exception("Settings loading failed")
                
                result, status_code = dummy_function()
                
                assert status_code == 401
                assert 'error' in result
                assert result['error'] == 'Authentication failed'
    
    def test_require_auth_validate_token_exception(self):
        """Test authentication when token validation raises exception."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer test-token'}):
            with patch('app.load_settings') as mock_load_settings:
                with patch('app.validate_api_token') as mock_validate:
                    mock_load_settings.return_value = {'api_bearer_token': 'valid-token'}
                    mock_validate.side_effect = Exception("Validation failed")
                    
                    result, status_code = dummy_function()
                    
                    assert status_code == 401
                    assert 'error' in result
                    assert result['error'] == 'Authentication failed'
    
    def test_require_auth_compare_digest_exception(self):
        """Test authentication when secrets.compare_digest raises exception."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer test-token'}):
            with patch('app.load_settings') as mock_load_settings:
                with patch('app.validate_api_token') as mock_validate:
                    with patch('app.secrets.compare_digest') as mock_compare:
                        mock_load_settings.return_value = {'api_bearer_token': 'valid-token'}
                        mock_validate.return_value = (True, 'valid-token')
                        mock_compare.side_effect = Exception("Comparison failed")
                        
                        result, status_code = dummy_function()
                        
                        assert status_code == 401
                        assert 'error' in result
                        assert result['error'] == 'Authentication failed'
    
    def test_require_auth_with_none_remote_addr(self):
        """Test authentication when request.remote_addr is None."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer wrong-token'}):
            with patch('app.load_settings') as mock_load_settings:
                with patch('app.validate_api_token') as mock_validate:
                    with patch('app.secrets.compare_digest') as mock_compare:
                        with patch('app.logger') as mock_logger:
                            mock_load_settings.return_value = {'api_bearer_token': 'correct-token'}
                            mock_validate.return_value = (True, 'correct-token')
                            mock_compare.return_value = False
                            
                            result, status_code = dummy_function()
                            
                            assert status_code == 401
                            assert result['error'] == 'Invalid or expired token'
                            mock_logger.warning.assert_called_once()
    
    def test_require_auth_empty_token_after_bearer(self):
        """Test authentication with empty token after Bearer."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        with app.test_request_context(headers={'Authorization': 'Bearer '}):
            result, status_code = dummy_function()
            
            assert status_code == 401
            assert result['error'] == 'Invalid authorization header format. Use: Bearer <token>'
            assert result['code'] == 'INVALID_AUTH_FORMAT'
    
    def test_require_auth_token_with_spaces(self):
        """Test authentication with token containing spaces."""
        @require_auth
        def dummy_function():
            return {"success": True}
        
        token_with_spaces = 'token with spaces here'
        with app.test_request_context(headers={'Authorization': f'Bearer {token_with_spaces}'}):
            with patch('app.load_settings') as mock_load_settings:
                with patch('app.validate_api_token') as mock_validate:
                    with patch('app.secrets.compare_digest') as mock_compare:
                        mock_load_settings.return_value = {'api_bearer_token': token_with_spaces}
                        mock_validate.return_value = (True, token_with_spaces)
                        mock_compare.return_value = True
                        
                        result = dummy_function()
                        
                        assert result == {"success": True}
