import pytest
import json
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app import (
    safe_file_read, safe_file_write, load_settings, save_settings,
    migrate_dns_providers_to_multi_account
)

class TestFileOperations:
    """Test file operation utility functions."""
    
    def test_safe_file_read_json_valid(self):
        """Test reading valid JSON file."""
        test_data = {"test": "value", "number": 42}
        
        with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("fcntl.flock"):
                    result = safe_file_read("test.json", is_json=True)
                    assert result == test_data
    
    def test_safe_file_read_json_invalid(self):
        """Test reading invalid JSON file."""
        with patch("builtins.open", mock_open(read_data="invalid json")):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("fcntl.flock"):
                    result = safe_file_read("test.json", is_json=True, default={})
                    assert result == {}
    
    def test_safe_file_read_text_file(self):
        """Test reading text file."""
        test_content = "This is test content"
        
        with patch("builtins.open", mock_open(read_data=test_content)):
            with patch("pathlib.Path.exists", return_value=True):
                with patch("fcntl.flock"):
                    result = safe_file_read("test.txt", is_json=False)
                    assert result == test_content
    
    def test_safe_file_read_nonexistent_file(self):
        """Test reading non-existent file."""
        with patch("pathlib.Path.exists", return_value=False):
            result = safe_file_read("nonexistent.json", is_json=True, default={"default": True})
            assert result == {"default": True}
    
    def test_safe_file_read_permission_error(self):
        """Test handling permission errors."""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with patch("pathlib.Path.exists", return_value=True):
                result = safe_file_read("test.json", is_json=True, default={"error": True})
                assert result == {"error": True}
    
    def test_safe_file_write_json_success(self):
        """Test successful JSON file writing."""
        test_data = {"test": "value"}
        
        with patch("builtins.open", mock_open()) as mock_file:
            with patch("pathlib.Path.mkdir"):
                with patch("pathlib.Path.rename"):
                    with patch("os.chmod"):
                        with patch("os.fsync"):
                            with patch("fcntl.flock"):
                                result = safe_file_write("test.json", test_data, is_json=True)
                                assert result is True
    
    def test_safe_file_write_text_success(self):
        """Test successful text file writing."""
        test_content = "Test content"
        
        with patch("builtins.open", mock_open()) as mock_file:
            with patch("pathlib.Path.mkdir"):
                with patch("pathlib.Path.rename"):
                    with patch("os.chmod"):
                        with patch("os.fsync"):
                            with patch("fcntl.flock"):
                                result = safe_file_write("test.txt", test_content, is_json=False)
                                assert result is True
    
    def test_safe_file_write_permission_error(self):
        """Test handling permission errors during write."""
        with patch("builtins.open", side_effect=PermissionError("Permission denied")):
            with patch("pathlib.Path.mkdir"):
                result = safe_file_write("test.json", {"test": "data"}, is_json=True)
                assert result is False
    
    def test_safe_file_write_os_error(self):
        """Test handling OS errors during write."""
        with patch("builtins.open", side_effect=OSError("No space left on device")):
            with patch("pathlib.Path.mkdir"):
                result = safe_file_write("test.json", {"test": "data"}, is_json=True)
                assert result is False

class TestSettingsManagement:
    """Test settings loading and saving functionality."""
    
    @patch('app.SETTINGS_FILE')
    @patch('app.safe_file_read')
    @patch('app.save_settings')
    def test_load_settings_first_time(self, mock_save, mock_read, mock_settings_file):
        """Test loading settings for the first time."""
        mock_settings_file.exists.return_value = False
        
        result = load_settings()
        
        # Should return default settings
        assert 'cloudflare_token' in result
        assert 'domains' in result
        assert 'email' in result
        assert 'api_bearer_token' in result
        assert 'dns_providers' in result
        
        # Should call save_settings to create the file
        mock_save.assert_called_once()
    
    @patch('app.SETTINGS_FILE')
    @patch('app.safe_file_read')
    def test_load_settings_existing_file(self, mock_read, mock_settings_file):
        """Test loading settings from existing file."""
        mock_settings_file.exists.return_value = True
        existing_settings = {
            'cloudflare_token': 'test-token',
            'email': 'test@example.com',
            'api_bearer_token': 'secure-token-123456789012345678901234567890'
        }
        mock_read.return_value = existing_settings
        
        result = load_settings()
        
        # Should merge with defaults
        assert result['cloudflare_token'] == 'test-token'
        assert result['email'] == 'test@example.com'
        assert 'domains' in result  # Default value
    
    @patch('app.SETTINGS_FILE')
    @patch('app.safe_file_read')
    @patch('app.save_settings')
    @patch('app.generate_secure_token')
    def test_load_settings_insecure_token(self, mock_generate, mock_save, mock_read, mock_settings_file):
        """Test loading settings with insecure API token."""
        mock_settings_file.exists.return_value = True
        mock_generate.return_value = 'new-secure-token-123456789012345678901234567890'
        
        insecure_settings = {
            'api_bearer_token': 'change-this-token'  # Insecure token
        }
        mock_read.return_value = insecure_settings
        
        result = load_settings()
        
        # Should generate new token and save
        mock_generate.assert_called_once()
        mock_save.assert_called_once()
        assert result['api_bearer_token'] == 'new-secure-token-123456789012345678901234567890'
    
    @patch('app.safe_file_write')
    @patch('app.validate_email')
    @patch('app.validate_api_token')
    @patch('app.validate_domain')
    def test_save_settings_valid_data(self, mock_validate_domain, mock_validate_token, mock_validate_email, mock_write):
        """Test saving valid settings."""
        mock_validate_email.return_value = (True, 'test@example.com')
        mock_validate_token.return_value = (True, 'valid-token-123456789012345678901234567890')
        mock_validate_domain.return_value = (True, 'example.com')
        mock_write.return_value = True
        
        settings = {
            'email': 'test@example.com',
            'api_bearer_token': 'valid-token-123456789012345678901234567890',
            'domains': ['example.com']
        }
        
        result = save_settings(settings)
        assert result is True
        mock_write.assert_called_once()
    
    @patch('app.validate_email')
    def test_save_settings_invalid_email(self, mock_validate_email):
        """Test saving settings with invalid email."""
        mock_validate_email.return_value = (False, 'Invalid email format')
        
        settings = {
            'email': 'invalid-email'
        }
        
        result = save_settings(settings)
        assert result is False
    
    @patch('app.validate_email')
    @patch('app.validate_api_token')
    def test_save_settings_invalid_token(self, mock_validate_token, mock_validate_email):
        """Test saving settings with invalid API token."""
        mock_validate_email.return_value = (True, 'test@example.com')
        mock_validate_token.return_value = (False, 'Token too short')
        
        settings = {
            'email': 'test@example.com',
            'api_bearer_token': 'short'
        }
        
        result = save_settings(settings)
        assert result is False

class TestDNSProviderMigration:
    """Test DNS provider migration functionality."""
    
    def test_migrate_dns_providers_no_migration_needed(self):
        """Test migration when no migration is needed."""
        # Already in multi-account format
        settings = {
            'dns_providers': {
                'cloudflare': {
                    'production': {
                        'name': 'Production',
                        'api_token': 'prod-token'
                    }
                }
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        assert result == settings  # Should be unchanged
    
    def test_migrate_dns_providers_cloudflare_single_to_multi(self):
        """Test migrating Cloudflare from single to multi-account."""
        settings = {
            'dns_providers': {
                'cloudflare': {
                    'api_token': 'old-single-token'
                }
            }
        }
        
        with patch('app.logger') as mock_logger:
            result = migrate_dns_providers_to_multi_account(settings)
        
        # Should be migrated to multi-account format
        expected_structure = {
            'dns_providers': {
                'cloudflare': {
                    'default': {
                        'name': 'Default Account',
                        'description': 'Migrated from single-account configuration',
                        'api_token': 'old-single-token'
                    }
                }
            },
            'default_accounts': {
                'cloudflare': 'default'
            }
        }
        
        assert result['dns_providers']['cloudflare']['default']['api_token'] == 'old-single-token'
        assert result['default_accounts']['cloudflare'] == 'default'
        mock_logger.info.assert_called()
    
    def test_migrate_dns_providers_route53_single_to_multi(self):
        """Test migrating Route53 from single to multi-account."""
        settings = {
            'dns_providers': {
                'route53': {
                    'access_key_id': 'AKIATEST',
                    'secret_access_key': 'secret-key'
                }
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # Should be migrated
        migrated_config = result['dns_providers']['route53']['default']
        assert migrated_config['access_key_id'] == 'AKIATEST'
        assert migrated_config['secret_access_key'] == 'secret-key'
        assert result['default_accounts']['route53'] == 'default'
    
    def test_migrate_dns_providers_multiple_providers(self):
        """Test migrating multiple providers."""
        settings = {
            'dns_providers': {
                'cloudflare': {
                    'api_token': 'cf-token'
                },
                'route53': {
                    'access_key_id': 'AKIATEST',
                    'secret_access_key': 'secret'
                },
                'digitalocean': {
                    'api_token': 'do-token'
                }
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # All should be migrated
        for provider in ['cloudflare', 'route53', 'digitalocean']:
            assert 'default' in result['dns_providers'][provider]
            assert result['default_accounts'][provider] == 'default'
    
    def test_migrate_dns_providers_empty_config(self):
        """Test migration with empty or invalid config."""
        settings = {
            'dns_providers': {
                'cloudflare': {},  # Empty config
                'route53': {
                    'some_other_field': 'value'  # No credentials
                }
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # Should keep empty configs as-is
        assert result['dns_providers']['cloudflare'] == {}
        assert result['dns_providers']['route53'] == {'some_other_field': 'value'}
    
    def test_migrate_dns_providers_no_dns_providers(self):
        """Test migration when dns_providers key doesn't exist."""
        settings = {
            'email': 'test@example.com'
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        assert result == settings  # Should be unchanged
    
    def test_migrate_dns_providers_mixed_format(self):
        """Test migration with mixed old/new format."""
        settings = {
            'dns_providers': {
                'cloudflare': {
                    'api_token': 'old-token'  # Old format
                },
                'route53': {
                    'production': {  # Already new format
                        'name': 'Production',
                        'access_key_id': 'AKIAPROD'
                    }
                }
            }
        }
        
        result = migrate_dns_providers_to_multi_account(settings)
        
        # Cloudflare should be migrated, Route53 should remain unchanged
        assert 'default' in result['dns_providers']['cloudflare']
        assert result['dns_providers']['cloudflare']['default']['api_token'] == 'old-token'
        assert 'production' in result['dns_providers']['route53']
        assert result['dns_providers']['route53']['production']['name'] == 'Production'
