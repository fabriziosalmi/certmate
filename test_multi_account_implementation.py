#!/usr/bin/env python3
"""
Test script for multi-account DNS provider implementation
This script tests the backend multi-account functionality without affecting the UI.
"""

import json
import tempfile
import os
import sys
from pathlib import Path

# Add the app directory to Python path so we can import functions
sys.path.insert(0, str(Path(__file__).parent))

from app import (
    migrate_dns_providers_to_multi_account,
    validate_dns_provider_account,
    get_dns_provider_account_config,
    list_dns_provider_accounts
)

def test_migration():
    """Test migration from single-account to multi-account format"""
    print("🧪 Testing migration from single-account to multi-account format...")
    
    # Test data - old single-account format
    old_settings = {
        "dns_provider": "cloudflare",
        "dns_providers": {
            "cloudflare": {
                "api_token": "test_token_123"
            },
            "route53": {
                "access_key_id": "AKIAIOSFODNN7EXAMPLE",
                "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        }
    }
    
    # Migrate
    migrated_settings = migrate_dns_providers_to_multi_account(old_settings.copy())
    
    # Verify migration
    assert "default_accounts" in migrated_settings
    assert migrated_settings["default_accounts"]["cloudflare"] == "default"
    assert migrated_settings["default_accounts"]["route53"] == "default"
    
    # Check Cloudflare migration
    cf_config = migrated_settings["dns_providers"]["cloudflare"]["default"]
    assert cf_config["name"] == "Default Account"
    assert cf_config["api_token"] == "test_token_123"
    assert "Migrated from single-account configuration" in cf_config["description"]
    
    # Check Route53 migration
    r53_config = migrated_settings["dns_providers"]["route53"]["default"]
    assert r53_config["name"] == "Default Account"
    assert r53_config["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
    assert r53_config["secret_access_key"] == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    print("✅ Migration test passed!")
    return migrated_settings

def test_validation():
    """Test account validation for different providers"""
    print("🧪 Testing account validation...")
    
    # Test Cloudflare validation
    cf_valid_config = {
        "name": "Production CF",
        "api_token": "valid_long_token_12345"
    }
    is_valid, error = validate_dns_provider_account("cloudflare", "prod", cf_valid_config)
    assert is_valid, f"Cloudflare validation failed: {error}"
    
    # Test invalid Cloudflare config
    cf_invalid_config = {
        "name": "Invalid CF",
        "api_token": "short"  # Too short
    }
    is_valid, error = validate_dns_provider_account("cloudflare", "invalid", cf_invalid_config)
    assert not is_valid, "Should have failed validation for short token"
    
    # Test Route53 validation
    r53_valid_config = {
        "name": "Production AWS",
        "access_key_id": "AKIAIOSFODNN7EXAMPLE",
        "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
    is_valid, error = validate_dns_provider_account("route53", "prod", r53_valid_config)
    assert is_valid, f"Route53 validation failed: {error}"
    
    # Test missing name
    invalid_config = {
        "api_token": "valid_token"
    }
    is_valid, error = validate_dns_provider_account("cloudflare", "test", invalid_config)
    assert not is_valid, "Should have failed validation for missing name"
    
    print("✅ Validation test passed!")

def test_account_config_retrieval():
    """Test getting account configurations"""
    print("🧪 Testing account configuration retrieval...")
    
    settings = {
        "dns_providers": {
            "cloudflare": {
                "production": {
                    "name": "Production Account",
                    "api_token": "prod_token_123"
                },
                "staging": {
                    "name": "Staging Account", 
                    "api_token": "staging_token_456"
                }
            }
        },
        "default_accounts": {
            "cloudflare": "production"
        }
    }
    
    # Test getting specific account
    config, account_id = get_dns_provider_account_config("cloudflare", "staging", settings)
    assert config is not None
    assert account_id == "staging"
    assert config["name"] == "Staging Account"
    assert config["api_token"] == "staging_token_456"
    
    # Test getting default account (no account_id specified)
    config, account_id = get_dns_provider_account_config("cloudflare", None, settings)
    assert config is not None
    assert account_id == "production"  # Should use default
    assert config["name"] == "Production Account"
    
    # Test non-existent account
    config, account_id = get_dns_provider_account_config("cloudflare", "nonexistent", settings)
    assert config is None
    assert account_id is None
    
    print("✅ Account configuration retrieval test passed!")

def test_list_accounts():
    """Test listing accounts for a provider"""
    print("🧪 Testing account listing...")
    
    settings = {
        "dns_providers": {
            "cloudflare": {
                "production": {
                    "name": "Production Account",
                    "api_token": "prod_token_123",
                    "description": "Main production environment"
                },
                "staging": {
                    "name": "Staging Account", 
                    "api_token": "staging_token_456"
                }
            }
        }
    }
    
    accounts = list_dns_provider_accounts("cloudflare", settings)
    assert len(accounts) == 2
    assert "production" in accounts
    assert "staging" in accounts
    
    # Check that sensitive data is masked
    prod_account = accounts["production"]
    assert prod_account["name"] == "Production Account"
    assert prod_account["description"] == "Main production environment"
    assert prod_account["configured"] == True
    assert "api_token" not in prod_account  # Should be masked
    
    print("✅ Account listing test passed!")

def test_backward_compatibility():
    """Test that old format still works"""
    print("🧪 Testing backward compatibility...")
    
    # Old format settings
    old_settings = {
        "dns_providers": {
            "cloudflare": {
                "api_token": "legacy_token_123"
            }
        }
    }
    
    # Should work with old format after migration
    migrated = migrate_dns_providers_to_multi_account(old_settings.copy())
    config, account_id = get_dns_provider_account_config("cloudflare", None, migrated)
    
    assert config is not None
    assert config["api_token"] == "legacy_token_123"
    assert account_id == "default"
    
    print("✅ Backward compatibility test passed!")

def run_all_tests():
    """Run all tests"""
    print("🚀 Starting multi-account DNS provider implementation tests...\n")
    
    try:
        migrated_settings = test_migration()
        test_validation()
        test_account_config_retrieval()
        test_list_accounts()
        test_backward_compatibility()
        
        print("\n🎉 All tests passed! Multi-account DNS provider support is working correctly.")
        print("\n📋 Test Summary:")
        print("  ✅ Migration from single to multi-account format")
        print("  ✅ Account validation for all providers")
        print("  ✅ Account configuration retrieval")
        print("  ✅ Account listing with proper masking")
        print("  ✅ Backward compatibility maintained")
        
        return True
        
    except Exception as e:
        print(f"\n❌ Test failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
