#!/usr/bin/env python3
"""
Test script to verify DNS provider account configurations
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_dns_provider_accounts():
    """Test DNS provider account configurations"""
    
    from app import get_dns_provider_account_config, load_settings
    
    print("Testing DNS provider account configurations...")
    
    # Load your actual settings
    settings = load_settings()
    
    print(f"DNS Providers configured: {list(settings.get('dns_providers', {}).keys())}")
    print(f"Default accounts: {settings.get('default_accounts', {})}")
    
    # Test account configurations
    test_cases = [
        ("cloudflare", "default"),
        ("route53", "certmate_test"),
        ("cloudflare", None),  # Should use default
        ("route53", None),     # Should use default
    ]
    
    print(f"\nAccount Configuration Tests:")
    for provider, account_id in test_cases:
        try:
            config, used_account_id = get_dns_provider_account_config(provider, account_id, settings)
            if config:
                # Mask sensitive information
                safe_config = {}
                for key, value in config.items():
                    if key in ['api_token', 'secret_access_key', 'client_secret']:
                        safe_config[key] = f"***{value[-4:]}" if value else "not_set"
                    else:
                        safe_config[key] = value
                
                print(f"  ✓ {provider} (account: {account_id}) -> {used_account_id}")
                print(f"    Config: {safe_config}")
            else:
                print(f"  ✗ {provider} (account: {account_id}) -> No configuration found")
        except Exception as e:
            print(f"  ✗ {provider} (account: {account_id}) -> Error: {e}")
    
    print("\nTest completed!")

if __name__ == '__main__':
    test_dns_provider_accounts()
