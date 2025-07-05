#!/usr/bin/env python3
"""
Test DNS provider detection with actual settings
"""

import os
import sys
import json
import requests
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Configuration
BASE_URL = "http://localhost:8000"
API_TOKEN = "3kQlbC4OQIcKriSVJ7zYlX6vJy8w0HIOD-YyNSSXuC4"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

def test_current_certificate_dns_providers():
    """Test DNS provider detection for current certificates"""
    try:
        # Get current certificates
        response = requests.get(f"{BASE_URL}/api/certificates", headers=HEADERS, timeout=10)
        if response.status_code == 200:
            certificates = response.json()
            
            print("=== Current Certificate DNS Providers ===")
            print(f"Found {len(certificates)} certificates:")
            
            for cert in certificates:
                domain = cert.get('domain', 'Unknown')
                dns_provider = cert.get('dns_provider', 'Unknown')
                exists = cert.get('exists', False)
                
                print(f"  {domain}")
                print(f"    DNS Provider: {dns_provider}")
                print(f"    Certificate Exists: {exists}")
                print()
            
            # Check specific domains
            expected_providers = {
                "test2.audiolibri.org": "cloudflare",
                "cf-test1.audiolibri.org": "cloudflare", 
                "cf-test2.audiolibri.org": "cloudflare",
                "aws-test3.test.certmate.org": "route53"
            }
            
            print("=== DNS Provider Validation ===")
            for domain, expected_provider in expected_providers.items():
                found = False
                for cert in certificates:
                    if cert.get('domain') == domain:
                        actual_provider = cert.get('dns_provider')
                        status = "✓" if actual_provider == expected_provider else "✗"
                        print(f"{status} {domain}: {actual_provider} (expected: {expected_provider})")
                        found = True
                        break
                
                if not found:
                    print(f"✗ {domain}: NOT FOUND (expected: {expected_provider})")
            
            return True
        else:
            print(f"Failed to get certificates: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error testing DNS providers: {e}")
        return False

def test_settings_structure():
    """Test the settings structure"""
    try:
        response = requests.get(f"{BASE_URL}/api/settings", headers=HEADERS, timeout=10)
        if response.status_code == 200:
            settings = response.json()
            
            print("=== Settings Structure Analysis ===")
            print(f"Global DNS Provider: {settings.get('dns_provider', 'Not set')}")
            print(f"Number of domains: {len(settings.get('domains', []))}")
            
            domains = settings.get('domains', [])
            print("\nDomains configuration:")
            for i, domain in enumerate(domains):
                if isinstance(domain, dict):
                    print(f"  {i+1}. {domain.get('domain', 'Unknown')}")
                    print(f"     DNS Provider: {domain.get('dns_provider', 'Not set')}")
                    print(f"     Account ID: {domain.get('account_id', 'Not set')}")
                elif isinstance(domain, str):
                    print(f"  {i+1}. {domain} (old format - will inherit global DNS provider)")
                else:
                    print(f"  {i+1}. Invalid domain format: {domain}")
            
            # Check DNS providers structure
            dns_providers = settings.get('dns_providers', {})
            print(f"\nConfigured DNS Providers: {list(dns_providers.keys())}")
            
            for provider, accounts in dns_providers.items():
                if isinstance(accounts, dict):
                    print(f"  {provider}: {list(accounts.keys())}")
                else:
                    print(f"  {provider}: {accounts} (old format)")
            
            # Check default accounts
            default_accounts = settings.get('default_accounts', {})
            print(f"\nDefault Accounts: {default_accounts}")
            
            return True
        else:
            print(f"Failed to get settings: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"Error testing settings: {e}")
        return False

def main():
    """Main test function"""
    print("=== DNS Provider Detection Test ===")
    
    # Test API connectivity
    try:
        response = requests.get(f"{BASE_URL}/health", timeout=10)
        if response.status_code == 200:
            print("✓ API is accessible")
        else:
            print("✗ API is not accessible")
            return False
    except Exception as e:
        print(f"✗ API connection failed: {e}")
        return False
    
    # Test authentication
    try:
        response = requests.get(f"{BASE_URL}/api/settings", headers=HEADERS, timeout=10)
        if response.status_code == 200:
            print("✓ API authentication successful")
        else:
            print("✗ API authentication failed")
            return False
    except Exception as e:
        print(f"✗ API authentication failed: {e}")
        return False
    
    print()
    
    # Test settings structure
    if not test_settings_structure():
        print("Settings structure test failed")
        return False
    
    print()
    
    # Test current certificate DNS providers
    if not test_current_certificate_dns_providers():
        print("Certificate DNS provider test failed")
        return False
    
    print("\n=== Test Complete ===")
    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
