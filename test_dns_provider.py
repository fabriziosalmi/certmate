#!/usr/bin/env python3
"""
Test script to verify DNS provider detection for domains
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_dns_provider_detection():
    """Test that DNS providers are correctly detected for domains"""
    
    # Load settings
    settings_file = Path("data/settings.json")
    if not settings_file.exists():
        print("Settings file not found!")
        return
    
    with open(settings_file, 'r') as f:
        settings = json.load(f)
    
    # Import the function we need to test
    from app import get_domain_dns_provider
    
    print("Testing DNS provider detection...")
    print(f"Global DNS provider: {settings.get('dns_provider', 'not set')}")
    print()
    
    # Test domains
    test_domains = [
        "test2.audiolibri.org",
        "aws-test3.test.certmate.org", 
        "cf-test1.audiolibri.org",
        "nonexistent.domain.com"
    ]
    
    for domain in test_domains:
        provider = get_domain_dns_provider(domain, settings)
        print(f"Domain: {domain}")
        print(f"  DNS Provider: {provider}")
        
        # Check if domain is in settings
        domain_in_settings = False
        for domain_entry in settings.get('domains', []):
            if isinstance(domain_entry, dict):
                if domain_entry.get('domain') == domain:
                    domain_in_settings = True
                    expected_provider = domain_entry.get('dns_provider', settings.get('dns_provider', 'cloudflare'))
                    print(f"  Expected: {expected_provider}")
                    print(f"  Match: {'✓' if provider == expected_provider else '✗'}")
                    break
            elif isinstance(domain_entry, str) and domain_entry == domain:
                domain_in_settings = True
                expected_provider = settings.get('dns_provider', 'cloudflare')
                print(f"  Expected: {expected_provider} (global)")
                print(f"  Match: {'✓' if provider == expected_provider else '✗'}")
                break
        
        if not domain_in_settings:
            expected_provider = settings.get('dns_provider', 'cloudflare')
            print(f"  Expected: {expected_provider} (fallback)")
            print(f"  Match: {'✓' if provider == expected_provider else '✗'}")
        
        print()

if __name__ == '__main__':
    test_dns_provider_detection()
