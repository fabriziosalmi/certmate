#!/usr/bin/env python3
"""
Test script to verify DNS provider detection with actual settings
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_with_actual_settings():
    """Test DNS provider detection with actual settings file"""
    
    from app import get_domain_dns_provider, load_settings
    
    print("Testing DNS provider detection with actual settings...")
    
    # Load your actual settings
    settings = load_settings()
    
    print(f"Global DNS provider: {settings.get('dns_provider', 'cloudflare')}")
    print(f"Domains in settings: {len(settings.get('domains', []))}")
    
    # Test each domain in your settings
    domains = settings.get('domains', [])
    print(f"\nDomains configuration:")
    for domain_entry in domains:
        if isinstance(domain_entry, dict):
            domain = domain_entry.get('domain')
            configured_provider = domain_entry.get('dns_provider')
            account_id = domain_entry.get('account_id')
            print(f"  {domain}: {configured_provider} (account: {account_id})")
        else:
            print(f"  {domain_entry}: (old format - using global provider)")
    
    # Test DNS provider detection
    test_domains = [
        "test2.audiolibri.org",
        "aws-test3.test.certmate.org", 
        "cf-test1.audiolibri.org",
        "cf-test2.audiolibri.org"
    ]
    
    print(f"\nDNS Provider Detection Results:")
    for domain in test_domains:
        detected_provider = get_domain_dns_provider(domain, settings)
        print(f"  {domain} -> {detected_provider}")
    
    # Test some domains that don't exist in settings
    print(f"\nTesting non-configured domains (should use global default):")
    non_configured_domains = [
        "unknown-domain.com",
        "test.example.com"
    ]
    
    for domain in non_configured_domains:
        detected_provider = get_domain_dns_provider(domain, settings)
        print(f"  {domain} -> {detected_provider}")
    
    print("\nTest completed!")

if __name__ == '__main__':
    test_with_actual_settings()
