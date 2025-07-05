#!/usr/bin/env python3
"""
Test script to verify DNS provider inheritance and smart suggestions
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_dns_provider_inheritance():
    """Test DNS provider inheritance and smart suggestions"""
    
    # Import the functions we need to test
    from app import get_domain_dns_provider, suggest_dns_provider_for_domain
    
    print("Testing DNS provider inheritance and smart suggestions...")
    
    # Test settings similar to your current configuration
    test_settings = {
        "domains": [
            {
                "domain": "test2.audiolibri.org",
                "dns_provider": "cloudflare",
                "account_id": "default"
            },
            {
                "domain": "aws-test3.test.certmate.org",
                "dns_provider": "route53",
                "account_id": "certmate_test"
            },
            {
                "domain": "cf-test1.audiolibri.org",
                "dns_provider": "cloudflare",
                "account_id": "default"
            }
        ],
        "dns_provider": "route53",
        "default_accounts": {
            "cloudflare": "default",
            "route53": "certmate_test"
        }
    }
    
    # Test existing domain DNS provider detection
    print("\n1. Testing existing domain DNS provider detection:")
    test_cases = [
        ("test2.audiolibri.org", "cloudflare"),
        ("aws-test3.test.certmate.org", "route53"),
        ("cf-test1.audiolibri.org", "cloudflare"),
        ("unknown-domain.com", "route53")  # Should fall back to global default
    ]
    
    for domain, expected_provider in test_cases:
        detected_provider = get_domain_dns_provider(domain, test_settings)
        status = "✓" if detected_provider == expected_provider else "✗"
        print(f"  {status} {domain} -> {detected_provider} (expected: {expected_provider})")
    
    # Test smart DNS provider suggestions
    print("\n2. Testing smart DNS provider suggestions:")
    suggestion_test_cases = [
        ("new-cf-test.audiolibri.org", "cloudflare"),
        ("aws-new-test.test.certmate.org", "route53"),
        ("cf-something.example.com", "cloudflare"),
        ("random-domain.com", "route53")  # Should fall back to global default
    ]
    
    for domain, expected_provider in suggestion_test_cases:
        suggested_provider, confidence = suggest_dns_provider_for_domain(domain, test_settings)
        status = "✓" if suggested_provider == expected_provider else "✗"
        print(f"  {status} {domain} -> {suggested_provider} (confidence: {confidence}%, expected: {expected_provider})")
    
    print("\n3. Testing certificate creation logic simulation:")
    
    # Simulate the certificate creation DNS provider selection logic
    def simulate_dns_provider_selection(domain, provided_dns_provider, settings):
        """Simulate the DNS provider selection logic from certificate creation"""
        if provided_dns_provider:
            return provided_dns_provider
        
        # Check existing domain configuration
        existing_provider = get_domain_dns_provider(domain, settings)
        if existing_provider and existing_provider != settings.get('dns_provider', 'cloudflare'):
            return existing_provider
        
        # Use smart suggestion
        suggested_provider, confidence = suggest_dns_provider_for_domain(domain, settings)
        if confidence >= 70:
            return suggested_provider
        
        # Fall back to global default
        return settings.get('dns_provider', 'cloudflare')
    
    creation_test_cases = [
        ("test2.audiolibri.org", None, "cloudflare"),  # Existing domain
        ("new-cf-domain.audiolibri.org", None, "cloudflare"),  # Smart suggestion
        ("aws-new-domain.test.certmate.org", None, "route53"),  # Smart suggestion
        ("random-new-domain.com", None, "route53"),  # Global default
        ("any-domain.com", "digitalocean", "digitalocean"),  # Explicit provider
    ]
    
    for domain, provided_provider, expected_provider in creation_test_cases:
        selected_provider = simulate_dns_provider_selection(domain, provided_provider, test_settings)
        status = "✓" if selected_provider == expected_provider else "✗"
        print(f"  {status} {domain} (provided: {provided_provider}) -> {selected_provider} (expected: {expected_provider})")
    
    print("\nTest completed!")

if __name__ == '__main__':
    test_dns_provider_inheritance()
