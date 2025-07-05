#!/usr/bin/env python3
"""
Test script to simulate certificate creation with DNS provider inheritance
"""

import os
import sys
import json
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def simulate_certificate_creation():
    """Simulate the certificate creation process"""
    
    from app import (
        get_domain_dns_provider, 
        get_dns_provider_account_config,
        suggest_dns_provider_for_domain,
        load_settings
    )
    
    print("Simulating certificate creation process...")
    
    # Load your actual settings
    settings = load_settings()
    
    # Test scenarios
    test_scenarios = [
        # Scenario 1: Creating cert for existing domain (should use configured provider)
        {
            "domain": "test2.audiolibri.org",
            "provided_dns_provider": None,
            "provided_account_id": None,
            "expected_provider": "cloudflare",
            "expected_account": "default"
        },
        # Scenario 2: Creating cert for Route53 domain
        {
            "domain": "aws-test3.test.certmate.org",
            "provided_dns_provider": None,
            "provided_account_id": None,
            "expected_provider": "route53",
            "expected_account": "certmate_test"
        },
        # Scenario 3: Creating cert for new Cloudflare domain (smart suggestion)
        {
            "domain": "new-cf-test.audiolibri.org",
            "provided_dns_provider": None,
            "provided_account_id": None,
            "expected_provider": "cloudflare",
            "expected_account": "default"
        },
        # Scenario 4: Creating cert for new Route53 domain (smart suggestion)
        {
            "domain": "new-aws-test.test.certmate.org",
            "provided_dns_provider": None,
            "provided_account_id": None,
            "expected_provider": "route53",
            "expected_account": "certmate_test"
        },
        # Scenario 5: Explicit provider override
        {
            "domain": "any-domain.com",
            "provided_dns_provider": "cloudflare",
            "provided_account_id": "default",
            "expected_provider": "cloudflare",
            "expected_account": "default"
        }
    ]
    
    print(f"\nSimulating certificate creation scenarios:")
    
    for i, scenario in enumerate(test_scenarios, 1):
        domain = scenario["domain"]
        provided_dns_provider = scenario["provided_dns_provider"]
        provided_account_id = scenario["provided_account_id"]
        expected_provider = scenario["expected_provider"]
        expected_account = scenario["expected_account"]
        
        print(f"\n{i}. Testing: {domain}")
        print(f"   Provided DNS provider: {provided_dns_provider or 'None'}")
        print(f"   Provided account ID: {provided_account_id or 'None'}")
        
        # Simulate the certificate creation DNS provider selection logic
        if provided_dns_provider:
            dns_provider = provided_dns_provider
            print(f"   Using provided DNS provider: {dns_provider}")
        else:
            # Check existing domain configuration
            existing_provider = get_domain_dns_provider(domain, settings)
            if existing_provider and existing_provider != settings.get('dns_provider', 'cloudflare'):
                dns_provider = existing_provider
                print(f"   Using existing domain DNS provider: {dns_provider}")
            else:
                # Use smart suggestion
                suggested_provider, confidence = suggest_dns_provider_for_domain(domain, settings)
                if confidence >= 70:
                    dns_provider = suggested_provider
                    print(f"   Using smart suggestion: {dns_provider} (confidence: {confidence}%)")
                else:
                    dns_provider = settings.get('dns_provider', 'cloudflare')
                    print(f"   Using global default: {dns_provider}")
        
        # Determine account_id
        if provided_account_id:
            account_id = provided_account_id
        else:
            default_accounts = settings.get('default_accounts', {})
            account_id = default_accounts.get(dns_provider, 'default')
            print(f"   Using default account for {dns_provider}: {account_id}")
        
        # Validate account configuration
        account_config, used_account_id = get_dns_provider_account_config(dns_provider, account_id, settings)
        
        if account_config:
            print(f"   ✓ Account configuration found: {used_account_id}")
            
            # Check if results match expectations
            provider_match = dns_provider == expected_provider
            account_match = used_account_id == expected_account
            
            if provider_match and account_match:
                print(f"   ✓ Result matches expectations: {dns_provider}/{used_account_id}")
            else:
                print(f"   ✗ Result mismatch:")
                print(f"     Expected: {expected_provider}/{expected_account}")
                print(f"     Got:      {dns_provider}/{used_account_id}")
        else:
            print(f"   ✗ No account configuration found for {dns_provider}/{account_id}")
    
    print("\nSimulation completed!")

if __name__ == '__main__':
    simulate_certificate_creation()
