#!/usr/bin/env python3
"""
Test script to verify certificate listing functionality
"""

import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_certificate_listing():
    """Test that certificates are properly listed after creation"""
    
    # Import the functions we need to test
    from app import get_certificate_info, load_settings, CERT_DIR
    
    print("Testing certificate listing functionality...")
    
    # Create a test certificate directory structure
    test_domain = "test.example.com"
    test_cert_dir = CERT_DIR / test_domain
    test_cert_dir.mkdir(parents=True, exist_ok=True)
    
    # Create a dummy certificate file
    cert_file = test_cert_dir / "cert.pem"
    with open(cert_file, 'w') as f:
        f.write("-----BEGIN CERTIFICATE-----\nDUMMY CERTIFICATE FOR TESTING\n-----END CERTIFICATE-----\n")
    
    # Test get_certificate_info function
    print(f"Testing get_certificate_info for {test_domain}...")
    cert_info = get_certificate_info(test_domain)
    
    if cert_info:
        print(f"✓ Certificate info found: {cert_info}")
        if cert_info.get('domain') == test_domain:
            print("✓ Domain matches")
        else:
            print(f"✗ Domain mismatch: expected {test_domain}, got {cert_info.get('domain')}")
    else:
        print("✗ No certificate info returned")
    
    # Test certificate listing from API endpoint logic
    print("\nTesting certificate listing logic...")
    
    # We can't directly test the API method without proper Flask context,
    # but we can test the core logic
    settings = load_settings()
    certificates = []
    
    # Get all domains from settings
    domains_from_settings = settings.get('domains', [])
    
    # Also check for certificates that exist on disk but might not be in settings
    cert_dirs = []
    if CERT_DIR.exists():
        cert_dirs = [d for d in CERT_DIR.iterdir() if d.is_dir()]
    
    # Create a set of all domains to check (from settings and disk)
    all_domains = set()
    
    # Add domains from settings
    for domain_config in domains_from_settings:
        domain_name = domain_config.get('domain') if isinstance(domain_config, dict) else domain_config
        if domain_name:
            all_domains.add(domain_name)
    
    # Add domains from disk
    for cert_dir in cert_dirs:
        all_domains.add(cert_dir.name)
    
    print(f"Found domains: {all_domains}")
    
    # Get certificate info for all domains
    for domain_name in all_domains:
        if domain_name:
            cert_info = get_certificate_info(domain_name)
            if cert_info:
                certificates.append(cert_info)
    
    print(f"Found {len(certificates)} certificates")
    
    # Check if our test domain is in the list
    test_domain_found = False
    for cert in certificates:
        if cert.get('domain') == test_domain:
            test_domain_found = True
            break
    
    if test_domain_found:
        print(f"✓ Test domain {test_domain} found in certificate list")
    else:
        print(f"✗ Test domain {test_domain} not found in certificate list")
    
    # Clean up
    print("\nCleaning up test files...")
    shutil.rmtree(test_cert_dir, ignore_errors=True)
    
    print("Test completed!")

if __name__ == '__main__':
    test_certificate_listing()
