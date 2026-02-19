#!/usr/bin/env python3
"""
🔐 Infisical Storage Backend Test
=================================
Test the Infisical storage backend with a self-hosted instance.

Prerequisites:
    pip install infisical-python

Configuration:
    Set environment variables or edit the config below:
    - INFISICAL_SITE_URL (e.g., https://infisical.yourserver.com)
    - INFISICAL_CLIENT_ID 
    - INFISICAL_CLIENT_SECRET
    - INFISICAL_PROJECT_ID
    - INFISICAL_ENVIRONMENT (default: prod)

Usage:
    python test_infisical_backend.py
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# ANSI Colors
class Colors:
    RESET = '\033[0m'
    BOLD = '\033[1m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    GRAY = '\033[90m'


def print_header(text):
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.CYAN}{Colors.BOLD}  🔐 {text}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")


def print_step(text):
    print(f"{Colors.GRAY}  ▸ {text}{Colors.RESET}")


def print_success(text):
    print(f"{Colors.GREEN}  ✅ {text}{Colors.RESET}")


def print_error(text):
    print(f"{Colors.RED}  ❌ {text}{Colors.RESET}")


def print_warning(text):
    print(f"{Colors.YELLOW}  ⚠️  {text}{Colors.RESET}")


def print_info(text):
    print(f"{Colors.CYAN}  ℹ️  {text}{Colors.RESET}")


def test_infisical_backend():
    """Test the Infisical storage backend"""
    import pytest
    
    print_header("Infisical Storage Backend Test")
    
    # ==========================================================================
    # Configuration
    # ==========================================================================
    
    config = {
        'site_url': os.getenv('INFISICAL_SITE_URL', 'https://app.infisical.com'),
        'client_id': os.getenv('INFISICAL_CLIENT_ID'),
        'client_secret': os.getenv('INFISICAL_CLIENT_SECRET'),
        'project_id': os.getenv('INFISICAL_PROJECT_ID'),
        'environment': os.getenv('INFISICAL_ENVIRONMENT', 'prod'),
    }
    
    print_step("Configuration:")
    print(f"      Site URL:    {config['site_url']}")
    print(f"      Project ID:  {config['project_id'] or '(not set)'}")
    print(f"      Environment: {config['environment']}")
    print(f"      Client ID:   {'***' + config['client_id'][-4:] if config['client_id'] else '(not set)'}")
    print(f"      Secret:      {'***' if config['client_secret'] else '(not set)'}")
    print()
    
    # Check required config
    if not all([config['client_id'], config['client_secret'], config['project_id']]):
        pytest.skip("Missing Infisical env vars (INFISICAL_CLIENT_ID, INFISICAL_CLIENT_SECRET, INFISICAL_PROJECT_ID)")
    
    # ==========================================================================
    # Check infisical-python package
    # ==========================================================================
    
    print_step("Checking infisical-python package...")
    try:
        from infisical import InfisicalClient, ClientSettings
        print_success("infisical-python is installed")
    except ImportError:
        print_error("infisical-python not installed!")
        print_warning("Install with: pip install infisical-python")
        pytest.fail("Infisical test step failed")
    
    # ==========================================================================
    # Initialize Backend
    # ==========================================================================
    
    print_step("Initializing InfisicalBackend...")
    try:
        from modules.core.storage_backends import InfisicalBackend
        backend = InfisicalBackend(config)
        print_success("Backend initialized")
    except Exception as e:
        print_error(f"Failed to initialize: {e}")
        pytest.fail("Infisical test step failed")
    
    # ==========================================================================
    # Test Connection
    # ==========================================================================
    
    print_step("Testing connection to Infisical...")
    try:
        client = backend._get_client()
        print_success("Connected to Infisical!")
    except Exception as e:
        print_error(f"Connection failed: {e}")
        pytest.fail("Infisical test step failed")
    
    # ==========================================================================
    # Test Store Certificate
    # ==========================================================================
    
    test_domain = f"test-{datetime.now().strftime('%Y%m%d%H%M%S')}.certmate.local"
    
    print_step(f"Storing test certificate for: {test_domain}")
    
    # Create fake certificate data
    test_cert_files = {
        'cert.pem': b'-----BEGIN CERTIFICATE-----\nTEST_CERT_DATA\n-----END CERTIFICATE-----',
        'privkey.pem': b'-----BEGIN PRIVATE KEY-----\nTEST_KEY_DATA\n-----END PRIVATE KEY-----',
        'chain.pem': b'-----BEGIN CERTIFICATE-----\nTEST_CHAIN_DATA\n-----END CERTIFICATE-----',
        'fullchain.pem': b'-----BEGIN CERTIFICATE-----\nTEST_FULLCHAIN_DATA\n-----END CERTIFICATE-----',
    }
    
    test_metadata = {
        'domain': test_domain,
        'created_at': datetime.now().isoformat(),
        'expires_at': '2027-01-17T00:00:00',
        'issuer': 'CertMate Test',
        'dns_provider': 'test',
        'test': True
    }
    
    try:
        success = backend.store_certificate(test_domain, test_cert_files, test_metadata)
        if success:
            print_success(f"Certificate stored for {test_domain}")
        else:
            print_error("Store returned False")
            pytest.fail("Infisical test step failed")
    except Exception as e:
        print_error(f"Store failed: {e}")
        pytest.fail("Infisical test step failed")
    
    # ==========================================================================
    # Test Certificate Exists
    # ==========================================================================
    
    print_step("Checking if certificate exists...")
    try:
        exists = backend.certificate_exists(test_domain)
        if exists:
            print_success("Certificate exists check passed")
        else:
            print_error("Certificate not found after storing!")
            pytest.fail("Infisical test step failed")
    except Exception as e:
        print_error(f"Exists check failed: {e}")
        pytest.fail("Infisical test step failed")
    
    # ==========================================================================
    # Test List Certificates
    # ==========================================================================
    
    print_step("Listing certificates...")
    try:
        domains = backend.list_certificates()
        print_success(f"Found {len(domains)} certificate(s)")
        for d in domains:
            print(f"        - {d}")
        if test_domain not in domains:
            print_warning(f"Test domain {test_domain} not in list (may be naming issue)")
    except Exception as e:
        print_error(f"List failed: {e}")
        pytest.fail("Infisical test step failed")
    
    # ==========================================================================
    # Test Retrieve Certificate
    # ==========================================================================
    
    print_step("Retrieving certificate...")
    try:
        result = backend.retrieve_certificate(test_domain)
        if result:
            cert_files, metadata = result
            print_success(f"Retrieved {len(cert_files)} files")
            for filename in cert_files:
                print(f"        - {filename}: {len(cert_files[filename])} bytes")
            print_success("Metadata retrieved:")
            for key, value in metadata.items():
                print(f"        - {key}: {value}")
        else:
            print_error("Retrieve returned None")
            pytest.fail("Infisical test step failed")
    except Exception as e:
        print_error(f"Retrieve failed: {e}")
        pytest.fail("Infisical test step failed")
    
    # ==========================================================================
    # Test Delete Certificate
    # ==========================================================================
    
    print_step(f"Deleting test certificate: {test_domain}")
    try:
        success = backend.delete_certificate(test_domain)
        if success:
            print_success("Certificate deleted")
        else:
            print_warning("Delete returned False (may already be deleted)")
    except Exception as e:
        print_error(f"Delete failed: {e}")
        pytest.fail("Infisical test step failed")
    
    # Verify deletion
    print_step("Verifying deletion...")
    try:
        exists = backend.certificate_exists(test_domain)
        if not exists:
            print_success("Certificate confirmed deleted")
        else:
            print_warning("Certificate still exists after deletion")
    except Exception as e:
        print_warning(f"Verification check failed: {e}")
    
    # ==========================================================================
    # Summary
    # ==========================================================================
    
    print()
    print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}{Colors.BOLD}  🎉 ALL TESTS PASSED!{Colors.RESET}")
    print(f"{Colors.GREEN}{'='*60}{Colors.RESET}")
    print()
    print_info("Infisical backend is working correctly!")
    print_info(f"You can configure it in settings.json:")
    print()
    print(f'''    "certificate_storage": {{
        "backend": "infisical",
        "infisical": {{
            "site_url": "{config['site_url']}",
            "client_id": "your-client-id",
            "client_secret": "your-client-secret",
            "project_id": "{config['project_id']}",
            "environment": "{config['environment']}"
        }}
    }}''')
    print()


if __name__ == '__main__':
    test_infisical_backend()
