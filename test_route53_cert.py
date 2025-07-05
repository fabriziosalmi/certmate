#!/usr/bin/env python3
"""
Quick test for Route53 certificate creation
"""

import os
import sys
import requests
import random
import string
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:8000"
API_TOKEN = "3kQlbC4OQIcKriSVJ7zYlX6vJy8w0HIOD-YyNSSXuC4"
HEADERS = {
    "Authorization": f"Bearer {API_TOKEN}",
    "Content-Type": "application/json"
}

def generate_random_subdomain():
    """Generate a random subdomain for testing"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))

def log_test(message):
    """Log test message with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}")

def create_route53_certificate():
    """Test Route53 certificate creation"""
    # Generate a random subdomain
    subdomain = generate_random_subdomain()
    domain = f"{subdomain}.test.certmate.org"
    
    payload = {
        "domain": domain,
        "dns_provider": "route53",
        "account_id": "certmate_test",
        "staging": True  # Use staging to avoid rate limits
    }
    
    log_test(f"Creating Route53 certificate for: {domain}")
    log_test(f"Payload: {payload}")
    
    try:
        response = requests.post(
            f"{BASE_URL}/api/certificates/create",
            headers=HEADERS,
            json=payload,
            timeout=300
        )
        
        log_test(f"Response status: {response.status_code}")
        
        if response.status_code == 200:
            result = response.json()
            log_test(f"Response: {result}")
            
            if result.get("success"):
                log_test(f"✓ Route53 certificate created successfully for {domain}")
                return True
            else:
                log_test(f"✗ Route53 certificate creation failed: {result.get('message', 'Unknown error')}")
                return False
        else:
            log_test(f"✗ HTTP error: {response.status_code}")
            try:
                error_detail = response.json()
                log_test(f"Error details: {error_detail}")
            except:
                log_test(f"Error response: {response.text}")
            return False
    
    except Exception as e:
        log_test(f"✗ Exception: {e}")
        return False

if __name__ == '__main__':
    log_test("=== Route53 Certificate Creation Test ===")
    success = create_route53_certificate()
    log_test(f"Test result: {'SUCCESS' if success else 'FAILED'}")
    sys.exit(0 if success else 1)
