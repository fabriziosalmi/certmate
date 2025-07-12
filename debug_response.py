#!/usr/bin/env python3
"""
Test script to see the actual response from storage backend test
"""

import pytest
import json
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def test_storage_response():
    """Test to see the actual storage backend response"""
    
    # Create a minimal test like in test_storage_backend_api.py
    import tempfile
    import shutil
    from pathlib import Path
    
    # Set up test environment like conftest.py does
    test_dir = tempfile.mkdtemp()
    
    os.environ['TESTING'] = 'True'
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['SECRET_KEY'] = 'test-secret-key-12345'
    
    # Import the app
    from app import app as flask_app
    
    # Configure app for testing
    flask_app.config.update({
        'TESTING': True,
        'WTF_CSRF_ENABLED': False,
        'SECRET_KEY': 'test-secret-key-12345',
        'CERT_DIR': os.path.join(test_dir, 'certificates'),
        'DATA_DIR': os.path.join(test_dir, 'data'),
    })
    
    # Create test directories
    os.makedirs(flask_app.config['CERT_DIR'], exist_ok=True)
    os.makedirs(flask_app.config['DATA_DIR'], exist_ok=True)
    
    # Create test settings file
    test_settings = {
        "cloudflare_api_token": "test-token",
        "cloudflare_zone_id": "test-zone-id",
        "cloudflare_email": "test@example.com",
        "certbot_email": "test@example.com",
        "auto_renew": False,
        "renewal_threshold_days": 30,
        "api_bearer_token": "test-api-bearer-token"
    }
    
    settings_path = os.path.join(flask_app.config['DATA_DIR'], 'settings.json')
    with open(settings_path, 'w') as f:
        json.dump(test_settings, f)
    
    # Create test client
    client = flask_app.test_client()
    
    # Set up headers
    auth_headers = {
        'Authorization': 'Bearer test-api-bearer-token',
        'Content-Type': 'application/json'
    }
    
    print("Testing local filesystem backend...")
    
    # Test data for local filesystem
    test_data = {
        'backend': 'local_filesystem',
        'config': {
            'cert_dir': 'test_certificates'
        }
    }
    
    # Make the request
    response = client.post(
        '/api/storage/test',
        headers=auth_headers,
        data=json.dumps(test_data)
    )
    
    print(f"Status Code: {response.status_code}")
    print(f"Headers: {dict(response.headers)}")
    print(f"Raw Response: {response.get_data(as_text=True)}")
    
    if response.status_code == 200:
        try:
            response_json = response.get_json()
            print(f"JSON Response: {json.dumps(response_json, indent=2)}")
            
            # Check response structure for UI
            required_fields = ['success', 'message', 'backend']
            for field in required_fields:
                if field in response_json:
                    print(f"✅ {field}: {response_json[field]}")
                else:
                    print(f"❌ Missing field: {field}")
                    
        except Exception as e:
            print(f"Error parsing JSON: {e}")
    else:
        print(f"❌ Request failed")
        
    # Test Azure KeyVault (should fail)
    print("\n" + "="*50)
    print("Testing Azure KeyVault backend (invalid config)...")
    
    test_data_azure = {
        'backend': 'azure_keyvault',
        'config': {
            'vault_url': 'https://invalid.vault.azure.net/',
            'tenant_id': 'test-tenant',
            'client_id': 'test-client',
            'client_secret': 'test-secret'
        }
    }
    
    response2 = client.post(
        '/api/storage/test',
        headers=auth_headers,
        data=json.dumps(test_data_azure)
    )
    
    print(f"Status Code: {response2.status_code}")
    print(f"Raw Response: {response2.get_data(as_text=True)}")
    
    if response2.status_code == 200:
        try:
            response_json = response2.get_json()
            print(f"JSON Response: {json.dumps(response_json, indent=2)}")
            
            # Check response structure for UI
            required_fields = ['success', 'message', 'backend']
            for field in required_fields:
                if field in response_json:
                    print(f"✅ {field}: {response_json[field]}")
                else:
                    print(f"❌ Missing field: {field}")
                    
        except Exception as e:
            print(f"Error parsing JSON: {e}")
    
    # Cleanup
    try:
        shutil.rmtree(test_dir, ignore_errors=True)
    except:
        pass

if __name__ == "__main__":
    test_storage_response()
