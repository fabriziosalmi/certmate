#!/usr/bin/env python3
"""
Debug script to test storage backend endpoint response
"""

import sys
import os
import tempfile

# Add the parent directory to the path so we can import the modules
sys.path.insert(0, os.path.dirname(__file__))

def test_storage_backend_endpoint():
    """Test the storage backend endpoint directly"""
    print("Testing storage backend endpoint...")
    
    # Set up test environment
    test_dir = tempfile.mkdtemp()
    os.environ['TESTING'] = 'True'
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['SECRET_KEY'] = 'test-secret-key-12345'
    
    from app import app as flask_app
    import json
    
    # Configure the app for testing
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
    
    # Create a test settings file with the token
    test_settings = {
        "api_bearer_token": "test-api-bearer-token",
        "certbot_email": "test@example.com",
        "auto_renew": False,
        "renewal_threshold_days": 30
    }
    
    settings_path = os.path.join(flask_app.config['DATA_DIR'], 'settings.json')
    with open(settings_path, 'w') as f:
        json.dump(test_settings, f)
    
    client = flask_app.test_client()
    
    # Test data
    test_data = {
        'backend': 'local_filesystem',
        'config': {
            'cert_dir': 'certificates'
        }
    }
    
    headers = {
        'Authorization': 'Bearer test-api-bearer-token',
        'Content-Type': 'application/json'
    }
    
    # Test the endpoint
    response = client.post(
        '/api/storage/test',
        headers=headers,
        data=json.dumps(test_data)
    )
    
    print(f"Status Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    print(f"Response Data: {response.get_data(as_text=True)}")
    
    if response.status_code == 200:
        try:
            response_json = response.get_json()
            print(f"Parsed JSON: {json.dumps(response_json, indent=2)}")
        except Exception as e:
            print(f"Error parsing JSON: {e}")
    
    print("\nTesting Azure KeyVault (should fail due to invalid config):")
    
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
        headers=headers,
        data=json.dumps(test_data_azure)
    )
    
    print(f"Status Code: {response2.status_code}")
    print(f"Response Data: {response2.get_data(as_text=True)}")
    
    if response2.status_code == 200:
        try:
            response_json = response2.get_json()
            print(f"Parsed JSON: {json.dumps(response_json, indent=2)}")
        except Exception as e:
            print(f"Error parsing JSON: {e}")

if __name__ == "__main__":
    test_storage_backend_endpoint()
