#!/usr/bin/env python3
"""
Simple test script to debug storage backend test connection
"""

import sys
import os
import pytest
sys.path.insert(0, os.path.dirname(__file__))

def test_storage_backend_manually():
    """Test the storage backend with pytest style setup"""
    
    # Use pytest to set up the environment like the tests do
    from tests.conftest import app
    
    # This will give us an app with proper test setup
    flask_app = None
    for test_app in app():
        flask_app = test_app
        break
    
    if not flask_app:
        print("Failed to create test app")
        return
    
    import json
    
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
    
    print("Testing storage backend endpoint with proper test setup...")
    
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
            
            # Check the expected format
            if 'success' in response_json:
                print(f"✅ Success field present: {response_json['success']}")
            if 'message' in response_json:
                print(f"✅ Message field present: {response_json['message']}")
            if 'backend' in response_json:
                print(f"✅ Backend field present: {response_json['backend']}")
                
        except Exception as e:
            print(f"Error parsing JSON: {e}")
    else:
        print(f"❌ Request failed with status {response.status_code}")
        
    print("\n" + "="*50)
    print("Testing Azure KeyVault (should fail gracefully):")
    
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
            
            # Check the expected format
            if 'success' in response_json:
                print(f"✅ Success field present: {response_json['success']}")
                if not response_json['success']:
                    print("✅ Correctly returned success=false for invalid config")
            if 'message' in response_json:
                print(f"✅ Message field present: {response_json['message']}")
                
        except Exception as e:
            print(f"Error parsing JSON: {e}")

if __name__ == "__main__":
    test_storage_backend_manually()
