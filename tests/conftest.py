import pytest
import tempfile
import os
import shutil
from pathlib import Path
import json
import sys

# Add the parent directory to the path so we can import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

@pytest.fixture(scope='session')
def app():
    """Create application for the tests."""
    # Create a temporary directory for test data
    test_dir = tempfile.mkdtemp()
    
    # Set environment variables for testing
    os.environ['TESTING'] = 'True'
    os.environ['FLASK_ENV'] = 'testing'
    os.environ['SECRET_KEY'] = 'test-secret-key-12345'
    
    # Import after setting environment variables
    from app import app as flask_app
    
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
    
    # Create a test settings file
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
    
    yield flask_app
    
    # Cleanup
    shutil.rmtree(test_dir, ignore_errors=True)

@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()

@pytest.fixture
def sample_settings():
    """Sample settings for testing."""
    return {
        "cloudflare_api_token": "test-token-123",
        "cloudflare_zone_id": "test-zone-456",
        "cloudflare_email": "test@example.com",
        "certbot_email": "test@example.com",
        "auto_renew": True,
        "renewal_threshold_days": 30
    }

@pytest.fixture
def mock_certificate_data():
    """Mock certificate data for testing."""
    return {
        "domain": "test.example.com",
        "status": "valid",
        "expiry_date": "2025-12-31",
        "issuer": "Let's Encrypt"
    }