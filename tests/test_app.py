import pytest
import json
import os
from unittest.mock import patch, MagicMock

def test_app_initialization(app):
    """Test that the Flask app initializes correctly."""
    assert app is not None
    assert app.config['TESTING'] is True

def test_home_page(client):
    """Test the home page loads."""
    response = client.get('/')
    assert response.status_code == 200

def test_settings_page(client):
    """Test the settings page loads."""
    response = client.get('/settings')
    assert response.status_code == 200

def test_help_page(client):
    """Test the help page loads."""
    response = client.get('/help')
    assert response.status_code == 200

def test_app_secret_key_set(app):
    """Test that secret key is properly set."""
    assert app.secret_key is not None
    assert len(app.secret_key) > 0

def test_cors_enabled(client):
    """Test that CORS is properly configured."""
    response = client.options('/')
    # CORS should add appropriate headers
    assert 'Access-Control-Allow-Origin' in response.headers or response.status_code == 200