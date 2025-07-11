"""
Authentication module for CertMate
Handles authentication decorators and security functions
"""

import logging
from functools import wraps
from flask import request, jsonify

logger = logging.getLogger(__name__)


class AuthManager:
    """Class to handle authentication and authorization"""
    
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager

    def require_auth(self, f):
        """Enhanced decorator to require bearer token authentication"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Get bearer token from Authorization header
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                return {'error': 'Missing or invalid authorization header. Expected: Bearer <token>'}, 401
            
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            
            # Load current settings to get the valid token
            settings = self.settings_manager.load_settings()
            valid_token = settings.get('api_bearer_token')
            
            if not valid_token:
                return {'error': 'API authentication not configured'}, 500
            
            if token != valid_token:
                logger.warning(f"Invalid API token attempt from {request.remote_addr}")
                return {'error': 'Invalid authentication token'}, 401
            
            return f(*args, **kwargs)
        
        return decorated_function

    def validate_api_token(self, token):
        """Validate API token against current settings"""
        try:
            settings = self.settings_manager.load_settings()
            valid_token = settings.get('api_bearer_token')
            return token == valid_token if valid_token else False
        except Exception as e:
            logger.error(f"Error validating API token: {e}")
            return False

    def get_current_token(self):
        """Get the current API bearer token from settings"""
        try:
            settings = self.settings_manager.load_settings()
            return settings.get('api_bearer_token')
        except Exception as e:
            logger.error(f"Error getting current token: {e}")
            return None
