"""
Authentication module for CertMate
Handles authentication decorators and security functions
"""

import logging
import secrets
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
            try:
                # Get bearer token from Authorization header
                auth_header = request.headers.get('Authorization')
                if not auth_header:
                    return {'error': 'Authorization header required', 'code': 'AUTH_HEADER_MISSING'}, 401
                
                try:
                    scheme, token = auth_header.split(' ', 1)
                    if scheme.lower() != 'bearer':
                        return {'error': 'Invalid authorization scheme. Use Bearer token', 'code': 'INVALID_AUTH_SCHEME'}, 401
                    if not token.strip():
                        return {'error': 'Invalid authorization header format. Use: Bearer <token>', 'code': 'INVALID_AUTH_FORMAT'}, 401
                except ValueError:
                    return {'error': 'Invalid authorization header format. Use: Bearer <token>', 'code': 'INVALID_AUTH_FORMAT'}, 401
                
                # Load current settings to get the valid token
                settings = self.settings_manager.load_settings()
                expected_token = settings.get('api_bearer_token')
                
                if not expected_token:
                    return {'error': 'Server configuration error: no API token configured', 'code': 'SERVER_CONFIG_ERROR'}, 500
                
                # Validate token strength using imported function
                from modules.core.utils import validate_api_token
                is_valid, validation_error = validate_api_token(expected_token)
                if not is_valid:
                    logger.error(f"Server has weak API token: {validation_error}")
                    return {'error': 'Server security configuration error', 'code': 'WEAK_SERVER_TOKEN'}, 500
                
                # Use constant-time comparison to prevent timing attacks
                if not secrets.compare_digest(token, expected_token):
                    logger.warning(f"Invalid API token attempt from {request.remote_addr}")
                    return {'error': 'Invalid or expired token', 'code': 'INVALID_TOKEN'}, 401
                
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Authentication error: {e}")
                return {'error': 'Authentication failed', 'code': 'AUTH_ERROR'}, 401
        
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
