"""
Authentication module for CertMate
Handles authentication decorators and security functions
Supports both API token and local username/password authentication
"""

import logging
import secrets
import hashlib
import threading
import uuid
import time
from functools import wraps
from flask import request, jsonify, session
from datetime import datetime, timedelta

try:
    import bcrypt
    BCRYPT_AVAILABLE = True
except ImportError:
    BCRYPT_AVAILABLE = False

logger = logging.getLogger(__name__)

ROLE_HIERARCHY = {'viewer': 0, 'operator': 1, 'admin': 2}


class AuthManager:
    """Class to handle authentication and authorization"""
    
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager
        self._sessions = {}  # In-memory session store: {session_id: {user, expires, created}}
        self._session_lock = threading.Lock()  # Thread-safe session access
        self._session_timeout = 8 * 60 * 60  # 8 hours in seconds
        if not BCRYPT_AVAILABLE:
            logger.warning("bcrypt not available, falling back to SHA-256 (less secure)")

    @staticmethod
    def _normalize_role(role):
        """Normalize legacy role names to the current 3-tier model."""
        if role == 'user':
            return 'operator'  # backward compat: 'user' → 'operator'
        return role if role in ROLE_HIERARCHY else 'viewer'

    def _hash_password(self, password, salt=None):
        """Hash password using bcrypt (preferred) or SHA-256 with salt (fallback)
        
        bcrypt is the industry standard for password hashing as it's designed
        to be slow and resistant to GPU/ASIC attacks.
        """
        if BCRYPT_AVAILABLE:
            # bcrypt handles salt internally, rounds=12 provides good security
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        else:
            # Fallback to SHA-256 with salt (less secure but functional)
            if salt is None:
                salt = secrets.token_hex(16)
            hashed = hashlib.sha256((salt + password).encode()).hexdigest()
            return f"sha256:{salt}:{hashed}"
    
    def _verify_password(self, password, stored_hash):
        """Verify password against stored hash (supports bcrypt and legacy SHA-256)"""
        try:
            # Check if it's a bcrypt hash (starts with $2b$ or $2a$)
            if stored_hash.startswith('$2'):
                if BCRYPT_AVAILABLE:
                    return bcrypt.checkpw(password.encode(), stored_hash.encode())
                else:
                    logger.error("bcrypt hash found but bcrypt not available")
                    return False
            
            # Legacy SHA-256 format: "sha256:salt:hash" or "salt:hash"
            if stored_hash.startswith('sha256:'):
                parts = stored_hash.split(':', 2)
                if len(parts) == 3:
                    _, salt, expected_hash = parts
                else:
                    return False
            else:
                # Old format without prefix
                salt, expected_hash = stored_hash.split(':', 1)
            
            actual_hash = hashlib.sha256((salt + password).encode()).hexdigest()
            return secrets.compare_digest(actual_hash, expected_hash)
        except (ValueError, AttributeError) as e:
            logger.debug(f"Password verification error: {e}")
            return False
    
    def _get_users(self):
        """Get all users from settings"""
        settings = self.settings_manager.load_settings()
        return settings.get('users', {})
    
    def _save_users(self, users):
        """Save users to settings"""
        settings = self.settings_manager.load_settings()
        settings['users'] = users
        return self.settings_manager.save_settings(settings, "user_management")
    
    def create_user(self, username, password, role='operator', email=None):
        """Create a new user"""
        try:
            users = self._get_users()

            if username in users:
                return False, "User already exists"

            normalized = self._normalize_role(role)
            users[username] = {
                'password_hash': self._hash_password(password),
                'role': normalized,
                'email': email,
                'created_at': datetime.utcnow().isoformat(),
                'last_login': None,
                'enabled': True
            }
            
            if self._save_users(users):
                logger.info(f"User '{username}' created successfully")
                return True, "User created successfully"
            return False, "Failed to save user"
        except Exception as e:
            logger.error(f"Error creating user: {e}")
            return False, "An internal error occurred"
    
    def update_user(self, username, password=None, role=None, email=None, enabled=None):
        """Update an existing user"""
        try:
            users = self._get_users()
            
            if username not in users:
                return False, "User not found"
            
            if password:
                users[username]['password_hash'] = self._hash_password(password)
            if role is not None:
                users[username]['role'] = role
            if email is not None:
                users[username]['email'] = email
            if enabled is not None:
                users[username]['enabled'] = enabled
            
            if self._save_users(users):
                logger.info(f"User '{username}' updated successfully")
                return True, "User updated successfully"
            return False, "Failed to save user"
        except Exception as e:
            logger.error(f"Error updating user: {e}")
            return False, "An internal error occurred"
    
    def delete_user(self, username):
        """Delete a user"""
        try:
            users = self._get_users()
            
            if username not in users:
                return False, "User not found"
            
            # Prevent deleting the last admin
            admin_count = sum(1 for u in users.values() if u.get('role') == 'admin' and u.get('enabled', True))
            if users[username].get('role') == 'admin' and admin_count <= 1:
                return False, "Cannot delete the last admin user"
            
            del users[username]
            
            if self._save_users(users):
                logger.info(f"User '{username}' deleted successfully")
                return True, "User deleted successfully"
            return False, "Failed to delete user"
        except Exception as e:
            logger.error(f"Error deleting user: {e}")
            return False, "An internal error occurred"
    
    def list_users(self):
        """List all users (without password hashes)"""
        users = self._get_users()
        return {
            username: {
                'role': self._normalize_role(data.get('role', 'operator')),
                'email': data.get('email'),
                'created_at': data.get('created_at'),
                'last_login': data.get('last_login'),
                'enabled': data.get('enabled', True)
            }
            for username, data in users.items()
        }
    
    def authenticate_user(self, username, password):
        """Authenticate user with username and password"""
        try:
            users = self._get_users()
            
            if username not in users:
                logger.warning(f"Login attempt for non-existent user: {username}")
                return None
            
            user = users[username]
            
            if not user.get('enabled', True):
                logger.warning(f"Login attempt for disabled user: {username}")
                return None
            
            if self._verify_password(password, user.get('password_hash', '')):
                # Update last login
                user['last_login'] = datetime.utcnow().isoformat()
                self._save_users(users)
                
                logger.info(f"User '{username}' authenticated successfully")
                return {
                    'username': username,
                    'role': self._normalize_role(user.get('role', 'operator')),
                    'email': user.get('email')
                }
            
            logger.warning(f"Failed login attempt for user: {username}")
            return None
        except Exception as e:
            logger.error(f"Error authenticating user: {e}")
            return None
    
    def create_session(self, username):
        """Create a new session for authenticated user"""
        session_id = secrets.token_urlsafe(32)
        users = self._get_users()
        user = users.get(username, {})

        with self._session_lock:
            self._sessions[session_id] = {
                'user': username,
                'role': self._normalize_role(user.get('role', 'operator')),
                'created': time.time(),
                'expires': time.time() + self._session_timeout
            }
            # Cleanup expired sessions occasionally
            self._cleanup_sessions()

        return session_id

    def validate_session(self, session_id):
        """Validate a session and return user info if valid"""
        with self._session_lock:
            if not session_id or session_id not in self._sessions:
                return None

            session_data = self._sessions[session_id]

            if time.time() > session_data['expires']:
                del self._sessions[session_id]
                return None

            return {
                'username': session_data['user'],
                'role': self._normalize_role(session_data['role'])
            }

    def invalidate_session(self, session_id):
        """Invalidate/logout a session"""
        with self._session_lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                return True
            return False

    def _cleanup_sessions(self):
        """Remove expired sessions (caller must hold _session_lock)"""
        current_time = time.time()
        expired = [sid for sid, data in self._sessions.items() if current_time > data['expires']]
        for sid in expired:
            del self._sessions[sid]
    
    def is_local_auth_enabled(self):
        """Check if local authentication is enabled"""
        settings = self.settings_manager.load_settings()
        return settings.get('local_auth_enabled', False)
    
    def enable_local_auth(self, enable=True):
        """Enable or disable local authentication"""
        settings = self.settings_manager.load_settings()
        settings['local_auth_enabled'] = enable
        return self.settings_manager.save_settings(settings, "auth_config")
    
    def has_any_users(self):
        """Check if any users exist"""
        return len(self._get_users()) > 0
    
    def require_auth(self, f):
        """Enhanced decorator to require authentication (API token or session)"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                # Allow unauthenticated access during initial setup
                # (matches require_web_auth: bypass if auth disabled OR no users)
                if not self.is_local_auth_enabled() or not self.has_any_users():
                    request.current_user = {'username': 'setup_user', 'role': 'admin'}
                    return f(*args, **kwargs)

                # Check for session-based auth first (for web UI)
                session_id = request.cookies.get('certmate_session')
                if session_id:
                    user_info = self.validate_session(session_id)
                    if user_info:
                        request.current_user = user_info
                        return f(*args, **kwargs)
                
                # Fall back to bearer token auth (for API)
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
                is_valid, token_or_error = validate_api_token(expected_token)
                if not is_valid:
                    logger.error(f"Server has weak API token: {token_or_error}")
                    return {'error': 'Server security configuration error', 'code': 'WEAK_SERVER_TOKEN'}, 500
                
                # Use constant-time comparison to prevent timing attacks
                if not secrets.compare_digest(token, expected_token):
                    logger.warning(f"Invalid API token attempt from {request.remote_addr}")
                    return {'error': 'Invalid or expired token', 'code': 'INVALID_TOKEN'}, 401
                
                request.current_user = {'username': 'api_user', 'role': 'admin'}
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Authentication error: {e}")
                return {'error': 'Authentication failed', 'code': 'AUTH_ERROR'}, 401
        
        return decorated_function
    
    def require_role(self, min_role):
        """Decorator factory requiring a minimum role level.

        Usage::

            @auth_manager.require_role('operator')
            def create_cert(): ...
        """
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                # Authenticate first (sets request.current_user)
                auth_result = self.require_auth(lambda: None)()
                if isinstance(auth_result, tuple) and len(auth_result) == 2:
                    return auth_result  # Return auth error

                # Check role level
                user = getattr(request, 'current_user', None)
                if not user:
                    return {'error': 'Authentication required', 'code': 'AUTH_REQUIRED'}, 401

                user_level = ROLE_HIERARCHY.get(user.get('role'), -1)
                required_level = ROLE_HIERARCHY.get(min_role, 999)
                if user_level < required_level:
                    return {'error': f'{min_role} privileges required', 'code': 'INSUFFICIENT_ROLE'}, 403

                return f(*args, **kwargs)
            return decorated_function
        return decorator

    def require_admin(self, f):
        """Decorator to require admin role (backward compat wrapper)."""
        return self.require_role('admin')(f)

    def validate_api_token(self, token):
        """Validate API token against current settings"""
        try:
            settings = self.settings_manager.load_settings()
            valid_token = settings.get('api_bearer_token')
            return secrets.compare_digest(token, valid_token) if valid_token else False
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
