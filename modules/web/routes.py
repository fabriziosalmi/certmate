"""
Web routes module for CertMate
Handles web interface routes and form-based endpoints
"""

import json
import logging
import os
import re
import tempfile
import zipfile
import concurrent.futures
from datetime import datetime
from functools import wraps
from pathlib import Path
from collections import defaultdict
from time import time
from modules.core.auth import ROLE_HIERARCHY
from flask import (render_template, request, jsonify, send_file,
                   send_from_directory, redirect, url_for, after_this_request,
                   Response, stream_with_context)

from ..core.metrics import generate_metrics_response

logger = logging.getLogger(__name__)

# Simple login rate limiter (5 attempts per IP per minute)
_login_attempts = defaultdict(list)
_LOGIN_RATE_LIMIT = 5
_LOGIN_RATE_WINDOW = 60  # seconds


def _check_login_rate_limit(ip_address):
    """Check if login attempt is allowed for this IP
    
    Returns:
        tuple: (allowed: bool, retry_after: int or None)
    """
    current_time = time()
    window_start = current_time - _LOGIN_RATE_WINDOW
    
    # Clean old attempts
    _login_attempts[ip_address] = [
        t for t in _login_attempts[ip_address] if t > window_start
    ]
    
    if len(_login_attempts[ip_address]) >= _LOGIN_RATE_LIMIT:
        oldest = min(_login_attempts[ip_address])
        retry_after = int(oldest + _LOGIN_RATE_WINDOW - current_time) + 1
        return False, retry_after
    
    return True, None


def _record_login_attempt(ip_address):
    """Record a login attempt for rate limiting"""
    _login_attempts[ip_address].append(time())


# Import certificate files constant
from ..core.constants import CERTIFICATE_FILES

# Thread pool for background certificate operations (max 4 concurrent)
_cert_executor = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix='certmate-cert')

# Domain name validation pattern
_DOMAIN_RE = re.compile(r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def _is_localhost(addr):
    """Check if address is localhost (IPv4/IPv6 loopback only)"""
    if not addr:
        return False
    # Only accept true loopback addresses — not entire private ranges
    return addr in ('127.0.0.1', '::1', '::ffff:127.0.0.1')


def _sanitize_domain(domain, cert_base_dir):
    """Validate domain name and prevent path traversal.

    Returns:
        tuple: (safe_path, error_message) - safe_path is None if invalid
    """
    if not domain or '..' in domain or '/' in domain or '\\' in domain or '\x00' in domain:
        return None, 'Invalid domain name'
    if not _DOMAIN_RE.match(domain):
        return None, 'Invalid domain format'
    cert_dir = Path(cert_base_dir) / domain
    # Verify resolved path is within cert_base_dir
    try:
        resolved = cert_dir.resolve()
        base_resolved = Path(cert_base_dir).resolve()
        if not str(resolved).startswith(str(base_resolved) + os.sep) and resolved != base_resolved:
            return None, 'Invalid domain path'
    except (OSError, ValueError):
        return None, 'Invalid domain path'
    return cert_dir, None


def register_web_routes(app, managers):
    """Register all web interface routes
    
    Args:
        app: Flask app instance
        managers: Dictionary of manager instances
    """
    
    auth_manager = managers['auth']
    settings_manager = managers['settings']
    certificate_manager = managers['certificates']
    file_ops = managers['file_ops']
    cache_manager = managers['cache']
    dns_manager = managers['dns']

    def require_web_auth(f):
        """Decorator for web pages: redirect to /login if not authenticated"""
        @wraps(f)
        def decorated(*args, **kwargs):
            # Skip auth if local auth is not enabled or no users exist
            if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
                return f(*args, **kwargs)
            # Check session cookie
            session_id = request.cookies.get('certmate_session')
            if session_id:
                user_info = auth_manager.validate_session(session_id)
                if user_info:
                    request.current_user = user_info
                    return f(*args, **kwargs)
            return redirect(url_for('login_page'))
        return decorated


    from .ui_routes import register_ui_routes
    from .misc_routes import register_misc_routes
    from .auth_routes import register_auth_routes
    from .cert_routes import register_cert_routes
    from .settings_routes import register_settings_routes
    from .backup_cache_routes import register_backup_cache_routes

    register_ui_routes(app, managers, require_web_auth)
    register_misc_routes(app, managers, require_web_auth, auth_manager)
    register_auth_routes(app, managers, require_web_auth, auth_manager, _check_login_rate_limit, _record_login_attempt)
    register_cert_routes(app, managers, require_web_auth, auth_manager, certificate_manager, _sanitize_domain, file_ops, settings_manager, dns_manager, _cert_executor, CERTIFICATE_FILES)
    register_settings_routes(app, managers, require_web_auth, auth_manager, settings_manager, dns_manager, _is_localhost)
    register_backup_cache_routes(app, managers, require_web_auth, auth_manager, file_ops, settings_manager, cache_manager)
