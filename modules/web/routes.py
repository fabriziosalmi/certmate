"""
Web routes module for CertMate
Handles web interface routes and form-based endpoints
"""

import logging
import os
import re
from functools import wraps
from pathlib import Path
from collections import defaultdict
from time import time
from flask import request, redirect, url_for

logger = logging.getLogger(__name__)

# Login rate limit policy. Two buckets per attempt:
#
#   - per-IP        (default 5 attempts / 60s)   throttles a single attacker
#                                                 from one source IP.
#   - per-username  (default 10 attempts / 300s) throttles a *target* under
#                                                 a distributed/botnet attack
#                                                 where each source IP is
#                                                 fresh to the per-IP bucket.
#
# F-7 (2026-05-12 API auth audit follow-up): per-IP alone fails open to
# distributed brute force. The per-username bucket caps attempts against
# a single account regardless of where they come from. The window is
# wider than the per-IP one because legitimate users may legitimately
# fat-finger several times in a row from different devices/networks.
_login_attempts_by_ip = defaultdict(list)
_LOGIN_RATE_LIMIT_IP = 5
_LOGIN_RATE_WINDOW_IP = 60  # seconds

_login_attempts_by_user = defaultdict(list)
_LOGIN_RATE_LIMIT_USER = 10
_LOGIN_RATE_WINDOW_USER = 300  # seconds (5 minutes)

# Domain name validation pattern
_DOMAIN_RE = re.compile(r'^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$')


def _trim_attempts(bucket, key, window):
    """Drop attempts older than `window` from bucket[key]. Mutates in place."""
    cutoff = time() - window
    bucket[key] = [t for t in bucket[key] if t > cutoff]


def _check_login_rate_limit(ip_address, username=None):
    """Check whether a login attempt is allowed.

    Returns ``(allowed, retry_after)`` — ``allowed`` is False if either
    bucket is full. ``retry_after`` is the worst-case wait across the
    two buckets, so the client backs off enough to clear both.

    Backward compatible signature: ``username`` is optional. Callers
    that don't pass it skip the per-username bucket (used by tests
    and existing callers during the migration window).
    """
    now = time()
    retry_after = None

    # --- per-IP ---
    _trim_attempts(_login_attempts_by_ip, ip_address, _LOGIN_RATE_WINDOW_IP)
    if len(_login_attempts_by_ip[ip_address]) >= _LOGIN_RATE_LIMIT_IP:
        oldest = min(_login_attempts_by_ip[ip_address])
        retry_after = int(oldest + _LOGIN_RATE_WINDOW_IP - now) + 1
        return False, retry_after

    # --- per-username ---
    if username:
        ukey = username.strip().lower()
        if ukey:
            _trim_attempts(_login_attempts_by_user, ukey, _LOGIN_RATE_WINDOW_USER)
            if len(_login_attempts_by_user[ukey]) >= _LOGIN_RATE_LIMIT_USER:
                oldest = min(_login_attempts_by_user[ukey])
                retry_after = int(oldest + _LOGIN_RATE_WINDOW_USER - now) + 1
                return False, retry_after

    return True, None


def _record_login_attempt(ip_address, username=None):
    """Record a failed login attempt against both buckets."""
    now = time()
    _login_attempts_by_ip[ip_address].append(now)
    if username:
        ukey = username.strip().lower()
        if ukey:
            _login_attempts_by_user[ukey].append(now)


def _sanitize_domain(domain, cert_base_dir):
    """Validate domain name and prevent path traversal."""
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
    """Register all web interface routes"""
    auth_manager = managers['auth']
    settings_manager = managers['settings']
    certificate_manager = managers['certificates']
    file_ops = managers['file_ops']
    cache_manager = managers['cache']
    dns_manager = managers['dns']

    # Import constant here to avoid top-level E402
    from ..core.constants import CERTIFICATE_FILES

    def require_web_auth(f):
        """Decorator for web pages: redirect to /login if not authenticated"""
        @wraps(f)
        def decorated(*args, **kwargs):
            if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
                return f(*args, **kwargs)
            session_id = request.cookies.get('certmate_session')
            if session_id:
                user_info = auth_manager.validate_session(session_id)
                if user_info:
                    request.current_user = user_info
                    return f(*args, **kwargs)
            # Preserve the originally-requested path as ?next=… so a
            # successful login can bounce the user back where they
            # were trying to go (6.2 fix).
            return redirect(url_for('login_page', next=request.path))
        return decorated

    # Expose the authenticated user to every Jinja template so base.html
    # can render the logout button server-side instead of via a 500ms-
    # delayed JS fetch that produces a visible layout shift. Templates
    # see this as `current_user` (truthy dict / falsy None).
    @app.context_processor
    def _inject_current_user():
        return {
            'current_user': getattr(request, 'current_user', None),
        }

    from .ui_routes import register_ui_routes
    from .misc_routes import register_misc_routes
    from .auth_routes import register_auth_routes
    from .cert_routes import register_cert_routes
    from .settings_routes import register_settings_routes
    from .backup_cache_routes import register_backup_cache_routes

    register_ui_routes(app, managers, require_web_auth, auth_manager)
    register_misc_routes(app, managers, require_web_auth, auth_manager)
    register_auth_routes(app, managers, require_web_auth, auth_manager,
                         _check_login_rate_limit, _record_login_attempt)
    register_cert_routes(app, managers, require_web_auth, auth_manager,
                         certificate_manager, _sanitize_domain, file_ops,
                         settings_manager, dns_manager, CERTIFICATE_FILES)
    register_settings_routes(app, managers, require_web_auth, auth_manager,
                             settings_manager, dns_manager)
    register_backup_cache_routes(app, managers, require_web_auth, auth_manager,
                                 file_ops, settings_manager, cache_manager)
