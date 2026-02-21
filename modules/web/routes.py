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

    # Static file routes — serve images from static/img/ for well-known paths
    _img_dir = os.path.join(app.root_path, 'static', 'img')

    @app.route('/favicon.ico')
    def favicon():
        """Serve favicon"""
        return send_from_directory(_img_dir, 'favicon.ico')

    @app.route('/certmate_logo.png')
    def logo():
        """Serve logo"""
        return send_from_directory(_img_dir, 'certmate_logo.png')

    @app.route('/certmate_logo_256.png')
    def logo_256():
        """Serve logo (256px)"""
        return send_from_directory(_img_dir, 'certmate_logo_256.png')

    @app.route('/apple-touch-icon.png')
    def apple_touch_icon():
        """Serve Apple touch icon"""
        return send_from_directory(_img_dir, 'apple-touch-icon.png')

    @app.route('/redoc/')
    @app.route('/redoc')
    def redoc():
        """Serve ReDoc API documentation UI"""
        # ReDoc uses external CDNs — override CSP for this route only
        html = '''<!DOCTYPE html>
<html><head><title>CertMate API - ReDoc</title>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1">
<link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
<style>body{margin:0;padding:0;}</style></head>
<body><redoc spec-url="/api/swagger.json"></redoc>
<script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body></html>'''
        response = app.make_response((html, 200, {'Content-Type': 'text/html'}))
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.redoc.ly; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data: blob:; "
            "worker-src blob:; "
            "connect-src 'self'; "
            "frame-ancestors 'self'; "
            "form-action 'self'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )
        return response

    # ACME HTTP-01 challenge endpoint (no auth — ACME servers must reach it)
    @app.route('/.well-known/acme-challenge/<token>')
    def acme_challenge(token):
        """Serve HTTP-01 ACME challenge response files."""
        if not re.match(r'^[A-Za-z0-9_-]+$', token):
            return 'Invalid token', 400
        challenge_dir = Path(app.config.get('DATA_DIR', 'data')) / 'acme-challenges' / '.well-known' / 'acme-challenge'
        challenge_file = challenge_dir / token
        # Prevent path traversal
        try:
            challenge_file = challenge_file.resolve()
            if not str(challenge_file).startswith(str(challenge_dir.resolve())):
                return 'Invalid token', 400
        except (OSError, ValueError):
            return 'Invalid token', 400
        if not challenge_file.exists():
            return 'Not found', 404
        return challenge_file.read_text(), 200, {'Content-Type': 'text/plain'}

    # Main web interface routes
    @app.route('/')
    @require_web_auth
    def index():
        """Main dashboard page"""
        try:
            settings = settings_manager.load_settings()
            certificates = []

            # Get all domains from settings
            domains_from_settings = settings.get('domains', [])

            # Also check for certificates that exist on disk but might not be in settings
            cert_dirs = []
            cert_dir = certificate_manager.cert_dir
            if cert_dir.exists():
                cert_dirs = [d for d in cert_dir.iterdir() if d.is_dir()]

            # Create a set of all domains to check (from settings and disk)
            all_domains = set()

            # Add domains from settings
            for domain_config in domains_from_settings:
                if isinstance(domain_config, str):
                    domain_name = domain_config
                elif isinstance(domain_config, dict):
                    domain_name = domain_config.get('domain')
                else:
                    continue
                if domain_name:
                    all_domains.add(domain_name)

            # Add domains from disk (for backward compatibility with existing certificates)
            for cert_dir_path in cert_dirs:
                all_domains.add(cert_dir_path.name)

            # Get certificate info for all domains
            for domain_name in all_domains:
                if domain_name:
                    cert_info = certificate_manager.get_certificate_info(domain_name)
                    if cert_info:
                        certificates.append(cert_info)

            return render_template('index.html', certificates=certificates)
        except Exception as e:
            logger.error(f"Failed to load settings for index page: {e}")
            return render_template('index.html', certificates=[])

    @app.route('/settings')
    @require_web_auth
    def settings_page():
        """Settings configuration page"""
        return render_template('settings.html')

    @app.route('/help')
    @require_web_auth
    def help_page():
        """Help and documentation page"""
        return render_template('help.html')

    @app.route('/client-certificates')
    @require_web_auth
    def client_certificates_page():
        """Redirect to unified certificates page with client tab"""
        return redirect('/#client')

    @app.route('/activity')
    @require_web_auth
    def activity_page():
        """Activity timeline page"""
        return render_template('activity.html')

    @app.route('/api/activity')
    @auth_manager.require_auth
    def activity_api():
        """Get recent audit log entries."""
        audit_logger = managers.get('audit')
        if not audit_logger:
            return jsonify({'entries': []})
        limit = request.args.get('limit', 50, type=int)
        limit = min(limit, 500)
        entries = audit_logger.get_recent_entries(limit=limit)
        # Return newest first
        entries.reverse()
        return jsonify({'entries': entries})

    @app.route('/api/notifications/config', methods=['GET', 'POST'])
    @auth_manager.require_auth
    def notifications_config():
        """Get or update notification configuration."""
        settings = settings_manager.load_settings()

        if request.method == 'GET':
            notif_config = settings.get('notifications', {})
            # Strip passwords from response
            safe = json.loads(json.dumps(notif_config))
            smtp = safe.get('channels', {}).get('smtp', {})
            if smtp.get('password'):
                smtp['password'] = '••••••••'
            for wh in safe.get('channels', {}).get('webhooks', []):
                if wh.get('secret'):
                    wh['secret'] = '••••••••'
            return jsonify(safe)

        # POST — update notification config
        data = request.get_json(silent=True) or {}
        settings['notifications'] = data
        settings_manager.save_settings(settings)
        return jsonify({'status': 'saved'})

    @app.route('/api/notifications/test', methods=['POST'])
    @auth_manager.require_auth
    def notifications_test():
        """Test a notification channel."""
        notifier = managers.get('notifier')
        if not notifier:
            return jsonify({'error': 'Notifier not available'}), 500
        data = request.get_json(silent=True) or {}
        channel_type = data.get('channel_type', '')
        config = data.get('config', {})
        result = notifier.test_channel(channel_type, config)
        return jsonify(result)

    @app.route('/api/events/stream')
    @auth_manager.require_auth
    def event_stream():
        """SSE endpoint for real-time updates."""
        event_bus = managers.get('events')
        if not event_bus:
            return jsonify({'error': 'Event bus not available'}), 500
        q = event_bus.subscribe()
        return Response(
            stream_with_context(event_bus.stream(q)),
            mimetype='text/event-stream',
            headers={
                'Cache-Control': 'no-cache',
                'X-Accel-Buffering': 'no',
                'Connection': 'keep-alive'
            }
        )

    # Health check for Docker
    @app.route('/health')
    def health_check():
        """Simple health check endpoint"""
        try:
            from app import __version__
            settings = settings_manager.load_settings()
            return jsonify({
                'status': 'healthy',
                'version': __version__,
                'timestamp': str(datetime.now())
            })
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return jsonify({'status': 'unhealthy'}), 500

    # Prometheus metrics endpoint (requires auth to prevent info disclosure)
    @app.route('/metrics')
    @auth_manager.require_auth
    def metrics():
        """Prometheus metrics endpoint"""
        try:
            return generate_metrics_response()
        except Exception as e:
            logger.error(f"Error generating metrics: {e}")
            return "# Error generating metrics\n", 500

    # Authentication endpoints for local login
    @app.route('/login', methods=['GET'])
    def login_page():
        """Login page"""
        # Check if local auth is enabled and has users
        if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
            # Redirect to main page if local auth not set up
            return redirect(url_for('index'))
        return render_template('login.html')
    
    @app.route('/api/auth/login', methods=['POST'])
    def api_login():
        """Login endpoint for local authentication"""
        try:
            # Rate limiting - prevent brute force attacks
            client_ip = request.remote_addr or 'unknown'
            allowed, retry_after = _check_login_rate_limit(client_ip)
            if not allowed:
                logger.warning(f"Login rate limit exceeded for IP: {client_ip}")
                response = jsonify({
                    'error': 'Too many login attempts. Please try again later.',
                    'retry_after': retry_after
                })
                response.headers['Retry-After'] = str(retry_after)
                return response, 429
            
            data = request.json
            username = data.get('username', '').strip()
            password = data.get('password', '')
            
            if not username or not password:
                return jsonify({'error': 'Username and password are required'}), 400
            
            # Check if local auth is enabled
            if not auth_manager.is_local_auth_enabled():
                return jsonify({'error': 'Local authentication is not enabled'}), 403
            
            # Record attempt before authentication
            _record_login_attempt(client_ip)
            
            # Authenticate user
            user_info = auth_manager.authenticate_user(username, password)
            
            if not user_info:
                return jsonify({'error': 'Invalid username or password'}), 401
            
            # Create session
            session_id = auth_manager.create_session(username)
            
            response = jsonify({
                'message': 'Login successful',
                'user': user_info
            })
            
            # Set session cookie with security flags
            # secure=True requires HTTPS (disabled for local dev, enable in production)
            # samesite='Strict' prevents CSRF attacks
            response.set_cookie(
                'certmate_session',
                session_id,
                httponly=True,
                secure=request.is_secure,  # Auto-enable on HTTPS
                samesite='Strict',
                path='/',
                max_age=8 * 60 * 60  # 8 hours
            )
            
            return response
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'error': 'Login failed'}), 500
    
    @app.route('/api/auth/logout', methods=['POST'])
    def api_logout():
        """Logout endpoint"""
        try:
            session_id = request.cookies.get('certmate_session')
            if session_id:
                auth_manager.invalidate_session(session_id)
            
            response = jsonify({'message': 'Logged out successfully'})
            response.delete_cookie(
                'certmate_session',
                path='/',
                secure=request.is_secure,
                httponly=True,
                samesite='Strict'
            )
            return response
        except Exception as e:
            logger.error(f"Logout error: {e}")
            return jsonify({'error': 'Logout failed'}), 500
    
    @app.route('/api/auth/me', methods=['GET'])
    def api_current_user():
        """Get current user info"""
        try:
            session_id = request.cookies.get('certmate_session')
            if session_id:
                user_info = auth_manager.validate_session(session_id)
                if user_info:
                    return jsonify({'user': user_info})
            
            return jsonify({'user': None}), 401
        except Exception as e:
            logger.error(f"Get current user error: {e}")
            return jsonify({'error': 'Failed to get user info'}), 500
    
    @app.route('/api/auth/token', methods=['GET'])
    @auth_manager.require_auth
    def api_get_token():
        """Get API bearer token (for settings page reveal button)"""
        try:
            settings = settings_manager.load_settings()
            token = settings.get('api_bearer_token', '')
            return jsonify({'token': token})
        except Exception as e:
            logger.error(f"Get token error: {e}")
            return jsonify({'error': 'Failed to get token'}), 500

    # User management endpoints (admin only)
    @app.route('/api/users', methods=['GET', 'POST'])
    @auth_manager.require_admin
    def api_users():
        """List or create users"""
        if request.method == 'GET':
            try:
                users = auth_manager.list_users()
                return jsonify({'users': users})
            except Exception as e:
                logger.error(f"Error listing users: {e}")
                return jsonify({'error': 'Failed to list users'}), 500
        
        elif request.method == 'POST':
            try:
                data = request.json
                username = data.get('username', '').strip()
                password = data.get('password', '')
                role = data.get('role', 'user')
                email = data.get('email', '').strip() or None
                
                if not username or not password:
                    return jsonify({'error': 'Username and password are required'}), 400
                
                if role not in ['admin', 'user']:
                    return jsonify({'error': 'Role must be admin or user'}), 400
                
                success, message = auth_manager.create_user(username, password, role, email)
                
                if success:
                    return jsonify({'message': message})
                else:
                    return jsonify({'error': message}), 400
            except Exception as e:
                logger.error(f"Error creating user: {e}")
                return jsonify({'error': 'Failed to create user'}), 500
    
    @app.route('/api/users/<string:username>', methods=['GET', 'PUT', 'DELETE'])
    @auth_manager.require_admin
    def api_user(username):
        """Get, update, or delete a specific user"""
        if request.method == 'GET':
            try:
                users = auth_manager.list_users()
                if username not in users:
                    return jsonify({'error': 'User not found'}), 404
                return jsonify({'user': {username: users[username]}})
            except Exception as e:
                logger.error(f"Error getting user: {e}")
                return jsonify({'error': 'Failed to get user'}), 500
        
        elif request.method == 'PUT':
            try:
                data = request.json
                password = data.get('password')
                role = data.get('role')
                email = data.get('email')
                enabled = data.get('enabled')
                
                if role and role not in ['admin', 'user']:
                    return jsonify({'error': 'Role must be admin or user'}), 400
                
                success, message = auth_manager.update_user(
                    username, password=password, role=role, email=email, enabled=enabled
                )
                
                if success:
                    return jsonify({'message': message})
                else:
                    return jsonify({'error': message}), 400
            except Exception as e:
                logger.error(f"Error updating user: {e}")
                return jsonify({'error': 'Failed to update user'}), 500
        
        elif request.method == 'DELETE':
            try:
                success, message = auth_manager.delete_user(username)
                
                if success:
                    return jsonify({'message': message})
                else:
                    return jsonify({'error': message}), 400
            except Exception as e:
                logger.error(f"Error deleting user: {e}")
                return jsonify({'error': 'Failed to delete user'}), 500
    
    @app.route('/api/auth/config', methods=['GET', 'POST'])
    @auth_manager.require_auth
    def api_auth_config():
        """Get or update authentication configuration"""
        if request.method == 'GET':
            try:
                return jsonify({
                    'local_auth_enabled': auth_manager.is_local_auth_enabled(),
                    'has_users': auth_manager.has_any_users()
                })
            except Exception as e:
                logger.error(f"Error getting auth config: {e}")
                return jsonify({'error': 'Failed to get auth config'}), 500
        
        elif request.method == 'POST':
            try:
                data = request.json
                enable = data.get('local_auth_enabled', False)
                
                # Require at least one admin user before enabling local auth
                if enable and not auth_manager.has_any_users():
                    return jsonify({'error': 'Create at least one admin user before enabling local auth'}), 400
                
                if auth_manager.enable_local_auth(enable):
                    return jsonify({'message': f'Local authentication {"enabled" if enable else "disabled"}'})
                else:
                    return jsonify({'error': 'Failed to update auth config'}), 500
            except Exception as e:
                logger.error(f"Error updating auth config: {e}")
                return jsonify({'error': 'Failed to update auth config'}), 500

    # Special download endpoint for easy automation
    @app.route('/<string:domain>/tls')
    @auth_manager.require_auth
    def download_tls(domain):
        """Download all TLS certificate files as a ZIP archive for automation"""
        try:
            cert_path, err = _sanitize_domain(domain, file_ops.cert_dir)
            if err:
                return jsonify({'error': err}), 400

            # Verify at least one certificate file exists
            existing_files = [f for f in CERTIFICATE_FILES if (cert_path / f).exists()]
            if not existing_files:
                return jsonify({'error': f'Certificate not found for domain: {domain}'}), 404

            # Build ZIP file with all certificate components
            import tempfile
            tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
            tmp_path = tmp.name
            tmp.close()

            with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for cert_file in CERTIFICATE_FILES:
                    file_path = cert_path / cert_file
                    if file_path.exists():
                        zipf.write(file_path, cert_file)

            return send_file(
                tmp_path,
                as_attachment=True,
                download_name=f'{domain}_certificates.zip',
                mimetype='application/zip'
            )

        except Exception as e:
            logger.error(f"Error downloading TLS certificate for {domain}: {e}")
            return jsonify({'error': 'Failed to download certificate'}), 500

    @app.route('/<string:domain>/tls/<string:component>')
    @auth_manager.require_auth
    def download_tls_component(domain, component):
        """Download individual TLS certificate component (cert, key, chain, fullchain)"""
        try:
            # Map component names to filenames
            component_map = {
                'cert': 'cert.pem',
                'key': 'privkey.pem',
                'chain': 'chain.pem',
                'fullchain': 'fullchain.pem',
            }

            filename = component_map.get(component)
            if not filename:
                return jsonify({
                    'error': f'Unknown certificate component: {component}',
                    'valid_components': list(component_map.keys())
                }), 400

            cert_path, err = _sanitize_domain(domain, file_ops.cert_dir)
            if err:
                return jsonify({'error': err}), 400

            file_path = cert_path / filename
            if not file_path.exists():
                return jsonify({'error': f'{component} not found for domain: {domain}'}), 404

            return send_file(
                file_path,
                as_attachment=True,
                download_name=f'{domain}_{filename}',
                mimetype='application/x-pem-file'
            )

        except Exception as e:
            logger.error(f"Error downloading TLS {component} for {domain}: {e}")
            return jsonify({'error': f'Failed to download {component}'}), 500

    # Web-specific settings endpoints (no auth required for initial setup)
    @app.route('/api/web/settings', methods=['GET', 'POST'])
    def web_settings():
        """Web interface settings endpoint"""
        if request.method == 'GET':
            try:
                settings = settings_manager.load_settings()
                
                # Check if setup is completed
                setup_completed = settings.get('setup_completed', False)
                
                # For initial setup, return minimal safe settings
                if not setup_completed:
                    return jsonify({
                        'setup_completed': False,
                        'email': settings.get('email', ''),
                        'dns_provider': settings.get('dns_provider', 'cloudflare'),
                        'auto_renew': settings.get('auto_renew', True),
                        'domains': []
                    })
                
                # For completed setup, require auth (session cookie or Bearer token)
                # Allow bypass when auth is disabled (setup mode)
                authenticated = False
                if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
                    authenticated = True
                if not authenticated:
                    session_id = request.cookies.get('certmate_session')
                    if session_id and auth_manager.validate_session(session_id):
                        authenticated = True
                if not authenticated:
                    auth_header = request.headers.get('Authorization', '')
                    if auth_header.startswith('Bearer ') and auth_manager.validate_api_token(auth_header[7:]):
                        authenticated = True
                if not authenticated:
                    return jsonify({'error': 'Authentication required'}), 401
                
                # Return full settings (with sensitive data fully masked)
                safe_settings = dict(settings)
                if 'api_bearer_token' in safe_settings:
                    safe_settings['api_bearer_token'] = '********'
                
                return jsonify(safe_settings)
                
            except Exception as e:
                logger.error(f"Error getting web settings: {e}")
                return jsonify({'error': 'Failed to load settings'}), 500
        
        elif request.method == 'POST':
            try:
                new_settings = request.json
                if not new_settings:
                    return jsonify({'error': 'No settings provided'}), 400
                
                current_settings = settings_manager.load_settings()
                setup_completed = current_settings.get('setup_completed', False)

                if setup_completed:
                    # Require auth for updates after setup
                    # Allow bypass when auth is disabled (setup mode)
                    authenticated = False
                    if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
                        authenticated = True
                    if not authenticated:
                        session_id = request.cookies.get('certmate_session')
                        if session_id and auth_manager.validate_session(session_id):
                            authenticated = True
                    if not authenticated:
                        auth_header = request.headers.get('Authorization', '')
                        if auth_header.startswith('Bearer ') and auth_manager.validate_api_token(auth_header[7:]):
                            authenticated = True
                    if not authenticated:
                        return jsonify({'error': 'Authentication required'}), 401
                else:
                    # Initial setup: allow if auth is disabled (setup mode),
                    # or from localhost, or with valid token
                    if not (not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users()):
                        client_ip = request.remote_addr or ''
                        auth_header = request.headers.get('Authorization', '')
                        has_valid_token = False
                        if auth_header.startswith('Bearer '):
                            has_valid_token = auth_manager.validate_api_token(auth_header[7:])
                        if not _is_localhost(client_ip) and not has_valid_token:
                            logger.warning(f"Setup attempt from non-local IP: {client_ip}")
                            return jsonify({'error': 'Initial setup only allowed from localhost'}), 403
                
                # Merge with existing settings
                merged_settings = {**current_settings, **new_settings}
                
                # Mark setup as completed if not already
                if not setup_completed and all(key in merged_settings and merged_settings[key] 
                                             for key in ['email', 'dns_provider']):
                    merged_settings['setup_completed'] = True
                
                # Save settings
                success = settings_manager.save_settings(merged_settings, "web_update")
                
                if success:
                    return jsonify({'message': 'Settings updated successfully'})
                else:
                    return jsonify({'error': 'Failed to save settings'}), 500
                    
            except Exception as e:
                logger.error(f"Error updating web settings: {e}")
                return jsonify({'error': 'Failed to update settings'}), 500

    # DNS Provider Account Management endpoints for web interface
    @app.route('/api/dns/<string:provider>/accounts', methods=['GET', 'POST'])
    @auth_manager.require_auth
    def web_dns_provider_accounts(provider):
        """Manage DNS provider accounts"""
        if request.method == 'GET':
            try:
                accounts = dns_manager.list_dns_provider_accounts(provider)
                return jsonify(accounts)
            except Exception as e:
                logger.error(f"Error listing DNS accounts for {provider}: {e}")
                return jsonify({'error': 'Failed to list DNS accounts'}), 500
        
        elif request.method == 'POST':
            try:
                data = request.json
                account_id = data.get('account_id')
                account_config = data.get('config', {})
                
                if not account_id:
                    return jsonify({'error': 'Account ID is required'}), 400
                
                success = dns_manager.create_dns_account(provider, account_id, account_config)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} created/updated successfully'})
                else:
                    return jsonify({'error': 'Failed to create/update DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error creating DNS account for {provider}: {e}")
                return jsonify({'error': 'Failed to create DNS account'}), 500

    @app.route('/api/dns/<string:provider>/accounts/<string:account_id>', methods=['GET', 'PUT', 'DELETE'])
    @auth_manager.require_auth
    def web_dns_provider_account(provider, account_id):
        """Manage specific DNS provider account"""
        # Validate account_id to prevent path traversal
        if '..' in account_id or '/' in account_id or '\\' in account_id or '\x00' in account_id:
            return jsonify({'error': 'Invalid account ID'}), 400
        if '..' in provider or '/' in provider or '\\' in provider or '\x00' in provider:
            return jsonify({'error': 'Invalid provider'}), 400
        if request.method == 'GET':
            try:
                config, _ = dns_manager.get_dns_provider_account_config(provider, account_id)
                if config:
                    return jsonify(config)
                else:
                    return jsonify({'error': 'Account not found'}), 404
            except Exception as e:
                logger.error(f"Error getting DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to get DNS account'}), 500
        
        elif request.method == 'PUT':
            try:
                account_config = request.json
                if not account_config:
                    return jsonify({'error': 'Account configuration is required'}), 400
                
                success = dns_manager.create_dns_account(provider, account_id, account_config)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} updated successfully'})
                else:
                    return jsonify({'error': 'Failed to update DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error updating DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to update DNS account'}), 500
        
        elif request.method == 'DELETE':
            try:
                success = dns_manager.delete_dns_account(provider, account_id)
                
                if success:
                    return jsonify({'message': f'DNS account {account_id} deleted successfully'})
                else:
                    return jsonify({'error': 'Failed to delete DNS account'}), 500
                    
            except Exception as e:
                logger.error(f"Error deleting DNS account {account_id} for {provider}: {e}")
                return jsonify({'error': 'Failed to delete DNS account'}), 500

    # Web Certificate API Routes (for form-based frontend)
    @app.route('/api/web/certificates')
    @auth_manager.require_auth
    def web_list_certificates():
        """Web interface endpoint to list certificates"""
        try:
            settings = settings_manager.load_settings()
            certificates = []
            
            # Get all domains from settings
            domains_from_settings = settings.get('domains', [])
            
            # Also check for certificates that exist on disk but might not be in settings
            cert_dirs = []
            cert_dir = certificate_manager.cert_dir
            if cert_dir.exists():
                cert_dirs = [d for d in cert_dir.iterdir() if d.is_dir()]
            
            # Create a set of all domains to check (from settings and disk)
            all_domains = set()
            
            # Add domains from settings
            for domain_config in domains_from_settings:
                if isinstance(domain_config, str):
                    domain_name = domain_config
                elif isinstance(domain_config, dict):
                    domain_name = domain_config.get('domain')
                else:
                    continue
                if domain_name:
                    all_domains.add(domain_name)
            
            # Add domains from disk (for backward compatibility with existing certificates)
            for cert_dir_path in cert_dirs:
                all_domains.add(cert_dir_path.name)
            
            # Get certificate info for all domains
            for domain_name in all_domains:
                if domain_name:
                    cert_info = certificate_manager.get_certificate_info(domain_name)
                    if cert_info:
                        certificates.append(cert_info)
            
            return jsonify(certificates)
        except Exception as e:
            logger.error(f"Error fetching certificates via web: {e}")
            # Return empty array on error to ensure frontend compatibility
            return jsonify([])

    @app.route('/api/web/certificates/create', methods=['POST'])
    @auth_manager.require_auth
    def web_create_certificate():
        """Web interface endpoint to create certificate"""
        try:
            # Handle both form data and JSON
            if request.is_json:
                data = request.json
            else:
                data = request.form.to_dict()
            
            domain = data.get('domain', '').strip()
            san_domains_raw = data.get('san_domains', '')  # Can be comma-separated string or list
            dns_provider = data.get('dns_provider')  # Optional, uses default from settings
            account_id = data.get('account_id')      # Optional, uses default account
            challenge_type = data.get('challenge_type')  # Optional: 'dns-01' or 'http-01'
            
            # Parse SAN domains (support both comma-separated string and list)
            san_domains = []
            if san_domains_raw:
                if isinstance(san_domains_raw, list):
                    san_domains = [d.strip() for d in san_domains_raw if d.strip()]
                elif isinstance(san_domains_raw, str):
                    san_domains = [d.strip() for d in san_domains_raw.split(',') if d.strip()]
            
            # Validate domain
            if not domain:
                return jsonify({
                    'error': 'Domain is required',
                    'hint': 'Please enter a valid domain name (e.g., example.com or *.example.com for wildcard)'
                }), 400
            
            # Basic domain validation
            if ' ' in domain:
                return jsonify({
                    'error': 'Invalid domain format',
                    'hint': 'Enter the primary domain name only. Use the SAN domains field for additional domains.'
                }), 400
            
            # Check for common domain format issues
            if domain.startswith('http://') or domain.startswith('https://'):
                return jsonify({
                    'error': 'Invalid domain format',
                    'hint': 'Enter domain name only (e.g., example.com), not the full URL.'
                }), 400
            
            settings = settings_manager.load_settings()
            email = settings.get('email')
            
            if not email:
                return jsonify({
                    'error': 'Email not configured',
                    'hint': 'Go to Settings and configure your email address first. This is required by certificate authorities.'
                }), 400
            
            # Resolve challenge type from settings if not provided
            if not challenge_type:
                challenge_type = settings.get('challenge_type', 'dns-01')

            # DNS provider validation (skip for HTTP-01)
            if challenge_type != 'http-01':
                # Determine DNS provider
                if not dns_provider:
                    dns_provider = settings_manager.get_domain_dns_provider(domain, settings)

                if not dns_provider:
                    return jsonify({
                        'error': 'No DNS provider configured',
                        'hint': 'Go to Settings and select a DNS provider. Configure the provider credentials to enable certificate creation.'
                    }), 400

                # Validate DNS provider configuration exists
                dns_providers_config = settings.get('dns_providers', {})
                provider_config = dns_providers_config.get(dns_provider, {})

                # Check if account_id is provided, validate it exists
                if account_id:
                    config, _ = dns_manager.get_dns_provider_account_config(dns_provider, account_id)
                    if not config:
                        available_accounts = list(dns_manager.list_dns_provider_accounts(dns_provider).keys())
                        hint = f"Available accounts: {', '.join(available_accounts)}" if available_accounts else "Configure a DNS account in Settings first."
                        return jsonify({
                            'error': f'DNS account "{account_id}" not found for provider {dns_provider}',
                            'hint': hint
                        }), 400
                else:
                    # Check if default account is configured
                    config, _ = dns_manager.get_dns_provider_account_config(dns_provider, None)
                    if not config:
                        # Check if there are any accounts for this provider
                        accounts = dns_manager.list_dns_provider_accounts(dns_provider)
                        if not accounts:
                            return jsonify({
                                'error': f'No {dns_provider} credentials configured',
                                'hint': f'Go to Settings → DNS Providers → {dns_provider.title()} and add your API credentials.'
                            }), 400
                        else:
                            return jsonify({
                                'error': f'No default account set for {dns_provider}',
                                'hint': f'Select an account or configure a default account in Settings for {dns_provider}.'
                            }), 400
            
            # All validations passed, create certificate in background (bounded pool)
            def create_cert_async():
                try:
                    certificate_manager.create_certificate(
                        domain, email, dns_provider,
                        account_id=account_id,
                        san_domains=san_domains if san_domains else None,
                        challenge_type=challenge_type
                    )
                    domains_info = f"{domain}" + (f" (+ {len(san_domains)} SANs)" if san_domains else "")
                    logger.info(f"Background certificate creation completed for {domains_info}")
                except Exception as e:
                    logger.error(f"Background certificate creation failed for {domain}: {e}")
                    evt = managers.get('events')
                    if evt:
                        evt.publish('certificate_failed', {'domain': domain, 'error': str(e)})

            _cert_executor.submit(create_cert_async)
            
            # Build response message
            if san_domains:
                msg = f'Certificate creation started for {domain} with {len(san_domains)} additional SAN(s)'
            else:
                msg = f'Certificate creation started for {domain}'
            
            # Publish SSE event
            event_bus = managers.get('events')
            if event_bus:
                event_bus.publish('certificate_created', {'domain': domain, 'san_domains': san_domains})

            return jsonify({
                'success': True,
                'message': msg,
                'domain': domain,
                'san_domains': san_domains,
                'dns_provider': dns_provider,
                'account_id': account_id
            })
            
        except Exception as e:
            logger.error(f"Certificate creation failed via web: {str(e)}")
            return jsonify({'error': 'Certificate creation failed'}), 500

    @app.route('/api/web/certificates/<string:domain>/download')
    @auth_manager.require_auth
    def web_download_certificate(domain):
        """Web interface endpoint to download certificate as ZIP file"""
        try:
            cert_dir, err = _sanitize_domain(domain, file_ops.cert_dir)
            if err:
                return jsonify({'error': err}), 400
            if not cert_dir.exists():
                return jsonify({'error': f'Certificate not found for domain: {domain}'}), 404

            # Create temporary ZIP file
            with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as tmp_file:
                tmp_path = tmp_file.name
                with zipfile.ZipFile(tmp_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for cert_file in CERTIFICATE_FILES:
                        file_path = cert_dir / cert_file
                        if file_path.exists():
                            zipf.write(file_path, cert_file)

                @after_this_request
                def remove_file(response):
                    try:
                        os.remove(tmp_path)
                    except Exception as e:
                        logger.debug(f"Could not remove temp file {tmp_path}: {e}")
                    return response

                return send_file(
                    tmp_path,
                    as_attachment=True,
                    download_name=f'{domain}_certificates.zip',
                    mimetype='application/zip'
                )
                
        except Exception as e:
            logger.error(f"Error downloading certificate via web: {e}")
            return jsonify({'error': 'Failed to download certificate'}), 500

    @app.route('/api/web/certificates/<string:domain>/renew', methods=['POST'])
    @auth_manager.require_auth
    def web_renew_certificate(domain):
        """Web interface endpoint to renew certificate"""
        try:
            settings = settings_manager.load_settings()
            
            # Check if domain exists in settings
            domain_exists = False
            for domain_config in settings.get('domains', []):
                if isinstance(domain_config, str) and domain_config == domain:
                    domain_exists = True
                    break
                elif isinstance(domain_config, dict) and domain_config.get('domain') == domain:
                    domain_exists = True
                    break
            
            if not domain_exists:
                return jsonify({'error': f'Domain {domain} not found in settings'}), 404
            
            # Renew certificate in background
            def renew_cert_async():
                try:
                    certificate_manager.renew_certificate(domain)
                    logger.info(f"Background certificate renewal completed for {domain}")
                except Exception as e:
                    logger.error(f"Background certificate renewal failed for {domain}: {e}")
                    evt = managers.get('events')
                    if evt:
                        evt.publish('certificate_failed', {'domain': domain, 'error': str(e)})

            _cert_executor.submit(renew_cert_async)

            event_bus = managers.get('events')
            if event_bus:
                event_bus.publish('certificate_renewed', {'domain': domain})

            return jsonify({'success': True, 'message': f'Certificate renewal started for {domain}'})
            
        except Exception as e:
            logger.error(f"Certificate renewal failed via web: {str(e)}")
            return jsonify({'error': 'Certificate renewal failed'}), 500

    # Backup management endpoints
    @app.route('/api/web/backups')
    @auth_manager.require_auth
    def web_list_backups():
        """Web interface endpoint to list backups"""
        try:
            backups = file_ops.list_backups()
            return jsonify(backups)
        except Exception as e:
            logger.error(f"Error listing backups via web: {e}")
            return jsonify({'error': 'Failed to list backups'}), 500

    @app.route('/api/web/backups/create', methods=['POST'])
    @auth_manager.require_auth
    def web_create_backup():
        """Web interface endpoint to create backup"""
        try:
            data = request.json or {}
            backup_type = data.get('type', 'unified')
            reason = data.get('reason', 'manual')
            
            created_backups = []
            
            # Only create unified backups
            settings = settings_manager.load_settings()
            filename = file_ops.create_unified_backup(settings, reason)
            if filename:
                created_backups.append({'type': 'unified', 'filename': filename})
            
            if created_backups:
                return jsonify({
                    'success': True,
                    'message': 'Backup created successfully',
                    'backups': created_backups
                })
            else:
                return jsonify({'error': 'Failed to create backup'}), 500
                
        except Exception as e:
            logger.error(f"Error creating backup via web: {e}")
            return jsonify({'error': 'Failed to create backup'}), 500

    @app.route('/api/web/backups/download/<backup_type>/<filename>')
    @auth_manager.require_auth
    def web_download_backup(backup_type, filename):
        """Web interface endpoint to download unified backup"""
        try:
            if backup_type != 'unified':
                return jsonify({'error': 'Only unified backup download is supported'}), 400

            # Validate filename — reject path traversal attempts
            if '..' in filename or '/' in filename or '\\' in filename or '\x00' in filename:
                return jsonify({'error': 'Invalid filename'}), 400
            if not filename.endswith('.zip'):
                return jsonify({'error': 'Invalid backup file format'}), 400

            backup_path = Path(file_ops.backup_dir) / backup_type / filename

            if not backup_path.exists():
                return jsonify({'error': 'Backup file not found'}), 404

            # Security check — resolved path must stay within backup_dir
            if not str(backup_path.resolve()).startswith(str(Path(file_ops.backup_dir).resolve())):
                return jsonify({'error': 'Access denied'}), 403
            
            return send_file(
                backup_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
            
        except Exception as e:
            logger.error(f"Error downloading backup via web: {e}")
            return jsonify({'error': 'Failed to download backup'}), 500

    # Cache management endpoints
    @app.route('/api/web/cache/stats')
    @auth_manager.require_auth
    def web_cache_stats():
        """Web interface endpoint to get cache statistics"""
        try:
            stats = cache_manager.get_cache_stats()
            return jsonify(stats)
        except Exception as e:
            logger.error(f"Error getting cache stats for web: {e}")
            return jsonify({'error': 'Failed to get cache statistics'}), 500

    @app.route('/api/web/cache/clear', methods=['POST'])
    @auth_manager.require_auth
    def web_cache_clear():
        """Web interface endpoint to clear cache"""
        try:
            cleared_count = cache_manager.clear_cache()
            return jsonify({
                'success': True,
                'message': 'Cache cleared successfully',
                'cleared_entries': cleared_count
            })
        except Exception as e:
            logger.error(f"Error clearing cache for web: {e}")
            return jsonify({'error': 'Failed to clear cache'}), 500
