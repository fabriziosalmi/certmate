import logging
from flask import render_template, request, jsonify, redirect, url_for


logger = logging.getLogger(__name__)


def register_auth_routes(app, managers, require_web_auth, auth_manager,
                         _check_login_rate_limit, _record_login_attempt):
    """Register authentication routes"""
    audit_logger = managers.get('audit')

    @app.route('/login', methods=['GET'])
    def login_page():
        """Login page"""
        if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
            return redirect(url_for('index'))
        return render_template('login.html')

    @app.route('/api/auth/login', methods=['POST'])
    def api_login():
        """Login endpoint"""
        try:
            client_ip = request.remote_addr or 'unknown'
            allowed, retry_after = _check_login_rate_limit(client_ip)
            if not allowed:
                response = jsonify({
                    'error': 'Too many attempts. Please try again later.',
                    'retry_after': retry_after
                })
                response.headers['Retry-After'] = str(retry_after)
                return response, 429

            data = request.json
            username = data.get('username', '').strip()
            password = data.get('password', '')

            if not username or not password:
                return jsonify({'error': 'Credentials required'}), 400

            if not auth_manager.is_local_auth_enabled():
                return jsonify({'error': 'Local auth disabled'}), 403

            _record_login_attempt(client_ip)
            user_info = auth_manager.authenticate_user(username, password)

            if not user_info:
                return jsonify({'error': 'Invalid credentials'}), 401

            session_id = auth_manager.create_session(username)
            response = jsonify({'message': 'Login successful', 'user': user_info})
            response.set_cookie(
                'certmate_session', session_id, httponly=True,
                secure=request.is_secure, samesite='Strict', path='/',
                max_age=8 * 60 * 60
            )
            return response
        except Exception as e:
            logger.error(f"Login error: {e}")
            return jsonify({'error': 'Login failed'}), 500

    @app.route('/api/auth/logout', methods=['POST'])
    def api_logout():
        """Logout endpoint"""
        session_id = request.cookies.get('certmate_session')
        if session_id:
            auth_manager.invalidate_session(session_id)
        response = jsonify({'message': 'Logged out successfully'})
        response.delete_cookie('certmate_session', path='/')
        return response

    @app.route('/api/auth/me', methods=['GET'])
    def api_current_user():
        """Current user info — used by the UI to hide controls for which
        the caller doesn't have the required role.

        Mirrors the bypass logic in AuthManager.require_auth: when local
        auth is disabled or no users have been created yet, every caller
        is treated as admin so the dashboard can render. Otherwise
        validates the session cookie. Returns 200 in the bypass case so
        clients don't need to special-case 401 during onboarding.
        """
        try:
            if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
                return jsonify({
                    'user': {'username': 'setup_user', 'role': 'admin'},
                    'auth_mode': 'bypass',
                })
        except Exception as e:
            logger.error(f"Failed to evaluate auth bypass: {e}")
            # Fall through and require a session.

        session_id = request.cookies.get('certmate_session')
        if session_id:
            user_info = auth_manager.validate_session(session_id)
            if user_info:
                return jsonify({'user': user_info, 'auth_mode': 'session'})
        return jsonify({'user': None}), 401

    @app.route('/api/auth/config', methods=['GET'])
    @auth_manager.require_role('viewer')
    def api_auth_config_get():
        """Read auth configuration. Viewers may read so the UI can render
        the correct affordances."""
        return jsonify({
            'local_auth_enabled': auth_manager.is_local_auth_enabled(),
            'has_users': auth_manager.has_any_users()
        })

    @app.route('/api/auth/config', methods=['POST'])
    @auth_manager.require_role('admin')
    def api_auth_config_post():
        """Mutate auth configuration. Admin-only — defense-in-depth at the
        decorator level so the role check fires before any handler logic
        runs.
        """
        data = request.json or {}
        enable = bool(data.get('local_auth_enabled', False))
        if enable and not auth_manager.has_any_users():
            return jsonify({'error': 'Create admin first'}), 400

        before = auth_manager.is_local_auth_enabled()
        if auth_manager.enable_local_auth(enable):
            if audit_logger and before != enable:
                user = getattr(request, 'current_user', {}) or {}
                audit_logger.log_auth_config_changed(
                    local_auth_enabled_before=before,
                    local_auth_enabled_after=enable,
                    user=user.get('username'),
                    ip_address=request.remote_addr,
                )
            return jsonify({'message': 'Auth config updated'})
        return jsonify({'error': 'Update failed'}), 500
