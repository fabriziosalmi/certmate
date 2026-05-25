import os
from flask import request, render_template, redirect, url_for, send_from_directory


def register_ui_routes(app, managers, require_web_auth, auth_manager):
    """Register UI-related routes"""

    @app.route('/')
    def index():
        """Main dashboard UI"""
        if not auth_manager.is_local_auth_enabled() or not auth_manager.has_any_users():
            return render_template('setup.html')

        session_id = request.cookies.get('certmate_session')
        user_info = auth_manager.validate_session(session_id)
        if not user_info:
            return redirect(url_for('login_page', next=request.path))
        # Mirror the require_role decorator behavior so the context
        # processor in routes.py sees the authenticated user and the
        # template can render the logout button server-side.
        request.current_user = user_info

        return render_template('index.html')

    @app.route('/certificates')
    def certificates_page():
        """Certificates list (alias) — unified into the dashboard at `/`.

        `certificates.html` never existed, so this route used to 500. The
        certificate list lives on the dashboard now; redirect there (the
        index route enforces auth), mirroring the client-certificates alias.
        """
        return redirect(url_for('index'))

    @app.route('/settings')
    @auth_manager.require_role('admin')
    def settings_page():
        """Settings page"""
        return render_template('settings.html')

    @app.route('/audit')
    def audit_page():
        """Audit log (alias) — unified into the activity page.

        `audit.html` never existed (route used to 500). The audit/activity
        log lives at `/activity`; redirect there (which enforces auth).
        """
        return redirect(url_for('activity_page'))

    @app.route('/help')
    @auth_manager.require_role('viewer')
    def help_page():
        """Help page"""
        return render_template('help.html')

    @app.route('/activity')
    @auth_manager.require_role('viewer')
    def activity_page():
        """Activity page"""
        return render_template('activity.html')

    @app.route('/redoc')
    @auth_manager.require_role('viewer')
    def redoc_page():
        """Redoc API documentation"""
        return render_template('redoc.html')

    @app.route('/client-certificates')
    @auth_manager.require_role('viewer')
    def client_certificates_page():
        """Client certificates page (alias) - redirects to unified view"""
        return redirect(url_for('index', _anchor='client'))

    # Status Asset Aliases
    @app.route('/favicon.ico')
    def favicon():
        return send_from_directory(os.path.join(app.static_folder, 'img'), 'favicon.ico')

    @app.route('/certmate_logo.png')
    def logo_std():
        return send_from_directory(os.path.join(app.static_folder, 'img'), 'certmate_logo.png')

    @app.route('/certmate_logo_256.png')
    def logo_256():
        return send_from_directory(os.path.join(app.static_folder, 'img'), 'certmate_logo_256.png')

    @app.route('/apple-touch-icon.png')
    def apple_touch_icon():
        return send_from_directory(os.path.join(app.static_folder, 'img'), 'apple-touch-icon.png')
