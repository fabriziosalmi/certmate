import os
from flask import request, render_template, redirect, url_for, send_from_directory

from ..core.client_certificates import default_client_organization


def _check_is_on(managers, name):
    """Whether the inventory check *name* (a manager with get_config) is enabled."""
    manager = managers.get(name)
    return bool(manager is not None and manager.get_config().get('enabled'))


def _pfx_password_set(managers):
    """Whether a PFX password is saved, by the test the client .pfx download applies."""
    settings_manager = managers.get('settings')
    settings = settings_manager.load_settings() if settings_manager else {}
    return bool(((settings or {}).get('pfx_password') or '').strip())


def register_ui_routes(app, managers, require_web_auth, auth_manager):
    """Register UI-related routes"""

    @app.route('/')
    def index():
        """Main dashboard UI"""
        if auth_manager.is_setup_mode():
            return render_template('setup.html', bootstrap_requires_token=False)
        # Bearer-only box: is_setup_mode() is False (the bearer token is
        # enforced on every gated surface), but local auth is not yet
        # provisioned, so a login redirect would dead-end at a 403 "Local auth
        # disabled". Surface the create-admin form instead; its two writes are
        # still bearer-gated (@require_role('admin')), so this grants nothing
        # to an anonymous caller. #397
        if auth_manager.needs_credentialed_bootstrap():
            return render_template('setup.html', bootstrap_requires_token=True)

        session_id = request.cookies.get('certmate_session')
        user_info = auth_manager.validate_session(session_id)
        if not user_info:
            return redirect(url_for('login_page', next=request.path))
        # Mirror the require_role decorator behavior so the context
        # processor in routes.py sees the authenticated user and the
        # template can render the logout button server-side.
        request.current_user = user_info

        # The client-certificate form starts from the deployment's organisation.
        # It was the literal "CertMate" in the markup, and the form always sends
        # the field, so CERTMATE_CLIENT_CERT_DEFAULT_ORGANIZATION could never
        # reach a certificate created from the UI.
        #
        # Whether the client .pfx can be made, read as the download reads it:
        # the button looked available and refused only after the click (P49).
        return render_template(
            'index.html', client_cert_default_organization=default_client_organization(),
            pfx_password_set=_pfx_password_set(managers))

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
        # The backup section offers a complete, restorable backup only when
        # it is encrypted at rest (decided 2026-11-17).
        from ..core.file_operations import backup_passphrase_configured
        return render_template('settings.html',
                               backup_passphrase_configured=backup_passphrase_configured())

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
        """Help page.

        The provider count is passed in rather than written into the template.
        Hardcoded, it said 22 while the app supported 29 — a number nobody
        remembers to bump is a number that is wrong.
        """
        from ..core.dns_providers import DNSManager
        return render_template(
            'help.html',
            provider_count=len(DNSManager.SUPPORTED_PROVIDERS),
        )

    @app.route('/activity')
    @auth_manager.require_role('viewer')
    def activity_page():
        """Activity page"""
        return render_template('activity.html')

    @app.route('/inventory')
    @auth_manager.require_role('viewer')
    def inventory_page():
        """Certificate inventory page — issued + discovered certificates.

        Whether the two domain checks are on is decided here, so a check that
        is off is one line from the first paint: drawn as an empty card, the
        two pushed the certificate list below the fold, and collapsed from
        script they would have moved it after the page appeared.
        """
        return render_template(
            'inventory.html',
            registrations_on=_check_is_on(managers, 'domain_registration'),
            health_on=_check_is_on(managers, 'domain_health'))

    @app.route('/inventory/crypto-report')
    @auth_manager.require_role('viewer')
    def crypto_report_page():
        """Print-friendly cryptographic algorithm readiness report."""
        return render_template('crypto_report.html')

    @app.route('/notifications')
    @auth_manager.require_role('viewer')
    def notifications_page():
        """Notifications page — certificate expiry warnings, with client-side
        snooze. Warnings are derived in the browser from /api/certificates
        (same source as the top-bar bell badge), so no server-side state."""
        return render_template('notifications.html')

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
