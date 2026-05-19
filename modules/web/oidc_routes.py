"""OIDC/SSO HTTP routes.

All five endpoints live under ``/api/auth/oidc/`` so they line up with
the existing local-auth routes in ``modules/web/auth_routes.py``.

Public (no auth required, the UI uses them pre-login):
  - GET  /api/auth/oidc/config    — affordance probe for the login page
  - GET  /api/auth/oidc/login     — kicks off Authorization Code + PKCE
  - GET  /api/auth/oidc/callback  — IdP redirects back here

Admin-only:
  - GET  /api/auth/oidc/settings  — read full config (client_secret masked)
  - POST /api/auth/oidc/settings  — write config (atomic, audited)

The callback mints a regular ``certmate_session`` cookie with the same
attributes as the local login path (see ``auth_routes.py:64-68``), so the
@require_auth / @require_role decorators downstream cannot tell which
source authenticated the user. The new ``source`` kwarg on
``AuthManager.create_session`` is used by ``api_logout`` (and audit) to
distinguish them only where it actually matters.
"""

import logging
from urllib.parse import urlparse

from flask import jsonify, redirect, request, url_for

from modules.core.oidc import SECRET_MASK_SENTINEL

logger = logging.getLogger(__name__)


def _safe_next(value):
    """Return ``value`` only if it is a same-origin absolute path.

    Mirrors the client-side guard in ``templates/login.html`` (safeNextUrl)
    so a successful OIDC login can't be hijacked into an open redirect.
    """
    if not value or not isinstance(value, str):
        return '/'
    # Only allow absolute paths on this host; reject schemes, hostnames,
    # protocol-relative URLs, and backslash trickery.
    if not value.startswith('/') or value.startswith('//') or value.startswith('/\\'):
        return '/'
    parsed = urlparse(value)
    if parsed.netloc or parsed.scheme:
        return '/'
    return value


def register_oidc_routes(app, managers, auth_manager, oidc_manager,
                         _check_login_rate_limit, _record_login_attempt):
    """Register the /api/auth/oidc/* endpoints on ``app``."""
    audit_logger = managers.get('audit')

    @app.route('/api/auth/oidc/config', methods=['GET'])
    def api_oidc_config():
        """Public: lets the login page decide whether to render an SSO
        button. Returns only the affordances; secrets stay private.
        Mirrors the bypass shape of /api/auth/me (auth_routes.py:84).
        """
        try:
            cfg = oidc_manager.get_public_config()
            return jsonify(cfg)
        except Exception as exc:
            logger.error(f"OIDC config probe failed: {exc}")
            # Fail closed: the UI should hide the SSO button on error.
            return jsonify({'enabled': False, 'provider_name': 'SSO',
                            'login_url': '/api/auth/oidc/login',
                            'post_logout_redirect_uri': ''})

    @app.route('/api/auth/oidc/login', methods=['GET'])
    def api_oidc_login():
        """Public, rate-limited: starts the Authorization Code + PKCE
        flow. The next-URL is validated to be a same-origin absolute
        path before we stash it in flask.session.
        """
        client_ip = request.remote_addr or 'unknown'
        allowed, retry_after = _check_login_rate_limit(client_ip)
        if not allowed:
            response = jsonify({
                'error': 'Too many attempts. Please try again later.',
                'retry_after': retry_after,
            })
            response.headers['Retry-After'] = str(retry_after)
            return response, 429

        if not oidc_manager.is_enabled():
            return redirect('/login?error=oidc_disabled')

        next_url = _safe_next(request.args.get('next'))
        try:
            return oidc_manager.start_login(request, next_url)
        except Exception as exc:
            logger.error(f"OIDC login init failed: {exc}")
            _record_login_attempt(client_ip)
            return redirect('/login?error=oidc_init')

    @app.route('/api/auth/oidc/callback', methods=['GET'])
    def api_oidc_callback():
        """Public: the IdP redirects browsers here with ?code=... &state=...

        On success: mints a regular session cookie and redirects to the
        stored ``next`` URL (or /). On failure: bounces to /login with
        an error code the login template's existing showError() will
        render.
        """
        client_ip = request.remote_addr or 'unknown'

        # Don't gate the callback itself behind a rate-limit — Authlib's
        # state check is the real CSRF/replay defense. We do record
        # failed attempts so the next /api/auth/oidc/login from the
        # same IP backs off.
        if not oidc_manager.is_enabled():
            return redirect('/login?error=oidc_disabled')

        # IdP returned an error directly (e.g. user clicked Cancel).
        if request.args.get('error'):
            err = request.args.get('error')
            logger.info(f"OIDC callback error from IdP: {err}")
            _record_login_attempt(client_ip)
            _audit_failure(audit_logger, None, request,
                           details={'idp_error': err}, error='idp_error')
            return redirect('/login?error=oidc_denied')

        claims, err = oidc_manager.handle_callback(request)
        if err or not claims:
            _record_login_attempt(client_ip)
            _audit_failure(audit_logger, None, request,
                           details={'code': err}, error=err or 'unknown')
            return redirect(f'/login?error=oidc_{err or "unknown"}')

        username, err = oidc_manager.resolve_or_provision_user(claims)
        if err or not username:
            _record_login_attempt(client_ip, username=claims.get('sub'))
            _audit_failure(audit_logger, claims.get('sub'), request,
                           details={'code': err}, error=err or 'unknown')
            return redirect(f'/login?error=oidc_{err or "unknown"}')

        try:
            session_id = auth_manager.create_session(username, source='oidc')
        except Exception as exc:
            logger.error(f"OIDC session creation failed: {exc}")
            _audit_failure(audit_logger, username, request, error='session_create')
            return redirect('/login?error=oidc_session')

        next_url = oidc_manager.consume_next_url()
        response = redirect(next_url)
        # Match local-login cookie attributes verbatim
        # (auth_routes.py:64-68): HttpOnly, Secure when over HTTPS,
        # SameSite=Strict, path=/, 8h max_age.
        response.set_cookie(
            'certmate_session', session_id, httponly=True,
            secure=request.is_secure, samesite='Strict', path='/',
            max_age=8 * 60 * 60,
        )

        if audit_logger:
            try:
                audit_logger.log_operation(
                    operation='oidc_login_success',
                    resource_type='oidc_user',
                    resource_id=username,
                    status='success',
                    user=username,
                    ip_address=request.remote_addr,
                    details={'issuer': claims.get('iss'), 'sub': claims.get('sub')},
                )
            except Exception:  # audit must never break login
                logger.debug("OIDC login audit log failed", exc_info=True)

        return response

    @app.route('/api/auth/oidc/settings', methods=['GET'])
    @auth_manager.require_role('admin')
    def api_oidc_settings_get():
        """Admin-only: read the full OIDC config with client_secret masked
        (same '********' sentinel the rest of the settings UI uses)."""
        return jsonify(oidc_manager.get_admin_config())

    @app.route('/api/auth/oidc/settings', methods=['POST'])
    @auth_manager.require_role('admin')
    def api_oidc_settings_post():
        """Admin-only: validate + atomically persist the OIDC config.

        Mirrors the audit shape used by ``log_auth_config_changed`` so
        a downstream SIEM filtering on ``resource_type='auth_config'``
        sees this mutation too.
        """
        payload = request.json or {}
        before = oidc_manager.get_admin_config()
        ok, err = oidc_manager.update_config(payload)
        if not ok:
            return jsonify({'error': err or 'invalid OIDC settings'}), 400
        after = oidc_manager.get_admin_config()
        if audit_logger:
            try:
                # Surface which fields actually changed (not values, which
                # may include the freshly-rotated client_secret).
                changed = sorted(k for k in after.keys()
                                 if before.get(k) != after.get(k))
                sensitive = [k for k in changed if 'secret' in k or 'client_secret' in k]
                # ``before`` and ``after`` both come from get_admin_config(),
                # which masks ``client_secret`` to '********'. A genuine
                # rotation is therefore invisible to the snapshot diff —
                # detect it from the raw payload so SIEMs keyed on
                # ``sensitive_changed`` don't go blind on secret rotations.
                raw_secret = (payload.get('client_secret')
                              if isinstance(payload, dict) else None)
                if (isinstance(raw_secret, str) and raw_secret
                        and raw_secret != SECRET_MASK_SENTINEL):
                    if 'client_secret' not in changed:
                        changed.append('client_secret')
                        changed.sort()
                    if 'client_secret' not in sensitive:
                        sensitive.append('client_secret')
                user = getattr(request, 'current_user', {}) or {}
                audit_logger.log_operation(
                    operation='oidc_config_changed',
                    resource_type='auth_config',
                    resource_id='oidc',
                    status='success',
                    user=user.get('username'),
                    ip_address=request.remote_addr,
                    details={
                        'changed_keys': changed,
                        'sensitive_changed': sensitive,
                        'enabled_after': bool(after.get('enabled')),
                    },
                )
            except Exception:
                logger.debug("OIDC config audit log failed", exc_info=True)
        return jsonify({'message': 'OIDC settings updated'})


def _audit_failure(audit_logger, subject, request_obj, details=None, error=None):
    if not audit_logger:
        return
    try:
        audit_logger.log_operation(
            operation='oidc_login_failure',
            resource_type='oidc_user',
            resource_id=str(subject or 'unknown'),
            status='failure',
            user=str(subject or 'anonymous'),
            ip_address=request_obj.remote_addr,
            details=details or {},
            error=error,
        )
    except Exception:
        logger.debug("OIDC failure audit log failed", exc_info=True)
