"""Route-level tests for modules/web/oidc_routes.py.

Uses Flask's test_client against a hand-built app — same pattern as
test_settings_masking_allowlist.py — so the suite stays fast and does
not require the Docker fixture. Authlib's network calls are bypassed
by monkey-patching ``OIDCManager.start_login`` and ``handle_callback``;
the resolution + session-minting path is exercised end-to-end through
the real Flask route plumbing.
"""

from unittest.mock import MagicMock

import pytest
from flask import Flask, redirect

from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.oidc import OIDCManager
from modules.core.settings import SettingsManager
from modules.web.oidc_routes import register_oidc_routes


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# App + manager scaffolding
# ---------------------------------------------------------------------------


def _allow_all(_min_role):
    def deco(fn):
        return fn
    return deco


def _build_app(tmp_path, *, has_users=True, oidc_overrides=None, audit_logger=None):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=cert_dir, data_dir=data_dir,
        backup_dir=backup_dir, logs_dir=logs_dir,
    )
    settings_manager = SettingsManager(file_ops=file_ops,
                                        settings_file=data_dir / "settings.json")
    settings_manager.load_settings()

    auth_manager = AuthManager(settings_manager)
    auth_manager.set_hmac_key('test-secret-for-hmac')
    # The real require_role decorator inspects a Flask-bound session; for
    # these route tests we bypass it so we can focus on the OIDC logic.
    # require_role is patched at the *instance* level after construction.
    auth_manager.require_role = _allow_all  # type: ignore[assignment]

    if has_users:
        auth_manager.create_user('admin-user', 'pw123abc', role='admin')

    oidc_manager = OIDCManager(settings_manager, auth_manager)

    if oidc_overrides is not None:
        cfg = {
            'enabled': True,
            'provider_name': 'TestIdP',
            'issuer_url': 'https://idp.example.com',
            'client_id': 'cm-test',
            'client_secret': 'shh',
            'scopes': ['openid', 'email', 'profile', 'groups'],
            'username_claim': 'preferred_username',
            'email_claim': 'email',
            'role_claim': 'groups',
            'role_mappings': [],
            'default_role': 'viewer',
            'auto_create_users': True,
            'link_by_email': True,
            'post_logout_redirect_uri': '',
            'redirect_uri_override': '',
        }
        cfg.update(oidc_overrides)
        settings_manager.update(lambda s: s.__setitem__('oidc', cfg), 'test_seed')

    app = Flask(__name__)
    app.secret_key = 'test'
    # The rate-limit helpers are no-ops in this fixture so the tests
    # don't depend on the module-level state in modules/web/routes.py.
    register_oidc_routes(
        app,
        managers={'audit': audit_logger or MagicMock()},
        auth_manager=auth_manager,
        oidc_manager=oidc_manager,
        _check_login_rate_limit=lambda ip, username=None: (True, None),
        _record_login_attempt=lambda ip, username=None: None,
    )
    return app, settings_manager, auth_manager, oidc_manager


# ---------------------------------------------------------------------------
# Public /api/auth/oidc/config
# ---------------------------------------------------------------------------


def test_config_endpoint_default_disabled(tmp_path):
    app, *_ = _build_app(tmp_path)
    client = app.test_client()
    r = client.get('/api/auth/oidc/config')
    assert r.status_code == 200
    body = r.get_json()
    assert body['enabled'] is False
    assert body['login_url'] == '/api/auth/oidc/login'
    # Anonymous caller — public endpoint must not surface any secret.
    assert 'client_secret' not in body
    assert 'client_id' not in body


def test_config_endpoint_reports_enabled(tmp_path):
    app, *_ = _build_app(tmp_path, oidc_overrides={'provider_name': 'KeycloakProd'})
    client = app.test_client()
    body = client.get('/api/auth/oidc/config').get_json()
    assert body['enabled'] is True
    assert body['provider_name'] == 'KeycloakProd'


# ---------------------------------------------------------------------------
# /api/auth/oidc/login — disabled vs enabled
# ---------------------------------------------------------------------------


def test_login_redirects_to_login_page_when_disabled(tmp_path):
    app, *_ = _build_app(tmp_path)
    client = app.test_client()
    r = client.get('/api/auth/oidc/login', follow_redirects=False)
    assert r.status_code in (302, 303)
    assert '/login?error=oidc_disabled' in r.headers.get('Location', '')


def test_login_calls_start_login_when_enabled(tmp_path, monkeypatch):
    app, _settings, _auth, oidc_manager = _build_app(
        tmp_path, oidc_overrides={}
    )

    fake_response = redirect('https://idp.example.com/authorize?state=test')
    monkeypatch.setattr(oidc_manager, 'start_login',
                        lambda req, next_url: fake_response)

    client = app.test_client()
    r = client.get('/api/auth/oidc/login?next=/dashboard', follow_redirects=False)
    assert r.status_code in (302, 303)
    assert r.headers.get('Location', '').startswith('https://idp.example.com/authorize')


def test_login_rejects_open_redirect_next(tmp_path, monkeypatch):
    """``?next=https://evil/`` must be sanitized to '/' before being
    stashed in the Flask session, so the post-login redirect can't be
    weaponised into an open-redirect link."""
    app, _settings, _auth, oidc_manager = _build_app(
        tmp_path, oidc_overrides={}
    )

    captured = {}

    def fake_start_login(req, next_url):
        captured['next'] = next_url
        return redirect('https://idp.example.com/authorize')

    monkeypatch.setattr(oidc_manager, 'start_login', fake_start_login)

    client = app.test_client()
    client.get('/api/auth/oidc/login?next=https://evil.example/phish')
    assert captured['next'] == '/'

    client.get('/api/auth/oidc/login?next=//evil.example/phish')
    assert captured['next'] == '/'

    client.get('/api/auth/oidc/login?next=/dashboard%2Frenewals')
    # urldecoded paths starting with '/' (and not '//') are allowed
    assert captured['next'].startswith('/dashboard')


# ---------------------------------------------------------------------------
# /api/auth/oidc/callback — full path with patched IdP exchange
# ---------------------------------------------------------------------------


def test_callback_creates_session_and_user(tmp_path, monkeypatch):
    app, _settings, auth_manager, oidc_manager = _build_app(
        tmp_path, oidc_overrides={
            'role_mappings': [{'claim_value': 'eng-admins', 'role': 'admin'}],
            'default_role': 'viewer',
        }
    )

    canned_claims = {
        'iss': 'https://idp.example.com',
        'sub': 'idp-subject-callback-001',
        'preferred_username': 'bob',
        'email': 'bob@example.com',
        'groups': ['eng-admins'],
    }
    monkeypatch.setattr(oidc_manager, 'handle_callback',
                        lambda req: (canned_claims, None))
    monkeypatch.setattr(oidc_manager, 'consume_next_url', lambda: '/dashboard')

    client = app.test_client()
    r = client.get('/api/auth/oidc/callback?code=fake&state=fake',
                   follow_redirects=False)
    assert r.status_code in (302, 303)
    assert r.headers.get('Location') == '/dashboard'

    # Cookie set
    cookies = [c for c in r.headers.getlist('Set-Cookie') if 'certmate_session' in c]
    assert cookies, "callback did not set certmate_session cookie"
    assert 'HttpOnly' in cookies[0]
    assert 'SameSite=Strict' in cookies[0]

    # User row created with the mapped role and SSO-only password.
    users = auth_manager._get_users()
    assert 'bob' in users
    assert users['bob']['role'] == 'admin'
    assert users['bob']['password_hash'] == ''
    assert users['bob']['oidc_subject'] == 'idp-subject-callback-001'


def test_callback_redirects_to_login_on_idp_error(tmp_path):
    app, *_ = _build_app(tmp_path, oidc_overrides={})
    client = app.test_client()
    r = client.get('/api/auth/oidc/callback?error=access_denied',
                   follow_redirects=False)
    assert r.status_code in (302, 303)
    assert r.headers.get('Location', '').startswith('/login?error=oidc_denied')


def test_oidc_error_codes_whitelist_constrains_logged_value():
    """The callback logs only a value drawn from the constant OAuth/OIDC
    error-code set; an attacker-controlled ?error= value can't reach the log
    verbatim and forge entries (CodeQL py/log-injection)."""
    from modules.web.oidc_routes import _OIDC_ERROR_CODES
    assert 'access_denied' in _OIDC_ERROR_CODES
    assert 'server_error' in _OIDC_ERROR_CODES
    forged = "access_denied\r\nINFO forged-admin-login"
    assert forged not in _OIDC_ERROR_CODES


def test_callback_redirects_when_disabled(tmp_path):
    app, *_ = _build_app(tmp_path)  # oidc not enabled
    client = app.test_client()
    r = client.get('/api/auth/oidc/callback?code=fake',
                   follow_redirects=False)
    assert r.status_code in (302, 303)
    assert '/login?error=oidc_disabled' in r.headers.get('Location', '')


def test_callback_propagates_resolution_error(tmp_path, monkeypatch):
    """If the resolved claims can't be mapped to a user (e.g. provisioning
    disabled and unknown subject), redirect to /login with the error code."""
    app, _settings, _auth, oidc_manager = _build_app(
        tmp_path, oidc_overrides={
            'auto_create_users': False,
            'link_by_email': False,
        }
    )

    canned_claims = {
        'iss': 'https://idp.example.com',
        'sub': 'idp-subject-unknown',
        'preferred_username': 'mallory',
        'email': 'mallory@example.com',
        'groups': [],
    }
    monkeypatch.setattr(oidc_manager, 'handle_callback',
                        lambda req: (canned_claims, None))

    client = app.test_client()
    r = client.get('/api/auth/oidc/callback?code=fake',
                   follow_redirects=False)
    assert r.status_code in (302, 303)
    assert 'oidc_provisioning_disabled' in r.headers.get('Location', '')


# ---------------------------------------------------------------------------
# /api/auth/oidc/settings (admin-only handled by patched decorator)
# ---------------------------------------------------------------------------


def test_settings_get_returns_masked_secret(tmp_path):
    app, *_ = _build_app(tmp_path, oidc_overrides={'client_secret': 'real-secret'})
    client = app.test_client()
    body = client.get('/api/auth/oidc/settings').get_json()
    assert body['client_secret'] == '********'
    assert body['enabled'] is True


def test_settings_post_validates(tmp_path):
    app, *_ = _build_app(tmp_path, oidc_overrides={})
    client = app.test_client()
    r = client.post('/api/auth/oidc/settings', json={
        'enabled': True,
        'issuer_url': 'https://idp.example.com',
        'client_id': '',  # missing
    })
    assert r.status_code == 400
    assert 'client_id' in (r.get_json() or {}).get('error', '')


def test_settings_post_roundtrip_preserves_masked_secret(tmp_path):
    app, settings_manager, *_ = _build_app(
        tmp_path, oidc_overrides={'client_secret': 'real-secret'}
    )
    client = app.test_client()
    body = client.get('/api/auth/oidc/settings').get_json()
    # Mimic the UI: post the body back verbatim (masked secret included).
    r = client.post('/api/auth/oidc/settings', json=body)
    assert r.status_code == 200, r.get_json()

    on_disk = settings_manager.load_settings()['oidc']['client_secret']
    assert on_disk == 'real-secret'


def test_settings_post_audits_client_secret_rotation(tmp_path):
    """A non-sentinel client_secret in the payload is a genuine rotation;
    the masked before/after snapshot comparison alone hides it, so the
    audit details must call it out explicitly. Locks the fix for the
    SIEM blind-spot reported in the PR review."""
    audit = MagicMock()
    app, settings_manager, *_ = _build_app(
        tmp_path,
        oidc_overrides={'client_secret': 'SECRET-A'},
        audit_logger=audit,
    )
    client = app.test_client()
    body = client.get('/api/auth/oidc/settings').get_json()
    # Replace the masked sentinel with a fresh, real secret.
    body['client_secret'] = 'SECRET-B-rotated'
    r = client.post('/api/auth/oidc/settings', json=body)
    assert r.status_code == 200, r.get_json()

    # On-disk secret was rotated.
    on_disk = settings_manager.load_settings()['oidc']['client_secret']
    assert on_disk == 'SECRET-B-rotated'

    # Audit must surface the rotation in both `changed_keys` and `sensitive_changed`.
    config_calls = [c for c in audit.log_operation.call_args_list
                    if c.kwargs.get('operation') == 'oidc_config_changed']
    assert config_calls, 'expected oidc_config_changed audit entry'
    details = config_calls[-1].kwargs.get('details') or {}
    assert 'client_secret' in details.get('sensitive_changed', []), details
    assert 'client_secret' in details.get('changed_keys', []), details


def test_settings_post_roundtrip_does_not_log_secret_change(tmp_path):
    """The masked-sentinel round-trip (no real rotation) must NOT trigger
    a sensitive_changed entry — otherwise SIEMs would fire on every save."""
    audit = MagicMock()
    app, *_ = _build_app(
        tmp_path,
        oidc_overrides={'client_secret': 'SECRET-A'},
        audit_logger=audit,
    )
    client = app.test_client()
    body = client.get('/api/auth/oidc/settings').get_json()
    # Don't touch client_secret — it stays as '********'.
    r = client.post('/api/auth/oidc/settings', json=body)
    assert r.status_code == 200, r.get_json()

    config_calls = [c for c in audit.log_operation.call_args_list
                    if c.kwargs.get('operation') == 'oidc_config_changed']
    assert config_calls, 'expected oidc_config_changed audit entry'
    details = config_calls[-1].kwargs.get('details') or {}
    assert 'client_secret' not in details.get('sensitive_changed', []), details


def test_settings_post_resubmitting_same_plaintext_does_not_audit_rotation(tmp_path):
    """An admin who pastes the same plaintext secret that's already
    on-disk (e.g. copy-pasted from a password manager during an
    unrelated edit) must NOT trigger a rotation audit entry. Pre-fix
    the audit fired on any non-sentinel value; that produced SIEM
    noise for every same-value resubmit. Verified against the pre-
    update plaintext now."""
    audit = MagicMock()
    app, settings_manager, *_ = _build_app(
        tmp_path,
        oidc_overrides={'client_secret': 'SECRET-UNCHANGED'},
        audit_logger=audit,
    )
    client = app.test_client()
    body = client.get('/api/auth/oidc/settings').get_json()
    # Same plaintext as on disk — the UI sees the masked sentinel, but
    # an admin might paste the literal value during an unrelated edit.
    body['client_secret'] = 'SECRET-UNCHANGED'
    r = client.post('/api/auth/oidc/settings', json=body)
    assert r.status_code == 200, r.get_json()

    # On-disk value unchanged.
    on_disk = settings_manager.load_settings()['oidc']['client_secret']
    assert on_disk == 'SECRET-UNCHANGED'

    # Audit must NOT flag this as a rotation.
    config_calls = [c for c in audit.log_operation.call_args_list
                    if c.kwargs.get('operation') == 'oidc_config_changed']
    assert config_calls, 'expected oidc_config_changed audit entry'
    details = config_calls[-1].kwargs.get('details') or {}
    assert 'client_secret' not in details.get('sensitive_changed', []), details
    assert 'client_secret' not in details.get('changed_keys', []), details


def test_oidc_jit_race_under_concurrent_callbacks(tmp_path):
    """Two concurrent first-time OIDC callbacks for DISTINCT subjects
    must both end up persisted with their own users row. The pre-fix
    race did ``_get_users()`` outside any lock, picked the same
    suffixed username via _unique_username, and the last _save_users
    overwrote the first — silently losing one of the rows.

    Routing the read-mutate-write through ``settings_manager.update``
    serialises the whole sequence under the settings RLock so each
    thread observes the other's write before computing uniqueness."""
    import threading

    app, settings_manager, _auth_manager, oidc_manager = _build_app(
        tmp_path,
        oidc_overrides={'client_secret': 'SECRET'},
    )

    def call(subject):
        return oidc_manager.resolve_or_provision_user({
            'iss': 'https://idp.example.com',
            'sub': subject,
            'preferred_username': 'shared-name',  # forces collision path
            'email': f'{subject}@example.com',
            'email_verified': True,
        })

    results = {}

    def worker(subject):
        results[subject] = call(subject)

    threads = [threading.Thread(target=worker, args=(f'subject-{i}',))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # All 8 succeeded.
    assert all(err is None for _, err in results.values()), results
    usernames = {u for u, _ in results.values()}
    assert len(usernames) == 8, f'expected 8 distinct usernames, got {usernames}'

    # All 8 rows actually landed on disk.
    users = settings_manager.load_settings().get('users', {})
    for username in usernames:
        assert username in users, f'{username} missing from persisted users'


# ---------------------------------------------------------------------------
# Bulk-settings reject-list — confirms 'oidc' can't be smuggled in
# via the generic POST /api/web/settings endpoint.
# ---------------------------------------------------------------------------


def test_oidc_block_is_rejected_by_bulk_settings_post():
    """The 'oidc' key sits in SETTINGS_REJECT_KEYS so a generic POST to
    the bulk settings endpoint must reject it. Tests the gate in
    modules/core/settings.validate_settings_post."""
    from modules.core.settings import validate_settings_post

    filtered, rejected, unknown = validate_settings_post(
        {'oidc': {'enabled': True, 'client_id': 'evil'}},
        current={'oidc': {'enabled': False}},
    )
    assert 'oidc' not in filtered
    assert 'oidc' in rejected
