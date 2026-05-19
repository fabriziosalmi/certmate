"""Unit tests for modules/core/oidc.py (OIDCManager).

Pure-logic tests against a real SettingsManager (tmp_path-backed) and a
real AuthManager — no Flask request context, no HTTP, no Docker.

The Authlib flow itself is exercised by the integration suite (see
test_oidc_routes.py) where the discovery doc is mocked out; here we
focus on the parts that don't need a network: config validation,
role mapping, JIT, link-by-email and subject lookup.
"""

import pytest

from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.oidc import OIDCManager, OIDCConfigError, SECRET_MASK_SENTINEL
from modules.core.settings import SettingsManager


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def settings_manager(tmp_path):
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
    sm = SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")
    # Force creation of the defaults file.
    sm.load_settings()
    return sm


@pytest.fixture
def auth_manager(settings_manager):
    am = AuthManager(settings_manager)
    am.set_hmac_key("test-secret-for-hmac")
    return am


@pytest.fixture
def oidc(settings_manager, auth_manager):
    return OIDCManager(settings_manager, auth_manager)


def _enable_oidc(settings_manager, **overrides):
    """Persist a minimally-valid enabled OIDC config block."""
    config = {
        'enabled': True,
        'provider_name': 'TestIdP',
        'issuer_url': 'https://idp.example.com',
        'client_id': 'cm-test',
        'client_secret': 'shh',
        'scopes': ['openid', 'email', 'profile', 'groups'],
        'username_claim': 'preferred_username',
        'email_claim': 'email',
        'role_claim': 'groups',
        'role_mappings': [
            {'claim_value': 'eng-admins', 'role': 'admin'},
            {'claim_value': 'eng', 'role': 'operator'},
        ],
        'default_role': 'viewer',
        'auto_create_users': True,
        'link_by_email': True,
        'post_logout_redirect_uri': '',
        'redirect_uri_override': '',
    }
    config.update(overrides)
    settings_manager.update(lambda s: s.__setitem__('oidc', config), 'test_seed')


# ---------------------------------------------------------------------------
# Config validation
# ---------------------------------------------------------------------------


def test_is_enabled_requires_issuer_and_client_id(oidc, settings_manager):
    _enable_oidc(settings_manager, issuer_url='', client_id='')
    assert oidc.is_enabled() is False

    _enable_oidc(settings_manager, issuer_url='https://idp.example.com', client_id='')
    assert oidc.is_enabled() is False

    _enable_oidc(settings_manager)
    assert oidc.is_enabled() is True


def test_get_admin_config_masks_client_secret(oidc, settings_manager):
    _enable_oidc(settings_manager, client_secret='real-secret-value')
    cfg = oidc.get_admin_config()
    assert cfg['client_secret'] == SECRET_MASK_SENTINEL


def test_update_config_strips_masked_sentinel(oidc, settings_manager):
    _enable_oidc(settings_manager, client_secret='real-secret-value')
    ok, err = oidc.update_config({
        'enabled': True,
        'provider_name': 'TestIdP',
        'issuer_url': 'https://idp.example.com',
        'client_id': 'cm-test',
        'client_secret': SECRET_MASK_SENTINEL,  # UI round-trip
        'scopes': ['openid', 'email'],
    })
    assert ok is True, err
    # Original secret is preserved on disk
    on_disk = settings_manager.load_settings()['oidc']['client_secret']
    assert on_disk == 'real-secret-value'


def test_update_config_rejects_invalid_role_in_mappings(oidc, settings_manager):
    ok, err = oidc.update_config({
        'enabled': True,
        'issuer_url': 'https://idp.example.com',
        'client_id': 'cm-test',
        'role_mappings': [{'claim_value': 'devs', 'role': 'superuser'}],
    })
    assert ok is False
    assert 'role' in (err or '').lower()


def test_update_config_requires_client_id_when_enabled(oidc, settings_manager):
    ok, err = oidc.update_config({
        'enabled': True,
        'issuer_url': 'https://idp.example.com',
        'client_id': '',
    })
    assert ok is False
    assert 'client_id' in (err or '').lower()


def test_update_config_requires_https_issuer(oidc, settings_manager):
    ok, err = oidc.update_config({
        'enabled': True,
        'issuer_url': 'http://idp.example.com',  # non-localhost http
        'client_id': 'cm-test',
    })
    assert ok is False
    assert 'http' in (err or '').lower()


def test_update_config_allows_http_for_localhost(oidc, settings_manager):
    ok, err = oidc.update_config({
        'enabled': True,
        'issuer_url': 'http://localhost:8080',
        'client_id': 'cm-test',
        'client_secret': 'shh',
    })
    assert ok is True, err


def test_update_config_requires_openid_scope(oidc, settings_manager):
    ok, err = oidc.update_config({
        'enabled': True,
        'issuer_url': 'https://idp.example.com',
        'client_id': 'cm-test',
        'scopes': ['email', 'profile'],
    })
    assert ok is False
    assert 'openid' in (err or '').lower()


# ---------------------------------------------------------------------------
# Role mapping
# ---------------------------------------------------------------------------


def test_map_role_first_match_wins(oidc, settings_manager):
    _enable_oidc(settings_manager)
    cfg = oidc._load_config()
    # Both groups present — admin mapping appears first in role_mappings.
    role = oidc._map_role({'groups': ['eng', 'eng-admins']}, cfg)
    assert role == 'admin'


def test_map_role_falls_back_to_default(oidc, settings_manager):
    _enable_oidc(settings_manager, default_role='operator')
    cfg = oidc._load_config()
    role = oidc._map_role({'groups': ['nobody-knows-this-group']}, cfg)
    assert role == 'operator'


def test_map_role_handles_scalar_claim(oidc, settings_manager):
    _enable_oidc(settings_manager,
                 role_claim='role',
                 role_mappings=[{'claim_value': 'platform', 'role': 'operator'}])
    cfg = oidc._load_config()
    role = oidc._map_role({'role': 'platform'}, cfg)
    assert role == 'operator'


def test_map_role_missing_claim_uses_default(oidc, settings_manager):
    _enable_oidc(settings_manager, default_role='viewer')
    cfg = oidc._load_config()
    role = oidc._map_role({}, cfg)
    assert role == 'viewer'


def test_map_role_is_case_insensitive(oidc, settings_manager):
    """IdPs are inconsistent about group casing — AD ships uppercase
    (``Domain Admins``), Authentik capitalises (``Admin``), Keycloak
    follows whatever the realm operator typed. Admins should be able
    to configure ``eng-admins`` once and have it match every casing the
    IdP returns. Locks the case-insensitive contract."""
    # 1. Lowercase config + capitalised IdP claim must match.
    _enable_oidc(settings_manager, role_mappings=[
        {'claim_value': 'eng-admins', 'role': 'admin'},
        {'claim_value': 'eng', 'role': 'operator'},
    ])
    cfg = oidc._load_config()
    assert oidc._map_role({'groups': ['ENG-Admins']}, cfg) == 'admin'
    assert oidc._map_role({'groups': ['Domain ENG']}, cfg) == 'viewer'

    # 2. Capitalised config + lowercase IdP claim must match.
    _enable_oidc(settings_manager, role_mappings=[
        {'claim_value': 'Eng-Admins', 'role': 'admin'},
    ])
    cfg = oidc._load_config()
    assert oidc._map_role({'groups': ['eng-admins']}, cfg) == 'admin'

    # 3. First-match-wins semantics preserved across cases.
    _enable_oidc(settings_manager, role_mappings=[
        {'claim_value': 'eng-admins', 'role': 'admin'},
        {'claim_value': 'eng', 'role': 'operator'},
    ])
    cfg = oidc._load_config()
    assert oidc._map_role({'groups': ['ENG', 'ENG-ADMINS']}, cfg) == 'admin'


# ---------------------------------------------------------------------------
# JIT provisioning + linking + subject lookup
# ---------------------------------------------------------------------------


def test_jit_creates_disabled_password_user(oidc, settings_manager, auth_manager):
    _enable_oidc(settings_manager)
    claims = {
        'iss': 'https://idp.example.com',
        'sub': 'idp-subject-001',
        'preferred_username': 'alice',
        'email': 'alice@example.com',
        'groups': ['eng-admins'],
    }
    username, err = oidc.resolve_or_provision_user(claims)
    assert err is None
    assert username == 'alice'

    users = auth_manager._get_users()
    record = users['alice']
    assert record['password_hash'] == ''
    assert record['role'] == 'admin'
    assert record['oidc_subject'] == 'idp-subject-001'
    assert record['oidc_issuer'] == 'https://idp.example.com'
    assert record['enabled'] is True

    # Local login must refuse the SSO-only user regardless of password.
    assert auth_manager.authenticate_user('alice', 'anything') is None
    assert auth_manager.authenticate_user('alice', '') is None


def test_email_collision_links_existing_local_user(oidc, settings_manager, auth_manager):
    _enable_oidc(settings_manager)
    # Pre-seed a local admin called alice with a real password.
    auth_manager.create_user('alice', 'strongpw1', role='admin', email='alice@example.com')

    claims = {
        'iss': 'https://idp.example.com',
        'sub': 'idp-subject-002',
        'preferred_username': 'alice-from-idp',  # different username
        'email': 'alice@example.com',
        'groups': ['nobody-knows'],
    }
    username, err = oidc.resolve_or_provision_user(claims)
    assert err is None
    assert username == 'alice'  # linked, not a new account

    users = auth_manager._get_users()
    assert 'alice-from-idp' not in users
    record = users['alice']
    # Existing role preserved (admin), NOT downgraded by the OIDC default.
    assert record['role'] == 'admin'
    # Password hash preserved — alice can still log in locally too.
    assert record['password_hash']
    # Linked
    assert record['oidc_subject'] == 'idp-subject-002'
    assert record['oidc_issuer'] == 'https://idp.example.com'


def test_subject_lookup_wins_over_email_match(oidc, settings_manager, auth_manager):
    _enable_oidc(settings_manager)
    # Pre-seed an OIDC-provisioned user (subject already known) and a
    # separate local user sharing the email — subject lookup must take
    # precedence so we don't accidentally hijack the wrong account.
    auth_manager.create_user('local-alice', 'pw123abc', role='operator',
                              email='alice@example.com')

    users = auth_manager._get_users()
    users['oidc-alice'] = {
        'password_hash': '',
        'role': 'viewer',
        'email': 'alice@example.com',
        'enabled': True,
        'oidc_subject': 'idp-subject-003',
        'oidc_issuer': 'https://idp.example.com',
        'created_at': '2026-01-01T00:00:00',
    }
    auth_manager._save_users(users)

    claims = {
        'iss': 'https://idp.example.com',
        'sub': 'idp-subject-003',
        'preferred_username': 'alice2',
        'email': 'alice@example.com',
        'groups': [],
    }
    username, err = oidc.resolve_or_provision_user(claims)
    assert err is None
    assert username == 'oidc-alice'


def test_missing_sub_is_rejected(oidc, settings_manager):
    _enable_oidc(settings_manager)
    username, err = oidc.resolve_or_provision_user({
        'iss': 'https://idp.example.com',
        'email': 'noone@example.com',
    })
    assert username is None
    assert err == 'missing_sub'


def test_provisioning_disabled_rejects_unknown_user(oidc, settings_manager):
    _enable_oidc(settings_manager, auto_create_users=False, link_by_email=False)
    username, err = oidc.resolve_or_provision_user({
        'iss': 'https://idp.example.com',
        'sub': 'idp-subject-004',
        'preferred_username': 'newcomer',
        'email': 'new@example.com',
    })
    assert username is None
    assert err == 'provisioning_disabled'


def test_username_collision_appends_suffix(oidc, settings_manager, auth_manager):
    _enable_oidc(settings_manager, link_by_email=False)
    # Seed an existing local user named 'alice' that does NOT share the
    # claim email — link_by_email is off, so JIT must create a unique
    # username instead.
    auth_manager.create_user('alice', 'pw123abc', role='operator',
                              email='other@example.com')

    claims = {
        'iss': 'https://idp.example.com',
        'sub': 'idp-subject-005',
        'preferred_username': 'alice',
        'email': 'sso-alice@example.com',
        'groups': [],
    }
    username, err = oidc.resolve_or_provision_user(claims)
    assert err is None
    assert username == 'alice_2'

    users = auth_manager._get_users()
    assert 'alice_2' in users
    assert users['alice_2']['email'] == 'sso-alice@example.com'


# ---------------------------------------------------------------------------
# Public config shape — verifies the UI affordance never leaks secrets.
# ---------------------------------------------------------------------------


def test_public_config_omits_secrets(oidc, settings_manager):
    _enable_oidc(settings_manager, client_secret='shh',
                 role_mappings=[{'claim_value': 'admins', 'role': 'admin'}])
    cfg = oidc.get_public_config()
    assert cfg['enabled'] is True
    assert cfg['provider_name'] == 'TestIdP'
    assert cfg['login_url'] == '/api/auth/oidc/login'
    assert 'client_secret' not in cfg
    assert 'role_mappings' not in cfg
    assert 'role_claim' not in cfg


# ---------------------------------------------------------------------------
# End-session URL construction
# ---------------------------------------------------------------------------


def test_build_end_session_url_includes_id_token_hint(oidc, settings_manager):
    """The OIDC RP-Initiated Logout spec marks ``id_token_hint`` as
    RECOMMENDED, and Keycloak/Okta/Authentik treat it as effectively
    required: without it the IdP keeps the SSO session alive past a
    CertMate logout, so the next ``Login with SSO`` silently
    re-authenticates the just-logged-out user. Lock that the URL
    carries the hint when one is available."""
    from flask import Flask, session as flask_session
    _enable_oidc(settings_manager,
                 post_logout_redirect_uri='https://certmate.example.com/login')

    class _FakeClient:
        server_metadata = {
            'end_session_endpoint': 'https://idp.example.com/oauth2/logout',
        }

    oidc._client = lambda app: _FakeClient()  # type: ignore[assignment]

    app = Flask(__name__)
    app.secret_key = 'test'
    with app.test_request_context('/'):
        flask_session['_oidc_id_token'] = 'eyJhbGciOi.fake.idtoken'
        url = oidc.build_end_session_url()

    assert url is not None
    assert 'id_token_hint=eyJhbGciOi.fake.idtoken' in url
    # client_id helps Keycloak's headless logout path.
    assert 'client_id=cm-test' in url
    assert 'post_logout_redirect_uri=' in url


def test_build_end_session_url_without_id_token(oidc, settings_manager):
    """When no id_token was stashed (older session, downgrade), the URL
    must still come back — just without the hint. Don't break the existing
    redirect contract."""
    from flask import Flask
    _enable_oidc(settings_manager,
                 post_logout_redirect_uri='https://certmate.example.com/login')

    class _FakeClient:
        server_metadata = {
            'end_session_endpoint': 'https://idp.example.com/oauth2/logout',
        }

    oidc._client = lambda app: _FakeClient()  # type: ignore[assignment]

    app = Flask(__name__)
    app.secret_key = 'test'
    with app.test_request_context('/'):
        url = oidc.build_end_session_url()

    assert url is not None
    assert 'id_token_hint=' not in url
    assert 'post_logout_redirect_uri=' in url
