"""Sprint 1.5 (security audit follow-up) — pure unit tests.

Covers:
- AuthManager._authenticate_request returns (user, None) on success and
  (None, error) on failure, without touching request.current_user as a
  side effect (audit F-1 refactor).
- AuthManager._log_rbac_denial both emits an application log warning and
  writes audit_logger.log_authz_denied when audit_logger is wired
  (audit F-2).
- AuthManager.set_audit_logger plumbs the logger through correctly.

The download-endpoint role split (viewer cannot pull privkey material) is
exercised end-to-end and lives in a separate Flask test client class.

No Docker; runs in-process.
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from flask import Flask, request
from flask_restx import Api, Namespace

from modules.core.auth import AuthManager, ROLE_HIERARCHY
from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
import modules.api.resources as api_resources_module


# --- _authenticate_request (F-1 refactor) -----------------------------------

@pytest.fixture
def base_settings():
    return {
        'local_auth_enabled': False,
        'users': {},
        'api_keys': {},
        'api_bearer_token': 'legacy_test_token_abc123',
    }


@pytest.fixture
def auth(base_settings):
    sm = MagicMock()
    sm.load_settings.side_effect = lambda: base_settings
    sm.save_settings.side_effect = lambda s, reason=None: True

    def _update(mutator, reason=None):
        s = sm.load_settings()
        mutator(s)
        return sm.save_settings(s, reason)
    sm.update.side_effect = _update
    return AuthManager(sm)


@pytest.fixture
def flask_app():
    app = Flask(__name__)
    app.config['TESTING'] = True
    return app


class TestAuthenticateRequestBypassMode:
    """When local_auth is off and no users exist, every request is admin."""

    def test_returns_setup_admin_no_error(self, auth, flask_app):
        with flask_app.test_request_context('/some/path'):
            user, err = auth._authenticate_request()
        assert err is None
        assert user == {'username': 'setup_user', 'role': 'admin'}

    def test_does_not_touch_request_current_user(self, auth, flask_app):
        # The whole point of F-1: side effects must not leak from the
        # authentication helper. The caller (decorator) owns the
        # request.current_user assignment.
        with flask_app.test_request_context('/some/path'):
            user, err = auth._authenticate_request()
            assert not hasattr(request, 'current_user')
        assert user is not None


class TestAuthenticateRequestBearerToken:
    """With local_auth on + users present, bearer token is required."""

    def test_missing_header_returns_401(self, auth, base_settings, flask_app):
        base_settings['local_auth_enabled'] = True
        base_settings['users'] = {'admin': {'password_hash': 'x', 'role': 'admin', 'enabled': True}}
        with flask_app.test_request_context('/api/x'):
            user, err = auth._authenticate_request()
        assert user is None
        body, status = err
        assert status == 401
        assert body['code'] == 'AUTH_HEADER_MISSING'

    def test_wrong_scheme_returns_401(self, auth, base_settings, flask_app):
        base_settings['local_auth_enabled'] = True
        base_settings['users'] = {'admin': {'password_hash': 'x', 'role': 'admin', 'enabled': True}}
        with flask_app.test_request_context('/api/x', headers={'Authorization': 'Basic abc'}):
            user, err = auth._authenticate_request()
        body, status = err
        assert status == 401
        assert body['code'] == 'INVALID_AUTH_SCHEME'

    def test_invalid_token_returns_401(self, auth, base_settings, flask_app):
        base_settings['local_auth_enabled'] = True
        base_settings['users'] = {'admin': {'password_hash': 'x', 'role': 'admin', 'enabled': True}}
        with flask_app.test_request_context('/api/x', headers={'Authorization': 'Bearer wrong'}):
            user, err = auth._authenticate_request()
        body, status = err
        assert status == 401
        assert body['code'] == 'INVALID_TOKEN'

    def test_legacy_token_returns_admin(self, auth, base_settings, flask_app):
        base_settings['local_auth_enabled'] = True
        base_settings['users'] = {'admin': {'password_hash': 'x', 'role': 'admin', 'enabled': True}}
        with flask_app.test_request_context('/api/x',
                                            headers={'Authorization': 'Bearer legacy_test_token_abc123'}):
            user, err = auth._authenticate_request()
        assert err is None
        assert user['role'] == 'admin'

    def test_scoped_key_propagates_allowed_domains(self, auth, base_settings, flask_app):
        base_settings['local_auth_enabled'] = True
        base_settings['users'] = {'admin': {'password_hash': 'x', 'role': 'admin', 'enabled': True}}
        # Create a scoped key through the manager (will go via mocked update).
        ok, created = auth.create_api_key('ci', role='operator',
                                          allowed_domains=['*.ci.example.com'])
        assert ok
        token = created['token']
        with flask_app.test_request_context('/api/x',
                                            headers={'Authorization': f'Bearer {token}'}):
            user, err = auth._authenticate_request()
        assert err is None
        assert user['role'] == 'operator'
        assert user['allowed_domains'] == ['*.ci.example.com']


class TestRequireRoleDelegation:
    """The decorators are now thin wrappers over _authenticate_request."""

    def test_require_auth_assigns_current_user_on_success(self, auth, flask_app):
        @auth.require_auth
        def view():
            return {'user': request.current_user['username']}, 200

        with flask_app.test_request_context('/api/x'):
            response = view()
        assert response == ({'user': 'setup_user'}, 200)

    def test_require_role_assigns_current_user_only_after_success(self, auth, flask_app):
        # In bypass mode role=admin so this should pass.
        @auth.require_role('admin')
        def view():
            return {'ok': True, 'role': request.current_user['role']}, 200

        with flask_app.test_request_context('/api/x'):
            response = view()
        assert response == ({'ok': True, 'role': 'admin'}, 200)

    def test_require_role_returns_403_for_insufficient_role(self, auth, base_settings, flask_app):
        # Set up: local auth on, scoped viewer key.
        base_settings['local_auth_enabled'] = True
        base_settings['users'] = {'admin': {'password_hash': 'x', 'role': 'admin', 'enabled': True}}
        ok, created = auth.create_api_key('readonly', role='viewer')
        token = created['token']

        @auth.require_role('admin')
        def view():
            return {'ok': True}, 200

        with flask_app.test_request_context('/api/x',
                                            headers={'Authorization': f'Bearer {token}'}):
            response = view()
        body, status = response
        assert status == 403
        assert body['code'] == 'INSUFFICIENT_ROLE'


# --- RBAC denial audit emission (F-2) ---------------------------------------

class TestRbacDenialAudit:
    def test_audit_log_authz_denied_emitted_when_wired(self, auth, base_settings, flask_app):
        # Enable local auth + create a viewer key + wire audit logger.
        base_settings['local_auth_enabled'] = True
        base_settings['users'] = {'admin': {'password_hash': 'x', 'role': 'admin', 'enabled': True}}
        ok, created = auth.create_api_key('readonly', role='viewer')
        token = created['token']
        audit_logger = MagicMock()
        auth.set_audit_logger(audit_logger)

        @auth.require_role('admin')
        def view():
            return {'ok': True}, 200

        with flask_app.test_request_context('/api/admin/thing',
                                            headers={'Authorization': f'Bearer {token}'}):
            response = view()

        assert response[1] == 403
        audit_logger.log_authz_denied.assert_called_once()
        kwargs = audit_logger.log_authz_denied.call_args.kwargs
        assert kwargs['operation'] == 'access'
        assert kwargs['resource_type'] == 'endpoint'
        assert kwargs['resource_id'] == '/api/admin/thing'
        assert 'role=viewer' in kwargs['reason']
        assert 'required admin' in kwargs['reason']
        assert kwargs['user'] == 'api_key:readonly'

    def test_no_crash_when_audit_logger_not_wired(self, auth, base_settings, flask_app):
        # The default state (audit not wired) must still log a warning
        # and emit a clean 403 — never raise.
        base_settings['local_auth_enabled'] = True
        base_settings['users'] = {'admin': {'password_hash': 'x', 'role': 'admin', 'enabled': True}}
        ok, created = auth.create_api_key('readonly', role='viewer')
        token = created['token']

        @auth.require_role('admin')
        def view():
            return {'ok': True}, 200

        with flask_app.test_request_context('/api/x',
                                            headers={'Authorization': f'Bearer {token}'}):
            response = view()
        assert response[1] == 403


# --- PRIVKEY-DOWNLOAD: split role per-file ----------------------------------

def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


@pytest.fixture
def cert_dir(tmp_path):
    d = tmp_path / 'example.com'
    d.mkdir()
    (d / 'cert.pem').write_text('PUBLIC-cert')
    (d / 'chain.pem').write_text('PUBLIC-chain')
    (d / 'fullchain.pem').write_text('PUBLIC-fullchain')
    (d / 'privkey.pem').write_text('PRIVATE-key')
    return tmp_path


@pytest.fixture
def download_app(cert_dir, monkeypatch):
    # We bypass require_role to test the per-file gate independently of
    # the decorator. The role check the handler performs comes from
    # request.current_user, which we set via a before_request hook
    # below per test case.
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    # user_can_access_domain returns True (no scope filtering in this test)
    auth_manager.user_can_access_domain.return_value = True
    auth_manager.domain_matches_scope.return_value = True

    file_ops = MagicMock(cert_dir=Path(cert_dir))
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {}
    certificate_manager = MagicMock(cert_dir=Path(cert_dir))
    cache_manager = MagicMock()
    dns_manager = MagicMock()
    audit_logger = MagicMock()

    managers = {
        'auth': auth_manager,
        'settings': settings_manager,
        'certificates': certificate_manager,
        'file_ops': file_ops,
        'cache': cache_manager,
        'dns': dns_manager,
        'audit': audit_logger,
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)

    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['DownloadCertificate'], '/<string:domain>/download')

    return app, managers


def _attach_user(app, role):
    """Before-request hook that sets request.current_user to a fake of
    the given role. Equivalent to a successful auth path."""
    @app.before_request
    def _set_user():
        from flask import g, request as _r
        _r.current_user = {'username': f'fake_{role}', 'role': role,
                           'allowed_domains': None}


class TestDownloadRoleSplit:
    """Viewer can pull public material; private-key material requires operator."""

    def test_viewer_can_pull_public_fullchain(self, download_app):
        app, _ = download_app
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?file=fullchain.pem')
        assert r.status_code == 200
        assert b'PUBLIC-fullchain' in r.data

    def test_viewer_can_pull_public_cert(self, download_app):
        app, _ = download_app
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?file=cert.pem')
        assert r.status_code == 200
        assert b'PUBLIC-cert' in r.data

    def test_viewer_can_pull_public_chain(self, download_app):
        app, _ = download_app
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?file=chain.pem')
        assert r.status_code == 200
        assert b'PUBLIC-chain' in r.data

    def test_viewer_cannot_pull_privkey(self, download_app):
        app, managers = download_app
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?file=privkey.pem')
        assert r.status_code == 403
        body = r.get_json()
        assert body['code'] == 'PRIVKEY_REQUIRES_OPERATOR'
        # And the denial is audited.
        managers['audit'].log_authz_denied.assert_called()

    def test_viewer_cannot_pull_combined_pem(self, download_app):
        app, _ = download_app
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?file=combined.pem')
        assert r.status_code == 403
        assert r.get_json()['code'] == 'PRIVKEY_REQUIRES_OPERATOR'

    def test_viewer_cannot_pull_format_json(self, download_app):
        # format=json bundles the private key inline; must be operator+.
        app, _ = download_app
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?format=json')
        assert r.status_code == 403
        assert r.get_json()['code'] == 'PRIVKEY_REQUIRES_OPERATOR'

    def test_viewer_cannot_pull_default_zip(self, download_app):
        # The default ZIP includes privkey.pem; viewer must opt out.
        app, _ = download_app
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download')
        assert r.status_code == 403
        assert r.get_json()['code'] == 'PRIVKEY_REQUIRES_OPERATOR'

    def test_viewer_can_pull_public_zip_via_include_private_0(self, download_app):
        # The new opt-out path keeps the ZIP UX for monitoring callers.
        app, _ = download_app
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?include_private=0')
        assert r.status_code == 200
        # Disposition should reflect the public-only suffix.
        assert 'certificates_public.zip' in r.headers.get('Content-Disposition', '')
        # And the ZIP must not contain privkey.pem.
        import zipfile
        import io as _io
        with zipfile.ZipFile(_io.BytesIO(r.data)) as zf:
            names = set(zf.namelist())
        assert 'privkey.pem' not in names
        assert 'fullchain.pem' in names

    def test_operator_can_pull_privkey(self, download_app):
        app, _ = download_app
        _attach_user(app, 'operator')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?file=privkey.pem')
        assert r.status_code == 200
        assert b'PRIVATE-key' in r.data

    def test_operator_can_pull_format_json(self, download_app):
        app, _ = download_app
        _attach_user(app, 'operator')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download?format=json')
        assert r.status_code == 200
        payload = r.get_json()
        assert payload['private_key_pem'] == 'PRIVATE-key'
        assert payload['fullchain_pem'] == 'PUBLIC-fullchain'

    def test_operator_can_pull_default_zip(self, download_app):
        app, _ = download_app
        _attach_user(app, 'operator')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download')
        assert r.status_code == 200
        import zipfile
        import io as _io
        with zipfile.ZipFile(_io.BytesIO(r.data)) as zf:
            names = set(zf.namelist())
        assert 'privkey.pem' in names
