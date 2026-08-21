"""#564 — RP-initiated logout never executed.

The backend built ``oidc_logout_url`` and returned it; ``doLogout()`` in
templates/base.html threw the body away and went to /login. The IdP session
survived, and the next "Login with SSO" signed the user straight back in.

Three locks: the route still returns the URL for an OIDC-minted session
(and not for a local one), the template follows it, and the manager can
build it after a process restart, when Authlib's metadata cache is empty.
"""
import re
from pathlib import Path
from unittest.mock import MagicMock

from flask import Flask

from modules.web.auth_routes import register_auth_routes

REPO = Path(__file__).resolve().parent.parent


def _passthrough(*_a, **_kw):
    def deco(fn):
        return fn
    return deco


def _app(session_info, oidc_manager):
    app = Flask(__name__)
    app.secret_key = 'test'
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough)
    auth_manager.validate_session.return_value = session_info
    register_auth_routes(
        app,
        managers={'oidc': oidc_manager} if oidc_manager else {},
        require_web_auth=lambda f: f,
        auth_manager=auth_manager,
        _check_login_rate_limit=lambda *a, **kw: True,
        _record_login_attempt=lambda *a, **kw: None,
    )
    return app, auth_manager


def test_logout_returns_the_idp_end_session_url_for_sso_sessions():
    oidc = MagicMock()
    oidc.build_end_session_url.return_value = (
        'https://idp.example.com/logout?id_token_hint=x&client_id=cm')
    app, auth_manager = _app({'source': 'oidc', 'username': 'u'}, oidc)
    client = app.test_client()
    client.set_cookie('certmate_session', 'sess-1')

    r = client.post('/api/auth/logout')

    assert r.status_code == 200
    assert r.get_json()['oidc_logout_url'].startswith('https://idp.example.com/logout?')
    auth_manager.invalidate_session.assert_called_once_with('sess-1')
    oidc.clear_session_artifacts.assert_called_once()


def test_logout_of_a_local_session_carries_no_idp_url():
    oidc = MagicMock()
    app, _ = _app({'source': 'local', 'username': 'u'}, oidc)
    client = app.test_client()
    client.set_cookie('certmate_session', 'sess-1')

    body = client.post('/api/auth/logout').get_json()

    assert 'oidc_logout_url' not in body
    oidc.build_end_session_url.assert_not_called()


def test_the_logout_button_follows_the_url_the_backend_returns():
    """The defect was one function in one template: fix it there, and keep
    it fixed. The frontend must read the body and go where it says; a
    local session (no URL) still lands on /login."""
    html = (REPO / 'templates' / 'base.html').read_text(encoding='utf-8')
    start = re.search(r'function doLogout\(\)\s*\{', html)
    assert start, 'doLogout() not found in base.html'
    # Walk to the matching brace rather than trusting indentation.
    depth, i = 1, start.end()
    while depth and i < len(html):
        depth += {'{': 1, '}': -1}.get(html[i], 0)
        i += 1
    assert depth == 0, 'doLogout() body did not close'
    body = html[start.end():i - 1]
    assert 'oidc_logout_url' in body, (
        'doLogout() ignores the response body — the IdP session is never '
        'terminated (#564)')
    assert "'/login'" in body, 'local sessions must still land on /login'
    # Only an absolute http(s) URL is followed; anything else falls back.
    assert re.search(r'https\?:', body), (
        'doLogout() should only follow an absolute http(s) URL')


def test_end_session_url_is_built_after_a_restart(tmp_path):
    """Authlib fills ``server_metadata`` on the first authorize/token call.
    After a restart that cache is empty while the user's session and
    id_token cookie are still valid — so logout must fetch the discovery
    document itself, or every logout after a restart is local-only."""
    from modules.core.auth import AuthManager
    from modules.core.file_operations import FileOperations
    from modules.core.oidc import OIDCManager
    from modules.core.settings import SettingsManager
    from flask import session as flask_session

    for d in ('certificates', 'data', 'backups', 'logs'):
        (tmp_path / d).mkdir()
    file_ops = FileOperations(
        cert_dir=tmp_path / 'certificates', data_dir=tmp_path / 'data',
        backup_dir=tmp_path / 'backups', logs_dir=tmp_path / 'logs')
    sm = SettingsManager(file_ops=file_ops, settings_file=tmp_path / 'data' / 'settings.json')
    am = AuthManager(sm)
    am.set_hmac_key('k')
    settings = sm.load_settings()
    settings['oidc'] = {
        'enabled': True, 'provider_name': 'T',
        'issuer_url': 'https://idp.example.com', 'client_id': 'cm-test',
        'client_secret': 'shh', 'scopes': ['openid'],
        'username_claim': 'preferred_username', 'email_claim': 'email',
        'role_claim': 'groups', 'role_mappings': [], 'default_role': 'viewer',
        'post_logout_redirect_uri': 'https://certmate.example.com/login',
    }
    sm.save_settings(settings)
    oidc = OIDCManager(sm, am)

    class _ColdClient:
        """What Authlib looks like before its first network call. Returns
        None from the loader and only populates the attribute — the shape
        Copilot flagged as unhandled on #573; the dict-returning shape is
        covered by the same branch."""
        server_metadata = {}
        loads = 0

        def load_server_metadata(self):
            self.loads += 1
            self.server_metadata = {
                'end_session_endpoint': 'https://idp.example.com/logout'}
            return None

    cold = _ColdClient()
    oidc._client = lambda app: cold  # type: ignore[assignment]

    app = Flask(__name__)
    app.secret_key = 'test'
    with app.test_request_context('/'):
        flask_session['_oidc_id_token'] = 'id.token.value'
        url = oidc.build_end_session_url()

    assert cold.loads == 1
    assert url is not None and url.startswith('https://idp.example.com/logout?')
    assert 'id_token_hint=id.token.value' in url
    assert 'client_id=cm-test' in url
