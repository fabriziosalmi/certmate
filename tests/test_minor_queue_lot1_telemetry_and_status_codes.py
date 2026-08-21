"""Two findings from the 2026-08-18 audit's minor queue, verified before fixing.

1. ``authenticate_api_token`` persisted ``last_used_at`` as a datetime object.
   ``json.dump`` refused it, the error was swallowed on purpose (auth must not
   fail on telemetry), and the column stayed empty for every key, forever.
2. The client-certificate resources wrapped their handlers in ``except
   Exception`` and re-aborted as 500. ``abort(4xx)`` raises HTTPException, a
   subclass of Exception, so every 400/403/404 the handler meant to send came
   out as a 500 — except the download handler, which had grown its own
   pass-through. Now they all have it.
"""
import json
from unittest.mock import MagicMock

import pytest
from flask import Flask, request
from flask_restx import Api, Namespace

from modules.api.client_certificates import (
    create_client_certificate_models, create_client_certificate_resources,
)
from modules.core.auth import AuthManager, ROLE_HIERARCHY
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------- #
# 1. last_used_at
# --------------------------------------------------------------------------- #

@pytest.fixture
def auth(tmp_path, monkeypatch):
    monkeypatch.setenv('CERTMATE_LAST_USED_PERSIST_SECONDS', '0')
    dirs = [tmp_path / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir()
    sm = SettingsManager(file_ops=FileOperations(*dirs), settings_file=dirs[1] / "settings.json")
    sm.load_settings()
    am = AuthManager(sm)
    am.set_hmac_key("test-secret-for-hmac")
    return am, sm, dirs[1] / "settings.json"


def test_last_used_at_is_persisted_as_iso_text(auth):
    am, sm, settings_file = auth
    ok, data = am.create_api_key('ci', role='viewer')
    assert ok, data
    token = data['token']

    who = am.authenticate_api_token(token)
    assert who and who['role'] == 'viewer'

    on_disk = json.loads(settings_file.read_text())
    stored = [k for k in on_disk['api_keys'].values() if k.get('name') == 'ci'][0]
    assert isinstance(stored['last_used_at'], str) and stored['last_used_at'], (
        "last_used_at never reached the disk: the datetime object could not be "
        "serialised and the failure was swallowed")
    assert stored['last_used_at'].startswith('20') and 'T' in stored['last_used_at']


# --------------------------------------------------------------------------- #
# 2. status codes
# --------------------------------------------------------------------------- #

@pytest.fixture
def client_cert_app():
    def require_role_factory(min_role):
        def deco(fn):
            def wrapped(*args, **kwargs):
                user = getattr(request, 'current_user', None) or {}
                if ROLE_HIERARCHY.get(user.get('role'), -1) < ROLE_HIERARCHY.get(min_role, 999):
                    from flask import abort
                    abort(403)
                return fn(*args, **kwargs)
            return wrapped
        return deco
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=require_role_factory)
    cert_manager = MagicMock()
    cert_manager.get_certificate_metadata.return_value = None          # unknown id
    cert_manager.get_certificate_file.return_value = None              # no such file
    cert_manager.revoke_certificate.return_value = (False, 'already revoked')
    cert_manager.renew_certificate.return_value = (False, 'revoked certificates cannot be renewed', None)
    managers = {'auth': auth_manager, 'client_certificates': cert_manager,
                'ocsp': MagicMock(), 'crl': MagicMock(), 'settings': MagicMock()}
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    create_client_certificate_models(api)
    resources = create_client_certificate_resources(api, managers)
    ns = Namespace('client-certs')
    api.add_namespace(ns)
    ns.add_resource(resources['ClientCertificateCreate'], '/create')
    ns.add_resource(resources['ClientCertificateDetail'], '/<string:identifier>')
    ns.add_resource(resources['ClientCertificateDownload'], '/<string:identifier>/download/<string:file_type>')
    ns.add_resource(resources['ClientCertificateRevoke'], '/<string:identifier>/revoke')
    ns.add_resource(resources['ClientCertificateRenew'], '/<string:identifier>/renew')

    @app.before_request
    def _as_admin():
        request.current_user = {'username': 'admin', 'role': 'admin'}
    return app.test_client()


@pytest.mark.parametrize('method, path, body, expected', [
    ('get', '/api/client-certs/nope', None, 404),
    ('get', '/api/client-certs/../etc', None, 404),        # routing, still not 500
    ('post', '/api/client-certs/create', {}, 400),
    ('post', '/api/client-certs/create', {'common_name': 'x' * 65}, 400),
    ('post', '/api/client-certs/create', {'common_name': 'ok', 'days_valid': 'soon'}, 400),
    ('get', '/api/client-certs/nope/download/crt', None, 404),
    ('get', '/api/client-certs/abc/download/exe', None, 400),
    ('post', '/api/client-certs/abc/revoke', {}, 400),
    ('post', '/api/client-certs/abc/renew', None, 400),
])
def test_client_cert_handlers_send_the_status_they_meant(client_cert_app, method, path, body, expected):
    call = getattr(client_cert_app, method)
    r = call(path, json=body) if body is not None else call(path)
    assert r.status_code == expected, (r.status_code, r.get_data(as_text=True)[:200])
    assert r.status_code != 500
