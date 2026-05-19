"""Regression test for issue #212.

The discussion at https://github.com/fabriziosalmi/certmate/discussions/183
documents the canonical scripting URL for fetching a single PEM file as::

    GET /api/certificates/<domain>/download/<cert|chain|fullchain|privkey>

But the route registered in factory.py only carried the query-string form
``/<domain>/download`` (consumed by ``?file=<name>.pem``). Path-style URLs
returned 404 — reported by SpeeDFireCZE as issue #212, "BUG: download
specific cert file thru API". The user reproduced it with the exact curl
example from discussion #183.

This test pins the new ``DownloadCertificateFile`` route so the documented
path-style URL works for every short name and applies the same role and
scope checks the query-string form already had (Sprint 1.5 audit
follow-up: viewer cannot pull private-key material).

No Docker; runs in-process.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock

from flask import Flask, request
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources


pytestmark = [pytest.mark.unit]


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
def app_with_path_download(cert_dir):
    """Flask test client with the path-style download route wired up.

    Bypasses ``require_role`` so per-file role gating is tested via the
    handler's own checks against ``request.current_user`` (set by
    ``_attach_user`` per test)."""
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.user_can_access_domain.return_value = True
    auth_manager.domain_matches_scope.return_value = True

    file_ops = MagicMock(cert_dir=Path(cert_dir))
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {}
    certificate_manager = MagicMock(cert_dir=Path(cert_dir))
    audit_logger = MagicMock()

    managers = {
        'auth': auth_manager,
        'settings': settings_manager,
        'certificates': certificate_manager,
        'file_ops': file_ops,
        'cache': MagicMock(),
        'dns': MagicMock(),
        'audit': audit_logger,
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)

    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(
        resources['DownloadCertificateFile'],
        '/<string:domain>/download/<string:file_type>',
    )

    return app, managers


def _attach_user(app, role):
    @app.before_request
    def _set_user():
        from flask import request as _r
        _r.current_user = {
            'username': f'fake_{role}',
            'role': role,
            'allowed_domains': None,
        }


class TestPathStyleDownload:
    """The documented ``/download/<short>`` URLs must work for the four
    short names and apply identical role gating to the query-string form."""

    @pytest.mark.parametrize('short,expected_body', [
        ('cert', b'PUBLIC-cert'),
        ('chain', b'PUBLIC-chain'),
        ('fullchain', b'PUBLIC-fullchain'),
    ])
    def test_viewer_can_pull_public_short_names(
        self, app_with_path_download, short, expected_body,
    ):
        app, _ = app_with_path_download
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get(f'/api/certificates/example.com/download/{short}')
        assert r.status_code == 200, r.data
        assert expected_body in r.data
        assert r.headers['Content-Type'] == 'application/x-pem-file'

    def test_viewer_cannot_pull_privkey_short_name(self, app_with_path_download):
        app, managers = app_with_path_download
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download/privkey')
        assert r.status_code == 403
        body = r.get_json()
        assert body['code'] == 'PRIVKEY_REQUIRES_OPERATOR'
        managers['audit'].log_authz_denied.assert_called()

    def test_viewer_cannot_pull_combined_short_name(self, app_with_path_download):
        app, managers = app_with_path_download
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download/combined')
        assert r.status_code == 403
        body = r.get_json()
        assert body['code'] == 'PRIVKEY_REQUIRES_OPERATOR'
        managers['audit'].log_authz_denied.assert_called()

    def test_operator_can_pull_privkey_short_name(self, app_with_path_download):
        app, _ = app_with_path_download
        _attach_user(app, 'operator')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download/privkey')
        assert r.status_code == 200
        assert b'PRIVATE-key' in r.data

    def test_operator_can_pull_combined_short_name(self, app_with_path_download):
        app, _ = app_with_path_download
        _attach_user(app, 'operator')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download/combined')
        assert r.status_code == 200
        # Combined = fullchain + privkey concatenated.
        assert b'PUBLIC-fullchain' in r.data
        assert b'PRIVATE-key' in r.data

    def test_unknown_short_name_returns_400(self, app_with_path_download):
        app, _ = app_with_path_download
        _attach_user(app, 'operator')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download/bogus')
        assert r.status_code == 400
        body = r.get_json()
        assert 'Invalid file type' in body['error']

    def test_path_short_name_does_not_accept_pem_suffix(self, app_with_path_download):
        """The documented contract is bare short names. ``fullchain.pem``
        as a path segment is NOT the documented form and must 400 so
        callers don't get a misleading "file not found" for what is a
        URL-shape error."""
        app, _ = app_with_path_download
        _attach_user(app, 'operator')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download/fullchain.pem')
        assert r.status_code == 400

    def test_missing_domain_returns_404(self, app_with_path_download):
        app, _ = app_with_path_download
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/nope.example.com/download/fullchain')
        assert r.status_code == 404

    def test_missing_file_on_disk_returns_404(self, app_with_path_download, cert_dir):
        # Delete chain.pem and ensure we 404 with a useful message rather
        # than crashing or 500ing.
        (Path(cert_dir) / 'example.com' / 'chain.pem').unlink()
        app, _ = app_with_path_download
        _attach_user(app, 'viewer')
        client = app.test_client()
        r = client.get('/api/certificates/example.com/download/chain')
        assert r.status_code == 404
