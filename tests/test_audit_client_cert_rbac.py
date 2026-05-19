"""Regression tests for the client-certificate API role gating gap
(internal security audit, May 2026, finding H1).

Before this fix every Resource in ``modules/api/client_certificates.py``
used::

    method_decorators = [auth_manager.require_auth]

``require_auth`` (modules/core/auth.py:703-718) only authenticates the
caller — it does NOT check role. So a ``viewer``-role API key (the
safest tier the admin can hand out) could:

- ``POST /api/client-certs/create`` — mint a CA-signed mTLS identity
- ``POST /api/client-certs/<id>/revoke`` — revoke any client identity
- ``POST /api/client-certs/<id>/renew`` — re-mint an identity
- ``POST /api/client-certs/batch`` — batch up to 100 identities
- ``GET /api/client-certs/<id>/download/key`` — pull the private key

The fix mirrors the TLS-side `CertificateManager` role stratification
that already exists for server certificates:

- reads (list / detail / stats / public-material download) — viewer
- mints / renews / batch — operator
- revoke (destructive, parallel to TLS-cert delete) — admin
- private-key download — operator+ (per-file gate inside the handler,
  mirroring the ``_PRIVATE_KEY_FILES`` gate on the TLS path)

OCSP and CRL responders are RFC-public and remain unauthenticated; the
audit confirmed these are intentional, and the source comments now
say so explicitly.
"""

import pytest
from unittest.mock import MagicMock

from flask import Flask, request
from flask_restx import Api, Namespace

from modules.api.client_certificates import (
    create_client_certificate_models,
    create_client_certificate_resources,
)
from modules.core.auth import ROLE_HIERARCHY


pytestmark = [pytest.mark.unit]


@pytest.fixture
def app_with_client_cert_routes():
    """Flask test client with every client-cert Resource wired up and
    a stub ``current_user`` injected before each request — bypasses the
    real auth pipeline so we can measure the role decorator's behaviour
    directly. The auth_manager's ``require_role`` is mocked to behave
    like the production decorator: it checks the caller's role against
    the configured floor and abort(403)s if below."""

    def require_role_factory(min_role):
        def deco(fn):
            def wrapped(*args, **kwargs):
                user = getattr(request, 'current_user', None) or {}
                role = user.get('role')
                level = ROLE_HIERARCHY.get(role, -1)
                floor = ROLE_HIERARCHY.get(min_role, 999)
                if level < floor:
                    from flask import abort
                    abort(403)
                return fn(*args, **kwargs)
            return wrapped
        return deco

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=require_role_factory)
    auth_manager.require_auth = lambda fn: fn  # not used after the fix

    cert_manager = MagicMock()
    cert_manager.list_client_certificates.return_value = []
    cert_manager.create_client_certificate.return_value = (
        True, None, {'identifier': 'fake-id', 'common_name': 'alice'},
    )
    cert_manager.get_certificate_metadata.return_value = {'identifier': 'fake-id'}
    cert_manager.get_certificate_file.return_value = b'-----BEGIN ...-----'
    cert_manager.revoke_certificate.return_value = (True, None)
    cert_manager.renew_certificate.return_value = (
        True, None, {'identifier': 'fake-id'},
    )
    cert_manager.get_statistics.return_value = {'total': 0}

    managers = {
        'auth': auth_manager,
        'client_certificates': cert_manager,
        'ocsp': MagicMock(),
        'crl': MagicMock(),
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    create_client_certificate_models(api)
    resources = create_client_certificate_resources(api, managers)

    ns = Namespace('client-certs', description='client certs')
    api.add_namespace(ns)
    ns.add_resource(resources['ClientCertificateList'], '')
    ns.add_resource(resources['ClientCertificateCreate'], '/create')
    ns.add_resource(resources['ClientCertificateDetail'], '/<string:identifier>')
    ns.add_resource(resources['ClientCertificateDownload'], '/<string:identifier>/download/<string:file_type>')
    ns.add_resource(resources['ClientCertificateRevoke'], '/<string:identifier>/revoke')
    ns.add_resource(resources['ClientCertificateRenew'], '/<string:identifier>/renew')
    ns.add_resource(resources['ClientCertificateStatistics'], '/stats')
    ns.add_resource(resources['ClientCertificateBatch'], '/batch')

    return app, managers


def _as(app, role):
    @app.before_request
    def _set_user():
        request.current_user = {
            'username': f'fake_{role}', 'role': role, 'allowed_domains': None,
        }


class TestViewerCannotMintOrRevoke:
    """The CRITICAL finding: viewer must NOT reach create / revoke /
    renew / batch endpoints. Pin a 403 on every one."""

    @pytest.mark.parametrize('method,path,payload', [
        ('POST', '/api/client-certs/create', {'common_name': 'alice'}),
        ('POST', '/api/client-certs/abc/revoke', {'reason': 'compromise'}),
        ('POST', '/api/client-certs/abc/renew', {}),
        ('POST', '/api/client-certs/batch', {'headers': ['common_name'], 'rows': [['alice']]}),
    ])
    def test_viewer_is_rejected(self, app_with_client_cert_routes, method, path, payload):
        app, managers = app_with_client_cert_routes
        _as(app, 'viewer')
        client = app.test_client()
        r = client.open(path, method=method, json=payload)
        assert r.status_code == 403, r.data
        # And the underlying manager was NOT invoked — the role gate
        # must short-circuit before any side effect.
        managers['client_certificates'].create_client_certificate.assert_not_called()
        managers['client_certificates'].revoke_certificate.assert_not_called()
        managers['client_certificates'].renew_certificate.assert_not_called()


class TestViewerCanRead:
    """Reads (list / detail / stats) must still work for viewer. The
    fix tightens write paths, not the read floor."""

    def test_viewer_can_list(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'viewer')
        # The list route is registered at the namespace base path (''),
        # so the canonical URL has no trailing slash.
        r = app.test_client().get('/api/client-certs')
        assert r.status_code == 200, r.data

    def test_viewer_can_read_detail(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'viewer')
        r = app.test_client().get('/api/client-certs/abc')
        assert r.status_code == 200, r.data

    def test_viewer_can_read_stats(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'viewer')
        r = app.test_client().get('/api/client-certs/stats')
        assert r.status_code == 200, r.data


class TestPrivateKeyDownloadStratification:
    """Public material (crt / csr) — viewer-OK. Private key (key) —
    operator+ floor. Mirrors the TLS-side DownloadCertificate /
    DownloadCertificateFile contract; the per-file gate runs inside
    the handler so the route itself stays at the viewer decorator
    floor (consistent with the rest of the file)."""

    @pytest.mark.parametrize('file_type', ['crt', 'csr'])
    def test_viewer_can_pull_public_material(self, app_with_client_cert_routes, file_type):
        app, _ = app_with_client_cert_routes
        _as(app, 'viewer')
        r = app.test_client().get(f'/api/client-certs/abc/download/{file_type}')
        assert r.status_code == 200

    def test_viewer_cannot_pull_private_key(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'viewer')
        r = app.test_client().get('/api/client-certs/abc/download/key')
        assert r.status_code == 403

    def test_operator_can_pull_private_key(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'operator')
        r = app.test_client().get('/api/client-certs/abc/download/key')
        assert r.status_code == 200


class TestOperatorAndAdminPaths:
    """Operator can mint / renew / batch; admin can also revoke.
    Operator is below admin so the revoke 403 is the explicit test
    that the stratification matters."""

    def test_operator_can_create(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'operator')
        r = app.test_client().post('/api/client-certs/create', json={'common_name': 'bob'})
        assert r.status_code == 201, r.data

    def test_operator_cannot_revoke(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'operator')
        r = app.test_client().post('/api/client-certs/abc/revoke', json={'reason': 'compromise'})
        assert r.status_code == 403, r.data

    def test_admin_can_revoke(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'admin')
        r = app.test_client().post('/api/client-certs/abc/revoke', json={'reason': 'compromise'})
        assert r.status_code == 200, r.data

    def test_operator_can_renew(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'operator')
        r = app.test_client().post('/api/client-certs/abc/renew')
        assert r.status_code == 201, r.data

    def test_operator_can_batch(self, app_with_client_cert_routes):
        app, _ = app_with_client_cert_routes
        _as(app, 'operator')
        r = app.test_client().post(
            '/api/client-certs/batch',
            json={'headers': ['common_name'], 'rows': [['alice']]},
        )
        # The batch handler returns 201 on success (matching the
        # single-cert create endpoint shape).
        assert r.status_code == 201, r.data
