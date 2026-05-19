"""Regression tests for the domain validation gaps surfaced by the
internal security audit (May 2026).

Before this fix:

* ``POST /api/certificates/create`` and the web equivalents
  (``/api/web/certificates/create``, ``/api/web/certificates/batch``)
  validated only whitespace and the ``http://`` URL prefix on the
  primary ``domain`` body field. ``validate_domain()`` ran on every
  SAN entry but NOT on the primary, so a payload like
  ``{"domain": "../poisoned", ...}`` reached
  ``CertificateManager.create_certificate`` and the call
  ``cert_output_dir = cert_dir / domain ; mkdir(parents=True, ...)``
  created a directory above the cert root. Worse: the malicious
  ``domain`` was then persisted into ``settings.json`` via
  ``settings_manager.update`` and replayed by ``check_renewals``
  on every renewal tick.

* ``POST /api/certificates/<domain>/renew`` and
  ``GET /api/certificates/<domain>/dns-alias-check`` did not call
  ``_validate_domain_path`` (other ``<domain>``-bearing resources do).
  Flask's URL routing today scrubs ``/`` from a ``<string:domain>``
  slot, but the only line of defence was the routing layer — once a
  poisoned domain was persisted via the gap above, the
  ``check_renewals`` background loop would replay it through
  ``renew_certificate`` unchecked.

The fix tightens the WRITE boundary: ``validate_domain()`` runs on
the primary in every create path, and ``_validate_domain_path()``
runs on every ``<domain>`` handler. Defence in depth: the validator
on the read side did not change.
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
    """An on-disk cert root with one existing domain."""
    d = tmp_path / 'example.com'
    d.mkdir()
    (d / 'fullchain.pem').write_text('FAKE-fullchain')
    return tmp_path


def _make_app(cert_dir):
    """Flask test client wiring DownloadCertificate-style resources
    so we can exercise CreateCertificate / RenewCertificate /
    CertificateDNSAliasCheck handlers with their decorators bypassed."""
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.user_can_access_domain.return_value = True
    auth_manager.domain_matches_scope.return_value = True

    file_ops = MagicMock(cert_dir=Path(cert_dir))
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'email': 'ops@example.com',
        'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
    }
    certificate_manager = MagicMock(cert_dir=Path(cert_dir))
    certificate_manager.create_certificate.return_value = {'status': 'ok'}
    certificate_manager.renew_certificate.return_value = {'dns_provider': 'cloudflare', 'duration': 1.0}
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
    ns.add_resource(resources['CreateCertificate'], '/create')
    ns.add_resource(resources['RenewCertificate'], '/<string:domain>/renew')
    ns.add_resource(resources['CertificateDNSAliasCheck'], '/<string:domain>/dns-alias-check')

    @app.before_request
    def _attach_user():
        request.current_user = {
            'username': 'fake_operator',
            'role': 'operator',
            'allowed_domains': None,
        }

    return app, managers


class TestCreateCertificateRejectsPathTraversalDomain:
    """The primary ``domain`` field on the create endpoint must pass
    ``validate_domain()`` before any side effect — directory creation,
    settings persistence or certbot invocation. ``../poisoned`` is the
    canonical exploit shape; verify it is rejected at the API boundary,
    not just one layer down."""

    @pytest.mark.parametrize('bad_domain', [
        '../poisoned',
        '../../etc/passwd',
        '..',
        'foo/bar',
        'foo\\bar',
        'foo;bar',
        'with space.example.com',  # spaces always rejected, but pin it
        '\x00null.example.com',
    ])
    def test_create_rejects_invalid_domain(self, cert_dir, bad_domain):
        app, managers = _make_app(cert_dir)
        client = app.test_client()
        r = client.post('/api/certificates/create', json={
            'domain': bad_domain,
            'dns_provider': 'cloudflare',
            'account_id': 'e2e',
        })
        assert r.status_code == 400, r.data
        body = r.get_json()
        assert 'Invalid domain' in body['error'] or 'Invalid domain format' in body['error']
        # Critical: the create path must never have reached the cert
        # manager — that's the layer that would have built the unsafe
        # Path and persisted into settings.json.
        managers['certificates'].create_certificate.assert_not_called()

    def test_create_accepts_valid_apex(self, cert_dir):
        app, managers = _make_app(cert_dir)
        client = app.test_client()
        r = client.post('/api/certificates/create', json={
            'domain': 'shiny-new.example.com',
            'dns_provider': 'cloudflare',
            'account_id': 'e2e',
        })
        assert r.status_code in (200, 201), r.data
        managers['certificates'].create_certificate.assert_called_once()

    def test_create_accepts_wildcard(self, cert_dir):
        app, managers = _make_app(cert_dir)
        client = app.test_client()
        r = client.post('/api/certificates/create', json={
            'domain': '*.example.com',
            'dns_provider': 'cloudflare',
            'account_id': 'e2e',
        })
        assert r.status_code in (200, 201), r.data
        managers['certificates'].create_certificate.assert_called_once()


class TestRenewCertificateValidatesDomain:
    """``RenewCertificate`` handler must call ``_validate_domain_path``
    on its ``<domain>`` path param, mirroring the other
    ``<domain>``-bearing resources. Defence against a poisoned domain
    surviving in ``settings.json`` from an older permissive create
    path and being replayed by ``check_renewals``."""

    def test_renew_rejects_traversal_domain(self, cert_dir):
        app, managers = _make_app(cert_dir)
        client = app.test_client()
        # werkzeug URL normalisation already strips '..' from the
        # path segment, so we go in through .test_client() with an
        # already-decoded path that bypasses normalisation. The point
        # is to lock the handler contract independently of the
        # routing layer.
        r = client.open('/api/certificates/..poisoned/renew', method='POST')
        assert r.status_code == 400
        managers['certificates'].renew_certificate.assert_not_called()

    def test_renew_accepts_valid_domain(self, cert_dir):
        app, managers = _make_app(cert_dir)
        client = app.test_client()
        r = client.post('/api/certificates/example.com/renew')
        assert r.status_code == 200
        managers['certificates'].renew_certificate.assert_called_once_with(
            'example.com', force=False,
        )


class TestDNSAliasCheckValidatesDomain:
    """Same contract for ``CertificateDNSAliasCheck.get``."""

    def test_dns_alias_check_rejects_traversal_domain(self, cert_dir):
        app, managers = _make_app(cert_dir)
        client = app.test_client()
        r = client.get('/api/certificates/..poisoned/dns-alias-check')
        assert r.status_code == 400
        managers['certificates'].get_certificate_info.assert_not_called()


class TestCreateCertificatePoisonedDomainDoesNotPersist:
    """The most important property of the fix: a rejected create must
    NOT touch ``settings_manager.update``. Otherwise the malicious
    domain would survive into background renewals (via
    ``check_renewals``), which is the actual exploit chain the audit
    surfaced. Pin it."""

    def test_invalid_domain_does_not_call_settings_update(self, cert_dir):
        app, managers = _make_app(cert_dir)
        client = app.test_client()
        r = client.post('/api/certificates/create', json={
            'domain': '../escape',
            'dns_provider': 'cloudflare',
            'account_id': 'e2e',
        })
        assert r.status_code == 400
        managers['settings'].update.assert_not_called()
