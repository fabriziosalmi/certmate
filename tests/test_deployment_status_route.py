from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
import modules.api.resources as api_resources_module


pytestmark = [pytest.mark.unit]


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


def _build_app(managers):
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)

    ns_certificates = Namespace('certificates', description='Certificate operations')
    api.add_namespace(ns_certificates)
    ns_certificates.add_resource(resources['CertificateDeploymentStatus'], '/<string:domain>/deployment-status')
    return app


def test_deployment_status_route_exists_and_returns_match(tmp_path, monkeypatch):
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': MagicMock(
            cert_dir=Path(tmp_path),
            storage_manager=None,
            get_certificate_info=MagicMock(return_value={'exists': True}),
        ),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(
            get_deployment_status=MagicMock(return_value=None),
            set_deployment_status=MagicMock(),
        ),
        'dns': MagicMock(),
    }

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'other',
    )
    monkeypatch.setattr(
        api_resources_module,
        '_probe_https_certificate',
        lambda _domain: {'reachable': True, 'certificate_bytes': b'expected-cert-bytes'},
    )

    app = _build_app(managers)
    client = app.test_client()

    response = client.get(f'/api/certificates/{domain}/deployment-status')

    assert response.status_code == 200
    body = response.get_json()
    assert body['domain'] == domain
    assert body['deployed'] is True
    assert body['reachable'] is True
    assert body['certificate_match'] is True
    assert body['method'] == 'https-tls'


def test_deployment_status_refresh_bypasses_cache(tmp_path, monkeypatch):
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    cache_manager = MagicMock(
        get_deployment_status=MagicMock(return_value={
            'domain': domain,
            'deployed': True,
            'reachable': True,
            'certificate_match': True,
        }),
        set_deployment_status=MagicMock(),
        remove_from_cache=MagicMock(),
    )

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': MagicMock(
            cert_dir=Path(tmp_path),
            storage_manager=None,
            get_certificate_info=MagicMock(return_value={'exists': True}),
        ),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': cache_manager,
        'dns': MagicMock(),
    }

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'other',
    )
    monkeypatch.setattr(
        api_resources_module,
        '_probe_https_certificate',
        lambda _domain: {'reachable': True, 'certificate_bytes': b'expected-cert-bytes'},
    )

    app = _build_app(managers)
    client = app.test_client()

    response = client.get(f'/api/certificates/{domain}/deployment-status?refresh=1')

    assert response.status_code == 200
    body = response.get_json()
    assert body['certificate_match'] is True
    cache_manager.remove_from_cache.assert_called_once_with(domain)
    cache_manager.get_deployment_status.assert_not_called()
