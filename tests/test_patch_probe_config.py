"""PATCH /api/certificates/<domain> must not clobber deployment-probe config.

The probe config (deployment_port / deployment_protocol, #328) lives in the
cert's metadata.json. A PATCH that only changes the DNS provider must leave it
untouched — keying the set/delete on ``value is not None`` (rather than on the
key's presence in the payload) made a DNS-only PATCH silently wipe the probe
config, so an SMTP cert would fall back to https-tls:443. An explicit JSON null
still deletes the key.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources

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
    ns = Namespace('certificates', description='Certificate operations')
    api.add_namespace(ns)
    ns.add_resource(resources['CertificateDetail'], '/<string:domain>')
    return app


def _managers(tmp_path, saved):
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'cert')
    (cert_dir / 'metadata.json').write_text(json.dumps({
        'dns_provider': 'cloudflare',
        'deployment_port': 587,
        'deployment_protocol': 'smtp-starttls',
    }))

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.user_can_access_domain = MagicMock(return_value=True)

    certificate_manager = MagicMock()
    certificate_manager.cert_dir = Path(tmp_path)
    # Capture exactly what would be persisted.
    certificate_manager._save_metadata = MagicMock(
        side_effect=lambda _d, md: saved.update(md) or True
    )

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {'domains': [{'domain': domain}]}

    dns_manager = MagicMock()
    dns_manager.get_dns_provider_account_config = MagicMock(
        return_value=({'token': 'x'}, None)
    )

    return {
        'auth': auth_manager,
        'settings': settings_manager,
        'certificates': certificate_manager,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(),
        'dns': dns_manager,
    }


def test_dns_only_patch_preserves_probe_config(tmp_path):
    saved = {}
    app = _build_app(_managers(tmp_path, saved))

    resp = app.test_client().patch(
        '/api/certificates/example.com',
        json={'dns_provider': 'route53'},
    )

    assert resp.status_code == 200
    # The bug: these were deleted by a DNS-only PATCH.
    assert saved.get('deployment_port') == 587
    assert saved.get('deployment_protocol') == 'smtp-starttls'
    assert saved.get('dns_provider') == 'route53'


def test_explicit_null_deletes_probe_config(tmp_path):
    saved = {}
    app = _build_app(_managers(tmp_path, saved))

    resp = app.test_client().patch(
        '/api/certificates/example.com',
        json={'deployment_port': None, 'deployment_protocol': None},
    )

    assert resp.status_code == 200
    assert 'deployment_port' not in saved
    assert 'deployment_protocol' not in saved


def test_patch_sets_probe_config(tmp_path):
    saved = {}
    app = _build_app(_managers(tmp_path, saved))

    resp = app.test_client().patch(
        '/api/certificates/example.com',
        json={'deployment_port': 25, 'deployment_protocol': 'smtp-starttls'},
    )

    assert resp.status_code == 200
    assert saved.get('deployment_port') == 25
    assert saved.get('deployment_protocol') == 'smtp-starttls'


def test_patch_rejects_out_of_range_port(tmp_path):
    saved = {}
    app = _build_app(_managers(tmp_path, saved))

    resp = app.test_client().patch(
        '/api/certificates/example.com',
        json={'deployment_port': 99999},
    )

    assert resp.status_code == 400


def test_patch_sets_deployment_host(tmp_path):
    """deployment_host is the supported way to verify a wildcard cert (#381):
    it is persisted to metadata and echoed back."""
    saved = {}
    app = _build_app(_managers(tmp_path, saved))

    resp = app.test_client().patch(
        '/api/certificates/example.com',
        json={'deployment_host': 'www.example.com'},
    )

    assert resp.status_code == 200
    assert saved.get('deployment_host') == 'www.example.com'
    assert resp.get_json().get('deployment_host') == 'www.example.com'


def test_patch_rejects_bad_deployment_host(tmp_path):
    """A probe target is a bare hostname: reject scheme/path/whitespace and a
    wildcard label (you deploy a cert on a concrete name)."""
    saved = {}
    app = _build_app(_managers(tmp_path, saved))
    client = app.test_client()
    for bad in ('https://www.example.com', 'www.example.com/x', '*.example.com', 'a b'):
        resp = client.patch(
            '/api/certificates/example.com',
            json={'deployment_host': bad},
        )
        assert resp.status_code == 400, bad
        assert 'deployment_host' not in saved


def test_patch_null_deletes_deployment_host(tmp_path):
    saved = {}
    managers = _managers(tmp_path, saved)
    # Seed the on-disk metadata with a host, then delete it with a null PATCH.
    metadata_file = tmp_path / 'example.com' / 'metadata.json'
    metadata_file.write_text(json.dumps({
        'dns_provider': 'cloudflare',
        'deployment_host': 'www.example.com',
    }))
    app = _build_app(managers)

    resp = app.test_client().patch(
        '/api/certificates/example.com',
        json={'deployment_host': None},
    )
    assert resp.status_code == 200
    assert 'deployment_host' not in saved
