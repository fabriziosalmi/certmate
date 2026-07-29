"""API-level coverage for #465: the encrypted PKCS#12 bundle is included in the
server certificate ZIP, and client certificates gain a gated .pfx download.

In-process (no Docker), mirroring tests/test_issue212_download_path_style.py:
require_role is bypassed so the handler's own per-file role gate is exercised
against request.current_user.
"""

import io
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Namespace
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
from modules.api.client_certificates import create_client_certificate_resources
from modules.core.client_certificates import ClientCertificateManager

pytestmark = [pytest.mark.unit]


def _passthrough(_min_role):
    def deco(fn):
        return fn
    return deco


def _cert_and_key(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def _attach_user(app, role):
    @app.before_request
    def _set_user():
        from flask import request as _r
        _r.current_user = {'username': f'u_{role}', 'role': role,
                           'allowed_domains': None}


# --------------------------------------------------------------------------- #
# Server ZIP includes cert.pfx
# --------------------------------------------------------------------------- #

@pytest.fixture
def server_app(tmp_path):
    dom = tmp_path / 'example.com'
    dom.mkdir()
    for f in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
        (dom / f).write_text(f'DATA-{f}')
    (dom / 'cert.pfx').write_bytes(b'PKCS12-BLOB')

    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough)
    auth.user_can_access_domain.return_value = True
    auth.domain_matches_scope.return_value = True
    settings = MagicMock()
    settings.load_settings.return_value = {}

    managers = {
        'auth': auth, 'settings': settings,
        'certificates': MagicMock(cert_dir=Path(tmp_path)),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(), 'dns': MagicMock(), 'audit': MagicMock(),
    }
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    resources = create_api_resources(api, create_api_models(api), managers)
    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['DownloadCertificate'], '/<string:domain>/download')
    return app


def test_private_zip_includes_pfx(server_app):
    _attach_user(server_app, 'operator')
    r = server_app.test_client().get('/api/certificates/example.com/download')
    assert r.status_code == 200, r.data
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        assert 'cert.pfx' in zf.namelist()
        assert zf.read('cert.pfx') == b'PKCS12-BLOB'


def test_public_zip_excludes_pfx(server_app):
    _attach_user(server_app, 'viewer')
    r = server_app.test_client().get(
        '/api/certificates/example.com/download?include_private=0')
    assert r.status_code == 200, r.data
    with zipfile.ZipFile(io.BytesIO(r.data)) as zf:
        assert 'cert.pfx' not in zf.namelist()
        assert 'privkey.pem' not in zf.namelist()


# --------------------------------------------------------------------------- #
# Client certificate .pfx download
# --------------------------------------------------------------------------- #

@pytest.fixture
def client_app(tmp_path):
    ca_pem, _ = _cert_and_key('Client CA')
    ca_path = tmp_path / 'ca.crt'
    ca_path.write_bytes(ca_pem)
    ccm = ClientCertificateManager(
        client_certs_dir=tmp_path / 'cc',
        private_ca=SimpleNamespace(ca_cert_path=ca_path))
    d = ccm.client_certs_dir / 'api' / 'alice'
    d.mkdir(parents=True)
    crt, key = _cert_and_key('alice')
    (d / 'alice.crt').write_bytes(crt)
    (d / 'alice.key').write_bytes(key)

    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough)
    settings = MagicMock()
    settings.load_settings.return_value = {'pfx_password': 'zip-pw'}

    managers = {
        'client_certificates': ccm, 'auth': auth, 'settings': settings,
        'ocsp': MagicMock(), 'crl': MagicMock(),
    }
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    resources = create_client_certificate_resources(api, managers)
    ns = Namespace('client-certs', description='cc')
    api.add_namespace(ns)
    ns.add_resource(resources['ClientCertificateDownload'],
                    '/<string:identifier>/download/<string:file_type>')
    return app, settings


def test_client_pfx_download_operator(client_app):
    app, _ = client_app
    _attach_user(app, 'operator')
    r = app.test_client().get('/api/client-certs/alice/download/pfx')
    assert r.status_code == 200, r.data
    assert r.headers['Content-Type'] == 'application/x-pkcs12'
    key, cert, _chain = pkcs12.load_key_and_certificates(r.data, b'zip-pw')
    assert key is not None and cert is not None


def test_client_pfx_denied_for_viewer(client_app):
    app, _ = client_app
    _attach_user(app, 'viewer')
    r = app.test_client().get('/api/client-certs/alice/download/pfx')
    assert r.status_code == 403


def test_client_pfx_requires_password(client_app):
    app, settings = client_app
    settings.load_settings.return_value = {'pfx_password': ''}
    _attach_user(app, 'operator')
    r = app.test_client().get('/api/client-certs/alice/download/pfx')
    assert r.status_code == 400


def test_client_pfx_unknown_identifier_404(client_app):
    app, _ = client_app
    _attach_user(app, 'operator')
    r = app.test_client().get('/api/client-certs/nobody/download/pfx')
    assert r.status_code == 404
