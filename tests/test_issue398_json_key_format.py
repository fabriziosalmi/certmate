"""Issue #398: ?format=json&key_format=pkcs1 returns the legacy key inline.

``key_format=pkcs1`` (added for #233) converts certbot's PKCS#8 key into the
legacy PKCS#1/SEC1 form, but was rejected unless combined with
``?file=privkey.pem``. An automation that wanted the whole bundle *and* the
legacy key therefore had to make a second call and stage the key through a
file on disk — the exact complaint in #398.

The legacy key is now added to the JSON **alongside** the untouched
``private_key_pem``, so nothing that already consumes ``format=json`` changes.

No Docker; runs in-process.
"""
import pytest
from pathlib import Path
from unittest.mock import MagicMock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from flask import Flask
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources

pytestmark = [pytest.mark.unit]


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


def _pkcs8_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()


def _make_app(tmp_path, privkey_pem):
    d = tmp_path / 'example.com'
    d.mkdir()
    (d / 'cert.pem').write_text('PUBLIC-cert')
    (d / 'chain.pem').write_text('PUBLIC-chain')
    (d / 'fullchain.pem').write_text('PUBLIC-fullchain')
    (d / 'privkey.pem').write_text(privkey_pem)

    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth.user_can_access_domain.return_value = True
    auth.domain_matches_scope.return_value = True

    managers = {
        'auth': auth,
        'settings': MagicMock(load_settings=MagicMock(return_value={})),
        'certificates': MagicMock(cert_dir=Path(tmp_path)),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(),
        'dns': MagicMock(),
        'audit': MagicMock(),
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)
    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['DownloadCertificate'], '/<string:domain>/download')

    @app.before_request
    def _set_user():
        from flask import request as _r
        _r.current_user = {'username': 'op', 'role': 'operator', 'allowed_domains': None}

    return app


@pytest.fixture
def rsa_app(tmp_path):
    return _make_app(tmp_path, _pkcs8_pem(
        rsa.generate_private_key(public_exponent=65537, key_size=2048)))


class TestJsonKeyFormat:
    def test_pkcs1_is_added_without_disturbing_the_existing_field(self, rsa_app):
        """The whole point: one call, and no change for existing consumers."""
        with rsa_app.test_client() as c:
            res = c.get('/api/certificates/example.com/download'
                        '?format=json&key_format=pkcs1')
        assert res.status_code == 200
        body = res.get_json()

        assert 'BEGIN RSA PRIVATE KEY' in body['private_key_pkcs1_pem']
        # The original PKCS#8 key is still there, untouched.
        assert 'BEGIN PRIVATE KEY' in body['private_key_pem']
        # And the rest of the bundle is unaffected.
        assert body['cert_pem'] == 'PUBLIC-cert'
        assert body['fullchain_pem'] == 'PUBLIC-fullchain'

    def test_absent_by_default(self, rsa_app):
        """No key_format means exactly the previous response shape."""
        with rsa_app.test_client() as c:
            body = c.get('/api/certificates/example.com/download?format=json').get_json()
        assert 'private_key_pkcs1_pem' not in body
        assert 'BEGIN PRIVATE KEY' in body['private_key_pem']

    def test_pkcs8_is_a_no_op(self, rsa_app):
        """pkcs8 is what is already on disk, so there is nothing to add."""
        with rsa_app.test_client() as c:
            res = c.get('/api/certificates/example.com/download'
                        '?format=json&key_format=pkcs8')
        assert res.status_code == 200
        assert 'private_key_pkcs1_pem' not in res.get_json()

    def test_invalid_key_format_still_rejected(self, rsa_app):
        with rsa_app.test_client() as c:
            res = c.get('/api/certificates/example.com/download'
                        '?format=json&key_format=der')
        assert res.status_code == 400

    def test_ecdsa_yields_sec1_which_is_why_the_field_is_not_named_rsa(self, tmp_path):
        """CertMate issues ECDSA by default, and the traditional form for an
        EC key is SEC1 — a field called private_key_rsa_pem (as originally
        proposed in #398) would hold "BEGIN EC PRIVATE KEY" for most users."""
        app = _make_app(tmp_path, _pkcs8_pem(ec.generate_private_key(ec.SECP256R1())))
        with app.test_client() as c:
            body = c.get('/api/certificates/example.com/download'
                         '?format=json&key_format=pkcs1').get_json()
        assert 'BEGIN EC PRIVATE KEY' in body['private_key_pkcs1_pem']

    def test_unconvertible_key_is_422_not_500(self, tmp_path):
        """Ed25519 has no traditional encoding; the bundle must fail cleanly."""
        app = _make_app(tmp_path, _pkcs8_pem(ed25519.Ed25519PrivateKey.generate()))
        with app.test_client() as c:
            res = c.get('/api/certificates/example.com/download'
                        '?format=json&key_format=pkcs1')
        assert res.status_code == 422
        assert 'PKCS#1' in res.get_json()['error']

    def test_key_format_with_a_public_file_is_still_rejected(self, rsa_app):
        """Relaxing the guard for format=json must not relax it for files."""
        with rsa_app.test_client() as c:
            res = c.get('/api/certificates/example.com/download'
                        '?file=fullchain.pem&key_format=pkcs1')
        assert res.status_code == 400
