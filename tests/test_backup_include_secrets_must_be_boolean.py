"""POST /api/backups/create must not read include_secrets with bool().

`include_secrets` chooses between a share-safe masked archive and a plaintext
dump of every credential and private key. It was read as
``bool(data.get('include_secrets', False))``, and ``bool("false")`` is True —
so a client sending the value as a JSON *string* (trivial from a shell or an
untyped template) asked for masked and received the plaintext dump. The route
now requires a real JSON boolean and refuses anything else with 400, so the
dump can only be produced by an explicit ``true``.
"""
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask, request
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources

pytestmark = [pytest.mark.unit]


def _passthrough(_role):
    def deco(fn):
        return fn
    return deco


@pytest.fixture
def client(tmp_path):
    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough)

    file_ops = MagicMock(cert_dir=Path(tmp_path))
    # Record what include_secrets the route forwarded, and return a filename so
    # the success path completes.
    file_ops.create_unified_backup.return_value = 'backup_x.zip'

    settings = MagicMock()
    settings.load_settings.return_value = {'email': 'a@b.c'}

    managers = {
        'auth': auth, 'settings': settings, 'file_ops': file_ops,
        'certificates': MagicMock(), 'cache': MagicMock(), 'dns': MagicMock(),
        'audit': None,
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)
    ns = Namespace('backups', description='backups')
    api.add_namespace(ns)
    ns.add_resource(resources['BackupCreate'], '/create')

    @app.before_request
    def _attach_user():
        request.current_user = {'username': 'op', 'role': 'admin',
                                'allowed_domains': None}

    return app.test_client(), file_ops


def _forwarded_include_secrets(file_ops):
    """The include_secrets keyword the route passed to create_unified_backup."""
    _, kwargs = file_ops.create_unified_backup.call_args
    return kwargs.get('include_secrets')


@pytest.mark.parametrize('bad', ['false', 'true', '0', '1', 'no', 'yes'])
def test_a_string_is_refused_not_coerced(client, bad):
    """The bug: 'false' must not become a plaintext dump. Any string is 400."""
    c, file_ops = client
    r = c.post('/api/backups/create', json={'include_secrets': bad})
    assert r.status_code == 400
    file_ops.create_unified_backup.assert_not_called()


def test_a_number_is_refused(client):
    c, file_ops = client
    r = c.post('/api/backups/create', json={'include_secrets': 1})
    assert r.status_code == 400
    file_ops.create_unified_backup.assert_not_called()


def test_boolean_true_produces_a_plaintext_dump(client):
    c, file_ops = client
    r = c.post('/api/backups/create', json={'include_secrets': True})
    assert r.status_code in (200, 201)
    assert _forwarded_include_secrets(file_ops) is True


def test_boolean_false_produces_a_masked_archive(client):
    c, file_ops = client
    r = c.post('/api/backups/create', json={'include_secrets': False})
    assert r.status_code in (200, 201)
    assert _forwarded_include_secrets(file_ops) is False


def test_absent_defaults_to_masked(client):
    """CONTROL: the common case (no flag) must still work and stay masked."""
    c, file_ops = client
    r = c.post('/api/backups/create', json={'reason': 'nightly'})
    assert r.status_code in (200, 201)
    assert _forwarded_include_secrets(file_ops) is False
