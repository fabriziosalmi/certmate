"""When create_backup_before_restore is requested, a failed pre-restore backup
must abort the restore, not proceed without a safety net.

The pre-restore backup exists so the restore is reversible. create_unified_backup
returns None on failure (an unwritable backup dir, for one), and the handler did
not check: it logged the None and ran the restore anyway, overwriting settings
and certificates irreversibly while having told the operator it made a backup
first. It now refuses with 500 and does not touch the instance.
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
def env(tmp_path):
    unified = tmp_path / 'backups' / 'unified'
    unified.mkdir(parents=True)
    (unified / 'good.zip').write_bytes(b'PK\x03\x04placeholder')

    file_ops = MagicMock(backup_dir=str(tmp_path / 'backups'))
    settings = MagicMock()
    settings.load_settings.return_value = {'email': 'a@b.c'}

    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough)
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
    ns.add_resource(resources['BackupRestore'], '/restore/<string:backup_type>')

    @app.before_request
    def _u():
        request.current_user = {'username': 'op', 'role': 'admin',
                                'allowed_domains': None}

    return app.test_client(), file_ops


def test_a_failed_pre_backup_aborts_the_restore(env):
    client, file_ops = env
    file_ops.create_unified_backup.return_value = None       # pre-backup fails

    r = client.post('/api/backups/restore/unified',
                    json={'filename': 'good.zip',
                          'create_backup_before_restore': True})

    assert r.status_code == 500
    file_ops.restore_unified_backup.assert_not_called()      # nothing destroyed


def test_a_successful_pre_backup_lets_the_restore_run(env):
    """CONTROL: when the pre-backup succeeds, the restore proceeds."""
    client, file_ops = env
    file_ops.create_unified_backup.return_value = 'pre_restore_x.zip'
    file_ops.restore_unified_backup.return_value = True

    r = client.post('/api/backups/restore/unified',
                    json={'filename': 'good.zip',
                          'create_backup_before_restore': True})

    assert r.status_code in (200, 201)
    file_ops.restore_unified_backup.assert_called_once()


def test_opting_out_skips_the_pre_backup_and_restores(env):
    """CONTROL: create_backup_before_restore=false proceeds with no pre-backup,
    so the abort cannot block an operator who deliberately opted out."""
    client, file_ops = env
    file_ops.restore_unified_backup.return_value = True

    r = client.post('/api/backups/restore/unified',
                    json={'filename': 'good.zip',
                          'create_backup_before_restore': False})

    assert r.status_code in (200, 201)
    file_ops.create_unified_backup.assert_not_called()
    file_ops.restore_unified_backup.assert_called_once()
