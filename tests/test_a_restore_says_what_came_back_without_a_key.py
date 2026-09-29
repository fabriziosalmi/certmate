"""A restore says, at once, which certificates came back without a key (#966).

A share-safe archive carries no private keys, and only a reissue repairs a
certificate without one. The operator learned that from the first nightly
sweep, as a generic certbot failure. The decision recorded on #966: the
restore itself says so, with the list and the next step.
"""
import json

import pytest

from modules.core.file_operations import FileOperations

pytestmark = [pytest.mark.unit]


def _ops(root):
    dirs = [root / n for n in ('certificates', 'data', 'backups', 'logs')]
    for d in dirs:
        d.mkdir(parents=True)
    return FileOperations(*dirs)


def _cert(ops, domain, *, key=True, metadata=None):
    d = ops.cert_dir / domain
    d.mkdir()
    for name in ('cert.pem', 'chain.pem', 'fullchain.pem'):
        (d / name).write_text(name)
    if key:
        (d / 'privkey.pem').write_text('key')
    (d / 'metadata.json').write_text(json.dumps(metadata or {'domain': domain}))


def _round_trip(tmp_path, *, include_secrets):
    src = _ops(tmp_path / 'src')
    _cert(src, 'a.example.com')
    _cert(src, 'b.example.com')
    _cert(src, 'appliance.example.com', key=False,
          metadata={'domain': 'appliance.example.com', 'key_management': 'external'})
    name = src.create_unified_backup({'domains': ['a.example.com', 'b.example.com']},
                                     'test', include_secrets=include_secrets)
    dst = _ops(tmp_path / 'dst')
    assert dst.restore_unified_backup(str(src.backup_dir / 'unified' / name)) is True
    return dst


def test_a_share_safe_restore_lists_every_certificate_left_without_a_key(tmp_path):
    """THE regression. The CSR-only certificate is not listed: its key was
    never here, by design."""
    dst = _round_trip(tmp_path, include_secrets=False)
    assert dst.last_restore_keyless == ['a.example.com', 'b.example.com']


def test_a_full_restore_lists_nothing(tmp_path):
    """CONTROL: the disaster-recovery archive carries the keys."""
    dst = _round_trip(tmp_path, include_secrets=True)
    assert dst.last_restore_keyless == []


def _api(file_ops):
    from unittest.mock import MagicMock

    from flask import Flask, request
    from flask_restx import Api, Namespace

    from modules.api.models import create_api_models
    from modules.api.resources import create_api_resources

    def passthrough(_role):
        return lambda fn: fn

    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=passthrough)
    settings = MagicMock()
    settings.load_settings.return_value = {'email': 'a@b.c'}
    managers = {'auth': auth, 'settings': settings, 'file_ops': file_ops,
                'certificates': MagicMock(), 'cache': MagicMock(),
                'dns': MagicMock(), 'audit': None}
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    resources = create_api_resources(api, create_api_models(api), managers)
    ns = Namespace('backups', description='backups')
    api.add_namespace(ns)
    ns.add_resource(resources['BackupRestore'], '/restore/<string:backup_type>')

    @app.before_request
    def _user():
        request.current_user = {'username': 'op', 'role': 'admin', 'allowed_domains': None}

    return app.test_client()


def _restore_over_api(tmp_path, *, include_secrets):
    import shutil

    src = _ops(tmp_path / 'src')
    _cert(src, 'a.example.com')
    _cert(src, 'appliance.example.com', key=False,
          metadata={'domain': 'appliance.example.com', 'key_management': 'external'})
    name = src.create_unified_backup({'domains': ['a.example.com']}, 'test',
                                     include_secrets=include_secrets)
    dst = _ops(tmp_path / 'dst')
    (dst.backup_dir / 'unified').mkdir(parents=True, exist_ok=True)
    shutil.copy(src.backup_dir / 'unified' / name, dst.backup_dir / 'unified' / name)
    return _api(dst).post('/api/backups/restore/unified', json={'filename': name})


def test_the_api_answer_names_them_and_the_next_step(tmp_path):
    """Through the real route, with a real FileOperations and archive."""
    response = _restore_over_api(tmp_path, include_secrets=False)

    assert response.status_code == 200, response.get_json()
    body = response.get_json()
    assert body['reissue_required'] == ['a.example.com']
    assert 'reissue' in body['next_step'].lower()


def test_the_api_answer_has_nothing_to_do_after_a_full_restore(tmp_path):
    """CONTROL: the field is always there, empty, and no next step is invented."""
    response = _restore_over_api(tmp_path, include_secrets=True)

    body = response.get_json()
    assert response.status_code == 200, body
    assert body['reissue_required'] == []
    assert 'next_step' not in body
