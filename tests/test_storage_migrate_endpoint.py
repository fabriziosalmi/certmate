"""
Regression tests: POST /api/storage/migrate must accept the minimal
payload the Settings UI actually sends.

The Settings UI's "Start Migration" button has no way to remember the
previously-active backend identity (the dropdown already shows the
user's new target choice), so the JS only sends target_backend +
target_config. The previous endpoint required four fields and rejected
the UI payload with 400.

The endpoint is now lenient:

* source_backend / source_config default to the currently-saved
  certificate_storage when absent.
* target_backend may be inferred from target_config['backend'] when the
  UI passes the structured ``{backend, <backend>: {...}}`` envelope
  produced by collectStorageBackendSettings().
"""

import pytest


pytestmark = [pytest.mark.unit]


@pytest.fixture
def app_client(tmp_path, monkeypatch):
    """Stand up the real Flask app against tmp_path so we can hit the
    migrate endpoint end-to-end. Both source and target are
    local_filesystem so the test needs no cloud SDKs."""
    monkeypatch.setenv('CERTMATE_DATA_DIR', str(tmp_path / 'data'))
    monkeypatch.setenv('CERTMATE_CERT_DIR', str(tmp_path / 'certs'))
    monkeypatch.setenv('CERTMATE_BACKUP_DIR', str(tmp_path / 'backups'))
    monkeypatch.setenv('CERTMATE_LOGS_DIR', str(tmp_path / 'logs'))

    from modules.core.factory import create_app
    app, container = create_app()
    app.config['TESTING'] = True

    settings_manager = container.managers['settings']
    settings = settings_manager.load_settings()
    token = 'test-' + 'a' * 48
    settings['api_bearer_token'] = token
    settings['certificate_storage'] = {
        'backend': 'local_filesystem',
        'cert_dir': str(tmp_path / 'certs'),
    }
    settings_manager.save_settings(settings, 'test_seed')

    return app.test_client(), token, tmp_path


def _post(client, body, token):
    return client.post(
        '/api/storage/migrate',
        json=body,
        headers={'Authorization': f'Bearer {token}'},
    )


def test_minimal_payload_with_envelope_target_config(app_client):
    """The exact payload the fixed performStorageMigration sends."""
    client, token, tmp_path = app_client
    target_dir = tmp_path / 'migrated'

    resp = _post(client, {
        'target_backend': 'local_filesystem',
        'target_config': {
            'backend': 'local_filesystem',
            'cert_dir': str(target_dir),
        },
    }, token)
    assert resp.status_code == 200, resp.get_json()
    body = resp.get_json()
    assert body['success'] is True
    assert body['source_backend'] == 'local_filesystem'
    assert body['target_backend'] == 'local_filesystem'
    # migrated_count is the field the UI reads back to format its toast.
    assert 'migrated_count' in body


def test_target_backend_inferred_from_envelope_when_omitted(app_client):
    """If the caller forgets target_backend but includes the envelope
    target_config with a ``backend`` field, the endpoint accepts it."""
    client, token, tmp_path = app_client
    resp = _post(client, {
        'target_config': {
            'backend': 'local_filesystem',
            'cert_dir': str(tmp_path / 'inferred'),
        },
    }, token)
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()['target_backend'] == 'local_filesystem'


def test_invalid_target_backend_returns_400(app_client):
    client, token, _ = app_client
    resp = _post(client, {
        'target_backend': 'mongodb_or_something_weird',
        'target_config': {},
    }, token)
    assert resp.status_code == 400
