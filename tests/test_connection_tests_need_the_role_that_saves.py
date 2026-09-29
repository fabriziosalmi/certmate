"""A connection test needs the role that can save what it tests.

`POST /api/storage/test` and `POST /api/settings/test-ca-provider` take a
complete configuration in the request and make the server connect with it.
Saving that configuration has always required admin; testing it required only
operator. So an operator could have the server open connections, with a
configuration of its own choosing, that it was not allowed to keep.

Both tests now require admin, like the save they exist to support. The
settings page that offers them is where an admin saves the same settings.
Measured with a local listener: an operator gets 403 before any connection is
attempted, and an admin's test still connects.
"""
import http.server
import secrets
import threading

import pytest

pytestmark = [pytest.mark.unit]


@pytest.fixture
def instance(tmp_path, monkeypatch):
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(var, str(tmp_path / sub))
    token = secrets.token_urlsafe(32)
    monkeypatch.setenv('API_BEARER_TOKEN', token)
    from modules.factory import create_app
    app, _ = create_app()
    client = app.test_client()
    admin = {'Authorization': f'Bearer {token}'}
    minted = client.post('/api/keys', json={'name': 'op', 'role': 'operator'}, headers=admin)
    assert minted.status_code == 201, minted.get_data(as_text=True)
    body = minted.get_json()
    operator = {'Authorization': f"Bearer {body.get('token') or body.get('key')}"}
    return client, admin, operator


@pytest.fixture
def listener():
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(403)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], hits
    server.shutdown()


def _storage(port):
    return {'backend': 's3_compatible', 'config': {
        'endpoint_url': f'http://127.0.0.1:{port}', 'bucket': 'b',
        'access_key_id': 'k', 'secret_access_key': 's', 'region': 'us-east-1'}}


def test_an_operator_cannot_have_the_server_connect_for_storage(instance, listener):
    client, _, operator = instance
    port, hits = listener
    r = client.post('/api/storage/test', json=_storage(port), headers=operator)
    assert r.status_code == 403
    assert hits == [], 'the server connected before refusing'


def test_an_admin_storage_test_still_connects(instance, listener):
    """CONTROL: the refusal above is the role, not a broken endpoint."""
    client, admin, _ = instance
    port, hits = listener
    r = client.post('/api/storage/test', json=_storage(port), headers=admin)
    assert r.status_code == 200
    assert hits, 'the admin test no longer reaches the backend'


def test_an_operator_cannot_test_a_ca(instance):
    client, _, operator = instance
    r = client.post('/api/settings/test-ca-provider', headers=operator, json={
        'ca_provider': 'private_ca', 'config': {'acme_url': 'https://127.0.0.1:9/directory'}})
    assert r.status_code == 403


def test_an_admin_can_still_test_a_ca(instance):
    client, admin, _ = instance
    r = client.post('/api/settings/test-ca-provider', headers=admin, json={
        'ca_provider': 'private_ca', 'config': {'acme_url': 'https://127.0.0.1:9/directory'}})
    assert r.status_code != 403, r.get_data(as_text=True)
