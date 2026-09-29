"""Setup mode refuses what outlives it, and the first admin closes it.

Setup mode serves every caller as admin until a credential exists, so a fresh
instance can be bootstrapped. #862 stopped it minting API keys and extra users.
It still let anyone who could reach a fresh instance run a command on the host
through a deploy hook's test, plant a hook that stayed after setup, and carry
away private keys through downloads and backups. Measured on v2.40.0.

Now, while in setup mode, deploy-hook writes, tests and runs, certificate and
key downloads, and backup creation and download answer 409
SETUP_BOOTSTRAP_ONLY. Restoring and uploading a backup stay allowed: that is
how an instance is recovered onto a fresh host.

And the first admin closes setup in the same request. It used to take two
(create the admin, then enable local auth); an instance whose second request
never came stayed open as admin while its operator believed it had one.
"""
import secrets

import pytest

pytestmark = [pytest.mark.unit]

ORIGIN = {'Origin': 'http://localhost'}
PASSWORD = 'Setup-probe-pass-1!'


def _app(tmp_path, monkeypatch, token=None):
    for var, sub in (('CERTMATE_CERT_DIR', 'certs'), ('CERTMATE_DATA_DIR', 'data'),
                     ('CERTMATE_BACKUP_DIR', 'backups'), ('CERTMATE_LOGS_DIR', 'logs')):
        (tmp_path / sub).mkdir(exist_ok=True)
        monkeypatch.setenv(var, str(tmp_path / sub))
    if token:
        monkeypatch.setenv('API_BEARER_TOKEN', token)
    else:
        monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    from modules.factory import create_app
    app, container = create_app()
    return app, container


def _hook(marker):
    return {'enabled': True, 'global_hooks': [{
        'id': 'h1', 'name': 'probe', 'command': f'touch {marker}',
        'enabled': True, 'on_events': ['created', 'renewed']}], 'domain_hooks': {}}


REFUSED = [
    ('POST', '/api/deploy/config', 'hook'),
    ('POST', '/api/deploy/test/h1', None),
    ('POST', '/api/certificates/example.com/deploy', None),
    ('GET', '/api/certificates/example.com/download', None),
    ('GET', '/api/certificates/example.com/download/privkey', None),
    ('POST', '/api/web/certificates/download/batch', {'domains': ['example.com']}),
    ('GET', '/api/client-certs/some-client/download/key', None),
    ('GET', '/api/client-certs/some-client/download/pfx', None),
    ('POST', '/api/backups/create', {'type': 'unified', 'include_secrets': True}),
    ('POST', '/api/web/backups/create', {'include_secrets': True}),
    ('GET', '/api/backups/download/unified/x.zip', None),
]


@pytest.mark.parametrize('method,path,body', REFUSED)
def test_setup_mode_refuses_it(tmp_path, monkeypatch, method, path, body):
    app, _ = _app(tmp_path, monkeypatch)
    client = app.test_client()
    if body == 'hook':
        body = _hook(tmp_path / 'planted')
    r = client.open(path, method=method, json=body, headers=ORIGIN)
    assert r.status_code == 409, (path, r.status_code, r.get_data(as_text=True)[:200])
    assert r.get_json()['code'] == 'SETUP_BOOTSTRAP_ONLY'


def test_a_hook_cannot_be_planted_or_run_in_setup(tmp_path, monkeypatch):
    app, container = _app(tmp_path, monkeypatch)
    client = app.test_client()
    marker = tmp_path / 'planted'
    client.post('/api/deploy/config', json=_hook(marker), headers=ORIGIN)
    client.post('/api/deploy/test/h1', headers=ORIGIN)
    assert not marker.exists(), 'a command ran on the host from setup mode'
    hooks = (container.managers['settings'].load_settings().get('deploy_hooks') or {})
    assert not hooks.get('global_hooks'), 'the hook was saved in setup mode'


@pytest.mark.parametrize('method,path', [
    ('POST', '/api/backups/restore/unified'),
    ('POST', '/api/backups/upload'),
])
def test_recovery_onto_a_fresh_host_stays_allowed(tmp_path, monkeypatch, method, path):
    app, _ = _app(tmp_path, monkeypatch)
    r = app.test_client().open(path, method=method, json={}, headers=ORIGIN)
    assert r.status_code != 409, r.get_data(as_text=True)[:200]


def test_ordinary_setup_keeps_working(tmp_path, monkeypatch):
    app, _ = _app(tmp_path, monkeypatch)
    client = app.test_client()
    assert client.get('/api/certificates').status_code == 200
    assert client.get('/api/web/settings').status_code == 200


def test_the_first_admin_closes_setup(tmp_path, monkeypatch):
    app, _ = _app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.post('/api/web/settings/users', headers=ORIGIN, json={
        'username': 'admin', 'password': PASSWORD, 'role': 'admin'})
    assert r.status_code == 201 and r.get_json().get('local_auth_enabled') is True
    anon = app.test_client()
    assert anon.get('/api/settings').status_code == 401
    assert anon.get('/api/auth/me').status_code == 401
    assert anon.post('/api/auth/login', headers=ORIGIN, json={
        'username': 'admin', 'password': PASSWORD}).status_code == 200


def test_after_setup_the_admin_can_do_all_of_it(tmp_path, monkeypatch):
    """CONTROL: the refusals are the setup window's, not the endpoints'."""
    app, _ = _app(tmp_path, monkeypatch)
    client = app.test_client()
    client.post('/api/web/settings/users', headers=ORIGIN, json={
        'username': 'admin', 'password': PASSWORD, 'role': 'admin'})
    assert client.post('/api/auth/login', headers=ORIGIN, json={
        'username': 'admin', 'password': PASSWORD}).status_code == 200
    r = client.post('/api/deploy/config', json=_hook(tmp_path / 'm'), headers=ORIGIN)
    assert r.status_code == 200, r.get_data(as_text=True)[:200]
    r = client.post('/api/backups/create', json={'type': 'unified'}, headers=ORIGIN)
    assert r.status_code in (200, 201), r.get_data(as_text=True)[:200]


def test_a_first_user_that_is_not_admin_does_not_close_setup(tmp_path, monkeypatch):
    """Enabling login with no admin would lock everyone out."""
    app, _ = _app(tmp_path, monkeypatch)
    client = app.test_client()
    r = client.post('/api/web/settings/users', headers=ORIGIN, json={
        'username': 'viewer1', 'password': PASSWORD, 'role': 'viewer'})
    assert r.status_code == 201 and 'local_auth_enabled' not in r.get_json()


def test_a_token_configured_instance_is_unchanged(tmp_path, monkeypatch):
    token = secrets.token_urlsafe(32)
    app, _ = _app(tmp_path, monkeypatch, token=token)
    client = app.test_client()
    auth = dict(ORIGIN, Authorization=f'Bearer {token}')
    r = client.post('/api/web/settings/users', headers=auth, json={
        'username': 'admin', 'password': PASSWORD, 'role': 'admin'})
    assert r.status_code == 201 and 'local_auth_enabled' not in r.get_json()
    r = client.post('/api/deploy/config', json=_hook(tmp_path / 'm'), headers=auth)
    assert r.status_code == 200
