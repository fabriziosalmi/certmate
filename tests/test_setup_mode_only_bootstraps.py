"""Setup mode only bootstraps: the first admin, then login.

Until the first operator credential exists, every request is served as admin to
anyone who can reach the instance. Whatever is created in that window is
created by whoever was there, and credentials outlive the window. So in setup
mode the only credential that can be created is the first admin, which is what
the setup page does before it turns local login on. API keys and further users
wait until setup is complete (409 SETUP_BOOTSTRAP_ONLY).

Keys that earlier versions allowed to be created in setup mode are recognisable
(``created_by: setup_user``). They stay valid, because revoking by default
would break an operator who made one themselves. They are flagged in the key
listing and the startup log until an operator confirms or revokes them.

Everything here drives the real application; nothing about auth is mocked.
"""
import logging
import secrets

import pytest

from modules.core.auth import SETUP_USERNAME

pytestmark = [pytest.mark.unit]

STRONG_PASSWORD = 'Setup-window-' + secrets.token_hex(6) + '!1'


def _app(tmp_path, monkeypatch, bearer=None):
    from modules.core.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True, exist_ok=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    if bearer:
        monkeypatch.setenv('API_BEARER_TOKEN', bearer)
    else:
        monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    application, container = create_app()
    return application, container


def _complete_setup(client):
    """What templates/setup.html does: the first admin, then local login."""
    created = client.post('/api/web/settings/users', json={
        'username': 'operator', 'password': STRONG_PASSWORD, 'role': 'admin'})
    enabled = client.post('/api/auth/config', json={'local_auth_enabled': True})
    return created, enabled


def _login(client):
    r = client.post('/api/auth/login', json={'username': 'operator', 'password': STRONG_PASSWORD})
    assert r.status_code == 200, r.get_json()


# --------------------------------------------------------------------------- #
# What setup mode refuses
# --------------------------------------------------------------------------- #

def test_no_api_key_can_be_created_in_setup_mode(tmp_path, monkeypatch):
    application, container = _app(tmp_path, monkeypatch)
    assert container.managers['auth'].is_setup_mode()
    client = application.test_client()

    r = client.post('/api/keys', json={'name': 'k', 'role': 'admin'})
    assert r.status_code == 409
    assert r.get_json()['code'] == 'SETUP_BOOTSTRAP_ONLY'
    assert container.managers['auth'].list_api_keys() == {}


def test_nothing_created_in_setup_mode_survives_into_the_configured_instance(tmp_path, monkeypatch):
    """The whole window, end to end: an attempt to create a key during setup,
    then the operator completes setup; the configured instance holds only the
    operator's admin."""
    application, container = _app(tmp_path, monkeypatch)
    client = application.test_client()
    assert client.post('/api/keys', json={'name': 'k', 'role': 'admin'}).status_code == 409

    created, enabled = _complete_setup(client)
    assert (created.status_code, enabled.status_code) == (201, 200)
    auth = container.managers['auth']
    assert not auth.is_setup_mode()
    assert auth.list_api_keys() == {}
    assert list(auth.list_users()) == ['operator']


def test_setup_mode_creates_the_first_admin_and_no_second(tmp_path, monkeypatch):
    application, container = _app(tmp_path, monkeypatch)
    client = application.test_client()
    first = client.post('/api/web/settings/users', json={
        'username': 'operator', 'password': STRONG_PASSWORD, 'role': 'admin'})
    assert first.status_code == 201
    second = client.post('/api/users', json={
        'username': 'another', 'password': STRONG_PASSWORD, 'role': 'admin'})
    assert second.status_code == 409
    assert second.get_json()['code'] == 'SETUP_BOOTSTRAP_ONLY'
    assert list(container.managers['auth'].list_users()) == ['operator']


def test_a_half_finished_setup_still_completes(tmp_path, monkeypatch):
    """The setup page reads 409 on the user step as "an admin already exists"
    and goes on to enable login. A rerun after a half-finished setup must
    still end with login on."""
    application, container = _app(tmp_path, monkeypatch)
    client = application.test_client()
    assert client.post('/api/web/settings/users', json={
        'username': 'operator', 'password': STRONG_PASSWORD, 'role': 'admin'}).status_code == 201
    # The page is reloaded and the form submitted again.
    rerun, enabled = _complete_setup(client)
    assert rerun.status_code == 409
    assert enabled.status_code == 200
    assert not container.managers['auth'].is_setup_mode()


def test_after_setup_keys_and_users_are_created_normally(tmp_path, monkeypatch):
    application, container = _app(tmp_path, monkeypatch)
    client = application.test_client()
    _complete_setup(client)
    _login(client)
    origin = {'Origin': 'http://localhost'}
    key = client.post('/api/keys', headers=origin, json={'name': 'ci', 'role': 'operator'})
    assert key.status_code in (200, 201), key.get_json()
    user = client.post('/api/users', headers=origin, json={
        'username': 'second', 'password': STRONG_PASSWORD, 'role': 'viewer'})
    assert user.status_code == 201, user.get_json()


def test_refusals_are_audited(tmp_path, monkeypatch):
    application, container = _app(tmp_path, monkeypatch)
    audit = container.managers['audit']
    denied = []
    original = audit.log_authz_denied
    monkeypatch.setattr(audit, 'log_authz_denied',
                        lambda **kw: (denied.append(kw), original(**kw)))
    application.test_client().post('/api/keys', json={'name': 'k', 'role': 'admin'})
    assert [d['operation'] for d in denied] == ['create_api_key']
    assert 'setup mode' in denied[0]['reason']


# --------------------------------------------------------------------------- #
# Keys that already exist from the setup window
# --------------------------------------------------------------------------- #

def _legacy_setup_key(auth, name='from-setup'):
    """A key as an earlier version could create it in setup mode."""
    ok, data = auth.create_api_key(name, role='admin', created_by=SETUP_USERNAME)
    assert ok, data
    return data['id'] if isinstance(data, dict) and 'id' in data else next(
        k for k, v in auth.list_api_keys().items() if v['name'] == name)


@pytest.fixture
def configured(tmp_path, monkeypatch):
    bearer = secrets.token_urlsafe(32)
    application, container = _app(tmp_path, monkeypatch, bearer=bearer)
    assert not container.managers['auth'].is_setup_mode()
    return application, container, {'Authorization': f'Bearer {bearer}'}


def test_a_setup_key_is_flagged_for_review(configured):
    application, container, admin = configured
    auth = container.managers['auth']
    key_id = _legacy_setup_key(auth)
    listed = application.test_client().get('/api/keys', headers=admin).get_json()['keys'][key_id]
    assert listed['created_during_setup'] is True
    assert listed['needs_review'] is True
    assert auth.unreviewed_setup_keys() == [key_id]


def test_an_operator_key_is_not_flagged(configured):
    application, container, admin = configured
    ok, _ = container.managers['auth'].create_api_key('mine', role='viewer', created_by='operator')
    keys = application.test_client().get('/api/keys', headers=admin).get_json()['keys']
    assert all(not k['created_during_setup'] and not k['needs_review'] for k in keys.values())


def test_confirming_clears_the_flag_and_records_who(configured):
    application, container, admin = configured
    auth = container.managers['auth']
    key_id = _legacy_setup_key(auth)
    client = application.test_client()
    r = client.patch(f'/api/keys/{key_id}', headers=admin, json={'confirmed': True})
    assert r.status_code == 200, r.get_json()
    listed = client.get('/api/keys', headers=admin).get_json()['keys'][key_id]
    assert listed['needs_review'] is False
    assert listed['setup_origin_confirmed_at']
    assert listed['setup_origin_confirmed_by']
    assert auth.unreviewed_setup_keys() == []
    again = client.patch(f'/api/keys/{key_id}', headers=admin, json={'confirmed': True})
    assert again.status_code == 400
    assert again.get_json()['code'] == 'API_KEY_NOT_CONFIRMABLE'


def test_a_revoked_setup_key_needs_no_review(configured):
    application, container, admin = configured
    auth = container.managers['auth']
    key_id = _legacy_setup_key(auth)
    assert application.test_client().delete(f'/api/keys/{key_id}', headers=admin).status_code == 200
    assert auth.unreviewed_setup_keys() == []


@pytest.mark.parametrize('body, status, code', [
    ({}, 400, 'INVALID_REQUEST'),
    ({'confirmed': 'true'}, 400, 'INVALID_REQUEST'),   # a JSON boolean, not a string
    ({'confirmed': False}, 400, 'INVALID_REQUEST'),
])
def test_confirm_takes_only_a_json_true(configured, body, status, code):
    application, container, admin = configured
    key_id = _legacy_setup_key(container.managers['auth'])
    r = application.test_client().patch(f'/api/keys/{key_id}', headers=admin, json=body)
    assert (r.status_code, r.get_json()['code']) == (status, code)


def test_confirm_refuses_keys_it_has_no_business_with(configured):
    application, container, admin = configured
    client = application.test_client()
    unknown = client.patch('/api/keys/nope', headers=admin, json={'confirmed': True})
    assert (unknown.status_code, unknown.get_json()['code']) == (404, 'API_KEY_NOT_FOUND')
    container.managers['auth'].create_api_key('mine', role='viewer', created_by='operator')
    mine = next(k for k, v in container.managers['auth'].list_api_keys().items() if v['name'] == 'mine')
    not_setup = client.patch(f'/api/keys/{mine}', headers=admin, json={'confirmed': True})
    assert (not_setup.status_code, not_setup.get_json()['code']) == (400, 'API_KEY_NOT_CONFIRMABLE')


def test_confirming_is_refused_in_setup_mode(tmp_path, monkeypatch):
    """Otherwise the same anonymous admin who could mint the key could vouch
    for it."""
    application, container = _app(tmp_path, monkeypatch)
    key_id = _legacy_setup_key(container.managers['auth'])
    r = application.test_client().patch(f'/api/keys/{key_id}', json={'confirmed': True})
    assert (r.status_code, r.get_json()['code']) == (409, 'SETUP_BOOTSTRAP_ONLY')
    assert container.managers['auth'].list_api_keys()[key_id]['needs_review'] is True


def test_startup_says_how_many_keys_wait_for_review(tmp_path, monkeypatch, caplog):
    bearer = secrets.token_urlsafe(32)
    _, container = _app(tmp_path, monkeypatch, bearer=bearer)
    _legacy_setup_key(container.managers['auth'], 'a')
    _legacy_setup_key(container.managers['auth'], 'b')
    caplog.clear()
    with caplog.at_level(logging.CRITICAL, logger='certmate.factory'):
        _app(tmp_path, monkeypatch, bearer=bearer)   # restart on the same data
    said = [r.getMessage() for r in caplog.records if 'setup mode' in r.getMessage()]
    assert len(said) == 1 and said[0].startswith('2 API key(s)')
