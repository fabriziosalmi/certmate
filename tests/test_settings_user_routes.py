"""User creation and editing over the web API, at 38% before this (#662).

`modules/web/settings_routes.py` is the settings-mutation surface the issue
names, and the user routes are its sharpest edge: they create the credentials
that authenticate every other request. What was untested there was not the
happy path but the refusals — the password policy, the self-deletion guard, the
status code a duplicate username gets.

A refusal that returns the wrong status is not cosmetic here. A 500 where a 409
belongs tells an operator their instance is broken when they simply picked a
name that is taken; a policy that accepts a weak password is a credential that
should not exist.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.web.settings_routes import register_settings_routes

pytestmark = [pytest.mark.unit]

GOOD_PASSWORD = 'a-Long-Passw0rd!'


@pytest.fixture
def wired():
    app = Flask(__name__)
    app.config['TESTING'] = True

    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    audit = MagicMock()

    register_settings_routes(
        app, managers={'audit': audit, 'deployer': MagicMock()},
        require_web_auth=lambda fn: fn, auth_manager=auth,
        settings_manager=MagicMock(), dns_manager=MagicMock())
    return app.test_client(), auth, audit


# ---------------------------------------------------------------------------
# Creating a user
# ---------------------------------------------------------------------------

def test_a_user_is_created_and_audited(wired):
    client, auth, audit = wired
    auth.create_user.return_value = (True, 'User created successfully')

    response = client.post('/api/users', json={
        'username': 'alice', 'password': GOOD_PASSWORD, 'role': 'operator'})

    assert response.status_code == 201
    auth.create_user.assert_called_once_with('alice', GOOD_PASSWORD, 'operator')
    assert audit.log_user_created.called, (
        'creating a credential must leave an audit record'
    )


def test_the_default_role_is_the_least_privileged(wired):
    """An omitted role must not quietly mean admin."""
    client, auth, _audit = wired
    auth.create_user.return_value = (True, 'ok')

    client.post('/api/users', json={'username': 'bob', 'password': GOOD_PASSWORD})

    assert auth.create_user.call_args[0][2] == 'viewer'


@pytest.mark.parametrize('payload,because', [
    ({'password': GOOD_PASSWORD}, 'no username'),
    ({'username': 'alice'}, 'no password'),
    ({}, 'neither'),
])
def test_a_user_needs_both_a_name_and_a_password(wired, payload, because):
    client, auth, _audit = wired
    response = client.post('/api/users', json=payload)

    assert response.status_code == 400, because
    assert not auth.create_user.called


@pytest.mark.parametrize('password,missing', [
    ('short1!', 'too short'),
    ('nodigitshere!!!!', 'no digit'),
    ('nosymbolshere123', 'no symbol'),
])
def test_the_password_policy_is_enforced(wired, password, missing):
    """Twelve characters with a digit and a symbol. A policy that is documented
    and not applied is worse than none, because it is believed."""
    client, auth, _audit = wired
    response = client.post('/api/users', json={
        'username': 'alice', 'password': password})

    assert response.status_code == 400, missing
    assert not auth.create_user.called, (
        f'a password that is {missing} reached create_user'
    )


def test_a_password_that_satisfies_the_policy_is_accepted(wired):
    """CONTROL: a policy that rejected everything would pass every case above
    while making the instance unusable."""
    client, auth, _audit = wired
    auth.create_user.return_value = (True, 'ok')

    assert client.post('/api/users', json={
        'username': 'alice', 'password': GOOD_PASSWORD}).status_code == 201


@pytest.mark.parametrize('field,value', [
    ('username', 'u' * 65),
    ('password', 'P1!' + 'x' * 254),
])
def test_absurd_lengths_are_refused(wired, field, value):
    client, auth, _audit = wired
    payload = {'username': 'alice', 'password': GOOD_PASSWORD}
    payload[field] = value

    assert client.post('/api/users', json=payload).status_code == 400
    assert not auth.create_user.called


def test_a_duplicate_username_is_a_conflict_not_a_server_error(wired):
    """409, not 500. The difference is whether the operator thinks they made a
    mistake or thinks CertMate is broken."""
    client, auth, _audit = wired
    auth.create_user.return_value = (False, 'User already exists')

    response = client.post('/api/users', json={
        'username': 'alice', 'password': GOOD_PASSWORD})

    assert response.status_code == 409


def test_any_other_creation_failure_is_a_server_error(wired):
    client, auth, _audit = wired
    auth.create_user.return_value = (False, 'Failed to save user')

    response = client.post('/api/users', json={
        'username': 'alice', 'password': GOOD_PASSWORD})

    assert response.status_code == 500


def test_listing_users_returns_what_the_auth_manager_reports(wired):
    client, auth, _audit = wired
    auth.list_users.return_value = [{'username': 'alice', 'role': 'admin'}]

    response = client.get('/api/users')

    assert response.status_code == 200
    assert response.get_json()['users'][0]['username'] == 'alice'


# ---------------------------------------------------------------------------
# Editing and deleting
# ---------------------------------------------------------------------------

def test_an_admin_cannot_delete_their_own_account(wired):
    """The guard that stops an instance being locked out of itself."""
    client, auth, _audit = wired

    @client.application.before_request
    def _who():
        from flask import request as flask_request
        flask_request.current_user = {'username': 'alice', 'role': 'admin'}

    response = client.delete('/api/users/alice')

    assert response.status_code != 200, 'the last admin deleted themselves'
    assert not auth.delete_user.called


def test_deleting_someone_else_works(wired):
    """CONTROL: the self-deletion guard must not block ordinary deletion."""
    client, auth, _audit = wired
    auth.delete_user.return_value = (True, 'User deleted')

    @client.application.before_request
    def _who():
        from flask import request as flask_request
        flask_request.current_user = {'username': 'alice', 'role': 'admin'}

    response = client.delete('/api/users/bob')

    assert response.status_code == 200
    assert auth.delete_user.called


def test_deleting_a_missing_user_is_a_404(wired):
    client, auth, _audit = wired
    auth.delete_user.return_value = (False, 'User not found')

    @client.application.before_request
    def _who():
        from flask import request as flask_request
        flask_request.current_user = {'username': 'alice', 'role': 'admin'}

    assert client.delete('/api/users/ghost').status_code == 404


def test_an_update_with_nothing_to_change_is_refused(wired):
    client, auth, _audit = wired

    response = client.put('/api/users/bob', json={})

    assert response.status_code == 400
    assert not auth.update_user.called


def test_enabled_must_be_a_boolean(wired):
    client, auth, _audit = wired

    response = client.put('/api/users/bob', json={'enabled': 'yes'})

    assert response.status_code == 400
    assert not auth.update_user.called


def test_a_password_change_is_held_to_the_same_policy(wired):
    """The policy applies on update too, or it is a one-time formality."""
    client, auth, _audit = wired

    response = client.put('/api/users/bob', json={'password': 'weak'})

    assert response.status_code == 400
    assert not auth.update_user.called
