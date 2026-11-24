"""One email address belongs to one user (#1466).

SSO links an IdP login to an existing user by email, compared without case and
surrounding spaces (OIDCManager._find_by_email). Nothing kept two users from
holding the same address: the user routes checked only its format, so a second
user could be created with it, or a third updated to it, and SSO then linked
whichever matching user it met first.

A user taking an address another user already holds is now refused with 409, on
create and on update, compared the way SSO compares. A user keeping its own
address still succeeds. Installs may already hold duplicates, so SSO also
refuses to link by email when more than one user matches, and says so in the log.
"""
import logging

import pytest

from modules.core.oidc import OIDCManager
from modules.core.structured_logging import sanitize_text
from tests import contract_support
from tests.test_oidc_manager import _enable_oidc, auth_manager, oidc, settings_manager  # noqa: F401

pytestmark = [pytest.mark.unit]

PASSWORD = 'a-Long-Passw0rd!'


@pytest.fixture
def api():
    app, token = contract_support.build_app()
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}'}
    auth = app.extensions['certmate_container'].managers['auth']
    created = client.post('/api/users', headers=headers, json={
        'username': 'alice', 'password': PASSWORD, 'role': 'admin', 'email': 'shared@example.com'})
    assert created.status_code == 201, created.get_json()
    return client, headers, auth


def _create(client, headers, username, email):
    return client.post('/api/users', headers=headers, json={
        'username': username, 'password': PASSWORD, 'role': 'viewer', 'email': email})


@pytest.mark.parametrize('email', ['shared@example.com', ' Shared@Example.com ', 'SHARED@EXAMPLE.COM'])
def test_a_new_user_cannot_take_an_address_another_user_holds(api, email):
    client, headers, auth = api
    refused = _create(client, headers, 'bob', email)
    assert refused.status_code == 409, refused.get_json()
    assert refused.get_json()['error'] == 'Email address already in use by another user'
    assert 'bob' not in auth.list_users()


@pytest.mark.parametrize('email', ['shared@example.com', ' Shared@Example.com '])
def test_a_user_cannot_be_updated_to_an_address_another_user_holds(api, email):
    client, headers, auth = api
    assert _create(client, headers, 'carol', 'carol@example.com').status_code == 201
    refused = client.put('/api/users/carol', headers=headers, json={'email': email})
    assert refused.status_code == 409, refused.get_json()
    assert refused.get_json()['error'] == 'Email address already in use by another user'
    assert auth.list_users()['carol']['email'] == 'carol@example.com'


def test_a_user_keeps_or_recases_its_own_address(api):
    client, headers, auth = api
    for email in ('shared@example.com', 'Shared@Example.com'):
        kept = client.put('/api/users/alice', headers=headers, json={'email': email})
        assert kept.status_code == 200, kept.get_json()
    assert auth.list_users()['alice']['email'] == 'Shared@Example.com'


def test_users_without_an_address_or_with_different_ones_are_still_created(api):
    client, headers, auth = api
    assert _create(client, headers, 'dave', None).status_code == 201
    assert _create(client, headers, 'erin', None).status_code == 201
    assert _create(client, headers, 'frank', 'frank@example.com').status_code == 201
    # Clearing an address is never a conflict.
    assert client.put('/api/users/frank', headers=headers, json={'email': ''}).status_code == 200
    assert {name: user['email'] for name, user in auth.list_users().items()} == {
        'alice': 'shared@example.com', 'dave': None, 'erin': None, 'frank': ''}


def test_sso_refuses_to_link_by_email_when_two_users_hold_the_address(
        oidc, settings_manager, auth_manager, caplog):  # noqa: F811
    _enable_oidc(settings_manager)
    auth_manager.create_user('alice', PASSWORD, role='admin', email='shared@example.com')
    # An install from before #1466 can already hold the same address twice.
    users = auth_manager._get_users()
    # A name with a line break, as a row written before names were checked
    # can hold: the warning must not carry it into a second log record.
    users['bob\nforged'] = {**users['alice'], 'role': 'viewer', 'email': ' Shared@Example.com '}
    assert auth_manager._save_users(users)

    claims = {'iss': 'https://idp.example.com', 'sub': 'idp-subject-1466', 'preferred_username': 'mallory',
              'email': 'shared@example.com', 'email_verified': True, 'groups': []}
    with caplog.at_level(logging.WARNING, logger='modules.core.oidc'):
        username, err = oidc.resolve_or_provision_user(claims)

    assert (username, err) == (None, 'email_ambiguous')
    after = auth_manager._get_users()
    assert set(after) == {'alice', 'bob\nforged'}, 'no user was created for the address either'
    assert not after['alice'].get('oidc_subject') and not after['bob\nforged'].get('oidc_subject')
    said = [r.getMessage() for r in caplog.records if 'more than one user' in r.getMessage()]
    assert said, [r.getMessage() for r in caplog.records]
    assert 'alice' in said[0] and 'bobforged' in said[0]
    assert '\n' not in said[0] and '\r' not in said[0]
    assert sanitize_text(said[0]) == said[0]


def test_sso_does_not_create_a_second_holder_of_an_address(
        oidc, settings_manager, auth_manager, caplog):  # noqa: F811
    """With link_by_email off, a login whose address a local user holds used to
    create a second user with it."""
    _enable_oidc(settings_manager, link_by_email=False)
    auth_manager.create_user('alice', PASSWORD, role='admin', email='alice@example.com')
    users = auth_manager._get_users()
    users['dave\rforged'] = {**users['alice'], 'role': 'viewer', 'email': 'shared@example.com'}
    assert auth_manager._save_users(users)
    claims = {'iss': 'https://idp.example.com', 'sub': 'idp-subject-jit', 'preferred_username': 'mallory',
              'email': ' Shared@Example.com ', 'email_verified': True, 'groups': []}
    with caplog.at_level(logging.WARNING, logger='modules.core.oidc'):
        username, err = oidc.resolve_or_provision_user(claims)

    assert (username, err) == (None, 'email_taken')
    assert set(auth_manager._get_users()) == {'alice', 'dave\rforged'}
    said = [r.getMessage() for r in caplog.records if 'did not create a user' in r.getMessage()]
    assert said and 'daveforged' in said[0], [r.getMessage() for r in caplog.records]
    assert '\n' not in said[0] and '\r' not in said[0]
    assert sanitize_text(said[0]) == said[0]

    # CONTROL: an address nobody holds is provisioned as before.
    claims = {**claims, 'sub': 'idp-subject-new', 'preferred_username': 'nina', 'email': 'nina@example.com'}
    username, err = oidc.resolve_or_provision_user(claims)
    assert err is None and auth_manager._get_users()[username]['email'] == 'nina@example.com'


def test_a_user_sharing_an_address_from_before_can_still_save_its_own(api):
    client, headers, auth = api
    users = auth._get_users()
    users['bob'] = {**users['alice'], 'role': 'viewer', 'email': 'shared@example.com'}
    assert auth._save_users(users)
    for email in ('shared@example.com', ' SHARED@example.com '):
        kept = client.put('/api/users/bob', headers=headers, json={'email': email})
        assert kept.status_code == 200, kept.get_json()
    # A change to another held address is still refused.
    assert _create(client, headers, 'erin', 'erin@example.com').status_code == 201
    moved = client.put('/api/users/bob', headers=headers, json={'email': 'erin@example.com'})
    assert moved.status_code == 409, moved.get_json()


def test_sso_still_links_by_email_when_one_user_holds_the_address():
    """CONTROL: one match is a link, as before."""
    users = {'alice': {'email': 'Shared@Example.com'}, 'bob': {'email': 'bob@example.com'}}
    assert OIDCManager._find_by_email(users, ' shared@example.com ') == 'alice'
