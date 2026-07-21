"""Disabling an SSO user must actually lock them out, and roles must follow the IdP.

Regression tests for #408.

``resolve_or_provision_user`` short-circuited on a subject match without ever
consulting the row's ``enabled`` flag — the gate the local-password path in
``AuthManager`` has always applied. So an admin who disabled a user (which
also revokes their live sessions) achieved nothing against anyone who logs in
through the IdP: the next SSO login minted a fresh 8h session with the old
role.

The same branch never re-derived the role from the current claims, so removing
someone from the admin group in the IdP left them admin in CertMate forever.
"""

import pytest

from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.oidc import OIDCManager
from modules.core.settings import SettingsManager


pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_manager(tmp_path):
    dirs = [tmp_path / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir()
    file_ops = FileOperations(*dirs)
    sm = SettingsManager(file_ops=file_ops, settings_file=dirs[1] / "settings.json")
    sm.load_settings()  # force creation of the defaults file
    return sm


@pytest.fixture
def oidc(settings_manager):
    auth_manager = AuthManager(settings_manager)
    auth_manager.set_hmac_key("test-secret-for-hmac")
    return OIDCManager(settings_manager, auth_manager)


def _enable_oidc(settings_manager, **overrides):
    config = {
        'enabled': True,
        'provider_name': 'TestIdP',
        'issuer_url': 'https://idp.example.com',
        'client_id': 'cm-test',
        'client_secret': 'shh',
        'scopes': ['openid', 'email', 'profile', 'groups'],
        'username_claim': 'preferred_username',
        'email_claim': 'email',
        'role_claim': 'groups',
        'role_mappings': [
            {'claim_value': 'eng-admins', 'role': 'admin'},
            {'claim_value': 'eng', 'role': 'operator'},
        ],
        'default_role': 'viewer',
        'auto_create_users': True,
        'link_by_email': True,
    }
    config.update(overrides)
    settings_manager.update(lambda s: s.__setitem__('oidc', config), 'test_seed')


def _claims(sub='sub-1', username='bob', email='bob@example.com', groups=None):
    return {
        'sub': sub,
        'iss': 'https://idp.example.com',
        'preferred_username': username,
        'email': email,
        'email_verified': True,
        'groups': groups if groups is not None else ['eng'],
    }


def _users(settings_manager):
    return settings_manager.load_settings().get("users", {})


def test_disabled_user_cannot_log_back_in_through_the_idp(oidc, settings_manager):
    _enable_oidc(settings_manager)

    # First login provisions the row.
    username, err = oidc.resolve_or_provision_user(_claims())
    assert err is None and username == 'bob'

    # The admin disables them (and their live sessions are revoked elsewhere).
    settings_manager.update(
        lambda s: s['users']['bob'].__setitem__('enabled', False), 'disable_user'
    )

    username, err = oidc.resolve_or_provision_user(_claims())
    assert username is None, "a disabled user got back in through SSO"
    assert err == 'user_disabled'


def test_disabled_user_cannot_be_linked_by_email_either(oidc, settings_manager):
    _enable_oidc(settings_manager)

    def _seed(s):
        s.setdefault('users', {})['alice'] = {
            'password_hash': 'x',
            'role': 'admin',
            'email': 'alice@example.com',
            'enabled': False,
        }

    settings_manager.update(_seed, 'seed_disabled_local_user')

    username, err = oidc.resolve_or_provision_user(
        _claims(sub='sub-alice', username='alice', email='alice@example.com')
    )
    assert username is None
    assert err == 'user_disabled'
    # The link must not have been written onto the disabled row.
    assert 'oidc_subject' not in _users(settings_manager)['alice']


def test_role_is_re_derived_from_current_claims_on_every_login(oidc, settings_manager):
    _enable_oidc(settings_manager)

    username, err = oidc.resolve_or_provision_user(_claims(groups=['eng-admins']))
    assert err is None
    assert _users(settings_manager)[username]['role'] == 'admin'

    # Ops removes them from the admin group in the IdP.
    username, err = oidc.resolve_or_provision_user(_claims(groups=['eng']))
    assert err is None
    assert _users(settings_manager)[username]['role'] == 'operator', \
        "role kept its old value after the IdP demoted the user"

    # And all the way down to the default when they are in no mapped group.
    username, err = oidc.resolve_or_provision_user(_claims(groups=[]))
    assert _users(settings_manager)[username]['role'] == 'viewer'


def test_role_sync_can_be_turned_off_for_locally_managed_roles(oidc, settings_manager):
    _enable_oidc(settings_manager, sync_role_on_login=False)

    username, _ = oidc.resolve_or_provision_user(_claims(groups=['eng-admins']))
    assert _users(settings_manager)[username]['role'] == 'admin'

    oidc.resolve_or_provision_user(_claims(groups=[]))
    assert _users(settings_manager)[username]['role'] == 'admin'


def test_enabled_user_still_logs_in_normally(oidc, settings_manager):
    _enable_oidc(settings_manager)
    username, err = oidc.resolve_or_provision_user(_claims())
    assert (username, err) == ('bob', None)

    username, err = oidc.resolve_or_provision_user(_claims())
    assert (username, err) == ('bob', None)
    assert _users(settings_manager)['bob']['last_login']
