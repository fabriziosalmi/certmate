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
    # A local admin, which every real instance has — the first-run account.
    # Without one, `bob` below is the instance's ONLY admin and the last
    # step of this test is the admin lockout that the guard added in
    # test_the_idp_cannot_demote_the_last_admin now refuses. The point being
    # asserted here is that the role follows the claims, not that CertMate
    # will demote its way down to nobody.
    settings_manager.update(
        lambda s: s.setdefault('users', {}).__setitem__('root', {
            'password_hash': 'x', 'role': 'admin', 'enabled': True}),
        'local_admin')

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


# --- the guard the sync never had ----------------------------------------
#
# Found by the certmate-website session reading v2.35.0. `update_user` refuses
# to demote, disable or delete the last active admin — "the same lockout in a
# different shape", says the comment beside it. The sync branch above wrote
# `users[username]['role'] = role` with no such check, and the trigger is
# outside CertMate entirely: an IdP group edit, or a typo in role_mappings.
#
# It is worse than a local demotion because a JIT-provisioned row carries
# `password_hash: ''`, so the local login path refuses that user by design.
# With the last admin demoted there is no admin session and no password to
# get one — only hand-editing settings.json.

def _seed_sole_sso_admin(settings_manager):
    """One admin, SSO-provisioned, exactly as a first login leaves them."""
    def _seed(s):
        s['users'] = {'alice': {
            'password_hash': '',          # SSO rows have no local password
            'role': 'admin',
            'email': 'alice@example.com',
            'enabled': True,
            'oidc_subject': 'sub-1',
            'oidc_issuer': 'https://idp.example.com',
        }}
    settings_manager.update(_seed, 'seed_sole_admin')


def test_the_idp_cannot_demote_the_last_admin(oidc, settings_manager):
    """THE regression. The login still succeeds; the demotion does not."""
    _enable_oidc(settings_manager)
    _seed_sole_sso_admin(settings_manager)

    username, err = oidc.resolve_or_provision_user(
        _claims(username='alice', email='alice@example.com', groups=['eng']))

    assert (username, err) == ('alice', None), 'the login itself must still work'
    assert _users(settings_manager)['alice']['role'] == 'admin'
    admins = [u for u in _users(settings_manager).values()
              if u.get('role') == 'admin' and u.get('enabled', True)]
    assert len(admins) == 1, 'the instance was left with no administrator'


def test_it_demotes_when_another_admin_remains(oidc, settings_manager):
    """CONTROL. The guard is about the LAST admin, not about admins. A fix
    that simply stopped syncing admins would pass the test above and break
    the whole point of sync_role_on_login."""
    _enable_oidc(settings_manager)
    _seed_sole_sso_admin(settings_manager)
    settings_manager.update(
        lambda s: s['users'].__setitem__('root', {
            'password_hash': 'x', 'role': 'admin', 'enabled': True}),
        'second_admin')

    oidc.resolve_or_provision_user(
        _claims(username='alice', email='alice@example.com', groups=['eng']))

    assert _users(settings_manager)['alice']['role'] == 'operator'


def test_a_disabled_second_admin_does_not_count(oidc, settings_manager):
    """A disabled admin cannot log in, so they are not an escape route. The
    shared helper counts enabled admins for exactly this reason."""
    _enable_oidc(settings_manager)
    _seed_sole_sso_admin(settings_manager)
    settings_manager.update(
        lambda s: s['users'].__setitem__('root', {
            'password_hash': 'x', 'role': 'admin', 'enabled': False}),
        'disabled_admin')

    oidc.resolve_or_provision_user(
        _claims(username='alice', email='alice@example.com', groups=['eng']))

    assert _users(settings_manager)['alice']['role'] == 'admin'


def test_a_promotion_is_never_blocked(oidc, settings_manager):
    """CONTROL on the other direction: the guard must not make it impossible
    to gain the role, only to lose the last one."""
    _enable_oidc(settings_manager)
    _seed_sole_sso_admin(settings_manager)
    settings_manager.update(
        lambda s: s['users']['alice'].__setitem__('role', 'viewer'),
        'demote_first')

    oidc.resolve_or_provision_user(
        _claims(username='alice', email='alice@example.com',
                groups=['eng-admins']))

    assert _users(settings_manager)['alice']['role'] == 'admin'


def test_both_paths_ask_the_same_question():
    """The count was written out twice in auth.py and not at all in oidc.py.
    One helper, three callers — a fourth copy is the next silent divergence."""
    import inspect

    from modules.core import auth, oidc as oidc_module

    assert 'def active_admin_count' in inspect.getsource(auth)
    for module in (auth, oidc_module):
        source = inspect.getsource(module)
        assert 'active_admin_count(' in source
        assert "u.get('role') == 'admin' and u.get('enabled', True)" not in \
            source.split('def active_admin_count')[-1].split('\n\n\n')[1], \
            'the count is spelled out again outside the helper'


# --- two settings that existed only in the API ---------------------------

def test_the_form_offers_the_settings_the_api_accepts():
    """`require_verified_email` and `sync_role_on_login` round-tripped
    through POST /api/auth/oidc/settings and appeared nowhere in the UI. The
    first is the account-takeover gate described in oidc.py: a defence an
    operator cannot see is one they cannot check."""
    import pathlib

    repo = pathlib.Path(__file__).resolve().parent.parent
    panel = (repo / 'templates' / 'partials' /
             'settings_oidc.html').read_text(encoding='utf-8')

    for field in ('require_verified_email', 'sync_role_on_login'):
        assert f'cfg.{field}' in panel, f'the OIDC form has no control for {field}'


def test_the_form_covers_every_configurable_key():
    """The two above were not the only way to get here, only the ones that
    happened. This compares the whole normalized config against the panel."""
    import pathlib

    from modules.core.oidc import _normalize_oidc_config

    repo = pathlib.Path(__file__).resolve().parent.parent
    panel = (repo / 'templates' / 'partials' /
             'settings_oidc.html').read_text(encoding='utf-8')
    script = (repo / 'static' / 'js' /
              'settings-oidc.js').read_text(encoding='utf-8')

    # `scopes` is edited as a joined string (scopesString), and role_mappings
    # is a repeater; both are in the panel under those names.
    rendered_elsewhere = {'scopes', 'role_mappings'}
    missing = [key for key in _normalize_oidc_config({})
               if key not in rendered_elsewhere
               and f'cfg.{key}' not in panel and f'cfg.{key}' not in script]

    assert not missing, f'no control for: {sorted(missing)}'
