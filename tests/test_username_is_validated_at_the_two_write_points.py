"""A username is checked where it enters, and only for what actually harms.

A username is a key in `settings['users']`, a name rendered in the UI, and a
value written into every audit record for that session. Nothing constrained it,
and one of the two ways it can be created is not an operator typing it: the
OIDC path takes it from an IdP claim.

The risk in a check like this is not that it is too weak, it is that it is too
strong. An allowlist would lock real people out of a working SSO deployment —
IdPs legitimately issue addresses, dots, apostrophes and non-ASCII names as
`preferred_username`. So the rule is narrow: control characters, which no
person's name contains, and a length cap. The bulk of this file is the evidence
that legitimate names still get through, because that is the failure mode with
real users on the other side of it.

Validation is at write time only. Existing rows are left alone deliberately:
renaming or dropping an account that is already there would be destructive, and
the log paths that consume a username scrub their own values anyway.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.auth import USERNAME_MAX_LENGTH, validate_username

pytestmark = [pytest.mark.unit]

# Names an IdP really does put in preferred_username, or a person really picks.
LEGITIMATE = [
    'alice',
    'alice@example.com',
    'alice.smith',
    'alice-smith_1',
    "O'Brien",
    'José',
    'Ævar',
    '张伟',
    'Müller',
    'user+tag@example.com',
    'CN=alice,OU=staff',
    'a' * USERNAME_MAX_LENGTH,
]

HOSTILE = [
    'alice\nbob',
    'alice\rbob',
    'alice\tbob',
    'alice\x00bob',
    'alice\x1bbob',
    'alice\x7fbob',
    '\n',
]

EMPTY = ['', '   ', '\t\n', None, 42, [], {}]


@pytest.mark.parametrize('name', LEGITIMATE)
def test_names_real_people_and_idps_use_are_accepted(name):
    """The assertion that matters: this check must not lock anyone out."""
    clean, err = validate_username(name)
    assert err is None, f'{name!r} was refused: {err}'
    assert clean == name


@pytest.mark.parametrize('name', HOSTILE)
def test_control_characters_are_refused(name):
    clean, err = validate_username(name)
    assert err is not None, f'{name!r} was accepted'
    assert clean is None


@pytest.mark.parametrize('name', EMPTY)
def test_nothing_is_not_a_username(name):
    clean, err = validate_username(name)
    assert err is not None, f'{name!r} was accepted as a username'


def test_surrounding_whitespace_is_normalised_not_refused():
    """Stripping rather than rejecting is the deliberate choice.

    Nobody intends a trailing space as part of their identity, and normalising
    means the padded form now collides with the existing account instead of
    creating a second, visually identical one.
    """
    assert validate_username('  alice  ') == ('alice', None)


def test_a_name_one_character_over_the_cap_is_refused():
    """CONTROL: the cap has to be a boundary, not decoration. The accepted case
    at exactly the limit is in LEGITIMATE above."""
    clean, err = validate_username('a' * (USERNAME_MAX_LENGTH + 1))
    assert err is not None and clean is None


# ---------------------------------------------------------------------------
# The two write points
# ---------------------------------------------------------------------------

@pytest.fixture
def auth(tmp_path):
    """A real AuthManager over a settings file of our own.

    Built directly rather than through `create_app`: `setup_directories`
    resolves the data directory from the package location, not from DATA_DIR,
    so a factory-built manager reads and writes the checkout's real
    `data/settings.json`. A test that asserted on the stored user list that way
    would be reading whatever a previous run left behind — and did, before this
    fixture was rewritten.
    """
    from modules.core.auth import AuthManager
    from modules.core.file_operations import FileOperations
    from modules.core.settings import SettingsManager

    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    settings = SettingsManager(file_ops=FileOperations(*dirs),
                               settings_file=dirs[1] / 'settings.json')
    settings.load_settings()
    manager = AuthManager(settings)
    manager.set_hmac_key('test-secret-for-hmac')
    return manager


def test_create_user_refuses_a_control_character(auth):
    ok, msg = auth.create_user('bad\nname', 'S0me-Long-Passw0rd!')
    assert ok is False, f'the account was created: {msg}'
    assert not any('\n' in key for key in auth._get_users()), (
        'a username containing a newline was stored as a key in settings'
    )


def test_create_user_still_creates_ordinary_accounts(auth):
    """CONTROL: proves the refusal above is a refusal and not a broken path."""
    ok, msg = auth.create_user('alice@example.com', 'S0me-Long-Passw0rd!')
    assert ok is True, f'a legitimate account was refused: {msg}'
    assert 'alice@example.com' in auth._get_users()


def test_create_user_normalises_before_the_exists_check(auth):
    """The padded form must not become a second, visually identical account."""
    assert auth.create_user('alice', 'S0me-Long-Passw0rd!')[0] is True
    ok, msg = auth.create_user('  alice  ', 'An0ther-Long-Passw0rd!')
    assert ok is False and 'exists' in msg.lower(), (
        f'a second account was created for a padded name: {msg}'
    )


def _oidc_manager():
    from modules.core.oidc import OIDCManager
    settings = MagicMock()
    settings.load_settings.return_value = {
        'oidc': {'enabled': True, 'issuer_url': 'https://idp.example.com',
                 'client_id': 'x', 'auto_provision': True},
        'users': {},
    }
    manager = OIDCManager.__new__(OIDCManager)
    manager.settings_manager = settings
    return manager


def test_the_idp_claim_is_checked_too():
    """The one username CertMate does not get from an operator.

    Refused rather than sanitised: a claim carrying a control character is a
    misconfigured or hostile IdP, and quietly rewriting the identity it asserts
    would be worse than declining the login.
    """
    manager = _oidc_manager()
    username, err = manager.resolve_or_provision_user({
        'sub': 'subject-1',
        'preferred_username': 'evil\nname',
        'iss': 'https://idp.example.com',
    })
    assert username is None
    assert err == 'invalid_username', (
        f'expected the login to be declined with a nameable reason, got {err!r}'
    )
