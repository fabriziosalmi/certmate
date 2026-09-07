"""The env bearer token and the stored one must not disagree (#401).

Two pieces of code decided two different things about the same token.
`is_setup_mode()` asked whether the OPERATOR supplied one via
API_BEARER_TOKEN(_FILE); `authenticate_api_token()` checked the presented token
against the STORED hash. On a fresh install those agree, because the stored
value is seeded from the env one.

They diverge for an operator who ran once without a token — one was generated
and stored — then added or rotated API_BEARER_TOKEN and restarted. The
essential-keys merge never overwrites a token that is already there, so
enforcement saw the new token while authentication still checked the old one:
the first-run screen asked the operator to paste the token they had just
configured, and answered 401. The documented way out was a reset script.

Reconciliation makes the supplied token authoritative, which is how enforcement
already treats it. The tests that matter most here are the ones about what it
must NOT do: it must not act when the two already agree, must not store a
malformed token, and must not touch an instance where the operator supplied
nothing at all.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.auth import AuthManager
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]

SECRET = 'a-secret-key-for-hmac'
ENV_TOKEN = 'EXfHVajpXVkJBoXA5vu6_5DmuPnvhJqtcmoc4iF3j4J7Q9zm'
OTHER_TOKEN = 'Zq7WmTt2rXbN8sVcLpKdHgFjYuIoEaSxCvBnMlQwRtYu'


@pytest.fixture
def instance(tmp_path, monkeypatch):
    """A configured instance with a token already stored, and no env token."""
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    monkeypatch.delenv('API_BEARER_TOKEN_FILE', raising=False)

    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    settings = SettingsManager(FileOperations(*dirs), dirs[1] / 'settings.json')
    settings.load_settings()

    auth = AuthManager(settings)
    auth.set_hmac_key(SECRET)
    settings.set_token_hasher(auth.hash_api_token)
    # Whatever first boot generated and stored.
    settings.atomic_update({'api_bearer_token': OTHER_TOKEN})
    return auth, settings


def _authenticates(auth, settings, token):
    stored = settings.load_settings(use_cache=False).get('api_bearer_token_hash')
    return bool(stored) and auth._verify_api_token(token, stored)


# ---------------------------------------------------------------------------
# The lockout
# ---------------------------------------------------------------------------

def test_a_token_added_after_first_run_becomes_the_working_one(
        instance, monkeypatch):
    """The reported case: enforcement saw the new token, authentication did not."""
    auth, settings = instance
    monkeypatch.setenv('API_BEARER_TOKEN', ENV_TOKEN)

    assert not _authenticates(auth, settings, ENV_TOKEN), (
        'this test is only meaningful while the two disagree'
    )

    assert auth.reconcile_bearer_token_from_env() is True
    assert _authenticates(auth, settings, ENV_TOKEN), (
        'the operator would still be told to paste a token that 401s'
    )


def test_the_reconciled_token_is_stored_hashed_not_in_the_clear(
        instance, monkeypatch):
    """Reconciliation writes through a normal save, and that save is what
    hashes. Called before the hasher is installed it would persist plaintext,
    so this pins the outcome rather than the ordering."""
    auth, settings = instance
    monkeypatch.setenv('API_BEARER_TOKEN', ENV_TOKEN)

    auth.reconcile_bearer_token_from_env()
    stored = settings.load_settings(use_cache=False)

    assert 'api_bearer_token' not in stored, (
        'the bearer token was left on disk in plaintext'
    )
    assert stored.get('api_bearer_token_hash', '').startswith('hmac-sha256:')


def test_a_token_supplied_by_file_works_the_same(instance, monkeypatch, tmp_path):
    auth, settings = instance
    token_file = tmp_path / 'token'
    token_file.write_text(ENV_TOKEN + '\n')
    monkeypatch.setenv('API_BEARER_TOKEN_FILE', str(token_file))

    assert auth.reconcile_bearer_token_from_env() is True
    assert _authenticates(auth, settings, ENV_TOKEN)


def test_a_rotated_env_token_replaces_the_previous_one(instance, monkeypatch):
    """Rotation is the same path as addition, and the OLD token must stop
    working — otherwise a rotation leaves a credential live."""
    auth, settings = instance
    monkeypatch.setenv('API_BEARER_TOKEN', ENV_TOKEN)
    auth.reconcile_bearer_token_from_env()

    assert not _authenticates(auth, settings, OTHER_TOKEN), (
        'the previously stored token still authenticates after a rotation'
    )


# ---------------------------------------------------------------------------
# What it must NOT do
# ---------------------------------------------------------------------------

def test_nothing_happens_when_no_token_was_supplied(instance, monkeypatch):
    """An instance the operator never gave a token to must be left alone."""
    auth, settings = instance
    before = settings.load_settings(use_cache=False).get('api_bearer_token_hash')

    assert auth.reconcile_bearer_token_from_env() is False
    assert settings.load_settings(use_cache=False).get(
        'api_bearer_token_hash') == before


def test_nothing_happens_when_the_two_already_agree(instance, monkeypatch):
    """The common case — a fresh install — must not be rewritten on every boot."""
    auth, settings = instance
    monkeypatch.setenv('API_BEARER_TOKEN', OTHER_TOKEN)
    before = settings.load_settings(use_cache=False).get('api_bearer_token_hash')

    assert auth.reconcile_bearer_token_from_env() is False
    assert settings.load_settings(use_cache=False).get(
        'api_bearer_token_hash') == before


@pytest.mark.parametrize('bad', [
    'short',
    'x' * 600,
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',   # long enough, no variety
])
def test_a_malformed_token_makes_the_instance_refuse_to_serve(
        instance, monkeypatch, bad):
    """Stronger than "reconciliation skips it", which is what I first wrote.

    load_settings itself raises BearerTokenUnusableError when API_BEARER_TOKEN
    is set but unusable — ignoring it would leave the instance with no
    authentication at all. So a malformed token never reaches reconciliation:
    the boot fails first, loudly, and that is the better guarantee. Recorded
    here so a future change that softened it into a warning would have to
    change this test deliberately.
    """
    from modules.core.settings import BearerTokenUnusableError

    auth, settings = instance
    monkeypatch.setenv('API_BEARER_TOKEN', bad)

    with pytest.raises(BearerTokenUnusableError):
        settings.load_settings(use_cache=False)

    # And reconciliation, which loads settings, reports no change rather than
    # taking the process down from inside create_app.
    assert auth.reconcile_bearer_token_from_env() is False


def test_an_empty_env_token_is_not_a_configuration(instance, monkeypatch):
    """An empty string is "no token supplied", not "a bad token"."""
    auth, settings = instance
    monkeypatch.setenv('API_BEARER_TOKEN', '')
    before = settings.load_settings(use_cache=False).get('api_bearer_token_hash')

    assert auth.reconcile_bearer_token_from_env() is False
    assert settings.load_settings(use_cache=False).get(
        'api_bearer_token_hash') == before


def test_an_instance_with_nothing_stored_is_left_to_normal_seeding(
        tmp_path, monkeypatch):
    """A first boot seeds the token through the ordinary path; reconciliation
    must not race it or duplicate it."""
    monkeypatch.setenv('API_BEARER_TOKEN', ENV_TOKEN)
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    settings = SettingsManager(FileOperations(*dirs), dirs[1] / 'settings.json')
    auth = AuthManager(settings)
    auth.set_hmac_key(SECRET)
    settings.set_token_hasher(auth.hash_api_token)

    stored = settings.load_settings(use_cache=False)
    if not stored.get('api_bearer_token') and not stored.get('api_bearer_token_hash'):
        assert auth.reconcile_bearer_token_from_env() is False


def test_reconciliation_never_raises_into_startup(instance, monkeypatch):
    """It runs during create_app. A failure here must not take the process with
    it — an instance that will not boot is worse than one with a token
    mismatch, which at least has a documented recovery."""
    auth, _settings = instance
    monkeypatch.setenv('API_BEARER_TOKEN', ENV_TOKEN)
    auth.settings_manager = MagicMock()
    auth.settings_manager.load_settings.side_effect = OSError('disk gone')

    assert auth.reconcile_bearer_token_from_env() is False


def test_it_is_called_at_startup_after_the_hasher_is_installed():
    """Ordering is the difference between a hashed token and a plaintext one,
    and it is invisible at the call site — so it is asserted on the source."""
    import inspect

    from modules.core import factory

    src = inspect.getsource(factory.initialize_managers)
    hasher_at = src.index('set_token_hasher')
    reconcile_at = src.index('reconcile_bearer_token_from_env')
    assert reconcile_at > hasher_at, (
        'reconciliation runs before the token hasher is installed, so the '
        'token would be written to settings.json in plaintext'
    )
