"""A key file that cannot be read is not permission to invent a key.

`SECRET_KEY_FILE` names where the Flask session-signing key comes from —
usually a Docker or Kubernetes secret mount. When that file could not be read,
or was empty, CertMate logged a WARNING and generated a fresh key.

The warning said "generating a fresh secret key". It did not say what that
means, and what it means is three things:

* every existing session cookie becomes invalid, so every logged-in user is
  signed out;
* the key is regenerated on each start, so a restart loop signs them out again
  every time, with nothing connecting the symptom to the unmounted secret;
* the operator believes sessions are signed with a key they control — possibly
  one deliberately shared across replicas — and they are not.

An unmounted secret is a configuration error. This repository already refuses
to start on an unreadable `settings.json` (`SettingsUnreadableError`) and on an
unreadable `API_BEARER_TOKEN_FILE`; `SECRET_KEY_FILE` is the same shape and now
gets the same answer. `app.py` wraps `create_app` and exits 1, so the operator
gets one line and a container that stops instead of an instance running with a
key nobody chose.

The tests below separate the two things that can be wrong independently: what
the resolver decides, and whether the exception actually stops the process.
"""
import os
import stat
from pathlib import Path

import pytest

from modules.core.factory import (
    SecretKeyUnreadableError, _secret_key_from_env_or_generate,
)

pytestmark = [pytest.mark.unit]

KEY = 'a' * 64


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv('SECRET_KEY_FILE', raising=False)
    monkeypatch.delenv('SECRET_KEY', raising=False)


# --- what the resolver decides ------------------------------------------

def test_a_readable_key_file_is_used(tmp_path, monkeypatch):
    key_file = tmp_path / 'secret'
    key_file.write_text(KEY + '\n')
    monkeypatch.setenv('SECRET_KEY_FILE', str(key_file))

    assert _secret_key_from_env_or_generate(tmp_path) == KEY


def test_a_missing_key_file_refuses_to_start(tmp_path, monkeypatch):
    monkeypatch.setenv('SECRET_KEY_FILE', str(tmp_path / 'not-mounted'))

    with pytest.raises(SecretKeyUnreadableError) as caught:
        _secret_key_from_env_or_generate(tmp_path)
    assert 'not-mounted' in str(caught.value)


def test_an_unreadable_key_file_refuses_to_start(tmp_path, monkeypatch):
    """The shape a wrong-uid mount actually takes: the file is there and the
    process cannot read it."""
    key_file = tmp_path / 'secret'
    key_file.write_text(KEY)
    key_file.chmod(0o000)
    monkeypatch.setenv('SECRET_KEY_FILE', str(key_file))

    try:
        if os.access(str(key_file), os.R_OK):
            pytest.skip('running as a user that ignores file modes (root)')
        with pytest.raises(SecretKeyUnreadableError):
            _secret_key_from_env_or_generate(tmp_path)
    finally:
        key_file.chmod(stat.S_IRUSR | stat.S_IWUSR)


def test_an_empty_key_file_refuses_to_start(tmp_path, monkeypatch):
    """A Kubernetes secret that exists but has not been populated yet reads as
    an empty file, not as a missing one."""
    key_file = tmp_path / 'secret'
    key_file.write_text('')
    monkeypatch.setenv('SECRET_KEY_FILE', str(key_file))

    with pytest.raises(SecretKeyUnreadableError) as caught:
        _secret_key_from_env_or_generate(tmp_path)
    assert 'empty' in str(caught.value)


def test_a_key_file_of_whitespace_is_empty(tmp_path, monkeypatch):
    key_file = tmp_path / 'secret'
    key_file.write_text('   \n\t\n')
    monkeypatch.setenv('SECRET_KEY_FILE', str(key_file))

    with pytest.raises(SecretKeyUnreadableError):
        _secret_key_from_env_or_generate(tmp_path)


def test_the_message_states_the_consequence_not_just_the_cause(tmp_path,
                                                               monkeypatch):
    """The old warning said what it did, never what it cost. An operator
    reading "generating a fresh secret key" has no way to connect it to users
    being signed out."""
    monkeypatch.setenv('SECRET_KEY_FILE', str(tmp_path / 'absent'))

    with pytest.raises(SecretKeyUnreadableError) as caught:
        _secret_key_from_env_or_generate(tmp_path)

    message = str(caught.value)
    assert 'sign out every' in message or 'sign out' in message
    assert 'every restart' in message
    assert 'unset SECRET_KEY_FILE' in message, (
        'the message does not say how to get running again'
    )


# --- what must NOT change ------------------------------------------------

def test_no_key_file_still_generates_and_persists(tmp_path):
    """CONTROL: the failure is specific to a file the operator NAMED. An
    instance that was never given one must keep managing its own key."""
    key = _secret_key_from_env_or_generate(tmp_path)

    assert len(key) == 64
    assert (tmp_path / '.secret_key').read_text().strip() == key


def test_a_persisted_key_is_reused_so_sessions_survive_a_restart(tmp_path):
    first = _secret_key_from_env_or_generate(tmp_path)
    second = _secret_key_from_env_or_generate(tmp_path)
    assert first == second


def test_the_secret_key_variable_still_works(tmp_path, monkeypatch):
    monkeypatch.setenv('SECRET_KEY', KEY)
    assert _secret_key_from_env_or_generate(tmp_path) == KEY


@pytest.mark.parametrize('value', ['your-secret-key-here', 'change-me',
                                   'secret'])
def test_an_insecure_default_is_still_ignored(tmp_path, monkeypatch, value):
    monkeypatch.setenv('SECRET_KEY', value)
    assert _secret_key_from_env_or_generate(tmp_path) != value


def test_the_key_file_still_wins_over_the_variable(tmp_path, monkeypatch):
    """CONTROL: the two are mutually exclusive on purpose. If a broken
    SECRET_KEY_FILE fell through to SECRET_KEY, the refusal could be bypassed
    by a variable the operator forgot was set."""
    key_file = tmp_path / 'secret'
    key_file.write_text(KEY)
    monkeypatch.setenv('SECRET_KEY_FILE', str(key_file))
    monkeypatch.setenv('SECRET_KEY', 'b' * 64)

    assert _secret_key_from_env_or_generate(tmp_path) == KEY


def test_a_broken_key_file_does_not_fall_through_to_the_variable(tmp_path,
                                                                 monkeypatch):
    monkeypatch.setenv('SECRET_KEY_FILE', str(tmp_path / 'absent'))
    monkeypatch.setenv('SECRET_KEY', 'b' * 64)

    with pytest.raises(SecretKeyUnreadableError):
        _secret_key_from_env_or_generate(tmp_path)


# --- and it has to actually stop the process ----------------------------

def test_create_app_propagates_the_refusal(tmp_path, monkeypatch):
    """The resolver raising is worth nothing if create_app swallows it. app.py
    catches whatever create_app raises and exits 1, so what matters is that
    the exception gets out."""
    from modules.core.factory import create_app

    root = tmp_path / 'certmate'
    module_dir = root / 'modules' / 'core'
    module_dir.mkdir(parents=True)
    anchor = module_dir / 'factory.py'
    anchor.write_text('# test path anchor\n')
    for shared in ('templates', 'static'):
        source = Path(__file__).resolve().parent.parent / shared
        if source.is_dir():
            (root / shared).symlink_to(source)

    monkeypatch.setattr('modules.core.factory.__file__', str(anchor))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('SECRET_KEY_FILE', str(tmp_path / 'never-mounted'))

    with pytest.raises(SecretKeyUnreadableError):
        create_app()


def test_app_py_exits_rather_than_serving():
    """The last link: app.py wraps create_app and exits 1. Read rather than
    executed — importing app.py starts an application."""
    source = (Path(__file__).resolve().parent.parent / 'app.py').read_text()
    assert 'app, container = create_app()' in source
    assert 'sys.exit(1)' in source, (
        'app.py no longer stops on a create_app failure, so a refusal to '
        'start would be logged and then ignored'
    )
