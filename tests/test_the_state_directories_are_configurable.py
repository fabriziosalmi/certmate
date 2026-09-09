"""Four directories that nothing could move, and a config parameter read nowhere.

    def setup_directories(container: AppContainer, test_config=None):
        _base = Path(__file__).resolve().parent.parent.parent
        container.cert_dir = (_base / "certificates").resolve()
        ...

Deriving them from the module's own location is a good default — it is what
makes the image and the systemd unit work with no configuration at all — but it
was the only answer available. A deployment wanting certificates on one volume
and backups on another had to bind-mount over the install tree, and this
repository's own suite redirects state by monkeypatching
`modules.core.factory.__file__`, which is not something an application should
require of anyone.

`test_config` made it worse rather than better: `create_app(test_config={...})`
accepted a configuration that could not affect any of this, so a caller passing
paths in it got the install tree and no error.

The defaults are unchanged. What is new is that CERTMATE_CERT_DIR,
CERTMATE_DATA_DIR, CERTMATE_BACKUP_DIR and CERTMATE_LOGS_DIR are read, and that
`test_config` wins over them — a test that passes paths gets those paths rather
than whatever the developer has exported.
"""
import os

import pytest

from modules.core import factory

pytestmark = [pytest.mark.unit]

VARIABLES = ('CERTMATE_CERT_DIR', 'CERTMATE_DATA_DIR',
             'CERTMATE_BACKUP_DIR', 'CERTMATE_LOGS_DIR')


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in VARIABLES:
        monkeypatch.delenv(name, raising=False)


# --- the default is what it always was -----------------------------------

def test_with_nothing_set_the_directories_are_where_they_were():
    """CONTROL, and the one that matters most: the image, the compose file and
    the systemd unit all rely on this derivation and none of them was changed."""
    from pathlib import Path

    base = Path(factory.__file__).resolve().parent.parent.parent
    resolved = factory.resolve_state_directories()

    assert resolved == {
        'cert_dir': (base / 'certificates').resolve(),
        'data_dir': (base / 'data').resolve(),
        'backup_dir': (base / 'backups').resolve(),
        'logs_dir': (base / 'logs').resolve(),
    }


# --- THE change -----------------------------------------------------------

@pytest.mark.parametrize('name,attribute', [
    ('CERTMATE_CERT_DIR', 'cert_dir'),
    ('CERTMATE_DATA_DIR', 'data_dir'),
    ('CERTMATE_BACKUP_DIR', 'backup_dir'),
    ('CERTMATE_LOGS_DIR', 'logs_dir'),
])
def test_each_directory_moves_on_its_own(tmp_path, monkeypatch, name, attribute):
    """Separately, not as a set: the deployment this exists for puts
    certificates on one volume and backups on another."""
    target = tmp_path / attribute
    monkeypatch.setenv(name, str(target))

    resolved = factory.resolve_state_directories()

    assert resolved[attribute] == target.resolve()
    for other, value in resolved.items():
        if other != attribute:
            assert value != target.resolve()


def test_a_relative_value_resolves_and_is_absolute(tmp_path, monkeypatch):
    """What the container reports must be absolute wherever it came from: a
    relative path recorded as relative would mean something different to the
    scheduler thread than to the request that set it."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('CERTMATE_DATA_DIR', 'state/data')

    resolved = factory.resolve_state_directories()

    assert resolved['data_dir'].is_absolute()
    assert resolved['data_dir'] == (tmp_path / 'state' / 'data').resolve()


def test_an_empty_value_is_not_a_path(monkeypatch):
    """`CERTMATE_DATA_DIR=` in a compose file is an unset variable, not a
    request to put the data directory at the filesystem root."""
    from pathlib import Path

    monkeypatch.setenv('CERTMATE_DATA_DIR', '   ')

    base = Path(factory.__file__).resolve().parent.parent.parent
    assert factory.resolve_state_directories()['data_dir'] == (base / 'data').resolve()


# --- the parameter that was accepted and ignored -------------------------

def test_test_config_is_read_at_last(tmp_path, monkeypatch):
    """It was in the signature and consulted nowhere, so a caller passing
    paths got the install tree and no error."""
    from_env = tmp_path / 'from-env'
    from_config = tmp_path / 'from-config'
    monkeypatch.setenv('CERTMATE_DATA_DIR', str(from_env))

    resolved = factory.resolve_state_directories(
        {'CERTMATE_DATA_DIR': str(from_config)})

    assert resolved['data_dir'] == from_config.resolve()


def test_a_config_without_paths_leaves_the_environment_alone(tmp_path, monkeypatch):
    """CONTROL: `create_app(test_config={'TESTING': True})` is what most of
    this suite passes, and it must not mean 'put everything in the CWD'."""
    monkeypatch.setenv('CERTMATE_CERT_DIR', str(tmp_path / 'certs'))

    resolved = factory.resolve_state_directories({'TESTING': True})

    assert resolved['cert_dir'] == (tmp_path / 'certs').resolve()


# --- what the container ends up holding ----------------------------------

def test_the_container_gets_what_was_resolved(tmp_path, monkeypatch):
    monkeypatch.setenv('CERTMATE_BACKUP_DIR', str(tmp_path / 'b'))
    monkeypatch.setenv('CERTMATE_CERT_DIR', str(tmp_path / 'c'))
    monkeypatch.setenv('CERTMATE_DATA_DIR', str(tmp_path / 'd'))
    monkeypatch.setenv('CERTMATE_LOGS_DIR', str(tmp_path / 'l'))

    container = factory.AppContainer()
    factory.setup_directories(container)

    assert container.backup_dir == (tmp_path / 'b').resolve()
    assert container.cert_dir == (tmp_path / 'c').resolve()
    assert container.data_dir == (tmp_path / 'd').resolve()
    assert container.logs_dir == (tmp_path / 'l').resolve()
    # setup_directories also creates them; a configured directory that does
    # not exist yet is the ordinary first-boot case for a fresh volume.
    assert container.backup_dir.is_dir() and (container.backup_dir / 'unified').is_dir()


def test_a_directory_that_cannot_be_written_still_fails_at_boot(tmp_path):
    """CONTROL for #121, which is the reason this function does more than
    assign four attributes: a misconfigured mount must be a clean error at
    startup, not a half-succeeding setup wizard. Relocating them must not have
    routed around the probe."""
    unwritable = tmp_path / 'ro'
    unwritable.mkdir()
    unwritable.chmod(0o500)   # so the data directory cannot be created in it
    container = factory.AppContainer()
    try:
        with pytest.raises(RuntimeError) as caught:
            factory.setup_directories(
                container, {'CERTMATE_DATA_DIR': str(unwritable / 'data')})
    finally:
        unwritable.chmod(0o700)

    assert 'not writable' in str(caught.value)


# --- the suite cannot be steered by the developer's environment ----------

def test_the_suite_unsets_them():
    """The anchor in conftest redirects state by monkeypatching
    `factory.__file__`, and these variables now take precedence over it. A
    developer with CERTMATE_DATA_DIR exported at their own instance would
    otherwise have the suite write into it."""
    import pathlib

    source = (pathlib.Path(__file__).resolve().parent
              / 'conftest.py').read_text(encoding='utf-8')

    assert 'delenv' in source
    for name in VARIABLES:
        assert name in source, (
            f'{name} is not unset by the session fixture, so an exported '
            f'value would redirect the suite')


def test_they_are_unset_right_now():
    """The behavioural half of the check above."""
    assert not any(os.getenv(name) for name in VARIABLES)
