"""settings.json declares its schema, and a file from the future is refused (#669).

There was already a `certmate_version` on disk and a downgrade *warning*. That
field is the PRODUCT version: it moves on every release, including the many
with no shape change, and it compares only major.minor — so it cannot answer
"is this file a shape I understand", which is the question that matters when
someone rolls back.

`settings_schema_version` moves only when the shape does. A file declaring a
newer one is refused rather than read, because the failure a rollback actually
produces is silent: an older process reading a file it half-understands and
writing it back without the fields it never knew about.

The refusal is escapable — `CERTMATE_ALLOW_SCHEMA_DOWNGRADE=1` — because an
operator who has read the release notes may have good reason. Safe by default,
deliberate to override.

What did NOT change: the shape-sniffing migrations still run at every version.
They are not only migrations. Migration 4's own comment says it must stay
"idempotent and permanent" because a stale settings tab can POST an old payload
shape at any time, so gating them behind a version bump would remove a
defence, not a redundancy.
"""
import json

import pytest

from modules.core.constants import SETTINGS_SCHEMA_VERSION
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager, SettingsSchemaTooNewError

pytestmark = [pytest.mark.unit]


@pytest.fixture
def manager(tmp_path):
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for d in dirs:
        d.mkdir()
    return SettingsManager(FileOperations(*dirs), dirs[1] / 'settings.json')


def _write(manager, payload):
    manager.settings_file.write_text(json.dumps(payload))


# ---------------------------------------------------------------------------
# Stamping
# ---------------------------------------------------------------------------

def test_a_fresh_install_declares_the_current_schema(manager):
    settings = manager.load_settings(use_cache=False)
    assert settings['settings_schema_version'] == SETTINGS_SCHEMA_VERSION


def test_a_file_that_predates_versioning_is_stamped(manager):
    """Every existing install. It has just been through the shape migrations,
    so it IS the current schema whatever it was before."""
    _write(manager, {'domains': ['example.com'], 'email': 'a@b.com'})

    settings = manager.load_settings(use_cache=False)

    assert settings['settings_schema_version'] == SETTINGS_SCHEMA_VERSION
    assert json.loads(manager.settings_file.read_text())[
        'settings_schema_version'] == SETTINGS_SCHEMA_VERSION, 'not persisted'


def test_the_current_schema_is_read_without_complaint(manager):
    _write(manager, {'settings_schema_version': SETTINGS_SCHEMA_VERSION,
                     'domains': [], 'email': 'a@b.com'})
    assert manager.load_settings(use_cache=False)['email'] == 'a@b.com'


def test_a_write_that_omits_the_key_still_declares_the_schema(manager):
    """The one that makes the gate worth having.

    Stamping on load alone leaves a hole the app walks through daily: a caller
    that hands over a payload without the key — POST /api/settings does — wrote
    a file with NO declared schema, and a file with no declared schema is one an
    older build reads happily. The gate can only refuse what is written down.
    """
    manager.load_settings(use_cache=False)

    manager.save_settings({'email': 'b@example.com', 'domains': [],
                           'dns_provider': 'cloudflare'})

    on_disk = json.loads(manager.settings_file.read_text())
    assert on_disk.get('settings_schema_version') == SETTINGS_SCHEMA_VERSION, (
        'a save that omitted the key erased the schema declaration'
    )


# ---------------------------------------------------------------------------
# A file from the future
# ---------------------------------------------------------------------------

def test_a_newer_schema_is_refused(manager):
    _write(manager, {'settings_schema_version': SETTINGS_SCHEMA_VERSION + 1,
                     'domains': []})

    with pytest.raises(SettingsSchemaTooNewError) as excinfo:
        manager.load_settings(use_cache=False)

    message = str(excinfo.value)
    assert str(SETTINGS_SCHEMA_VERSION + 1) in message, (
        'the message does not say which schema the file declares'
    )
    assert 'CERTMATE_ALLOW_SCHEMA_DOWNGRADE' in message, (
        'the message does not tell the operator how to proceed anyway'
    )


def test_the_refusal_stops_the_process_rather_than_degrading(manager):
    """It subclasses SettingsUnreadableError on purpose: app.py exits rather
    than starting an instance that will write a shape it cannot read back."""
    from modules.core.settings import SettingsUnreadableError

    assert issubclass(SettingsSchemaTooNewError, SettingsUnreadableError)


def test_the_escape_hatch_proceeds(manager, monkeypatch):
    monkeypatch.setenv('CERTMATE_ALLOW_SCHEMA_DOWNGRADE', '1')
    _write(manager, {'settings_schema_version': SETTINGS_SCHEMA_VERSION + 5,
                     'domains': [], 'email': 'a@b.com'})

    assert manager.load_settings(use_cache=False)['email'] == 'a@b.com'


@pytest.mark.parametrize('value', ['2', 'v2', None, [], {}, 1.5])
def test_a_non_integer_schema_does_not_trip_the_gate(manager, value):
    """A hand-edited or corrupt field must not brick the instance. It is
    re-stamped instead — the shape migrations have run either way."""
    _write(manager, {'settings_schema_version': value, 'domains': [],
                     'email': 'a@b.com'})

    settings = manager.load_settings(use_cache=False)
    assert settings['settings_schema_version'] == SETTINGS_SCHEMA_VERSION


def test_an_older_schema_is_read_and_restamped(manager):
    """CONTROL: the gate must refuse only what is NEWER. Refusing an older
    file would make every upgrade fail."""
    _write(manager, {'settings_schema_version': 0, 'domains': [],
                     'email': 'a@b.com'})

    settings = manager.load_settings(use_cache=False)
    assert settings['email'] == 'a@b.com'
    assert settings['settings_schema_version'] == SETTINGS_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# What the version is NOT
# ---------------------------------------------------------------------------

def test_the_schema_version_is_not_the_product_version(manager):
    """They answer different questions and must not be conflated: the product
    version moves on every release, this one only when the shape changes."""
    settings = manager.load_settings(use_cache=False)

    assert settings['settings_schema_version'] != settings.get('certmate_version')
    assert isinstance(settings['settings_schema_version'], int)


def test_the_shape_migrations_still_run_at_the_current_version(manager):
    """The thing that must NOT have changed. Migration 4 drops a retired
    letsencrypt field, and its comment says it stays permanent because a stale
    settings tab can POST the old shape at any time. Gating it behind a version
    bump would remove a defence, not a redundancy.
    """
    _write(manager, {
        'settings_schema_version': SETTINGS_SCHEMA_VERSION,
        'ca_providers': {'letsencrypt': {'environment': 'staging'}},
        'domains': [], 'email': 'a@b.com',
    })

    settings = manager.load_settings(use_cache=False)

    assert 'environment' not in settings['ca_providers']['letsencrypt'], (
        'the retired field survived a load at the current schema version'
    )
