"""
Migration tests for #279: the letsencrypt 'environment' settings field
is retired in favour of the letsencrypt_staging CA entry.

The field never affected issuance — get_acme_server_url only consulted
the staging *boolean*, which no production caller set — so users who
saved environment='staging' were issued production certificates all
along. The migration therefore drops the field without flipping
default_ca: selecting staging is an explicit choice of the new entry.

It must be idempotent and permanent: a stale settings tab POSTing the
pre-#279 payload shape, or a backup restore, can reintroduce the field
at any time.
"""

import json
from unittest.mock import patch

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_manager(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=cert_dir,
        data_dir=data_dir,
        backup_dir=backup_dir,
        logs_dir=logs_dir,
    )
    return SettingsManager(
        file_ops=file_ops, settings_file=data_dir / "settings.json"
    )


def _seed(settings_manager, payload):
    settings_manager.settings_file.write_text(json.dumps(payload))


def test_environment_field_is_dropped_on_load(settings_manager):
    _seed(settings_manager, {
        'email': 'a@b.it',
        'default_ca': 'letsencrypt',
        'ca_providers': {
            'letsencrypt': {'environment': 'staging', 'email': 'a@b.it'},
        },
    })
    settings = settings_manager.load_settings()
    assert 'environment' not in settings['ca_providers']['letsencrypt']
    # The user was issued production certs all along — the migration must
    # not silently flip new issuance to untrusted staging certificates.
    assert settings['default_ca'] == 'letsencrypt'
    # And the rewrite is persisted, not just in-memory.
    on_disk = json.loads(settings_manager.settings_file.read_text())
    assert 'environment' not in on_disk['ca_providers']['letsencrypt']


def test_environment_dropped_from_accounts_shape(settings_manager):
    _seed(settings_manager, {
        'email': 'a@b.it',
        'ca_providers': {
            'letsencrypt': {
                'accounts': {
                    'default': {'environment': 'production', 'email': 'a@b.it'},
                    'second': {'environment': 'staging'},
                },
            },
        },
    })
    settings = settings_manager.load_settings()
    accounts = settings['ca_providers']['letsencrypt']['accounts']
    assert all('environment' not in acc for acc in accounts.values())


def test_migration_is_idempotent(settings_manager):
    _seed(settings_manager, {
        'email': 'a@b.it',
        'ca_providers': {'letsencrypt': {'environment': 'production'}},
    })
    first = settings_manager.load_settings()
    second = settings_manager.load_settings()
    assert 'environment' not in second['ca_providers']['letsencrypt']
    assert first['ca_providers'] == second['ca_providers']


def test_absent_ca_providers_subtree_is_untouched(settings_manager):
    _seed(settings_manager, {'email': 'a@b.it', 'domains': []})
    settings = settings_manager.load_settings()
    assert 'environment' not in json.dumps(settings.get('ca_providers', {}))


def test_migration_does_not_reenter_load_settings(settings_manager):
    """Regression (adversarial review): any migration setting migrated=True
    triggers _ensure_certificate_metadata, which used to call load_settings()
    before the cleaned settings were persisted — re-firing the migration in
    an unbounded recursion. The RecursionError was swallowed and the state
    self-healed, but the unwind performed ~250 redundant saves whose
    '_migration' backups evicted every pre-upgrade restore point from the
    50-file retention window. The helper now receives the in-memory dict."""
    _seed(settings_manager, {
        'email': 'a@b.it',
        'ca_providers': {'letsencrypt': {'environment': 'production'}},
    })
    depth = {'current': 0, 'max': 0}
    original = SettingsManager.load_settings

    def tracking(self, *args, **kwargs):
        depth['current'] += 1
        depth['max'] = max(depth['max'], depth['current'])
        try:
            return original(self, *args, **kwargs)
        finally:
            depth['current'] -= 1

    with patch.object(SettingsManager, 'load_settings', tracking):
        settings = settings_manager.load_settings()

    assert 'environment' not in settings['ca_providers']['letsencrypt']
    assert depth['max'] <= 2, (
        f"load_settings re-entered {depth['max']} deep during migration"
    )
    backups = list(
        (settings_manager.file_ops.backup_dir / 'unified').glob('backup_*.zip*')
    )
    assert len(backups) <= 2, (
        f"migration created {len(backups)} backup archives - the storm is back"
    )


def test_stale_post_payload_is_remigrated(settings_manager):
    """A pre-#279 client re-POSTing the old shape gets cleaned on next load."""
    _seed(settings_manager, {'email': 'a@b.it', 'ca_providers': {'letsencrypt': {}}})
    settings_manager.load_settings()
    # Simulate the stale-tab save: deep-merge writes 'environment' back.
    settings_manager.atomic_update({
        'ca_providers': {'letsencrypt': {'environment': 'staging'}},
    })
    settings = settings_manager.load_settings()
    assert 'environment' not in settings['ca_providers']['letsencrypt']
