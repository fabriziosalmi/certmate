"""Automatic backups are complete exactly when they can be encrypted (#655).

`include_secrets` and encryption are independent knobs in
`create_unified_backup`. That leaves four combinations, and only two of them
are sensible for a backup taken automatically on every settings save:

  masked + no passphrase   -> a configuration snapshot; cannot restore
  complete + passphrase    -> a disaster-recovery archive, encrypted at rest
  complete + no passphrase -> a plaintext credential dump written to disk on
                              every save. Never, from this path.
  masked + passphrase      -> an encrypted archive that still cannot restore;
                              a wasted opportunity, not a hazard.

So the automatic path ties the two together. The most important assertion in
this file is the negative one: whatever else changes, that third combination
must not be reachable automatically. A manual backup can still opt into
plaintext — that is a deliberate, audit-logged operator choice, and it stays.

The passphrase is the operator's to set. Storing it beside the archive it
protects would make the encryption theatre, so an instance without one gets a
notice rather than a generated secret.
"""
import json
import zipfile

import pytest

from modules.core.file_operations import FileOperations, _BACKUP_ENC_SUFFIX
from modules.core.settings import SECRET_MASK_SENTINEL, SettingsManager

pytestmark = [pytest.mark.unit]

PASSPHRASE = 'a-passphrase-an-operator-chose'
# A token that passes the api_bearer_token rules (length, and no repeating
# runs), so these tests exercise the backup path instead of quietly
# fighting settings validation.
REAL_TOKEN = 'EXfHVajpXVkJBoXA5vu6_5DmuPnvhJqtcmoc4iF3j4J7Q9zm'


@pytest.fixture
def manager(tmp_path):
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    (dirs[2] / 'unified').mkdir()
    settings = SettingsManager(file_ops=FileOperations(*dirs),
                               settings_file=dirs[1] / 'settings.json')
    settings.load_settings()
    # An existing settings file is what makes save_settings take a backup.
    settings.save_settings({'api_bearer_token': REAL_TOKEN}, backup_reason=None)
    return settings


def _archives(manager):
    return sorted((manager.file_ops.backup_dir / 'unified').glob('backup_*'))


def _only_archive(manager):
    found = _archives(manager)
    assert len(found) == 1, f'expected exactly one automatic backup, got {found}'
    return found[0]


def test_without_a_passphrase_the_automatic_backup_is_masked(manager, monkeypatch):
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    manager.save_settings({'api_bearer_token': REAL_TOKEN}, backup_reason='probe')

    archive = _only_archive(manager)
    with zipfile.ZipFile(archive) as zipf:
        body = zipf.read('settings.json').decode()

    assert REAL_TOKEN not in body, (
        'an automatic backup written without a passphrase carried the real '
        'credential in plaintext'
    )
    assert SECRET_MASK_SENTINEL in body


def test_the_automatic_path_never_writes_plaintext_secrets(manager, monkeypatch):
    """The assertion that must survive every future change to this code.

    Complete-without-encryption is the one combination that turns a routine
    settings save into a credential dump on disk. It is stated separately from
    the test above so that removing the masking would not merely change which
    branch is taken — it would fail a rule named after the hazard.
    """
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    manager.save_settings({'api_bearer_token': REAL_TOKEN}, backup_reason='probe')

    for archive in _archives(manager):
        if archive.name.endswith(_BACKUP_ENC_SUFFIX):
            continue
        # Read the ENTRIES, not the file's bytes. A zip is compressed, so
        # searching the raw bytes for the credential finds nothing even when
        # the credential is right there — a first version of this check did
        # exactly that and could not fail.
        with zipfile.ZipFile(archive) as zipf:
            for name in zipf.namelist():
                body = zipf.read(name).decode('utf-8', 'replace')
                assert REAL_TOKEN not in body, (
                    f'{archive.name} is unencrypted and {name} contains a '
                    f'real credential'
                )


def test_with_a_passphrase_the_automatic_backup_can_restore(manager, monkeypatch):
    """CONTROL: the point of the change, not just the safety of it.

    Without this, masking everything unconditionally would pass every
    assertion above while leaving the operator exactly where #655 found them.
    """
    monkeypatch.setenv('CERTMATE_BACKUP_PASSPHRASE', PASSPHRASE)
    manager.save_settings({'api_bearer_token': REAL_TOKEN}, backup_reason='probe')

    archive = _only_archive(manager)
    assert archive.name.endswith(_BACKUP_ENC_SUFFIX), (
        f'{archive.name} is not encrypted, so a complete archive would be '
        f'sitting in plaintext'
    )

    entry = next(e for e in manager.file_ops.list_backups()['unified']
                 if e['filename'] == archive.name)
    assert entry['can_restore'] is True, (
        f"the automatic backup still cannot restore: "
        f"{entry['restore_blocked_reason']}"
    )


def test_the_encrypted_archive_really_holds_the_secret(manager, monkeypatch):
    """`can_restore` is derived from a manifest flag, so it could in principle
    be true of an archive that does not actually carry the credentials. Open it
    and look."""
    from modules.core.file_operations import _decrypt_backup_payload
    import io

    monkeypatch.setenv('CERTMATE_BACKUP_PASSPHRASE', PASSPHRASE)
    manager.save_settings({'api_bearer_token': REAL_TOKEN}, backup_reason='probe')
    archive = _only_archive(manager)

    payload = _decrypt_backup_payload(archive.read_bytes(), PASSPHRASE)
    with zipfile.ZipFile(io.BytesIO(payload)) as zipf:
        raw = json.loads(zipf.read('settings.json').decode())
    body = raw.get('settings', raw)

    assert body.get('api_bearer_token') == REAL_TOKEN, (
        'the archive is marked restorable but the credential inside it is '
        'still the mask'
    )


def test_the_operator_is_told_once_not_every_save(manager, monkeypatch, caplog):
    """A warning repeated on every settings write is one people scroll past."""
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    with caplog.at_level('WARNING'):
        for _ in range(5):
            manager.save_settings({'api_bearer_token': REAL_TOKEN},
                                  backup_reason='probe')

    notices = [r for r in caplog.records
               if 'CERTMATE_BACKUP_PASSPHRASE' in r.getMessage()]
    assert len(notices) == 1, (
        f'the notice was emitted {len(notices)} times across five saves; it '
        f'must be said once, or it becomes noise and stops being read'
    )
    assert 'CANNOT restore' in notices[0].getMessage()


def test_no_notice_when_the_instance_is_configured(manager, monkeypatch, caplog):
    """CONTROL: proves the notice is conditional and not simply always emitted."""
    monkeypatch.setenv('CERTMATE_BACKUP_PASSPHRASE', PASSPHRASE)
    with caplog.at_level('WARNING'):
        manager.save_settings({'api_bearer_token': REAL_TOKEN},
                              backup_reason='probe')

    assert not [r for r in caplog.records
                if 'CERTMATE_BACKUP_PASSPHRASE' in r.getMessage()]
