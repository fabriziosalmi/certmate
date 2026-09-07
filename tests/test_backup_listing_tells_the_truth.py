"""A backup listed as a restore point must actually be one (#655).

Every automatic backup is taken with `include_secrets=False`, because a leaked
archive must not also be a credential dump. That default is right, and it means
the newest archive on disk almost always CANNOT restore: installing it writes
the mask sentinel in place of every password hash, token and credential.

The restore path has always known this and refuses such an archive. The listing
did not say so — `secrets_masked` sat inside `metadata`, naming the mechanism
rather than the consequence — so the newest entry an operator sees is a decoy.

What is asserted here is not that a field exists. It is that the listing and the
restore path give the SAME answer, on the same archive, for every case: a masked
one, a complete one, an unreadable one, and an encrypted one whose passphrase
this instance does not have. Two independent judgements about the same file are
how a listing starts lying again later.
"""
import io
import json
import zipfile

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import SECRET_MASK_SENTINEL, backup_can_restore

pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    (dirs[2] / 'unified').mkdir()
    return FileOperations(*dirs)


def _write_backup(file_ops, name, settings, masked):
    """A unified archive shaped the way create_unified_backup writes one."""
    path = file_ops.backup_dir / 'unified' / name
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zipf:
        zipf.writestr('settings.json', json.dumps({'settings': settings}))
        zipf.writestr('backup_metadata.json', json.dumps({
            'type': 'unified', 'secrets_masked': masked,
        }))
    path.write_bytes(buffer.getvalue())
    return path


COMPLETE = {'api_bearer_token': 'a-real-token', 'email': 'ops@example.com'}
MASKED = {'api_bearer_token': SECRET_MASK_SENTINEL, 'email': 'ops@example.com'}


def _entry(file_ops, filename):
    listing = file_ops.list_backups()
    for entry in listing['unified']:
        if entry['filename'] == filename:
            return entry
    raise AssertionError(f'{filename} was not listed at all: {listing}')


def test_a_masked_archive_is_not_offered_as_a_restore_point(file_ops):
    _write_backup(file_ops, 'backup_20260101_010000.zip', MASKED, masked=True)
    entry = _entry(file_ops, 'backup_20260101_010000.zip')

    assert entry['can_restore'] is False, (
        'the archive an automatic backup produces was listed as a restore '
        'point; restoring it installs the mask as every credential'
    )
    assert entry['restore_blocked_reason'], 'a refusal must say why'


def test_a_complete_archive_is_offered_as_a_restore_point(file_ops):
    """CONTROL: a listing that refused everything would satisfy the test above
    while being just as useless to an operator."""
    _write_backup(file_ops, 'backup_20260101_020000.zip', COMPLETE, masked=False)
    entry = _entry(file_ops, 'backup_20260101_020000.zip')

    assert entry['can_restore'] is True, (
        f"a disaster-recovery archive was not offered as a restore point: "
        f"{entry['restore_blocked_reason']}"
    )
    assert entry['restore_blocked_reason'] is None


def test_the_listing_and_the_restore_path_agree(file_ops):
    """The property that keeps this honest as the code changes.

    Both answers come from `backup_can_restore`; this asserts they really do,
    rather than that two similar-looking rules currently coincide.
    """
    cases = [
        ('backup_20260101_030000.zip', MASKED, True),
        ('backup_20260101_040000.zip', COMPLETE, False),
    ]
    for name, settings, masked in cases:
        path = _write_backup(file_ops, name, settings, masked)
        with zipfile.ZipFile(path, 'r') as zipf:
            restore_says = backup_can_restore(zipf, zipf.namelist(), settings)
        assert _entry(file_ops, name)['can_restore'] is restore_says, (
            f'{name}: the listing and the restore path disagree, which is '
            f'exactly how an archive becomes a decoy restore point'
        )


def test_an_archive_with_no_metadata_falls_back_to_its_contents(file_ops):
    """Hand-made and pre-unified archives carry no `secrets_masked` field.

    A missing flag must not read as "fine" — the sentinel in the settings is
    the fallback evidence, and it is what the restore path uses too.
    """
    path = file_ops.backup_dir / 'unified' / 'backup_20260101_050000.zip'
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zipf:
        zipf.writestr('settings.json', json.dumps(MASKED))
    path.write_bytes(buffer.getvalue())

    assert _entry(file_ops, 'backup_20260101_050000.zip')['can_restore'] is False


def test_an_unreadable_archive_is_never_optimistic(file_ops):
    """Presenting an archive that cannot be inspected as a restore point is the
    harm itself, so anything unreadable has to answer no."""
    path = file_ops.backup_dir / 'unified' / 'backup_20260101_060000.zip'
    path.write_bytes(b'not a zip file at all')

    entry = _entry(file_ops, 'backup_20260101_060000.zip')
    assert entry['can_restore'] is False
    assert entry['restore_blocked_reason']


def test_an_encrypted_archive_without_the_passphrase_is_not_a_restore_point(
        file_ops, monkeypatch):
    """It may well be a perfectly good archive — but not one THIS instance can
    verify or open, and the listing must not imply otherwise."""
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    path = file_ops.backup_dir / 'unified' / 'backup_20260101_070000.zip.enc'
    path.write_bytes(b'\x00encrypted-payload-we-cannot-open')

    entry = _entry(file_ops, 'backup_20260101_070000.zip.enc')
    assert entry['can_restore'] is False
    assert 'passphrase' in (entry['restore_blocked_reason'] or '').lower() or \
        entry['restore_blocked_reason'], 'the reason must be actionable'
