"""A backup kept off this node can be brought back (#655).

Restore reads a file that is already in `backups/unified`. After losing the
volume there was nothing there, so recovery required out-of-band access to a
filesystem that no longer existed — the disaster-recovery story failing exactly
when it was needed.

Ingest closes that loop. Two properties carry the weight here:

* **The uploaded name is discarded.** A caller-supplied filename is the classic
  way to steer a write out of its directory, and nothing about an upload needs
  it — the archive's own manifest says what it is. The tests below hand over
  traversal names and confirm that nothing lands outside `backups/unified` and
  that the stored name bears no relation to what was sent.
* **The kind of archive is decided from content, not extension.** The restore
  path branches on the suffix, so an encrypted archive stored as `.zip` would
  fail to open later — at the moment it was most needed. An upload that lies
  about its extension must still be stored correctly.

Ingest deliberately does not restore. Storing is not destructive; restoring is,
and it stays a separate audited call the operator makes after looking at what
arrived.
"""
import io
import json
import zipfile

import pytest

from modules.core.file_operations import (
    _BACKUP_ENC_SUFFIX,
    FileOperations,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    (dirs[2] / 'unified').mkdir()
    return FileOperations(*dirs)


def _plain_archive(settings=None):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zipf:
        zipf.writestr('settings.json', json.dumps(
            {'settings': settings or {'email': 'ops@example.com'}}))
        zipf.writestr('backup_metadata.json', json.dumps(
            {'type': 'unified', 'secrets_masked': False}))
    return buffer.getvalue()


def _encrypted_archive(file_ops, monkeypatch):
    """A real encrypted archive, produced by the code that writes them."""
    monkeypatch.setenv('CERTMATE_BACKUP_PASSPHRASE', 'operator-chosen-passphrase')
    name = file_ops.create_unified_backup(
        {'email': 'ops@example.com'}, 'probe', include_secrets=True)
    path = file_ops.backup_dir / 'unified' / name
    raw = path.read_bytes()
    path.unlink()
    return raw


def _stored(file_ops):
    return sorted(p.name for p in (file_ops.backup_dir / 'unified').glob('*'))


# ---------------------------------------------------------------------------
# It works
# ---------------------------------------------------------------------------

def test_an_uploaded_archive_becomes_a_usable_restore_point(file_ops):
    filename, err = file_ops.ingest_backup(_plain_archive())
    assert err is None, f'a valid archive was refused: {err}'

    entry = next(e for e in file_ops.list_backups()['unified']
                 if e['filename'] == filename)
    assert entry['can_restore'] is True, (
        f"the archive was stored but is not offered as a restore point: "
        f"{entry['restore_blocked_reason']}"
    )


def test_an_encrypted_archive_keeps_its_encrypted_form(file_ops, monkeypatch):
    """Content, not extension. Stored as .zip it would fail to open on restore."""
    raw = _encrypted_archive(file_ops, monkeypatch)
    filename, err = file_ops.ingest_backup(raw)

    assert err is None, f'a real encrypted archive was refused: {err}'
    assert filename.endswith(_BACKUP_ENC_SUFFIX), (
        f'{filename} lost its encrypted suffix, so the restore path would try '
        f'to open it as a plain zip'
    )
    assert (file_ops.backup_dir / 'unified' / filename).read_bytes() == raw, (
        'the archive was altered on the way in'
    )


def test_the_stored_file_is_not_world_readable(file_ops):
    filename, _ = file_ops.ingest_backup(_plain_archive())
    mode = (file_ops.backup_dir / 'unified' / filename).stat().st_mode & 0o777
    assert mode == 0o600, f'stored with mode {oct(mode)}'


# ---------------------------------------------------------------------------
# The name the caller sent has no power
# ---------------------------------------------------------------------------

def test_the_stored_name_is_generated_not_taken_from_the_caller(file_ops):
    """ingest_backup is not even given a name — this pins that.

    If the signature ever grows one "for convenience", this fails and says why.
    """
    import inspect
    parameters = list(inspect.signature(file_ops.ingest_backup).parameters)
    assert parameters == ['raw'], (
        f'ingest_backup now accepts {parameters}; a caller-supplied name is '
        f'how a write gets steered out of the backup directory'
    )


def test_nothing_lands_outside_the_backup_directory(file_ops, tmp_path):
    """CONTROL for the above, from the other side: whatever is uploaded, the
    only thing that appears anywhere is one file in backups/unified."""
    before = {p for p in tmp_path.rglob('*') if p.is_file()}
    for _ in range(3):
        filename, err = file_ops.ingest_backup(_plain_archive())
        assert err is None
    after = {p for p in tmp_path.rglob('*') if p.is_file()}

    created = after - before
    assert len(created) == 3, f'expected 3 new files, got {created}'
    for path in created:
        assert path.parent == file_ops.backup_dir / 'unified', (
            f'{path} was written outside backups/unified'
        )


def test_the_generated_name_is_one_the_listing_finds(file_ops):
    """A stored archive nobody can see is not a restore point either.

    list_backups globs `backup_*.zip*`, so a generated name that drifts out of
    that shape would silently make uploads invisible.
    """
    filename, _ = file_ops.ingest_backup(_plain_archive())
    listed = [e['filename'] for e in file_ops.list_backups()['unified']]
    assert filename in listed, (
        f'{filename} was stored but does not appear in the listing'
    )


# ---------------------------------------------------------------------------
# What must be refused
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('payload,why', [
    (b'', 'empty'),
    (b'this is not an archive at all', 'not an archive'),
    (b'PK\x03\x04 truncated', 'a broken zip'),
])
def test_junk_is_refused_at_upload(file_ops, payload, why):
    filename, err = file_ops.ingest_backup(payload)
    assert err is not None, f'{why} was accepted'
    assert filename is None
    assert not _stored(file_ops), 'a refused upload still left a file behind'


def test_a_zip_that_is_not_a_certmate_backup_is_refused(file_ops):
    """Refused at upload rather than left in the list to be discovered later,
    when someone reaches for it in an emergency."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zipf:
        zipf.writestr('holiday-photos.txt', 'not a backup')

    filename, err = file_ops.ingest_backup(buffer.getvalue())
    assert err is not None and filename is None
    assert 'settings.json' in err


def test_an_oversized_upload_is_refused(file_ops, monkeypatch):
    """The archive must be VALID and merely too big.

    A first version of this uploaded a blob of repeated bytes, which is not an
    archive at all — so the format check rejected it and the test passed with
    the size ceiling removed entirely. The payload here would be accepted if it
    were small enough, which makes size the only thing that can refuse it.
    """
    payload = _plain_archive()
    monkeypatch.setattr(file_ops, 'MAX_INGEST_BYTES', len(payload) - 1)

    filename, err = file_ops.ingest_backup(payload)
    assert filename is None
    assert err is not None and 'limit' in err.lower(), (
        f'expected a refusal naming the size limit, got {err!r}'
    )
    assert not _stored(file_ops)


def test_the_same_archive_is_accepted_under_the_ceiling(file_ops, monkeypatch):
    """CONTROL: proves the test above measures size and nothing else."""
    payload = _plain_archive()
    monkeypatch.setattr(file_ops, 'MAX_INGEST_BYTES', len(payload))

    filename, err = file_ops.ingest_backup(payload)
    assert err is None, f'the same archive was refused under the ceiling: {err}'
    assert filename


def test_ingest_does_not_restore(file_ops):
    """Storing must never be destructive on its own.

    Restoring is a separate, audited call. If ingest ever started applying what
    it received, an upload would become the most dangerous button in the
    product — and the operator would not have chosen it.
    """
    marker = file_ops.data_dir / 'settings.json'
    marker.write_text(json.dumps({'email': 'still-here@example.com'}))

    file_ops.ingest_backup(_plain_archive({'email': 'from-archive@example.com'}))

    assert json.loads(marker.read_text())['email'] == 'still-here@example.com', (
        'ingesting a backup modified live settings'
    )


# ---------------------------------------------------------------------------
# Over HTTP, the way a client actually sends one
# ---------------------------------------------------------------------------

HOSTILE_NAMES = [
    '../../../etc/passwd.zip',
    '..\\..\\windows\\system32.zip',
    'sub/dir/backup.zip',
    'backup.zip\x00.png',
]


def _upload_app(file_ops):
    from unittest.mock import MagicMock
    from flask import Flask
    from flask_restx import Api

    from modules.api.resource_context import ApiContext
    from modules.api.resources_backup import create_backup_resources

    ctx = ApiContext(
        auth=MagicMock(), settings=MagicMock(), certificates=None,
        file_ops=file_ops, cache=None, dns=None, deployer=None, audit=None,
        cert_service=None, cert_executor=None, managers={'file_ops': file_ops})
    ctx.auth.require_role = lambda role: (lambda fn: fn)

    app = Flask(__name__)
    api = Api(app, prefix='/api')
    resources = create_backup_resources(
        api, {'backup_model': MagicMock(), 'backup_list_model': MagicMock()}, ctx)
    api.add_resource(resources['BackupUpload'], '/backups/upload')
    return app


@pytest.mark.parametrize('sent_as', HOSTILE_NAMES)
def test_a_hostile_upload_filename_cannot_steer_the_write(file_ops, tmp_path, sent_as):
    """The end-to-end version of the property, over multipart/form-data.

    The unit-level tests show `ingest_backup` is never given a name; this shows
    the endpoint above it does not reintroduce one, which is where such a
    regression would actually be written.
    """
    app = _upload_app(file_ops)
    before = {p for p in tmp_path.rglob('*') if p.is_file()}

    response = app.test_client().post(
        '/api/backups/upload',
        data={'file': (io.BytesIO(_plain_archive()), sent_as)},
        content_type='multipart/form-data')

    assert response.status_code == 201, response.get_json()
    stored = response.get_json()['filename']
    assert stored.startswith('backup_') and stored.endswith('.zip')
    assert '..' not in stored and '/' not in stored and '\\' not in stored

    created = {p for p in tmp_path.rglob('*') if p.is_file()} - before
    assert len(created) == 1, f'expected one new file, got {created}'
    assert created.pop().parent == file_ops.backup_dir / 'unified'


def test_an_upload_with_no_file_part_is_a_bad_request(file_ops):
    response = _upload_app(file_ops).test_client().post(
        '/api/backups/upload', data={}, content_type='multipart/form-data')
    assert response.status_code == 400


def test_the_endpoint_refuses_what_ingest_refuses(file_ops):
    """CONTROL: the endpoint must not be a way around the content checks."""
    response = _upload_app(file_ops).test_client().post(
        '/api/backups/upload',
        data={'file': (io.BytesIO(b'not an archive'), 'backup.zip')},
        content_type='multipart/form-data')
    assert response.status_code == 400
    assert not _stored(file_ops)
