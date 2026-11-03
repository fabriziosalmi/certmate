"""One restore may write only so many bytes in all, however the archive is built.

Each member of a backup was bounded (10 MB for a certificate file, 512 MB for
the data tree) and the archive as a whole by 40 MB compressed, but nothing
bounded the sum: deflate compresses zeros about a thousand to one, so a
0.56 MB archive of 60 members of 9 MiB wrote 540 MiB, and the restore answered
True. Inside the 40 MB ingest cap that is about 38 GiB from one upload, which
fills the disk the certificates and the audit chain live on.
"""
import io
import zipfile

import pytest

from modules.core import file_operations
from modules.core.file_operations import FileOperations

pytestmark = [pytest.mark.unit]

MEMBER = 5 * 1024 * 1024          # under the per-member cap of 10 MiB
MEMBERS = 20                      # 100 MiB once restored, about 100 KiB zipped


@pytest.fixture
def files(tmp_path):
    for name in ('certificates', 'data', 'backups', 'logs'):
        (tmp_path / name).mkdir()
    return FileOperations(cert_dir=tmp_path / 'certificates', data_dir=tmp_path / 'data',
                          backup_dir=tmp_path / 'backups', logs_dir=tmp_path / 'logs')


def _bomb(tmp_path, members=MEMBERS, size=MEMBER):
    path = tmp_path / 'bomb.zip'
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        archive.writestr('settings.json', '{"email": "a@example.com", "domains": []}')
        for index in range(members):
            archive.writestr(f'certificates/bomb-{index}.example/junk-{index}.pem', b'\0' * size)
    return path


def _bytes_under(directory):
    return sum(item.stat().st_size for item in directory.rglob('*') if item.is_file())


def test_an_archive_that_would_write_more_than_the_ceiling_stops_at_it(files, tmp_path, monkeypatch):
    ceiling = 30 * 1024 * 1024
    monkeypatch.setattr(file_operations, '_MAX_RESTORE_BYTES', ceiling)
    archive = _bomb(tmp_path)
    assert archive.stat().st_size < 1024 * 1024          # a small file, which is the point

    try:
        outcome = files.restore_unified_backup(str(archive))
    except file_operations.RestoreIncompleteError:
        outcome = False

    assert outcome is not True, 'a restore that was cut short must not report success'
    assert _bytes_under(tmp_path / 'certificates') <= ceiling


def test_the_ceiling_can_be_set_by_the_environment(files, tmp_path, monkeypatch):
    monkeypatch.setenv('CERTMATE_RESTORE_MAX_BYTES', str(10 * 1024 * 1024))
    archive = _bomb(tmp_path, members=4)

    try:
        files.restore_unified_backup(str(archive))
    except file_operations.RestoreIncompleteError:
        pass

    assert _bytes_under(tmp_path / 'certificates') <= 10 * 1024 * 1024


def test_an_ordinary_backup_is_far_below_the_ceiling_and_restores(files, tmp_path):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        archive.writestr('settings.json', '{"email": "a@example.com", "domains": []}')
        archive.writestr('certificates/site.example/cert.pem', b'-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n')
    path = tmp_path / 'ordinary.zip'
    path.write_bytes(buffer.getvalue())

    assert files.restore_unified_backup(str(path)) is True
    assert (tmp_path / 'certificates' / 'site.example' / 'cert.pem').exists()
