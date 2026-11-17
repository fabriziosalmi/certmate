"""The backup just made is listed first.

Found by the UX audit of 2026-11-17: backups were listed oldest first and the
settings page shows the first eight, so after about an hour of normal use (28
automatic backups) the one the operator had just made sat behind "Show 8 more
(20 hidden)". The listing is newest first now, by the UTC time in the name,
which a copy or a restore does not change the way it changes a file's mtime.
"""
import os
import time

import pytest

from modules.core.file_operations import FileOperations

pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    for name in ('certificates', 'data', 'backups', 'logs'):
        (tmp_path / name).mkdir()
    return FileOperations(cert_dir=tmp_path / 'certificates', data_dir=tmp_path / 'data',
                          backup_dir=tmp_path / 'backups', logs_dir=tmp_path / 'logs')


def _names(file_ops):
    return [entry['filename'] for entry in file_ops.list_backups()['unified']]


def test_the_backup_just_made_comes_first(file_ops):
    for _ in range(10):
        assert file_ops.create_unified_backup({'domains': []}, backup_reason='auto_save')
    made = file_ops.create_unified_backup({'domains': []}, backup_reason='manual')

    names = _names(file_ops)

    assert len(names) == 11
    assert names[0] == made, (made, names[:3])
    assert names == sorted(names, reverse=True)


def test_a_copied_old_backup_does_not_jump_ahead(file_ops):
    """A restore or a copy sets an old archive's mtime to now; the order is the
    time the backup was made, which is in its name."""
    first = file_ops.create_unified_backup({'domains': []}, backup_reason='first')
    second = file_ops.create_unified_backup({'domains': []}, backup_reason='second')
    later = time.time() + 3600
    os.utime(file_ops.backup_dir / 'unified' / first, (later, later))

    assert _names(file_ops) == [second, first]
