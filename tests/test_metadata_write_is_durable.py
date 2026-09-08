"""`metadata.json` must survive a power loss, not just a concurrent reader.

`_atomic_json_write` wrote a temp file and renamed it, and its docstring said
the mechanism existed "to avoid partial writes on crash". The rename gives
*atomicity* — a reader sees the old file or the new one — and says nothing
about crash safety: neither the temp file's contents nor the rename itself had
been pushed out of the page cache, so a power loss between the write and the
data reaching the platter can be replayed as a rename onto an empty or
truncated file.

That file is not incidental. It records key custody: `private_key_state` (the
`external` value that tells the renewal path a CSR-only certificate has no key
here and must not be reissued nightly), the CSR fingerprint, and the CA the
certificate came from — the value without which a private-CA certificate cannot
renew at all. Losing it does not lose a certificate; it loses the instance's
knowledge of what that certificate is.

Three syncs, three different losses, and the tests below pin each one
separately because dropping any of them still passes a naive "the file has the
right contents" assertion:

* `flush()`      — bytes leave Python's buffer
* `fsync(file)`  — bytes leave the kernel's page cache: the CONTENTS survive
* `fsync(dir)`   — the rename is persisted: the NAME survives

The same recipe `modules/core/file_operations.py` already uses for
settings.json, which is why the file that records key custody should not have
had a weaker one.
"""
import json
import os
from pathlib import Path

import pytest

from modules.core.certificates import CertificateManager, _fsync_directory

pytestmark = [pytest.mark.unit]

PAYLOAD = {
    'domain': 'example.com',
    'private_key_state': 'external',
    'ca': 'private',
    'csr_fingerprint': 'ab' * 32,
}


@pytest.fixture
def synced(monkeypatch):
    """Record every fsync, tagged with what kind of object it was called on."""
    calls = []
    real_fsync = os.fsync

    def spy(fd):
        try:
            kind = 'dir' if os.path.isdir('/proc/self/fd/%d' % fd) else 'file'
        except Exception:                      # pragma: no cover - non-Linux
            kind = 'file'
        try:
            kind = 'dir' if os.fstat(fd).st_mode & 0o040000 else 'file'
        except OSError:                        # pragma: no cover
            pass
        calls.append(kind)
        return real_fsync(fd)

    monkeypatch.setattr(os, 'fsync', spy)
    return calls


def test_the_contents_are_written(tmp_path):
    target = tmp_path / 'metadata.json'
    CertificateManager._atomic_json_write(target, PAYLOAD)
    assert json.loads(target.read_text()) == PAYLOAD


def test_the_file_is_fsynced_before_the_rename(tmp_path, synced):
    """Without this the rename can land on a file whose bytes never left the
    page cache: the name is right and the contents are empty."""
    CertificateManager._atomic_json_write(tmp_path / 'metadata.json', PAYLOAD)
    assert 'file' in synced, 'the temp file was renamed without being fsynced'


def test_the_directory_is_fsynced_after_the_rename(tmp_path, synced):
    """Syncing the file persists its contents. The link between the name and
    those contents lives in the directory, and until that is synced the rename
    itself can be lost."""
    CertificateManager._atomic_json_write(tmp_path / 'metadata.json', PAYLOAD)
    assert 'dir' in synced, 'the rename was never persisted'


def test_the_order_is_file_then_rename_then_directory(tmp_path, monkeypatch):
    """CONTROL: fsyncing the directory *before* the rename would pass both
    tests above and guarantee nothing."""
    order = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        order.append('dir' if os.fstat(fd).st_mode & 0o040000 else 'file')
        return real_fsync(fd)

    def replace(src, dst, *a, **kw):
        order.append('rename')
        return real_replace(src, dst, *a, **kw)

    monkeypatch.setattr(os, 'fsync', fsync)
    monkeypatch.setattr(os, 'replace', replace)
    monkeypatch.setattr(Path, 'replace',
                        lambda self, target: replace(str(self), str(target)))

    CertificateManager._atomic_json_write(tmp_path / 'metadata.json', PAYLOAD)
    assert order == ['file', 'rename', 'dir']


def test_no_temp_file_is_left_behind(tmp_path):
    target = tmp_path / 'metadata.json'
    CertificateManager._atomic_json_write(target, PAYLOAD)
    assert sorted(p.name for p in tmp_path.iterdir()) == ['metadata.json']


def test_a_failed_write_removes_the_temp_and_leaves_the_old_file(tmp_path,
                                                                 monkeypatch):
    """The property the rename buys, which must not be lost while adding the
    syncs: a failure leaves the previous metadata intact."""
    target = tmp_path / 'metadata.json'
    target.write_text('{"domain": "old"}')

    def boom(fd):
        raise OSError('disk full')

    monkeypatch.setattr(os, 'fsync', boom)
    with pytest.raises(OSError):
        CertificateManager._atomic_json_write(target, PAYLOAD)

    assert json.loads(target.read_text()) == {'domain': 'old'}
    assert sorted(p.name for p in tmp_path.iterdir()) == ['metadata.json']


# --- the directory helper on its own ------------------------------------

def test_fsyncing_a_directory_that_cannot_be_opened_is_not_an_error(tmp_path):
    """Some filesystems refuse to open a directory for fsync. The write has
    already succeeded by then; failing an issuance over the sync of a
    directory entry would trade a rare loss for a common one."""
    _fsync_directory(tmp_path / 'does-not-exist')


def test_fsyncing_a_directory_closes_its_descriptor(tmp_path, monkeypatch):
    """CONTROL: a leaked fd per metadata write is a slow death on a busy
    instance, and nothing else in the write path would notice."""
    opened, closed = [], []
    real_open, real_close = os.open, os.close
    monkeypatch.setattr(os, 'open',
                        lambda *a, **k: opened.append(real_open(*a, **k))
                        or opened[-1])
    monkeypatch.setattr(os, 'close',
                        lambda fd: closed.append(fd) or real_close(fd))

    _fsync_directory(tmp_path)
    assert opened and closed == opened


def test_a_failing_fsync_on_the_directory_still_closes_it(tmp_path,
                                                          monkeypatch):
    closed = []
    real_close = os.close
    monkeypatch.setattr(os, 'close',
                        lambda fd: closed.append(fd) or real_close(fd))
    monkeypatch.setattr(os, 'fsync',
                        lambda fd: (_ for _ in ()).throw(OSError('nope')))

    _fsync_directory(tmp_path)
    assert closed, 'the directory descriptor leaked when fsync failed'
