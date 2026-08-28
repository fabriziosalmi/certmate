"""A corrupt archive member must not destroy the live file it overwrites, and
a restore that loses even one member must not report success.

`restore_unified_backup` extracted each member with
``open(target_path, 'wb')`` in the same ``with`` as the zip member — so the
destination was truncated to zero *before* the first byte was read. A bad CRC
(bit rot, a partial object pulled back from an off-site copy) or an oversize
entry then hit ``except: ... continue``, leaving the pre-existing file at zero
bytes while the function returned True and the API answered
``200 "restored atomically successfully"``. The certificates/ branch, holding
every ``privkey.pem`` and the ACME account key, had no cleanup at all; the
data/ branch removed the half-written file but still returned success.

Both branches now stage into a sibling temp file and promote by atomic rename,
so the live file is untouched until a complete copy exists. Any member that
fails is recorded, and a non-empty failure list raises RestoreIncompleteError
rather than reporting a clean restore.
"""
import json
import zipfile
from pathlib import Path

import pytest

from modules.core.file_operations import (
    FileOperations,
    RestoreIncompleteError,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture
def instance(tmp_path):
    cert, data, back, logs = (tmp_path / 'certificates', tmp_path / 'data',
                              tmp_path / 'backups', tmp_path / 'logs')
    for d in (cert, data, back, logs):
        d.mkdir()
    fo = FileOperations(cert, data, back, logs)
    dom = cert / 'example.com'
    dom.mkdir()
    for name, body in {
        'cert.pem': 'CERT-ORIGINAL',
        'chain.pem': 'CHAIN',
        'fullchain.pem': 'FULL',
        'privkey.pem': '-----BEGIN PRIVATE KEY-----\nORIGINAL-KEY-BYTES\n'
                       '-----END PRIVATE KEY-----',
        'metadata.json': '{"domain": "example.com"}',
    }.items():
        (dom / name).write_text(body)
    (data / 'settings.json').write_text(
        json.dumps({'domains': [{'domain': 'example.com'}], 'email': 'a@b.c'}))
    return fo, cert, data, back


def _make_backup(fo, data):
    settings = json.loads((data / 'settings.json').read_text())
    name = fo.create_unified_backup(settings, 'dr', include_secrets=True)
    return fo.backup_dir / 'unified' / name


def _corrupt_member(src, member_suffix, dest):
    """Copy *src* to *dest*, storing the matching member uncompressed with its
    bytes altered so the stored CRC no longer matches."""
    target = None
    with zipfile.ZipFile(src) as zin, zipfile.ZipFile(dest, 'w') as zout:
        for it in zin.infolist():
            body = zin.read(it.filename)
            if it.filename.endswith(member_suffix):
                target = it.filename
                ni = zipfile.ZipInfo(it.filename)
                ni.compress_type = zipfile.ZIP_STORED
                zout.writestr(ni, body)
            else:
                zout.writestr(it, body)
    raw = bytearray(dest.read_bytes())
    i = raw.find(b'ORIGINAL-KEY-BYTES')
    assert i > 0, 'plaintext member not found to corrupt'
    raw[i:i + 8] = b'XXXXXXXX'
    dest.write_bytes(bytes(raw))
    return target


def test_a_corrupt_key_member_leaves_the_live_key_intact(instance):
    fo, cert, data, back = instance
    src = _make_backup(fo, data)
    corrupt = back / 'unified' / 'corrupt.zip'
    _corrupt_member(src, 'example.com/privkey.pem', corrupt)

    key = cert / 'example.com' / 'privkey.pem'
    before = key.read_bytes()
    assert before, 'precondition: key is non-empty'

    with pytest.raises(RestoreIncompleteError) as raised:
        fo.restore_unified_backup(corrupt)

    # The live key is byte-for-byte what it was — not zero, not absent.
    assert key.read_bytes() == before, 'the live private key was damaged'
    assert any('privkey.pem' in m for m in raised.value.failed)


def test_an_intact_archive_restores_and_returns_true(instance):
    """CONTROL. The same path with an unaltered archive must still restore the
    key and report success — otherwise the test above proves nothing."""
    fo, cert, data, back = instance
    src = _make_backup(fo, data)

    # Change the on-disk key so we can see the restore actually rewrite it.
    key = cert / 'example.com' / 'privkey.pem'
    key.write_text('SOMETHING-ELSE')

    assert fo.restore_unified_backup(src) is True
    assert 'ORIGINAL-KEY-BYTES' in key.read_text()


def test_the_key_that_survives_still_has_0600(instance):
    """A restored private key must be 0600; staging must not lose that."""
    fo, cert, data, back = instance
    src = _make_backup(fo, data)
    fo.restore_unified_backup(src)
    key = cert / 'example.com' / 'privkey.pem'
    assert (key.stat().st_mode & 0o777) == 0o600


def test_public_cert_material_is_0644_after_restore(instance):
    fo, cert, data, back = instance
    src = _make_backup(fo, data)
    fo.restore_unified_backup(src)
    assert (cert / 'example.com' / 'cert.pem').stat().st_mode & 0o777 == 0o644


def test_no_restoring_temp_files_are_left_behind(instance):
    """The atomic staging must clean up after itself, success or failure."""
    fo, cert, data, back = instance
    src = _make_backup(fo, data)
    corrupt = back / 'unified' / 'corrupt.zip'
    _corrupt_member(src, 'example.com/privkey.pem', corrupt)
    try:
        fo.restore_unified_backup(corrupt)
    except RestoreIncompleteError:
        pass
    leftovers = [p for p in cert.rglob('*.restoring*')]
    assert leftovers == [], f"temp files left behind: {leftovers}"
