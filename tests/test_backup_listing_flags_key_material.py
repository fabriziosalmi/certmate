"""The backup list says which archives carry private keys (#595).

Every backup CertMate made before v2.26.0 with the default settings contains
the private key of every certificate, while its manifest says
`secrets_masked: true` and the interface called it *share-safe*. Archives from
v2.22.0 also carry the private CA key and every client-certificate key.

That is a published advisory, and an advisory is something an operator has to
go and read. The archives are still on their disk, still described by a
manifest that says the wrong thing, and the advice — unzip and grep — assumes
they already know to look.

So the listing looks. It reads the archive's NAME LIST rather than its
manifest, because the manifest is precisely the thing that was wrong.

The important negative: an archive that cannot be inspected reports `None`, not
`False`. "I could not look" and "there is nothing there" are different answers,
and conflating them is the same mistake the old manifests made.
"""
import io
import json
import zipfile

import pytest

from modules.core.file_operations import FileOperations

pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    dirs = [tmp_path / n for n in ('certificates', 'data', 'backups', 'logs')]
    for directory in dirs:
        directory.mkdir()
    (dirs[2] / 'unified').mkdir()
    return FileOperations(*dirs)


def _archive(file_ops, name, entries, masked=True):
    """An archive with an arbitrary entry list and a v2.25-style manifest."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zipf:
        zipf.writestr('settings.json', json.dumps({'settings': {'email': 'a@b.c'}}))
        zipf.writestr('backup_metadata.json',
                      json.dumps({'type': 'unified', 'secrets_masked': masked}))
        for entry in entries:
            zipf.writestr(entry, 'x')
    path = file_ops.backup_dir / 'unified' / name
    path.write_bytes(buffer.getvalue())
    return path


def _entry(file_ops, filename):
    return next(e for e in file_ops.list_backups()['unified']
                if e['filename'] == filename)


# ---------------------------------------------------------------------------
# The archives the advisory is about
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('key_entry', [
    'certificates/example.com/privkey.pem',
    'certificates/example.com/privkey1.pem',
    'data/certs/ca/ca.key',
    'data/certs/clients/alice.pfx',
    'data/acme/private_key.json',
    'certificates/example.com/0000_key-certbot.pem',
])
def test_an_archive_that_carries_a_key_is_flagged(file_ops, key_entry):
    """These are the shapes `_is_key_material` knows, seen through the listing.

    The manifest on these says `secrets_masked: true` — which is exactly the
    claim that was wrong, so the flag must not be derived from it.
    """
    _archive(file_ops, 'backup_20250101_000000.zip',
             ['certificates/example.com/cert.pem', key_entry], masked=True)

    entry = _entry(file_ops, 'backup_20250101_000000.zip')

    assert entry['contains_key_material'] is True, (
        f'{key_entry} was not recognised as key material'
    )
    assert entry['key_file_count'] == 1


def test_a_modern_share_safe_archive_is_not_flagged(file_ops):
    """CONTROL: flagging everything would make the flag useless, and would tell
    operators to reissue certificates that were never exposed."""
    _archive(file_ops, 'backup_20260101_000000.zip', [
        'certificates/example.com/cert.pem',
        'certificates/example.com/chain.pem',
        'certificates/example.com/fullchain.pem',
    ])

    entry = _entry(file_ops, 'backup_20260101_000000.zip')

    assert entry['contains_key_material'] is False
    assert entry['key_file_count'] == 0


def test_every_key_in_an_archive_is_counted(file_ops):
    """The count is what tells an operator how much to reissue."""
    _archive(file_ops, 'backup_20250102_000000.zip', [
        'certificates/a.example.com/privkey.pem',
        'certificates/b.example.com/privkey.pem',
        'data/certs/ca/ca.key',
    ])

    assert _entry(file_ops, 'backup_20250102_000000.zip')['key_file_count'] == 3


# ---------------------------------------------------------------------------
# "I could not look" is not "there is nothing there"
# ---------------------------------------------------------------------------

def test_an_archive_that_cannot_be_read_reports_unknown(file_ops):
    path = file_ops.backup_dir / 'unified' / 'backup_20250103_000000.zip'
    path.write_bytes(b'not a zip at all')

    entry = _entry(file_ops, 'backup_20250103_000000.zip')

    assert entry['contains_key_material'] is None, (
        'an unreadable archive was reported as carrying no keys, which is the '
        'same false reassurance the old manifests gave'
    )
    assert entry['key_file_count'] is None


def test_an_encrypted_archive_without_the_passphrase_reports_unknown(
        file_ops, monkeypatch):
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    path = file_ops.backup_dir / 'unified' / 'backup_20250104_000000.zip.enc'
    path.write_bytes(b'\x00encrypted-and-unopenable-here')

    entry = _entry(file_ops, 'backup_20250104_000000.zip.enc')
    assert entry['contains_key_material'] is None


def test_an_encrypted_archive_is_inspected_when_it_can_be_opened(
        file_ops, monkeypatch):
    """CONTROL for the case above: with the passphrase, the answer is definite —
    otherwise `None` would just mean "encrypted" and say nothing useful."""
    monkeypatch.setenv('CERTMATE_BACKUP_PASSPHRASE', 'operator-chosen')
    name = file_ops.create_unified_backup(
        {'email': 'ops@example.com'}, 'probe', include_secrets=True)

    entry = _entry(file_ops, name)
    assert entry['contains_key_material'] is not None, (
        'an archive this instance can open was still reported as uninspectable'
    )


# ---------------------------------------------------------------------------
# The predicate itself
# ---------------------------------------------------------------------------

def test_the_scanner_reads_names_only(file_ops):
    """It must not need to decompress anything: the listing runs while a page
    is rendering, and an archive can be hundreds of megabytes."""
    names = ['certificates/x/cert.pem', 'certificates/x/privkey.pem',
             'certificates/x/', 'data/certs/ca/ca.key']

    found = FileOperations._archive_key_material(names)

    assert found == ['certificates/x/privkey.pem', 'data/certs/ca/ca.key']


def test_a_directory_entry_is_not_mistaken_for_a_key(file_ops):
    assert FileOperations._archive_key_material(['data/certs/ca.key/']) == []
