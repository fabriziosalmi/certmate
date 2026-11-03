"""A client certificate's record is replaced whole or not at all.

`metadata.json` is the only place a client certificate's identity, serial and
revocation live. Three writers (create, revoke, and the supersede marker of a
renewal) opened it with 'w', which truncates the file before the first byte of
the new content is written. A write that stopped in between (a disk that filled,
a process killed) left an empty or half-written file. The listing skips a file
it cannot parse with one warning, so the certificate vanished from the
inventory, and it could no longer be revoked through the API while the
certificate itself stayed valid for the relying parties.
"""
import errno
import json

import pytest

pytestmark = [pytest.mark.unit]


@pytest.fixture
def manager(tmp_path):
    from modules.core.client_certificates import ClientCertificateManager
    from modules.core.private_ca import PrivateCAGenerator

    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    return ClientCertificateManager(tmp_path / 'clients', ca)


def _create(manager):
    ok, err, data = manager.create_client_certificate(common_name='alice.example.com', organization='Acme')
    assert ok, err
    return data['identifier']


def _metadata_file(manager, identifier):
    return next(manager.client_certs_dir.glob(f'*/{identifier}/metadata.json'))


def _no_space(*_args, **_kwargs):
    raise OSError(errno.ENOSPC, 'No space left on device')


class _DiskFull:
    """A json.dump that writes the first bytes of the document and then fails, as a full disk does."""

    def __init__(self, real_dump):
        self.real_dump = real_dump

    def __call__(self, obj, fp, **kwargs):
        text = json.dumps(obj, **kwargs)
        fp.write(text[:20])
        fp.flush()
        raise OSError(errno.ENOSPC, 'No space left on device')


def test_a_revocation_that_cannot_be_written_leaves_the_record_as_it_was(manager, monkeypatch):
    identifier = _create(manager)
    path = _metadata_file(manager, identifier)
    before = json.loads(path.read_text())

    # A full disk, seen from either way of writing: halfway through the document
    # (an in-place write), or when the new file is flushed (a write to a sibling).
    monkeypatch.setattr('modules.core.client_certificates.json.dump', _DiskFull(json.dump))
    monkeypatch.setattr('os.fsync', _no_space)
    ok, _error = manager.revoke_certificate(identifier, reason='key compromise')
    monkeypatch.undo()

    assert ok is False
    assert json.loads(path.read_text()) == before        # parses, and is the record it was
    assert manager.get_certificate_metadata(identifier)['revoked'] is False
    assert [c['identifier'] for c in manager.list_client_certificates()] == [identifier]


def test_a_revocation_that_can_be_written_still_lands(manager):
    identifier = _create(manager)

    ok, error = manager.revoke_certificate(identifier, reason='key compromise')

    assert ok, error
    assert manager.get_certificate_metadata(identifier)['revoked'] is True


def test_the_record_is_not_world_readable(manager):
    identifier = _create(manager)

    assert _metadata_file(manager, identifier).stat().st_mode & 0o077 == 0


def test_no_writer_of_the_record_truncates_it_in_place():
    """The renewal's supersede marker has no failure of its own to inject; this holds all three writers to the helper."""
    import pathlib
    import re
    source = pathlib.Path('modules/core/client_certificates.py').read_text()

    assert not re.search(r"open\((metadata_path|metadata_file)[^)]*['\"]w['\"]", source)
