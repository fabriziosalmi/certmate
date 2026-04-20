"""
Regression tests for ``iter_cert_domain_dirs``.

Background: the cert storage root is often a volume mount point in Docker
deployments, so it tends to accumulate filesystem artifacts that look like
directories but aren't CertMate cert stores — classically ``lost+found``
(ext-family mount roots), hidden dirs, and unrelated user folders. Prior
to the fix, every ``iterdir()`` call surfaced these as "ghost" cert
entries in the dashboard and weekly digest, polluted backup metadata,
and caused ``_ensure_certificate_metadata`` to write ``metadata.json``
into non-cert directories.

Reported on issue #99 by @SpeeDFireCZE (screenshot showing `certs`,
`config`, `lost+found` as "Not Found" certificate rows).

These tests pin the filter so any future iteration code that uses the
helper stays safe.
"""
from pathlib import Path

import pytest

from modules.core.constants import iter_cert_domain_dirs


@pytest.fixture
def populated_cert_dir(tmp_path: Path) -> Path:
    # Real cert directories (have cert.pem)
    for name in ('example.com', 'foo.bar.duckdns.org', '*.wildcard.example'):
        d = tmp_path / name
        d.mkdir()
        (d / 'cert.pem').write_bytes(b'-----BEGIN CERTIFICATE-----\nfake\n')

    # Filesystem artifacts and unrelated dirs that live at the mount root
    (tmp_path / 'lost+found').mkdir()                   # ext artifact
    (tmp_path / 'certs').mkdir()                         # unrelated
    (tmp_path / 'config').mkdir()                        # unrelated
    (tmp_path / '.cache').mkdir()                        # hidden
    (tmp_path / '.git').mkdir()                          # hidden
    (tmp_path / 'empty-domain.example').mkdir()          # cert dir pending: no cert.pem yet

    # Stray non-directory entries
    (tmp_path / 'README.md').write_text('root readme')

    return tmp_path


def test_yields_only_directories_with_cert_pem(populated_cert_dir):
    names = {p.name for p in iter_cert_domain_dirs(populated_cert_dir)}
    assert names == {'example.com', 'foo.bar.duckdns.org', '*.wildcard.example'}


def test_skips_lost_found(populated_cert_dir):
    """`lost+found` appears on every ext2/3/4 mount root; must never surface."""
    names = {p.name for p in iter_cert_domain_dirs(populated_cert_dir)}
    assert 'lost+found' not in names


def test_skips_hidden_directories(populated_cert_dir):
    names = {p.name for p in iter_cert_domain_dirs(populated_cert_dir)}
    assert '.cache' not in names
    assert '.git' not in names


def test_skips_unrelated_folders(populated_cert_dir):
    """Directories without cert.pem (certs/, config/, empty-domain/) should
    not surface even if their name looks domain-like or not."""
    names = {p.name for p in iter_cert_domain_dirs(populated_cert_dir)}
    assert 'certs' not in names
    assert 'config' not in names
    assert 'empty-domain.example' not in names


def test_skips_regular_files(populated_cert_dir):
    names = {p.name for p in iter_cert_domain_dirs(populated_cert_dir)}
    assert 'README.md' not in names


def test_returns_empty_when_cert_dir_missing(tmp_path):
    missing = tmp_path / 'nope'
    assert list(iter_cert_domain_dirs(missing)) == []


def test_even_lost_found_with_cert_pem_is_filtered(tmp_path):
    """Defensive: if somebody really did create a cert under lost+found,
    we still suppress it. Real domains don't have '+' in their labels."""
    (tmp_path / 'lost+found').mkdir()
    (tmp_path / 'lost+found' / 'cert.pem').write_bytes(b'fake')
    names = {p.name for p in iter_cert_domain_dirs(tmp_path)}
    assert names == set()
