"""
Unit test for the one-pass iterdir optimisation in
FileOperations.create_unified_backup.

The function used to walk cert_dir twice: once to build the domain-name
list embedded in the backup metadata, and again to copy each domain's
files into the zip. After the refactor, iterdir is called once and the
resulting Path objects are reused for the zip step.

The optimisation is small (N saved stat calls per backup, noticeable on
NFS / spinning disk) but the test pins the contract so a future
maintenance edit cannot silently regress to two-pass without anyone
noticing.

Also pins the functional contract:
- the zip contains settings.json + backup_metadata.json
- the zip contains every cert.pem from every domain directory
- the metadata.json domains list matches what's on disk
"""
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.core.file_operations import FileOperations


@pytest.fixture
def file_ops(tmp_path):
    cert_dir = tmp_path / "certs"
    cert_dir.mkdir()
    # Seed three domain directories with cert files.
    for domain in ("a.example.com", "b.example.com", "c.example.com"):
        d = cert_dir / domain
        d.mkdir()
        (d / "cert.pem").write_text(f"-----BEGIN CERTIFICATE-----\n{domain}\n")
        (d / "privkey.pem").write_text(f"-----BEGIN PRIVATE KEY-----\n{domain}\n")
    # Also a file that is NOT a directory at the top level — must be ignored.
    (cert_dir / "not-a-domain.txt").write_text("ignore me")

    return FileOperations(
        cert_dir=cert_dir,
        data_dir=tmp_path / "data",
        backup_dir=tmp_path / "backups",
        logs_dir=tmp_path / "logs",
    )


def test_create_unified_backup_iterdir_called_once(file_ops):
    """The refactor turned a 2-pass walk into a 1-pass walk. Assert that."""
    settings = {"email": "test@example.com", "domains": []}

    # Spy on Path.iterdir specifically when called on the cert_dir we set up.
    real_iterdir = Path.iterdir
    cert_dir_iterdir_calls = [0]
    target_path = file_ops.cert_dir.resolve()

    def counted_iterdir(self):
        if Path(self).resolve() == target_path:
            cert_dir_iterdir_calls[0] += 1
        return real_iterdir(self)

    with patch.object(Path, 'iterdir', counted_iterdir):
        ok = file_ops.create_unified_backup(settings, backup_reason="test")

    assert ok, "create_unified_backup must succeed"
    assert cert_dir_iterdir_calls[0] == 1, (
        f"create_unified_backup must walk cert_dir exactly once "
        f"(got {cert_dir_iterdir_calls[0]} iterdir calls). A second pass "
        f"would mean the optimisation has regressed."
    )


def test_create_unified_backup_contents(file_ops, tmp_path):
    """Functional contract: zip has the expected entries and metadata."""
    settings = {"email": "test@example.com", "domains": ["a.example.com"]}

    ok = file_ops.create_unified_backup(settings, backup_reason="contents")
    assert ok

    unified_dir = file_ops.backup_dir / "unified"
    zips = list(unified_dir.glob("backup_*.zip"))
    assert len(zips) == 1, f"expected exactly one backup zip, got {zips}"

    with zipfile.ZipFile(zips[0]) as zf:
        names = set(zf.namelist())
        assert "settings.json" in names
        assert "backup_metadata.json" in names
        # Every seeded cert file must be present.
        for domain in ("a.example.com", "b.example.com", "c.example.com"):
            assert f"certificates/{domain}/cert.pem" in names
            assert f"certificates/{domain}/privkey.pem" in names

        meta = json.loads(zf.read("backup_metadata.json").decode())
        assert meta["type"] == "unified"
        assert sorted(meta["domains"]) == sorted(
            ["a.example.com", "b.example.com", "c.example.com"]
        )
        assert meta["total_domains"] == 3

        # The non-directory at cert_dir level must NOT appear.
        assert not any("not-a-domain.txt" in n for n in names)


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
