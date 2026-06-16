"""Regression: restoring a unified backup must not leave private keys 0644.

restore_unified_backup chmod'd only the exact name 'privkey.pem' to 0600 and
everything else to 0644. certbot keeps the real key bytes in
archive/<domain>/privkeyN.pem (live/privkey.pem symlinks to them) and the ACME
account key in accounts/.../private_key.json — both retained in the backup
(accounts/ and archive/ are intentionally kept). Restore therefore actively
downgraded served key material to world-readable.

The fix locks down every private-key filename while leaving public cert material
(cert/chain/fullchain + metadata json) at 0644, mirroring certbot's own perms.
"""
import os
import stat
import zipfile

import pytest

from modules.core.file_operations import FileOperations, _PRIVATE_KEY_FILE_RE

pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    return FileOperations(cert_dir=cert_dir, data_dir=data_dir,
                          backup_dir=backup_dir, logs_dir=logs_dir)


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


_PRIVATE = ["privkey.pem", "archive/d.com/privkey1.pem",
            "accounts/x/private_key.json", "extra.key"]
_PUBLIC = ["cert.pem", "fullchain.pem", "chain.pem",
           "archive/d.com/fullchain1.pem", "metadata.json",
           "accounts/x/regr.json"]


def test_restore_locks_down_every_private_key(file_ops, tmp_path):
    backup = tmp_path / "backup_test.zip"
    with zipfile.ZipFile(backup, "w") as zf:
        for rel in _PRIVATE + _PUBLIC:
            zf.writestr(f"certificates/d.com/{rel}", b"secret-or-not")

    assert file_ops.restore_unified_backup(str(backup)) is True

    base = file_ops.cert_dir / "d.com"
    for rel in _PRIVATE:
        assert _mode(base / rel) == 0o600, f"{rel} must be 0600, got {oct(_mode(base / rel))}"
    for rel in _PUBLIC:
        assert _mode(base / rel) == 0o644, f"{rel} must be 0644, got {oct(_mode(base / rel))}"


def test_private_key_pattern_matches_real_certbot_names():
    for name in ("privkey.pem", "privkey1.pem", "privkey42.pem",
                 "private_key.json", "client.key"):
        assert _PRIVATE_KEY_FILE_RE.search(name), f"{name} should be treated as private"
    for name in ("fullchain.pem", "cert.pem", "chain1.pem",
                 "metadata.json", "regr.json", "README"):
        assert not _PRIVATE_KEY_FILE_RE.search(name), f"{name} should stay public"
