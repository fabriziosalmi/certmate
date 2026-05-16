"""
Regression test for CertificateManager._load_metadata corruption handling.

Previously _load_metadata caught `Exception` broadly, logged a warning, and
returned `{}` whether the file was unparseable JSON or unreadable for some
other reason. Combined with `_save_metadata` writing whatever is in memory
back to the same path, a transient JSON corruption could become permanent
data loss on the next save — the empty dict overwrote the only copy.

The fix splits the handler:
- `json.JSONDecodeError`: rename the file to `metadata.json.corrupt-<utc>`
  before returning `{}`. The corrupted bytes are preserved for forensics
  and the next save cannot overwrite them.
- `OSError`: keep the previous behaviour (warning + `{}`); the file itself
  may be fine and a retry could succeed.

These tests pin both branches.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager


def _make_manager(tmp_path: Path) -> CertificateManager:
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=MagicMock(),
        dns_manager=MagicMock(),
        storage_manager=None,
        ca_manager=None,
    )


def _prepare_domain(cert_dir: Path, domain: str) -> Path:
    domain_dir = cert_dir / domain
    domain_dir.mkdir(parents=True, exist_ok=True)
    return domain_dir / "metadata.json"


def test_corrupt_json_quarantines_file_and_returns_empty(tmp_path):
    mgr = _make_manager(tmp_path)
    domain = "example.com"
    meta_path = _prepare_domain(tmp_path, domain)
    meta_path.write_text("{not valid json")

    result = mgr._load_metadata(domain)

    assert result == {}, "should return empty dict on JSON corruption"
    assert not meta_path.exists(), (
        "corrupt metadata.json should have been renamed away so the next "
        "_save_metadata cannot overwrite the only copy"
    )

    quarantined = list((tmp_path / domain).glob("metadata.json.corrupt-*"))
    assert len(quarantined) == 1, (
        f"expected exactly one quarantine file, got {quarantined}"
    )
    assert re.match(
        r"metadata\.json\.corrupt-\d{8}T\d{6}Z$", quarantined[0].name
    ), f"quarantine filename has unexpected shape: {quarantined[0].name}"
    assert quarantined[0].read_text() == "{not valid json", (
        "quarantined file must preserve the original corrupt bytes for forensics"
    )


def test_save_after_corrupt_does_not_clobber_quarantine(tmp_path):
    """The whole point of quarantine: a subsequent save must write a fresh
    metadata.json without touching the quarantined file."""
    mgr = _make_manager(tmp_path)
    domain = "example.com"
    meta_path = _prepare_domain(tmp_path, domain)
    meta_path.write_text('{"dns_provider": "cloudflare", "broken": ')  # truncated

    # First read: triggers quarantine.
    mgr._load_metadata(domain)
    quarantined = list((tmp_path / domain).glob("metadata.json.corrupt-*"))
    assert len(quarantined) == 1
    original_bytes = quarantined[0].read_bytes()

    # Now save fresh metadata. The quarantine must survive byte-for-byte.
    mgr._save_metadata(domain, {"dns_provider": "route53"})

    assert meta_path.exists(), "fresh metadata.json must be written"
    fresh = json.loads(meta_path.read_text())
    assert fresh == {"dns_provider": "route53"}

    assert quarantined[0].exists(), "quarantine file must survive the save"
    assert quarantined[0].read_bytes() == original_bytes, (
        "quarantine file must not be modified by the subsequent save"
    )


def test_missing_file_returns_empty_without_quarantine(tmp_path):
    """A missing metadata.json is the normal case for a freshly-issued cert
    and must not produce any quarantine artefact."""
    mgr = _make_manager(tmp_path)
    domain = "example.com"
    _prepare_domain(tmp_path, domain)  # parent dir exists, metadata.json does not

    result = mgr._load_metadata(domain)
    assert result == {}

    assert not list((tmp_path / domain).glob("metadata.json.corrupt-*")), (
        "no corruption => no quarantine artefact"
    )


def test_os_error_on_read_does_not_quarantine(tmp_path):
    """If the file is unreadable for I/O reasons (permissions, transient
    filesystem error), we must NOT quarantine — the bytes on disk may still
    be valid and a retry could succeed. Just log a warning and return {}."""
    mgr = _make_manager(tmp_path)
    domain = "example.com"
    meta_path = _prepare_domain(tmp_path, domain)
    meta_path.write_text('{"dns_provider": "cloudflare"}')

    with patch(
        "builtins.open", side_effect=OSError("simulated I/O error")
    ):
        result = mgr._load_metadata(domain)

    assert result == {}
    assert meta_path.exists(), "OSError on read must leave the file alone"
    assert not list((tmp_path / domain).glob("metadata.json.corrupt-*")), (
        "OSError is not corruption — no quarantine"
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
