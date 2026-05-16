"""
Regression test for UnboundLocalError in FileOperations.safe_file_write.

`safe_file_write` defined `temp_file = Path(_tmp_name)` only AFTER mkstemp()
returned successfully. If mkstemp() raised (parent directory unwritable,
disk full, sandbox restriction), control jumped straight to the
`except (PermissionError, OSError)` handler which then evaluated
`temp_file.exists()` against an unbound local — masking the real OSError
with an UnboundLocalError stack trace that gave the operator no clue what
the actual filesystem problem was.

The fix initialises `temp_file = None` at the top of the function and the
exception handlers test `temp_file is not None and temp_file.exists()`.

This test mocks `tempfile.mkstemp` to raise OSError and asserts:
- safe_file_write returns False (not bubble-up an exception)
- the original OSError message appears in the log
"""
from __future__ import annotations

import logging
from unittest.mock import patch

import pytest

from modules.core.file_operations import FileOperations


@pytest.fixture
def file_ops(tmp_path):
    return FileOperations(
        cert_dir=tmp_path / "certs",
        data_dir=tmp_path / "data",
        backup_dir=tmp_path / "backups",
        logs_dir=tmp_path / "logs",
    )


def test_safe_file_write_returns_false_when_mkstemp_fails(file_ops, tmp_path, caplog):
    target = tmp_path / "data" / "settings.json"
    target.parent.mkdir(parents=True, exist_ok=True)

    # Pre-fix: this would raise UnboundLocalError when the except handler
    # tried to test `temp_file.exists()`. Post-fix: returns False cleanly.
    with patch(
        "tempfile.mkstemp",
        side_effect=OSError("simulated disk-full from mkstemp"),
    ):
        with caplog.at_level(logging.ERROR, logger="modules.core.file_operations"):
            result = file_ops.safe_file_write(str(target), {"k": "v"})

    assert result is False, (
        "safe_file_write must return False (not raise) when mkstemp fails"
    )
    assert any(
        "simulated disk-full from mkstemp" in rec.message
        for rec in caplog.records
    ), (
        "Original OSError message must be in the log so the operator sees the "
        f"actual filesystem problem (not a masking UnboundLocalError). "
        f"Records: {[r.message for r in caplog.records]}"
    )


def test_safe_file_write_happy_path_still_works(file_ops, tmp_path):
    """Locks the contract that the temp_file=None initialisation didn't
    break the success path."""
    target = tmp_path / "data" / "settings.json"
    target.parent.mkdir(parents=True, exist_ok=True)

    ok = file_ops.safe_file_write(str(target), {"hello": "world"})

    assert ok is True
    assert target.exists()
    import json
    assert json.loads(target.read_text()) == {"hello": "world"}


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
