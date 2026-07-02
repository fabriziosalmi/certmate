"""CLI output for `certmate audit verify` (issue #378)."""
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from certmate_cli.main import app

runner = CliRunner()


def _invoke_audit_verify(api_response: dict):
    with patch("certmate_cli.main._client", return_value=MagicMock()):
        with patch("certmate_cli.main._run", return_value=api_response):
            return runner.invoke(app, ["audit", "verify"])


def test_audit_verify_healthy_suppresses_redundant_intact_reason():
    result = _invoke_audit_verify(
        {"ok": True, "reason": "intact", "checkpoint_verified": False}
    )
    assert result.exit_code == 0, result.stdout
    assert "intact — intact" not in result.stdout
    assert "audit chain:" in result.stdout


def test_audit_verify_broken_still_shows_reason():
    result = _invoke_audit_verify(
        {"ok": False, "reason": "hash mismatch at seq 3", "checkpoint_verified": None}
    )
    assert result.exit_code == 1
    assert "BROKEN" in result.stdout
    assert "hash mismatch at seq 3" in result.stdout