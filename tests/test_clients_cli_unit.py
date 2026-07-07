"""Unit tests for certmate-cli 0.1.2 output semantics (no server required).

The 0.1.1 CLI lied in two places: `audit verify` treated a tampered chain
(409, "chain file does not exist" AFTER signed checkpoints) as the benign
fresh-instance case, and `cert renew` printed a green "renewed" no matter
what the server did. These tests pin the corrected exit codes and wording,
driving the real command functions with the SDK client mocked out."""
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

pytest.importorskip("certmate_cli", reason="certmate-cli not installed")
from certmate import APIError, Job, TransportError  # noqa: E402
from certmate_cli.main import app  # noqa: E402

pytestmark = [pytest.mark.unit]

runner = CliRunner()


def _all_output(result) -> str:
    # click >= 8.2 separates stderr; older versions mix it into output.
    text = result.output
    try:
        text += result.stderr
    except Exception:
        pass
    return text


def _invoke_with_client(args, **client_methods):
    client = MagicMock()
    for name, value in client_methods.items():
        if isinstance(value, Exception):
            getattr(client, name).side_effect = value
        else:
            getattr(client, name).return_value = value
    with patch("certmate_cli.main._client", return_value=client):
        result = runner.invoke(app, args)
    return result, client


# --------------------------------------------------------------------------
# BUG 1 — audit verify: state='absent' is the ONLY benign not-ok result
# --------------------------------------------------------------------------

def test_audit_verify_absent_state_is_benign_exit_zero():
    result, _ = _invoke_with_client(
        ["audit", "verify"],
        audit_verify={"ok": False, "reason": "chain file does not exist",
                      "state": "absent", "_http_status": 200})
    assert result.exit_code == 0, _all_output(result)
    assert "none yet" in result.stdout
    assert "BROKEN" not in result.stdout


def test_audit_verify_deleted_chain_after_checkpoints_is_broken_exit_one():
    # Identical reason text, but a 409 without state='absent': the chain was
    # deleted after signed checkpoints attested it existed. Tampering.
    result, _ = _invoke_with_client(
        ["audit", "verify"],
        audit_verify={"ok": False, "reason": "chain file does not exist",
                      "_http_status": 409})
    assert result.exit_code == 1
    assert "BROKEN" in result.stdout
    assert "chain file does not exist" in result.stdout


def test_audit_verify_unreadable_checkpoint_fail_closed_is_broken():
    result, _ = _invoke_with_client(
        ["audit", "verify"],
        audit_verify={"ok": False, "reason": "checkpoint file unreadable",
                      "_http_status": 409})
    assert result.exit_code == 1
    assert "BROKEN" in result.stdout


def test_audit_verify_intact_exit_zero_without_redundant_reason():
    # Behavior contributed in PR #379: never print "intact — intact".
    result, _ = _invoke_with_client(
        ["audit", "verify"],
        audit_verify={"ok": True, "reason": "intact", "checkpoint_verified": True,
                      "checkpoint_seq": 7, "_http_status": 200})
    assert result.exit_code == 0, _all_output(result)
    assert "intact" in result.stdout
    assert "intact — intact" not in result.stdout


# --------------------------------------------------------------------------
# BUG 3 — cert renew: three-way outcome, never a fake green
# --------------------------------------------------------------------------

def test_renew_reports_green_only_when_server_says_renewed_true():
    result, client = _invoke_with_client(
        ["cert", "renew", "app.example.com", "--force"],
        renew_certificate={"message": "Certificate renewed successfully",
                           "renewed": True})
    assert result.exit_code == 0
    assert "renewed" in result.stdout
    client.renew_certificate.assert_called_once_with("app.example.com", force=True)


def test_renew_not_due_shows_server_message_exit_zero():
    result, _ = _invoke_with_client(
        ["cert", "renew", "app.example.com"],
        renew_certificate={"message": "Certificate not due for renewal",
                           "renewed": False})
    assert result.exit_code == 0
    assert "not due" in result.stdout
    assert "Certificate not due for renewal" in result.stdout


def test_renew_older_server_without_outcome_is_neutral_not_green():
    # 0.1.1-era servers return no `renewed` key; the CLI must not claim
    # success it cannot know about.
    result, _ = _invoke_with_client(
        ["cert", "renew", "app.example.com"],
        renew_certificate={"message": "Certificate renewed successfully for app.example.com"})
    assert result.exit_code == 0
    assert "renew requested" in result.stdout
    assert "did not report" in result.stdout
    assert "renewed app.example.com" not in result.stdout


# --------------------------------------------------------------------------
# BUG 4 — transport failures print one clean red line, no traceback
# --------------------------------------------------------------------------

def test_health_unreachable_server_clean_error_exit_one():
    result, _ = _invoke_with_client(
        ["health"],
        health=TransportError("cannot reach server at http://127.0.0.1:1: "
                              "connection refused"))
    assert result.exit_code == 1
    text = _all_output(result)
    assert "cannot reach server" in text
    assert "Traceback" not in text


def test_dns_test_older_server_400_shows_error_cleanly():
    # Older servers 400 on an empty config instead of falling back to stored
    # credentials; the CLI must relay the message, not a traceback.
    result, _ = _invoke_with_client(
        ["dns", "test", "cloudflare"],
        test_dns_provider=APIError("Cloudflare API token required", status=400))
    assert result.exit_code == 1
    text = _all_output(result)
    assert "Cloudflare API token required" in text
    assert "Traceback" not in text


# --------------------------------------------------------------------------
# BUG 8 — cert create SAN parsing drops empties from trailing commas
# --------------------------------------------------------------------------

def test_create_san_trailing_comma_produces_no_empty_entry():
    result, client = _invoke_with_client(
        ["cert", "create", "app.example.com",
         "--san", "a.example.com, b.example.com,", "--no-wait"],
        create_certificate=Job.from_dict({"job_id": "j1", "status": "pending"}))
    assert result.exit_code == 0, _all_output(result)
    kwargs = client.create_certificate.call_args.kwargs
    assert kwargs["san_domains"] == ["a.example.com", "b.example.com"]


# --------------------------------------------------------------------------
# BUG 9 — --token on argv warns interactively; CERTMATE_TOKEN stays silent
# --------------------------------------------------------------------------

def test_token_flag_warns_on_a_tty(monkeypatch):
    monkeypatch.setattr("sys.argv", ["certmate", "--token", "sekrit", "cert", "ls"])
    with patch("certmate_cli.main._stderr_isatty", return_value=True):
        result, _ = _invoke_with_client(["--token", "sekrit", "cert", "ls"],
                                        list_certificates=[])
    text = _all_output(result)
    assert "warning" in text
    assert "CERTMATE_TOKEN" in text


def test_token_from_environment_does_not_warn(monkeypatch):
    monkeypatch.setattr("sys.argv", ["certmate", "cert", "ls"])
    monkeypatch.setenv("CERTMATE_TOKEN", "sekrit")
    with patch("certmate_cli.main._stderr_isatty", return_value=True):
        result, _ = _invoke_with_client(["cert", "ls"], list_certificates=[])
    assert "warning" not in _all_output(result)


def test_token_flag_stays_quiet_when_not_interactive(monkeypatch):
    monkeypatch.setattr("sys.argv", ["certmate", "--token", "sekrit", "cert", "ls"])
    with patch("certmate_cli.main._stderr_isatty", return_value=False):
        result, _ = _invoke_with_client(["--token", "sekrit", "cert", "ls"],
                                        list_certificates=[])
    assert "warning" not in _all_output(result)
