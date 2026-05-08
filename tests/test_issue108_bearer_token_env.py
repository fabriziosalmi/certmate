"""
Regression tests for issue #108.

A misconfigured API_BEARER_TOKEN environment variable (empty placeholder
left over from `${API_BEARER_TOKEN}` in docker-compose, or a short hand-
typed value like "changeme") must NOT poison every subsequent save_settings
call. The previous behavior was: env var copied verbatim into the in-memory
defaults, then validate_api_token rejected it on every save with a
misleading "API token length must be between 32 and 512 characters" error,
breaking onboarding and user creation alike.
"""

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import (
    SettingsManager,
    _bearer_token_from_env_or_generate,
)
from modules.core.utils import validate_api_token


pytestmark = [pytest.mark.unit]


@pytest.fixture
def settings_manager(tmp_path):
    cert_dir = tmp_path / "certificates"
    data_dir = tmp_path / "data"
    backup_dir = tmp_path / "backups"
    logs_dir = tmp_path / "logs"
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    file_ops = FileOperations(
        cert_dir=cert_dir, data_dir=data_dir,
        backup_dir=backup_dir, logs_dir=logs_dir,
    )
    return SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")


def test_helper_falls_back_when_env_var_too_short(monkeypatch, caplog):
    monkeypatch.setenv("API_BEARER_TOKEN", "shortbad")  # 8 chars, < 32
    with caplog.at_level("WARNING"):
        token = _bearer_token_from_env_or_generate()
    is_valid, _ = validate_api_token(token)
    assert is_valid, "fallback token must pass validation"
    assert token != "shortbad"
    assert any("API_BEARER_TOKEN" in rec.message for rec in caplog.records), (
        "must log a warning so the operator knows their env var was rejected"
    )


def test_helper_accepts_valid_env_var(monkeypatch):
    # 40 ascii chars, mixed alphanumeric, no weak pattern, >=12 unique
    good = "9aZ8bY7cX6dW5eV4fU3gT2hS1iR0jQpNmLkJiHgF"
    monkeypatch.setenv("API_BEARER_TOKEN", good)
    token = _bearer_token_from_env_or_generate()
    assert token == good


def test_helper_generates_when_env_var_missing(monkeypatch):
    monkeypatch.delenv("API_BEARER_TOKEN", raising=False)
    token = _bearer_token_from_env_or_generate()
    is_valid, _ = validate_api_token(token)
    assert is_valid


def test_helper_rejects_weak_pattern(monkeypatch, caplog):
    # Long enough but matches the weak-pattern denylist.
    monkeypatch.setenv(
        "API_BEARER_TOKEN",
        "your_super_secure_api_token_here_change_this",
    )
    with caplog.at_level("WARNING"):
        token = _bearer_token_from_env_or_generate()
    is_valid, _ = validate_api_token(token)
    assert is_valid
    assert any("API_BEARER_TOKEN" in rec.message for rec in caplog.records)


GOOD_TOKEN = "9aZ8bY7cX6dW5eV4fU3gT2hS1iR0jQpNmLkJiHgF"  # 40 chars, valid


# ---------------------------------------------------------------------------
# API_BEARER_TOKEN_FILE tests
# ---------------------------------------------------------------------------

def test_file_var_used_when_set_and_valid(monkeypatch, tmp_path):
    token_file = tmp_path / "token.txt"
    token_file.write_text(GOOD_TOKEN)
    monkeypatch.setenv("API_BEARER_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("API_BEARER_TOKEN", raising=False)
    assert _bearer_token_from_env_or_generate() == GOOD_TOKEN


def test_file_var_takes_precedence_over_env_var(monkeypatch, tmp_path):
    """When API_BEARER_TOKEN_FILE is set, API_BEARER_TOKEN must never be consulted."""
    token_file = tmp_path / "token.txt"
    token_file.write_text(GOOD_TOKEN)
    monkeypatch.setenv("API_BEARER_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("API_BEARER_TOKEN", "Z" * 40)  # also valid but must be ignored
    assert _bearer_token_from_env_or_generate() == GOOD_TOKEN


def test_file_read_error_generates_immediately(monkeypatch, caplog):
    """If the file cannot be read, generate a fresh token without consulting API_BEARER_TOKEN."""
    monkeypatch.setenv("API_BEARER_TOKEN_FILE", "/nonexistent/path/token.txt")
    monkeypatch.setenv("API_BEARER_TOKEN", "Z" * 40)  # must be ignored
    with caplog.at_level("WARNING"):
        token = _bearer_token_from_env_or_generate()
    is_valid, _ = validate_api_token(token)
    assert is_valid
    assert token != "Z" * 40, "API_BEARER_TOKEN must not be consulted after file failure"
    assert any("API_BEARER_TOKEN_FILE" in rec.message for rec in caplog.records)


def test_file_with_invalid_token_generates_immediately(monkeypatch, tmp_path, caplog):
    """An invalid token in the file must generate immediately, not fall through to API_BEARER_TOKEN."""
    token_file = tmp_path / "token.txt"
    token_file.write_text("tooshort")
    monkeypatch.setenv("API_BEARER_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("API_BEARER_TOKEN", "Z" * 40)  # must be ignored
    with caplog.at_level("WARNING"):
        token = _bearer_token_from_env_or_generate()
    is_valid, _ = validate_api_token(token)
    assert is_valid
    assert token != "Z" * 40, "API_BEARER_TOKEN must not be consulted after invalid file token"


def test_file_var_absent_falls_through_to_env_var(monkeypatch):
    """When API_BEARER_TOKEN_FILE is not set, API_BEARER_TOKEN is used normally."""
    monkeypatch.delenv("API_BEARER_TOKEN_FILE", raising=False)
    monkeypatch.setenv("API_BEARER_TOKEN", GOOD_TOKEN)
    assert _bearer_token_from_env_or_generate() == GOOD_TOKEN


def test_file_strips_whitespace(monkeypatch, tmp_path):
    token_file = tmp_path / "token.txt"
    token_file.write_text(f"  {GOOD_TOKEN}\n")
    monkeypatch.setenv("API_BEARER_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("API_BEARER_TOKEN", raising=False)
    assert _bearer_token_from_env_or_generate() == GOOD_TOKEN


# ---------------------------------------------------------------------------


def test_save_settings_succeeds_after_bad_env_var(settings_manager, monkeypatch):
    """The end-to-end repro: with a bad API_BEARER_TOKEN env var, the
    initial save during the setup wizard must NOT fail."""
    monkeypatch.setenv("API_BEARER_TOKEN", "weak")  # 4 chars

    # Simulate the setup wizard payload (no api_bearer_token field).
    wizard_payload = {
        "email": "test@example.com",
        "dns_provider": "cloudflare",
        "dns_providers": {
            "cloudflare": {
                "accounts": {"default": {"api_token": "x" * 40}}
            }
        },
        "auto_renew": True,
        "setup_completed": True,
    }

    assert settings_manager.atomic_update(wizard_payload) is True, (
        "atomic_update must not fail because of a bad API_BEARER_TOKEN env var"
    )

    saved = settings_manager.load_settings()
    assert saved["email"] == "test@example.com"
    assert saved["setup_completed"] is True
