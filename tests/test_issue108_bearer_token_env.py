"""
Regression tests for issue #108.

A misconfigured API_BEARER_TOKEN environment variable (empty placeholder
left over from `${API_BEARER_TOKEN}` in docker-compose, or a short hand-
typed value like "changeme") must NOT poison every subsequent save_settings
call. The previous behavior was: env var copied verbatim into the in-memory
defaults, then validate_api_token rejected it on every save with a
misleading "API token length must be between 32 and 512 characters" error,
breaking onboarding and user creation alike.

That requirement still holds and is still tested here: an unusable token
never reaches settings.json.

What changed is the *reaction* to an unusable token. #108 substituted a
freshly generated one and carried on, which fixed the poisoned saves and
introduced something worse: the operator had said "this instance is
authenticated" by setting the variable, `_detect_operator_bearer_token()`
then found no operator credential, `is_setup_mode()` stayed true, and the
instance answered every gated endpoint to anonymous callers as admin —
while the log said a fresh token had been generated. The substitution is
now a refusal (`BearerTokenUnusableError`, which the auth layer turns into
401 on every request). The empty and whitespace-only cases that motivated
#108 are unchanged: they read as "not configured" and still generate.
"""

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import (
    BearerTokenUnusableError,
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


def test_too_short_env_var_refuses_instead_of_falling_back(monkeypatch):
    monkeypatch.setenv("API_BEARER_TOKEN", "shortbad")  # 8 chars, < 32
    with pytest.raises(BearerTokenUnusableError) as raised:
        _bearer_token_from_env_or_generate()
    assert "NO AUTHENTICATION" in str(raised.value), (
        "the message must say what ignoring it would cost, not just that the "
        "token was rejected"
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


def test_a_documentation_placeholder_refuses(monkeypatch):
    # Long enough, but it is the value from the docs, unedited.
    monkeypatch.setenv(
        "API_BEARER_TOKEN",
        "your_super_secure_api_token_here_change_this",
    )
    with pytest.raises(BearerTokenUnusableError):
        _bearer_token_from_env_or_generate()


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


def test_file_read_error_refuses_and_does_not_consult_the_env_var(monkeypatch):
    """A path typo must not silently downgrade to another source, or to none."""
    monkeypatch.setenv("API_BEARER_TOKEN_FILE", "/nonexistent/path/token.txt")
    monkeypatch.setenv("API_BEARER_TOKEN", GOOD_TOKEN)  # must not rescue it
    with pytest.raises(BearerTokenUnusableError) as raised:
        _bearer_token_from_env_or_generate()
    assert "API_BEARER_TOKEN_FILE" in str(raised.value)


def test_file_with_invalid_token_refuses(monkeypatch, tmp_path):
    """And does not fall through to API_BEARER_TOKEN either."""
    token_file = tmp_path / "token.txt"
    token_file.write_text("tooshort")
    monkeypatch.setenv("API_BEARER_TOKEN_FILE", str(token_file))
    monkeypatch.setenv("API_BEARER_TOKEN", GOOD_TOKEN)  # must not rescue it
    with pytest.raises(BearerTokenUnusableError):
        _bearer_token_from_env_or_generate()


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


def test_an_unusable_env_var_never_reaches_settings_json(settings_manager,
                                                        monkeypatch):
    """#108's actual requirement, kept: the invalid value must never be
    written. What changed is that the instance now refuses to serve rather
    than substituting a token nobody holds — the wizard save raises instead
    of succeeding into an unauthenticated instance.
    """
    monkeypatch.setenv("API_BEARER_TOKEN", "weak")  # 4 chars

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

    with pytest.raises(BearerTokenUnusableError):
        settings_manager.atomic_update(wizard_payload)

    on_disk = settings_manager.settings_file
    assert not on_disk.exists() or "weak" not in on_disk.read_text(), (
        "the rejected value must never be persisted — that was the whole "
        "point of #108"
    )


def test_the_wizard_still_works_with_a_usable_env_var(settings_manager,
                                                      monkeypatch):
    """CONTROL for the test above: the refusal is caused by the bad token,
    not by the wizard path being broken."""
    monkeypatch.setenv("API_BEARER_TOKEN", GOOD_TOKEN)

    assert settings_manager.atomic_update({
        "email": "test@example.com",
        "dns_provider": "cloudflare",
        "auto_renew": True,
        "setup_completed": True,
    }) is True

    saved = settings_manager.load_settings()
    assert saved["email"] == "test@example.com"
    assert saved["setup_completed"] is True
