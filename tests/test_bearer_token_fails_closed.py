"""An operator-supplied bearer token is honoured or refused — never ignored.

`_bearer_token_from_env_or_generate` used to drop an operator's API_BEARER_TOKEN
when `validate_api_token` disliked it, generate a random one in its place, and
carry on. The consequence was not a weaker token, it was *no authentication at
all*: `_detect_operator_bearer_token()` reports False, `is_setup_mode()` stays
true, and every gated endpoint answers an anonymous caller as admin. The log
said "generating a fresh random bearer token", which reads like the instance is
still protected.

Two halves, and both matter:

* the rejection was far too eager — the weak-pattern list held the bare nouns
  'api', 'key', 'token', 'secret', 'admin', 'test', matched as substrings, so
  `certmate-api-token-<random>` was refused for containing "api";
* and the reaction to a rejection was fail-open.

These tests pin both, plus the control that a first run with no token at all
still generates one and boots normally.
"""

import pytest

from modules.core.settings import (
    BearerTokenUnusableError,
    SettingsUnreadableError,
    _bearer_token_from_env_or_generate,
)
from modules.core.utils import validate_api_token

pytestmark = [pytest.mark.unit]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    monkeypatch.delenv('API_BEARER_TOKEN_FILE', raising=False)


# --- the over-eager rejection -------------------------------------------------

@pytest.mark.parametrize('token', [
    'certmate-api-token-7f3a9c2e5b8d1046af23',
    'prod-key-Zr7Qv3Xm9Lb2Nf6Hd8Wc4Ty1Ps5Gj0',
    'admin-console-Qv3Xm9Lb2Nf6Hd8Wc4Ty1Ps5G',
    'certmate-secret-Xm9Lb2Nf6Hd8Wc4Ty1Ps5Gj0',
    'staging-test-9Lb2Nf6Hd8Wc4Ty1Ps5Gj0KqZr7',
])
def test_a_strong_token_is_not_refused_for_containing_an_ordinary_word(token):
    """These are long, varied, unguessable — and every one was refused."""
    ok, reason = validate_api_token(token)
    assert ok, f"{token!r} refused: {reason}"


def test_the_placeholder_we_ship_is_still_refused():
    """.env.example carries API_BEARER_TOKEN=your_secure_api_token_here.

    It must stay refused after the weak-pattern list was narrowed. It is, on
    length alone (26 characters), which is why narrowing the list is safe.
    """
    ok, reason = validate_api_token('your_secure_api_token_here')
    assert not ok
    assert 'length' in reason


@pytest.mark.parametrize('token,expect', [
    ('short', 'length'),
    ('a' * 40, 'variety'),
    ('changeme-changeme-changeme-changeme', 'weak'),
    ('your_token_here_your_token_here_xx', 'weak'),
])
def test_genuinely_weak_tokens_are_still_refused(token, expect):
    ok, reason = validate_api_token(token)
    assert not ok and expect in reason.lower()


# --- the fail-open reaction ---------------------------------------------------

def test_an_unusable_env_token_refuses_instead_of_generating(monkeypatch):
    monkeypatch.setenv('API_BEARER_TOKEN', 'short')
    with pytest.raises(BearerTokenUnusableError) as raised:
        _bearer_token_from_env_or_generate()
    assert 'NO AUTHENTICATION' in str(raised.value)


def test_an_unusable_file_token_refuses_instead_of_generating(monkeypatch, tmp_path):
    bad = tmp_path / 'token'
    bad.write_text('short')
    monkeypatch.setenv('API_BEARER_TOKEN_FILE', str(bad))
    with pytest.raises(BearerTokenUnusableError):
        _bearer_token_from_env_or_generate()


def test_an_unreadable_token_file_refuses_instead_of_generating(monkeypatch, tmp_path):
    """The operator pointed at a file. A path typo must not mean "no auth"."""
    monkeypatch.setenv('API_BEARER_TOKEN_FILE', str(tmp_path / 'does-not-exist'))
    with pytest.raises(BearerTokenUnusableError):
        _bearer_token_from_env_or_generate()


def test_a_usable_token_is_returned_unchanged(monkeypatch):
    monkeypatch.setenv('API_BEARER_TOKEN', 'certmate-api-token-7f3a9c2e5b8d1046af23')
    assert (_bearer_token_from_env_or_generate()
            == 'certmate-api-token-7f3a9c2e5b8d1046af23')


def test_no_token_configured_still_generates_one():
    """CONTROL. A first run with no API_BEARER_TOKEN must keep working, or the
    fix above would have turned every fresh install into a hard failure."""
    generated = _bearer_token_from_env_or_generate()
    ok, reason = validate_api_token(generated)
    assert ok, reason


# --- the reason it is this exception type ------------------------------------

def test_the_error_is_not_swallowed_into_world_open_defaults():
    """load_settings re-raises SettingsUnreadableError specifically so it does
    not fall through to "return the defaults in-memory" — those carry
    setup_completed False, which is setup mode, which is world-open. The bearer
    token error inherits that treatment by subclassing it; if someone ever
    re-parents this exception, this test fails and says why.
    """
    assert issubclass(BearerTokenUnusableError, SettingsUnreadableError)
