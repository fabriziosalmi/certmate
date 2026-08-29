"""Startup warns when the bearer token hash no longer matches SECRET_KEY.

api_bearer_token_hash is HMAC-SHA256 keyed on SECRET_KEY. Restoring a backup
onto a host with a different SECRET_KEY leaves the hash unverifiable, so the
operator's own token 401s on every request with no explanation. This is
intended (the hash is bound to SECRET_KEY on purpose, and the instance is not
world-open — the bearer path fails closed) but silent. The diagnostic warning
fires only in that case: a supplied token that does not verify against a stored
HMAC hash. It is read-only — it must never change the stored hash.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.auth import AuthManager

pytestmark = [pytest.mark.unit]

_TOKEN = 'certmate-api-token-7f3a9c2e5b8d1046af23'
_OLD = 'secret-key-origin-aaaaaaaaaaaaaaaa'
_NEW = 'secret-key-newhost-bbbbbbbbbbbbbbbb'


def _mgr(stored_hash):
    sm = MagicMock()
    sm.load_settings.return_value = {'api_bearer_token_hash': stored_hash}
    return sm


def _hash_with(secret, token=_TOKEN):
    am = AuthManager(MagicMock())
    am.set_hmac_key(secret)
    return am.hash_api_token(token)


def _warned(am, caplog):
    caplog.clear()
    with caplog.at_level('WARNING'):
        am.warn_if_bearer_token_hash_is_stale()
    return any('does not match the stored' in r.message for r in caplog.records)


def test_warns_after_a_restore_onto_a_new_secret_key(monkeypatch, caplog):
    monkeypatch.setenv('API_BEARER_TOKEN', _TOKEN)
    am = AuthManager(_mgr(_hash_with(_OLD)))
    am.set_hmac_key(_NEW)                       # host now has a different key
    assert _warned(am, caplog) is True


def test_silent_when_the_key_matches(monkeypatch, caplog):
    monkeypatch.setenv('API_BEARER_TOKEN', _TOKEN)
    am = AuthManager(_mgr(_hash_with(_OLD)))
    am.set_hmac_key(_OLD)                        # same key that hashed it
    assert _warned(am, caplog) is False


def test_silent_when_no_token_is_supplied(monkeypatch, caplog):
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    monkeypatch.delenv('API_BEARER_TOKEN_FILE', raising=False)
    am = AuthManager(_mgr(_hash_with(_OLD)))
    am.set_hmac_key(_NEW)
    assert _warned(am, caplog) is False


def test_silent_when_there_is_no_hmac_hash(monkeypatch, caplog):
    monkeypatch.setenv('API_BEARER_TOKEN', _TOKEN)
    am = AuthManager(_mgr(''))                   # fresh install, no hash yet
    am.set_hmac_key(_NEW)
    assert _warned(am, caplog) is False


def test_silent_for_a_legacy_plain_sha256_hash(monkeypatch, caplog):
    """Only HMAC hashes are bound to SECRET_KEY; a legacy sha256: hash is not,
    so it must not trip the SECRET_KEY-mismatch warning."""
    monkeypatch.setenv('API_BEARER_TOKEN', _TOKEN)
    am = AuthManager(_mgr('sha256:deadbeef'))
    am.set_hmac_key(_NEW)
    assert _warned(am, caplog) is False


def test_reads_the_token_from_a_file(monkeypatch, caplog, tmp_path):
    f = tmp_path / 'token'
    f.write_text(_TOKEN + '\n')
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    monkeypatch.setenv('API_BEARER_TOKEN_FILE', str(f))
    am = AuthManager(_mgr(_hash_with(_OLD)))
    am.set_hmac_key(_NEW)
    assert _warned(am, caplog) is True


def test_the_check_never_writes_the_stored_hash(monkeypatch):
    """Read-only: a wrong token at startup must not overwrite the hash."""
    monkeypatch.setenv('API_BEARER_TOKEN', _TOKEN)
    sm = _mgr(_hash_with(_OLD))
    am = AuthManager(sm)
    am.set_hmac_key(_NEW)
    am.warn_if_bearer_token_hash_is_stale()
    sm.update.assert_not_called()
    sm.atomic_update.assert_not_called()


def test_silent_for_a_malformed_token(monkeypatch, caplog):
    """A malformed token is not a SECRET_KEY problem — the warning must not
    fire, or it would mislead (the bearer fail-closed path handles bad tokens)."""
    monkeypatch.setenv('API_BEARER_TOKEN', 'short')
    am = AuthManager(_mgr(_hash_with(_OLD)))
    am.set_hmac_key(_NEW)
    assert _warned(am, caplog) is False


def test_the_message_names_the_file_source(monkeypatch, caplog, tmp_path):
    """When the token came from API_BEARER_TOKEN_FILE the message must say so,
    not API_BEARER_TOKEN."""
    f = tmp_path / 'token'
    f.write_text(_TOKEN)
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    monkeypatch.setenv('API_BEARER_TOKEN_FILE', str(f))
    am = AuthManager(_mgr(_hash_with(_OLD)))
    am.set_hmac_key(_NEW)
    caplog.clear()
    with caplog.at_level('WARNING'):
        am.warn_if_bearer_token_hash_is_stale()
    msg = ' '.join(r.getMessage() for r in caplog.records)
    assert 'API_BEARER_TOKEN_FILE' in msg
