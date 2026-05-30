"""Unit coverage for the API-key last_used_at persistence debounce.

AuthManager debounces last_used_at writes so an authenticated API request no
longer rewrites the whole settings.json on every call (single-instance hot
path). The cert-info cache scoping that shipped alongside this in development
now lives in the upstream per-domain cache work, so this module covers only the
debounce.
"""
from unittest.mock import MagicMock

import pytest

from modules.core.auth import AuthManager

pytestmark = [pytest.mark.unit]


class TestLastUsedDebounce:
    def test_first_persists_then_debounced_within_interval(self, monkeypatch):
        monkeypatch.delenv("CERTMATE_LAST_USED_PERSIST_SECONDS", raising=False)  # default 60s
        am = AuthManager(MagicMock())
        assert am._should_persist_last_used("k1") is True   # first time
        assert am._should_persist_last_used("k1") is False  # again, within 60s -> skip
        assert am._should_persist_last_used("k2") is True    # a different key is independent

    def test_zero_interval_persists_every_time(self, monkeypatch):
        monkeypatch.setenv("CERTMATE_LAST_USED_PERSIST_SECONDS", "0")
        am = AuthManager(MagicMock())
        assert am._should_persist_last_used("k1") is True
        assert am._should_persist_last_used("k1") is True

    def test_interval_parsing_falls_back_on_garbage(self, monkeypatch):
        monkeypatch.setenv("CERTMATE_LAST_USED_PERSIST_SECONDS", "not-a-number")
        assert AuthManager._last_used_persist_interval() == 60.0

    def test_negative_interval_clamped_to_zero(self, monkeypatch):
        monkeypatch.setenv("CERTMATE_LAST_USED_PERSIST_SECONDS", "-10")
        assert AuthManager._last_used_persist_interval() == 0.0
