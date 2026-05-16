"""
Tests for the request-scoped settings cache in SettingsManager.

Without the cache, `/api/certificates` called `settings_manager.load_settings()`
once at the top of the handler PLUS once in `get_certificate_info` PLUS once
in `_parse_certificate_info` for every domain — so a request listing 50
certificates fired ~100 redundant disk reads + JSON parses + RLock
acquisitions for the same settings.json. The audit flagged this as
findings #1 and #6.

The fix caches the parsed settings on `flask.g` for the duration of one HTTP
request. The cache is invalidated by save_settings/atomic_update. Outside a
Flask request context the cache no-ops (scheduler, deploy worker, tests).

These tests pin five contracts:
1. Within one request, multiple load_settings calls hit disk only once.
2. save_settings inside the request clears the cache.
3. atomic_update inside the request clears the cache.
4. Two distinct requests each get their own fresh read.
5. Outside a request context every call hits disk (no leaked cache).
6. A caller that mutates the returned dict does NOT pollute the cache for
   the next reader in the same request (deepcopy semantic).
"""
from __future__ import annotations

from unittest.mock import patch
from pathlib import Path

import pytest
from flask import Flask

from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager


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
    mgr = SettingsManager(file_ops=file_ops, settings_file=data_dir / "settings.json")
    # Seed an initial settings.json so load_settings has something to parse.
    mgr.save_settings({'email': 'seed@example.com', 'dns_provider': 'cloudflare'})
    return mgr


@pytest.fixture
def flask_app():
    return Flask(__name__)


def _count_disk_reads(settings_manager):
    """Spy on FileOperations.safe_file_read to count how often load_settings
    actually hit disk. Returns a counter list that tests inspect."""
    real_read = settings_manager.file_ops.safe_file_read
    call_count = [0]

    def counted(*args, **kwargs):
        call_count[0] += 1
        return real_read(*args, **kwargs)

    return call_count, patch.object(
        settings_manager.file_ops, 'safe_file_read', side_effect=counted
    )


def test_load_settings_within_request_reads_disk_once(settings_manager, flask_app):
    counter, patcher = _count_disk_reads(settings_manager)
    with patcher, flask_app.test_request_context('/'):
        for _ in range(10):
            settings_manager.load_settings()

    assert counter[0] == 1, (
        f"Within one request, 10 load_settings calls must hit disk exactly "
        f"once thanks to the request-scoped cache (got {counter[0]})"
    )


def test_save_settings_invalidates_cache(settings_manager, flask_app):
    counter, patcher = _count_disk_reads(settings_manager)
    with patcher, flask_app.test_request_context('/'):
        settings_manager.load_settings()         # hit 1
        settings_manager.load_settings()         # cached
        settings_manager.save_settings({'email': 'after-save@example.com'})
        settings_manager.load_settings()         # hit 2 (cache cleared)

    assert counter[0] == 2, (
        f"save_settings must clear the request cache so the next reader sees "
        f"the new values (expected 2 disk reads, got {counter[0]})"
    )


def test_atomic_update_invalidates_cache(settings_manager, flask_app):
    counter, patcher = _count_disk_reads(settings_manager)
    with patcher, flask_app.test_request_context('/'):
        settings_manager.load_settings()                          # hit 1
        settings_manager.load_settings()                          # cached
        settings_manager.atomic_update({'email': 'atomic@example.com'})
        settings_manager.load_settings()                          # hit 2 (cleared)

    # atomic_update internally does load → merge → save, so the read inside
    # atomic_update is itself the 'hit 2' on a fresh cache, then save clears,
    # then the outer load_settings is hit 3. Either 2 or 3 is acceptable as
    # long as the post-save read does NOT serve the stale cached value.
    assert counter[0] >= 2, (
        f"atomic_update must trigger at least one fresh disk read after the "
        f"save clears the cache (got {counter[0]})"
    )
    # And the result on disk reflects the update.
    assert settings_manager.load_settings()['email'] == 'atomic@example.com'


def test_distinct_requests_do_not_share_cache(settings_manager, flask_app):
    counter, patcher = _count_disk_reads(settings_manager)
    with patcher:
        with flask_app.test_request_context('/req1'):
            settings_manager.load_settings()
            settings_manager.load_settings()
        with flask_app.test_request_context('/req2'):
            settings_manager.load_settings()
            settings_manager.load_settings()

    assert counter[0] == 2, (
        f"Two distinct requests must each trigger one fresh disk read "
        f"(cache is request-scoped, not process-wide). Got {counter[0]}."
    )


def test_outside_request_context_every_call_hits_disk(settings_manager):
    """Scheduler / deploy worker / startup paths run outside a Flask request
    context. The cache must no-op there — every call hits disk."""
    counter, patcher = _count_disk_reads(settings_manager)
    with patcher:
        for _ in range(5):
            settings_manager.load_settings()

    assert counter[0] == 5, (
        f"Outside a request context, the cache must no-op and every call "
        f"must hit disk. Got {counter[0]} reads for 5 calls."
    )


def test_caller_mutation_does_not_pollute_cached_dict(settings_manager, flask_app):
    """A caller that mutates the returned dict (load → mutate → use)
    must not leak that mutation to the next reader in the same request.
    The cache returns deepcopy on every hit."""
    with flask_app.test_request_context('/'):
        first = settings_manager.load_settings()
        first['_test_only_mutation'] = 'should-not-leak'

        second = settings_manager.load_settings()

    assert '_test_only_mutation' not in second, (
        "Caller mutation leaked into the cached dict and was visible to "
        "the next reader — deepcopy on cache hit is broken"
    )


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
