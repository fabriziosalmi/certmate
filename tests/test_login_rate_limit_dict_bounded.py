"""
Regression test for unbounded growth of the login rate-limit dicts.

`_login_attempts_by_ip` and `_login_attempts_by_user` are module-level
defaultdicts. Per-IP list size IS bounded (the rate limit kicks in at
5 attempts/min so each list never exceeds ~5 entries inside the window).
But the dict itself acquires one entry per unique IP, and entries are
never removed even after the window passes and the list trims to [].
A botnet rotating through unique source IPs would grow the dict without
bound.

`_sweep_empty_buckets()` runs opportunistically from
`_check_login_rate_limit` when either dict crosses its soft cap (default
10K). It trims every bucket to its active window, drops the now-empty
ones, and — as a hard backstop against within-window flooding — evicts the
oldest buckets if the dict still exceeds 2x cap. An empty-only sweep was
NOT enough: a rotated key is recorded once as a non-empty ``[ts]`` and
never revisited, so it was never reclaimed and the dict grew unbounded.

These tests assert:
- the dict does NOT keep growing unboundedly
- buckets with an attempt inside the active window are preserved
- stale non-empty buckets (rotated keys) ARE reclaimed
- the hard backstop caps the dict even under a within-window flood
"""
from __future__ import annotations

from time import time
from unittest.mock import patch

import pytest

from modules.web import routes as login_module


@pytest.fixture(autouse=True)
def reset_buckets():
    """Each test starts with empty dicts so we don't carry state across."""
    login_module._login_attempts_by_ip.clear()
    login_module._login_attempts_by_user.clear()
    yield
    login_module._login_attempts_by_ip.clear()
    login_module._login_attempts_by_user.clear()


def test_dict_grows_under_cap_then_sweeps(monkeypatch):
    """Below the cap, no sweep. Above the cap, empty buckets are removed."""
    # Use a tiny cap so the test runs in milliseconds.
    monkeypatch.setattr(login_module, '_MAX_TRACKED_IPS', 100)

    # Each IP records 1 attempt that we then trim out manually so the
    # list goes empty (mimicking what happens after the window passes).
    for i in range(50):
        login_module._login_attempts_by_ip[f'10.0.0.{i}'] = []

    # Under the cap: no sweep happens, dict size stays as-is.
    login_module._sweep_empty_buckets()
    assert len(login_module._login_attempts_by_ip) == 50, (
        "Under the soft cap, the sweep must be a no-op"
    )

    # Push past the cap.
    for i in range(50, 150):
        login_module._login_attempts_by_ip[f'10.0.1.{i}'] = []

    # Sweep should now run and remove the empties.
    login_module._sweep_empty_buckets()
    assert len(login_module._login_attempts_by_ip) == 0, (
        "Above the soft cap, all empty buckets must be removed"
    )


def test_sweep_preserves_active_rate_limit_windows(monkeypatch):
    """Buckets with an attempt inside the active window must NOT be reclaimed,
    even when the dict is over cap — otherwise an attacker could escape the
    rate limit by triggering a sweep."""
    monkeypatch.setattr(login_module, '_MAX_TRACKED_IPS', 10)

    now = time()
    # 10 IPs with a fresh (in-window) attempt — these are active windows.
    for i in range(10):
        login_module._login_attempts_by_ip[f'attacker-{i}'] = [now - 1.0]

    # 20 IPs whose only attempt has aged out of the window — non-empty, but
    # reclaimable (this is exactly the rotated-key case the old sweep missed).
    stale = now - login_module._LOGIN_RATE_WINDOW_IP - 100
    for i in range(20):
        login_module._login_attempts_by_ip[f'old-{i}'] = [stale]

    # Total 30 > cap 10, sweep runs.
    login_module._sweep_empty_buckets()

    # All 10 active windows survive; all 20 stale buckets are reclaimed.
    assert len(login_module._login_attempts_by_ip) == 10
    for i in range(10):
        assert f'attacker-{i}' in login_module._login_attempts_by_ip
    for i in range(20):
        assert f'old-{i}' not in login_module._login_attempts_by_ip


def test_reclaims_rotated_nonempty_buckets(monkeypatch):
    """The botnet case the cap exists for: each fresh IP is recorded once as a
    non-empty [ts] bucket and never revisited. Once those timestamps age out
    of the window, an over-cap sweep must reclaim them — the old empty-only
    sweep left them forever (unbounded growth)."""
    monkeypatch.setattr(login_module, '_MAX_TRACKED_IPS', 100)
    monkeypatch.setattr(login_module, '_LOGIN_RATE_WINDOW_IP', 60)

    stale = time() - 1000.0  # well outside the 60s window
    for i in range(5000):
        login_module._login_attempts_by_ip[f'10.{i // 256}.{i % 256}.1'] = [stale]
    assert len(login_module._login_attempts_by_ip) == 5000

    # A single live check triggers the sweep and reclaims every stale bucket.
    login_module._check_login_rate_limit('198.51.100.7')

    # Only the live caller's bucket remains; the 5000 rotated buckets are gone.
    assert len(login_module._login_attempts_by_ip) <= 1


def test_hard_cap_backstop_caps_within_window_flood(monkeypatch):
    """If an attacker floods distinct keys all within the window (so window
    trimming keeps them), the 2x-cap backstop must still bound the dict to the
    cap rather than letting it grow without limit."""
    monkeypatch.setattr(login_module, '_MAX_TRACKED_IPS', 100)
    monkeypatch.setattr(login_module, '_LOGIN_RATE_WINDOW_IP', 60)

    now = time()
    # 300 distinct keys, all fresh (in-window) -> trimming keeps them all, so
    # only the 2x-cap backstop can bound the dict.
    for i in range(300):
        login_module._login_attempts_by_ip[f'172.16.{i // 256}.{i % 256}'] = [now - (i % 5)]

    login_module._sweep_empty_buckets()
    assert len(login_module._login_attempts_by_ip) <= login_module._MAX_TRACKED_IPS


def test_check_login_rate_limit_triggers_sweep(monkeypatch):
    """The cleanup must be wired into the public entry point, not just a
    helper that nothing calls. Spy on the sweep to confirm."""
    monkeypatch.setattr(login_module, '_MAX_TRACKED_IPS', 5)

    # Seed an over-cap pile of empties.
    for i in range(20):
        login_module._login_attempts_by_ip[f'10.0.0.{i}'] = []

    # Wrap _sweep_empty_buckets so we can verify it actually fires.
    real_sweep = login_module._sweep_empty_buckets
    sweep_calls = [0]

    def counted_sweep():
        sweep_calls[0] += 1
        real_sweep()

    with patch.object(login_module, '_sweep_empty_buckets', side_effect=counted_sweep):
        login_module._check_login_rate_limit('1.2.3.4')

    assert sweep_calls[0] == 1, (
        "_check_login_rate_limit must call the sweep on every invocation"
    )
    # And the sweep actually shrunk the dict.
    assert len(login_module._login_attempts_by_ip) <= 1, (
        "After the rate-limit check, the dict should contain only the "
        "active 1.2.3.4 bucket (the empty 10.0.0.* were swept)"
    )


def test_rate_limiting_logic_still_works_with_sweep(monkeypatch):
    """End-to-end: the sweep must not interfere with the actual rate
    limiting. An IP that hits the limit must still be blocked."""
    monkeypatch.setattr(login_module, '_MAX_TRACKED_IPS', 100)
    monkeypatch.setattr(login_module, '_LOGIN_RATE_LIMIT_IP', 3)

    ip = '203.0.113.42'
    for _ in range(3):
        allowed, _ = login_module._check_login_rate_limit(ip)
        assert allowed is True
        login_module._record_login_attempt(ip)

    # Fourth attempt must be blocked.
    allowed, retry_after = login_module._check_login_rate_limit(ip)
    assert allowed is False
    assert retry_after is not None and retry_after > 0


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
