"""
Regression test for unbounded growth of the login rate-limit dicts.

`_login_attempts_by_ip` and `_login_attempts_by_user` are module-level
defaultdicts. Per-IP list size IS bounded (the rate limit kicks in at
5 attempts/min so each list never exceeds ~5 entries inside the window).
But the dict itself acquires one entry per unique IP, and entries are
never removed even after the window passes and the list trims to [].
A botnet rotating through unique source IPs would grow the dict without
bound.

The fix adds `_sweep_empty_buckets()` that drops dict entries whose list
is empty, triggered opportunistically from `_check_login_rate_limit`
when either dict crosses its soft cap (default 10K). Non-empty buckets
(active rate-limit windows) are kept.

This test simulates botnet-style IP rotation past the cap and asserts:
- the dict does NOT keep growing unboundedly
- active rate-limit windows are preserved (non-empty buckets survive)
"""
from __future__ import annotations

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
    """Buckets with attempts in the active window must NOT be swept."""
    monkeypatch.setattr(login_module, '_MAX_TRACKED_IPS', 10)

    # 10 IPs in an active rate-limit window (non-empty lists)
    for i in range(10):
        login_module._login_attempts_by_ip[f'attacker-{i}'] = [99999999.0]

    # 20 expired IPs (empty lists)
    for i in range(20):
        login_module._login_attempts_by_ip[f'old-{i}'] = []

    # Total 30 > cap 10, sweep runs.
    login_module._sweep_empty_buckets()

    # All 10 attackers survive (non-empty); all 20 olds gone.
    assert len(login_module._login_attempts_by_ip) == 10
    for i in range(10):
        assert f'attacker-{i}' in login_module._login_attempts_by_ip
    for i in range(20):
        assert f'old-{i}' not in login_module._login_attempts_by_ip


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
