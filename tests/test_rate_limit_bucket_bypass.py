"""The API rate limiter must not be bypassable by varying the bearer token.

Regression test for #420. The bucket was `sha256(<caller-supplied bearer
token>)`, computed *before* the token was validated, so every request with a
different Authorization header landed in a fresh bucket:

    for i in $(seq 100000); do
      curl -H "Authorization: Bearer $RANDOM" https://host/api/crl/download/pem
    done

was never limited. That also left the two deliberately unauthenticated
resources (OCSP status and CRL download) with no protection at all, and it
flooded SimpleRateLimiter towards MAX_KEYS, whose eviction then discarded
legitimate per-IP buckets.

The fix keeps the per-key bucket — many clients behind one NAT must not share
a limit — but adds a coarse per-IP ceiling that is always checked, and checked
first, so a token-varying caller is cut off before allocating buckets.
"""

import pytest

from modules.core.rate_limit import RateLimitConfig, SimpleRateLimiter


pytestmark = [pytest.mark.unit]


def _limiter(**limits):
    return SimpleRateLimiter(RateLimitConfig(custom_limits=limits or None))


def test_ip_ceiling_has_a_default_and_is_far_above_the_working_limits():
    cfg = RateLimitConfig()
    ceiling = cfg.get_limit('ip_ceiling')
    assert ceiling > cfg.get_limit('default')
    assert ceiling > cfg.get_limit('crl_download')
    assert ceiling > cfg.get_limit('ocsp_status')


def test_varying_the_token_no_longer_mints_an_unlimited_number_of_buckets():
    """The behaviour that made the limiter decorative."""
    limiter = _limiter(ip_ceiling=10, crl_download=5)
    ip = 'ip:203.0.113.9'

    allowed = 0
    for i in range(50):
        # What the attacker controls: a fresh key bucket every request.
        if not limiter.is_allowed(ip, 'ip_ceiling'):
            break
        limiter.is_allowed(f'key:token-{i}', 'crl_download')
        allowed += 1

    assert allowed == 10, f"the IP ceiling did not stop the sweep ({allowed} got through)"


def test_the_ceiling_is_checked_before_a_key_bucket_is_allocated():
    """Otherwise the sweep still floods the limiter toward MAX_KEYS."""
    limiter = _limiter(ip_ceiling=3, default=100)
    ip = 'ip:203.0.113.9'

    for i in range(20):
        if not limiter.is_allowed(ip, 'ip_ceiling'):
            continue  # the real code returns 429 here, touching nothing else
        limiter.is_allowed(f'key:token-{i}', 'default')

    key_buckets = [k for k in limiter.requests if k.startswith('key:')]
    assert len(key_buckets) == 3, \
        f"a rejected caller still allocated {len(key_buckets)} buckets"


def test_two_keys_behind_one_ip_still_get_independent_working_limits():
    """The reason the per-key bucket exists — do not regress it."""
    limiter = _limiter(ip_ceiling=1000, default=2)

    assert limiter.is_allowed('key:alice', 'default') is True
    assert limiter.is_allowed('key:alice', 'default') is True
    assert limiter.is_allowed('key:alice', 'default') is False
    # Bob is untouched by Alice exhausting her limit.
    assert limiter.is_allowed('key:bob', 'default') is True


def test_anonymous_callers_are_limited_per_ip():
    limiter = _limiter(ip_ceiling=1000, ocsp_status=2)

    assert limiter.is_allowed('ip:198.51.100.4', 'ocsp_status') is True
    assert limiter.is_allowed('ip:198.51.100.4', 'ocsp_status') is True
    assert limiter.is_allowed('ip:198.51.100.4', 'ocsp_status') is False
    # A different source IP is unaffected.
    assert limiter.is_allowed('ip:198.51.100.5', 'ocsp_status') is True


def test_dead_buckets_are_pruned_to_the_decision_window():
    """Retention used to be an hour while decisions look at 60s, so a
    token-varying caller could leave tens of thousands of dead buckets behind
    and push the table to MAX_KEYS — whose eviction then discards LIVE ones."""
    limiter = _limiter(ip_ceiling=1000, default=100)
    assert limiter.RETENTION_SECONDS <= 5 * limiter.WINDOW_SECONDS

    now = __import__('time').time()
    for i in range(50):
        limiter.requests[f'key:dead-{i}'] = [now - (limiter.RETENTION_SECONDS + 10)]
    limiter.requests['key:live'] = [now]

    limiter.cleanup_old_entries()

    assert 'key:live' in limiter.requests
    assert not [k for k in limiter.requests if k.startswith('key:dead-')]
