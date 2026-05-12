"""Sprint 1.6 (audit polish) — pure unit tests.

Covers:
- F-7: per-username login rate-limit bucket on top of per-IP.
- GET role normalization: /api/settings + /api/web/settings GET is now
  viewer-accessible (was admin-only on the web blueprint side); the
  decorator split surfaces correctly through Flask.

F-4 (UI confirm on empty allowed_domains) is a pure Alpine.js change
in static/js/settings-apikeys.js; the parseAllowedDomains helper that
drives the decision is already covered by the v2.4.12 suite
(TestCreateKeyWithAllowedDomains). The UI flow itself is exercised
by the existing Playwright fixture in CI.

F-6 (self-host ReDoc + CSP cleanup) is covered by the updated
tests/test_static_csp.py assertions in the same commit set.

No Docker; runs in-process.
"""

import time

import pytest

from modules.web import routes as web_routes


# --- F-7 per-username + per-IP rate limit -----------------------------------

@pytest.fixture(autouse=True)
def _reset_login_buckets():
    """Each test starts with empty buckets so assertions are deterministic."""
    web_routes._login_attempts_by_ip.clear()
    web_routes._login_attempts_by_user.clear()
    yield
    web_routes._login_attempts_by_ip.clear()
    web_routes._login_attempts_by_user.clear()


class TestPerIpBucket:
    """The original per-IP bucket still works on its own."""

    def test_allows_first_n_attempts(self):
        for _ in range(web_routes._LOGIN_RATE_LIMIT_IP):
            ok, _ = web_routes._check_login_rate_limit('1.2.3.4')
            web_routes._record_login_attempt('1.2.3.4')
            assert ok

    def test_blocks_after_limit(self):
        for _ in range(web_routes._LOGIN_RATE_LIMIT_IP):
            web_routes._record_login_attempt('1.2.3.4')
        ok, retry_after = web_routes._check_login_rate_limit('1.2.3.4')
        assert not ok
        assert retry_after is not None and retry_after > 0

    def test_username_optional_for_backward_compat(self):
        # Callers that don't pass username still work (legacy signature).
        ok, _ = web_routes._check_login_rate_limit('1.2.3.4')
        assert ok
        web_routes._record_login_attempt('1.2.3.4')


class TestPerUsernameBucket:
    """The new per-username bucket caps brute-force against a single target."""

    def test_blocks_distributed_attack_against_one_username(self):
        """Each attempt comes from a fresh IP (per-IP bucket never trips)
        but the per-username bucket fills up and rejects further tries.
        """
        target = 'admin'
        # Use a different IP for every attempt so the per-IP bucket
        # cannot be the one tripping.
        for i in range(web_routes._LOGIN_RATE_LIMIT_USER):
            ip = f'10.0.0.{i + 1}'
            ok, _ = web_routes._check_login_rate_limit(ip, target)
            assert ok, f"attempt {i+1} should have been allowed"
            web_routes._record_login_attempt(ip, target)

        ok, retry_after = web_routes._check_login_rate_limit('10.0.0.99', target)
        assert not ok
        assert retry_after is not None and retry_after > 0
        # Confirm the per-IP bucket is fresh for the rejecting IP — so
        # the rejection is unambiguously coming from the per-username
        # bucket, not from an accidental per-IP collision.
        assert len(web_routes._login_attempts_by_ip['10.0.0.99']) == 0

    def test_different_usernames_have_independent_buckets(self):
        # Use a different IP per attempt so the per-IP bucket doesn't
        # accidentally trip and mask the per-username independence we
        # actually want to verify.
        for i in range(web_routes._LOGIN_RATE_LIMIT_USER - 1):
            web_routes._record_login_attempt(f'10.0.0.{i+1}', 'alice')

        # bob's bucket is still empty, and the IP we're checking from
        # is fresh on the per-IP side too.
        ok, _ = web_routes._check_login_rate_limit('10.0.0.99', 'bob')
        assert ok

    def test_username_normalized_case_insensitive(self):
        """ADMIN and admin share the same bucket so an attacker can't
        side-step the limit by varying letter case."""
        for _ in range(web_routes._LOGIN_RATE_LIMIT_USER):
            web_routes._record_login_attempt('1.2.3.4', 'ADMIN')
        ok, _ = web_routes._check_login_rate_limit('9.9.9.9', 'admin')
        assert not ok

    def test_username_whitespace_normalized(self):
        for _ in range(web_routes._LOGIN_RATE_LIMIT_USER):
            web_routes._record_login_attempt('1.2.3.4', '  admin  ')
        ok, _ = web_routes._check_login_rate_limit('9.9.9.9', 'admin')
        assert not ok

    def test_empty_username_skips_per_user_bucket(self):
        # Empty/whitespace-only usernames must not poison the bucket
        # (otherwise a malicious client could pre-fill a wildcard slot).
        for _ in range(web_routes._LOGIN_RATE_LIMIT_USER + 5):
            web_routes._record_login_attempt('1.2.3.4', '   ')
        # The username bucket remains untouched.
        assert web_routes._login_attempts_by_user.get('') in (None, [])
        # IP bucket still trips because we recorded N+5 hits there.
        ok, _ = web_routes._check_login_rate_limit('1.2.3.4')
        assert not ok


class TestRetryAfterIsWorstCase:
    """retry_after should be the *longer* of the two outstanding windows
    so the client backs off enough to clear both buckets, not just one."""

    def test_per_ip_dominates_when_only_ip_full(self):
        for _ in range(web_routes._LOGIN_RATE_LIMIT_IP):
            web_routes._record_login_attempt('1.2.3.4', 'someuser')
        ok, retry = web_routes._check_login_rate_limit('1.2.3.4', 'someuser')
        assert not ok
        # The IP bucket window is 60s; per-user is 300s but only has
        # IP-bucket-count hits which is below USER limit. The block
        # comes from the IP bucket so retry_after must be <= 60s + a
        # second of slack.
        assert retry < web_routes._LOGIN_RATE_WINDOW_IP + 2

    def test_per_user_dominates_when_user_full_but_ip_fresh(self):
        # Pre-fill user bucket from many different IPs
        for i in range(web_routes._LOGIN_RATE_LIMIT_USER):
            web_routes._record_login_attempt(f'10.0.0.{i+1}', 'admin')
        # New IP, same username -> per-user bucket trips
        ok, retry = web_routes._check_login_rate_limit('9.9.9.9', 'admin')
        assert not ok
        # User bucket window is 300s; retry must reflect that.
        assert retry > web_routes._LOGIN_RATE_WINDOW_IP


class TestBucketWindowExpiry:
    """Attempts age out of their bucket after the window elapses."""

    def test_ip_attempts_outside_window_pruned(self, monkeypatch):
        # Plant fake stale attempts
        stale = time.time() - web_routes._LOGIN_RATE_WINDOW_IP - 10
        web_routes._login_attempts_by_ip['1.2.3.4'] = [stale] * 10
        # Bucket appears full but the entries are all stale; a fresh
        # check should prune them and allow.
        ok, _ = web_routes._check_login_rate_limit('1.2.3.4')
        assert ok
        assert web_routes._login_attempts_by_ip['1.2.3.4'] == []

    def test_user_attempts_outside_window_pruned(self):
        stale = time.time() - web_routes._LOGIN_RATE_WINDOW_USER - 10
        web_routes._login_attempts_by_user['admin'] = [stale] * 20
        ok, _ = web_routes._check_login_rate_limit('9.9.9.9', 'admin')
        assert ok
        assert web_routes._login_attempts_by_user['admin'] == []


# --- GET role normalization on /api/web/settings ----------------------------

class TestSettingsGetRoleNormalization:
    """Both GET endpoints (RESTX /api/settings and web /api/web/settings)
    must accept viewer role. POST stays admin on both."""

    def test_module_exposes_split_get_endpoint(self):
        """Sanity import: the new viewer-decorated GET handler exists in
        the settings_routes module and the admin-decorated POST one
        remains. The full Flask integration is exercised by the docker
        fixture in tests/test_auth.py."""
        from modules.web import settings_routes
        src = settings_routes.register_settings_routes.__code__
        # The handler names live as closures inside register_settings_routes;
        # we approximate by reading the function source text to confirm both
        # handlers and roles are present.
        import inspect
        text = inspect.getsource(settings_routes.register_settings_routes)
        assert "api_settings_get" in text
        assert "require_role('viewer')" in text
        assert "@auth_manager.require_role('admin')" in text
        # And both URL rules are registered under the GET route:
        assert "/api/settings" in text
        assert "/api/web/settings" in text
