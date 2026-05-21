"""Unit tests for modules/core/auth.py (AuthManager).

The module was at ~59% before this file landed. These tests target the
pure-logic and stateful-but-deterministic surfaces — role normalization,
password hashing round-trip, allowed-domain scope matching (the multi-
tenancy boundary), API-token hashing, user lifecycle, and session
lifecycle. No Flask request context, no HTTP, no Docker.
"""

import time
from unittest.mock import MagicMock

import pytest


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# Stub settings manager: deep-copy semantics on load + records mutations.
# Mirrors the pattern used by test_dns_manager_coverage.py so both files
# stay consistent.
# ---------------------------------------------------------------------------


def _mk_settings_manager(initial_settings):
    import copy
    sm = MagicMock()
    sm.load_settings.side_effect = lambda: copy.deepcopy(initial_settings)
    sm.migrate_dns_providers_to_multi_account.side_effect = lambda s: s

    def _update(fn, audit_label):
        state = copy.deepcopy(initial_settings)
        fn(state)
        # Mutations land in the seed dict so subsequent load_settings()
        # calls see them — that's what the real SettingsManager does.
        initial_settings.clear()
        initial_settings.update(state)
        return True

    sm.update.side_effect = _update
    return sm


@pytest.fixture
def auth_manager_factory():
    from modules.core.auth import AuthManager

    def _build(initial=None):
        sm = _mk_settings_manager(initial if initial is not None else {})
        return AuthManager(sm), sm

    return _build


# ---------------------------------------------------------------------------
# _normalize_role
# ---------------------------------------------------------------------------


class TestNormalizeRole:
    def test_known_roles_passthrough(self):
        from modules.core.auth import AuthManager
        assert AuthManager._normalize_role('admin') == 'admin'
        assert AuthManager._normalize_role('operator') == 'operator'
        assert AuthManager._normalize_role('viewer') == 'viewer'

    def test_legacy_user_maps_to_operator(self):
        """Pre-3-tier installs called this role 'user'."""
        from modules.core.auth import AuthManager
        assert AuthManager._normalize_role('user') == 'operator'

    def test_unknown_role_defaults_to_viewer(self):
        """Defense in depth: an attacker-supplied role string can't elevate."""
        from modules.core.auth import AuthManager
        assert AuthManager._normalize_role('superuser') == 'viewer'
        assert AuthManager._normalize_role('') == 'viewer'
        assert AuthManager._normalize_role(None) == 'viewer'


# ---------------------------------------------------------------------------
# Password hashing round-trip (bcrypt or SHA-256 fallback)
# ---------------------------------------------------------------------------


class TestPasswordHashing:
    def test_round_trip(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        hashed = mgr._hash_password('CorrectHorseBatteryStaple')
        assert mgr._verify_password('CorrectHorseBatteryStaple', hashed) is True

    def test_wrong_password_rejected(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        hashed = mgr._hash_password('s3cret')
        assert mgr._verify_password('wrong', hashed) is False

    def test_each_hash_is_unique_for_same_input(self, auth_manager_factory):
        """Salt (bcrypt or explicit) must make repeated hashes differ — else
        rainbow tables become viable. Pin the salting contract."""
        mgr, _ = auth_manager_factory()
        h1 = mgr._hash_password('same-input')
        h2 = mgr._hash_password('same-input')
        assert h1 != h2

    def test_verify_legacy_sha256_with_explicit_salt(self, auth_manager_factory):
        """Pre-bcrypt installs store passwords as 'sha256:<salt>:<hex>'.
        The verify path must still accept them so existing operators can
        log in after upgrade."""
        mgr, _ = auth_manager_factory()
        import hashlib
        salt = 'cafebabe' * 4
        digest = hashlib.sha256((salt + 'legacy-pw').encode()).hexdigest()
        legacy_hash = f"sha256:{salt}:{digest}"
        assert mgr._verify_password('legacy-pw', legacy_hash) is True
        assert mgr._verify_password('wrong', legacy_hash) is False

    def test_verify_legacy_format_without_prefix(self, auth_manager_factory):
        """Even older installs stored 'salt:hash' with no algorithm prefix."""
        mgr, _ = auth_manager_factory()
        import hashlib
        salt = 'deadbeef' * 4
        digest = hashlib.sha256((salt + 'older-pw').encode()).hexdigest()
        legacy_hash = f"{salt}:{digest}"
        assert mgr._verify_password('older-pw', legacy_hash) is True

    def test_verify_handles_malformed_hash_without_raising(self, auth_manager_factory):
        """Defense-in-depth: a corrupted stored_hash should return False,
        not propagate an exception that the caller would log as a 500."""
        mgr, _ = auth_manager_factory()
        assert mgr._verify_password('anything', 'not-a-real-hash-at-all') is False
        assert mgr._verify_password('anything', '') is False


# ---------------------------------------------------------------------------
# _normalize_allowed_domains — input validation for scoped API keys
# ---------------------------------------------------------------------------


class TestNormalizeAllowedDomains:
    def test_none_means_unrestricted(self):
        from modules.core.auth import AuthManager
        norm, err = AuthManager._normalize_allowed_domains(None)
        assert norm is None
        assert err is None

    def test_empty_list_is_locked_out_not_an_error(self):
        from modules.core.auth import AuthManager
        norm, err = AuthManager._normalize_allowed_domains([])
        assert norm == []
        assert err is None

    def test_strips_and_lowercases(self):
        from modules.core.auth import AuthManager
        norm, err = AuthManager._normalize_allowed_domains(['  Example.COM  '])
        assert err is None
        assert norm == ['example.com']

    def test_deduplicates_while_preserving_order(self):
        from modules.core.auth import AuthManager
        norm, _ = AuthManager._normalize_allowed_domains(
            ['a.test', 'b.test', 'a.test', 'A.TEST']
        )
        assert norm == ['a.test', 'b.test']

    def test_wildcard_pattern_accepted(self):
        from modules.core.auth import AuthManager
        norm, err = AuthManager._normalize_allowed_domains(['*.example.com'])
        assert err is None
        assert norm == ['*.example.com']

    def test_invalid_pattern_returns_error_and_none(self):
        from modules.core.auth import AuthManager
        norm, err = AuthManager._normalize_allowed_domains(['not_a_domain!'])
        assert norm is None
        assert err is not None
        assert 'not_a_domain!' in err

    def test_non_list_returns_error(self):
        from modules.core.auth import AuthManager
        norm, err = AuthManager._normalize_allowed_domains('example.com')
        assert norm is None
        assert err is not None

    def test_non_string_entry_returns_error(self):
        from modules.core.auth import AuthManager
        norm, err = AuthManager._normalize_allowed_domains(['example.com', 42])
        assert norm is None
        assert err is not None

    def test_empty_string_entries_skipped(self):
        """An empty/whitespace-only entry is silently dropped — strict
        validation only kicks in for non-empty values that don't match."""
        from modules.core.auth import AuthManager
        norm, err = AuthManager._normalize_allowed_domains(['', '   ', 'real.com'])
        assert err is None
        assert norm == ['real.com']


# ---------------------------------------------------------------------------
# domain_matches_scope — the security boundary for multi-tenant API keys
# ---------------------------------------------------------------------------


class TestDomainMatchesScope:
    def test_none_scope_matches_everything(self):
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('anything.com', None) is True

    def test_empty_scope_matches_nothing(self):
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('anything.com', []) is False

    def test_exact_match_case_insensitive(self):
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('Example.com', ['example.com']) is True

    def test_exact_match_rejects_subdomain(self):
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('sub.example.com', ['example.com']) is False

    def test_wildcard_matches_one_level_subdomain(self):
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('foo.example.com', ['*.example.com']) is True

    def test_wildcard_matches_nested_subdomain(self):
        """The pattern '*.example.com' matches any subdomain depth."""
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('a.b.example.com', ['*.example.com']) is True

    def test_wildcard_does_not_match_apex(self):
        """The pattern '*.example.com' must NOT match 'example.com' itself —
        otherwise '*.example.com' becomes a stealth alias for 'example.com'."""
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('example.com', ['*.example.com']) is False

    def test_non_matching_domain_rejected(self):
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('other.com', ['example.com']) is False

    def test_empty_domain_rejected_under_finite_scope(self):
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('', ['example.com']) is False

    def test_non_string_domain_rejected(self):
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope(None, ['example.com']) is False
        assert AuthManager.domain_matches_scope(42, ['example.com']) is False

    def test_input_wildcard_against_exact_scope_falls_through_apex(self):
        """The matcher strips '*.' from the requested domain, so a request
        for '*.example.com' becomes 'example.com' for matching purposes.
        Against an exact scope of 'example.com', that matches; against a
        wildcard scope of '*.example.com', it does NOT (the strict-
        subdomain rule), which is the same gotcha the apex-vs-wildcard
        test pins for forward inputs. Both cases are honest behaviour;
        future refactors must keep them consistent."""
        from modules.core.auth import AuthManager
        assert AuthManager.domain_matches_scope('*.example.com', ['example.com']) is True
        assert AuthManager.domain_matches_scope('*.example.com', ['*.example.com']) is False


# ---------------------------------------------------------------------------
# user_can_access_domain — wires up domain_matches_scope with the user's scope
# ---------------------------------------------------------------------------


class TestUserCanAccessDomain:
    def test_no_user_returns_false(self, auth_manager_factory):
        """Both None and empty-dict are treated as 'no caller identified' —
        no access. The legacy 'unrestricted' contract only kicks in for a
        user dict that exists but has no allowed_domains key set."""
        mgr, _ = auth_manager_factory()
        assert mgr.user_can_access_domain(None, 'example.com') is False
        assert mgr.user_can_access_domain({}, 'example.com') is False

    def test_user_without_allowed_domains_unrestricted(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        user = {'username': 'admin'}  # no allowed_domains key
        assert mgr.user_can_access_domain(user, 'whatever.com') is True

    def test_user_with_scope_can_access_in_scope_domain(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        user = {'username': 'tenant-a', 'allowed_domains': ['a.example.com', '*.tenant-a.io']}
        assert mgr.user_can_access_domain(user, 'a.example.com') is True
        assert mgr.user_can_access_domain(user, 'foo.tenant-a.io') is True

    def test_user_with_scope_cannot_access_out_of_scope_domain(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        user = {'username': 'tenant-a', 'allowed_domains': ['a.example.com']}
        assert mgr.user_can_access_domain(user, 'b.example.com') is False

    def test_user_with_empty_scope_locked_out_of_everything(self, auth_manager_factory):
        """A key with `allowed_domains=[]` is intentionally locked out — used
        e.g. for staging an admin-revoked key without deleting it."""
        mgr, _ = auth_manager_factory()
        user = {'username': 'locked', 'allowed_domains': []}
        assert mgr.user_can_access_domain(user, 'anything.com') is False


# ---------------------------------------------------------------------------
# API token hashing (HMAC-SHA256 preferred, plain SHA-256 fallback)
# ---------------------------------------------------------------------------


class TestApiTokenHashing:
    def test_round_trip_without_hmac_key(self, auth_manager_factory):
        """No hmac_key set → plain SHA-256 path, verifiable."""
        mgr, _ = auth_manager_factory()
        stored = mgr.hash_api_token('secret-token-abc')
        assert stored.startswith('sha256:')
        assert mgr._verify_api_token('secret-token-abc', stored) is True
        assert mgr._verify_api_token('wrong', stored) is False

    def test_round_trip_with_hmac_key(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.set_hmac_key('server-side-secret')
        stored = mgr.hash_api_token('user-token-xyz')
        assert stored.startswith('hmac-sha256:')
        assert mgr._verify_api_token('user-token-xyz', stored) is True
        assert mgr._verify_api_token('wrong', stored) is False

    def test_verify_legacy_sha256_token_after_hmac_key_set(self, auth_manager_factory):
        """A token hashed before the HMAC key was provisioned must still
        verify after the key is set — otherwise upgrade rotates every API
        key in a fleet."""
        mgr, _ = auth_manager_factory()
        legacy_hash = mgr.hash_api_token('legacy-token')
        assert legacy_hash.startswith('sha256:')
        # Now wire the HMAC key as if the operator just upgraded.
        mgr.set_hmac_key('newly-provisioned-key')
        assert mgr._verify_api_token('legacy-token', legacy_hash) is True

    def test_verify_returns_false_on_empty_stored_hash(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        assert mgr._verify_api_token('token', '') is False
        assert mgr._verify_api_token('token', None) is False

    def test_verify_returns_false_on_unknown_prefix(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        assert mgr._verify_api_token('token', 'argon2:something') is False


# ---------------------------------------------------------------------------
# User lifecycle — create / authenticate / update / delete / list
# ---------------------------------------------------------------------------


class TestUserLifecycle:
    def test_create_and_authenticate_user(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        ok, _ = mgr.create_user('alice', 'StrongP@ss-2026', role='admin', email='alice@example.com')
        assert ok is True

        user = mgr.authenticate_user('alice', 'StrongP@ss-2026')
        assert user is not None
        assert user['username'] == 'alice'
        assert user['role'] == 'admin'

    def test_authenticate_wrong_password_returns_none(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.create_user('bob', 'CorrectPw-1', role='viewer')
        assert mgr.authenticate_user('bob', 'wrong') is None

    def test_authenticate_unknown_user_returns_none(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        assert mgr.authenticate_user('ghost', 'x') is None

    def test_legacy_role_user_normalised_on_create(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.create_user('legacy', 'pw1234567', role='user')
        user = mgr.authenticate_user('legacy', 'pw1234567')
        assert user is not None
        assert user['role'] == 'operator'

    def test_unknown_role_defaults_to_viewer_on_create(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.create_user('lowpriv', 'pw1234567', role='superuser')  # not valid
        user = mgr.authenticate_user('lowpriv', 'pw1234567')
        assert user is not None
        assert user['role'] == 'viewer'

    def test_list_users_returns_metadata_only(self, auth_manager_factory):
        """list_users returns a dict keyed by username. Each value must
        contain role/email/created_at/last_login/enabled but NEVER the
        password hash — the route layer trusts this output to be safe to
        JSON-encode for the UI."""
        mgr, _ = auth_manager_factory()
        mgr.create_user('alice', 'StrongPw-1', role='admin')
        mgr.create_user('bob', 'StrongPw-2', role='viewer')

        users = mgr.list_users()
        assert isinstance(users, dict)
        assert set(users.keys()) == {'alice', 'bob'}
        for meta in users.values():
            assert 'role' in meta
            # The hash MUST NOT leak into the listing.
            assert 'password' not in meta
            assert 'password_hash' not in meta

    def test_update_user_changes_password_and_role(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.create_user('carol', 'OldPw-987654', role='viewer')

        ok, _ = mgr.update_user('carol', password='NewPw-987654', role='admin')
        assert ok is True

        # Old password no longer works.
        assert mgr.authenticate_user('carol', 'OldPw-987654') is None
        # New password works AND role rolled forward.
        new_user = mgr.authenticate_user('carol', 'NewPw-987654')
        assert new_user is not None
        assert new_user['role'] == 'admin'

    def test_update_unknown_user_returns_false(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        ok, msg = mgr.update_user('ghost', password='x')
        assert ok is False
        assert 'not found' in msg.lower()

    def test_delete_user(self, auth_manager_factory):
        """Delete via a viewer-role user so the 'last admin' guard doesn't
        fire — that guard has its own test below."""
        mgr, _ = auth_manager_factory()
        mgr.create_user('keeper', 'PwAdmin-1', role='admin')  # protect last-admin invariant
        mgr.create_user('temp', 'Pw-12345678', role='viewer')

        ok, _ = mgr.delete_user('temp')
        assert ok is True
        # User gone — auth fails.
        assert mgr.authenticate_user('temp', 'Pw-12345678') is None

    def test_delete_unknown_user_returns_false(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        ok, msg = mgr.delete_user('ghost')
        assert ok is False
        assert 'not found' in msg.lower()

    def test_cannot_delete_the_last_admin(self, auth_manager_factory):
        """Defense-in-depth: the only admin cannot be removed by accident,
        which would lock everyone out of admin-gated endpoints."""
        mgr, _ = auth_manager_factory()
        mgr.create_user('sole-admin', 'PwAdmin-1', role='admin')
        ok, msg = mgr.delete_user('sole-admin')
        assert ok is False
        assert 'last admin' in msg.lower()

    def test_update_user_toggles_enabled(self, auth_manager_factory):
        """enabled is honored by update_user so the disable/enable action
        actually persists (regression guard for the PUT route that used to
        drop everything but role)."""
        mgr, _ = auth_manager_factory()
        mgr.create_user('keeper', 'PwAdmin-1', role='admin')  # last-admin guard
        mgr.create_user('dora', 'Pw-12345678', role='operator')

        ok, _ = mgr.update_user('dora', enabled=False)
        assert ok is True
        # A disabled user can no longer authenticate.
        assert mgr.authenticate_user('dora', 'Pw-12345678') is None

        ok, _ = mgr.update_user('dora', enabled=True)
        assert ok is True
        assert mgr.authenticate_user('dora', 'Pw-12345678') is not None

    def test_cannot_disable_the_last_active_admin(self, auth_manager_factory):
        """Disabling the only active admin would lock everyone out, so it is
        refused — the delete path has the parallel guard (issue #229)."""
        mgr, _ = auth_manager_factory()
        mgr.create_user('sole-admin', 'PwAdmin-1', role='admin')
        ok, msg = mgr.update_user('sole-admin', enabled=False)
        assert ok is False
        assert 'last active admin' in msg.lower()

    def test_can_disable_admin_when_another_active_admin_exists(self, auth_manager_factory):
        """With two active admins, either may be disabled."""
        mgr, _ = auth_manager_factory()
        mgr.create_user('admin-a', 'PwAdmin-1', role='admin')
        mgr.create_user('admin-b', 'PwAdmin-2', role='admin')
        ok, _ = mgr.update_user('admin-a', enabled=False)
        assert ok is True

    def test_cannot_set_password_for_sso_user(self, auth_manager_factory):
        """SSO accounts authenticate via the IdP and keep an empty
        password_hash; setting a local password is refused (issue #229)."""
        mgr, _ = auth_manager_factory({'users': {
            'sso-bob': {
                'password_hash': '', 'role': 'operator', 'email': 'b@x.io',
                'created_at': 'now', 'last_login': None, 'enabled': True,
                'oidc_subject': 'sub-1', 'oidc_issuer': 'https://idp.example',
            },
        }})
        ok, msg = mgr.update_user('sso-bob', password='NewPw-987654')
        assert ok is False
        assert 'sso' in msg.lower()
        # Non-password fields on the same row still update fine.
        ok, _ = mgr.update_user('sso-bob', role='viewer')
        assert ok is True

    def test_list_users_marks_sso_accounts(self, auth_manager_factory):
        """list_users flags IdP-linked rows with sso=True and surfaces the
        issuer (but never the subject) so the UI can badge them."""
        mgr, _ = auth_manager_factory({'users': {
            'sso-bob': {
                'password_hash': '', 'role': 'operator', 'enabled': True,
                'oidc_subject': 'sub-1', 'oidc_issuer': 'https://idp.example',
            },
        }})
        mgr.create_user('local-alice', 'StrongPw-1', role='admin')

        users = mgr.list_users()
        assert users['sso-bob']['sso'] is True
        assert users['sso-bob']['oidc_issuer'] == 'https://idp.example'
        assert 'oidc_subject' not in users['sso-bob']
        assert users['local-alice']['sso'] is False


# ---------------------------------------------------------------------------
# Session lifecycle — create / validate / invalidate
# ---------------------------------------------------------------------------


class TestSessionLifecycle:
    def test_create_then_validate_session(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.create_user('alice', 'StrongPw-1', role='admin')

        session_id = mgr.create_session('alice')
        assert isinstance(session_id, str) and session_id

        user = mgr.validate_session(session_id)
        assert user is not None
        assert user['username'] == 'alice'
        assert user['role'] == 'admin'

    def test_validate_unknown_session_returns_none(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        assert mgr.validate_session('not-a-real-session') is None
        assert mgr.validate_session('') is None
        assert mgr.validate_session(None) is None

    def test_invalidate_session_removes_it(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.create_user('alice', 'StrongPw-1', role='admin')
        sid = mgr.create_session('alice')
        assert mgr.validate_session(sid) is not None

        mgr.invalidate_session(sid)
        assert mgr.validate_session(sid) is None

    def test_session_ids_are_unique(self, auth_manager_factory):
        """Two consecutive create_session calls must mint different tokens
        — otherwise session-fixation becomes trivial."""
        mgr, _ = auth_manager_factory()
        mgr.create_user('alice', 'StrongPw-1', role='admin')
        a = mgr.create_session('alice')
        b = mgr.create_session('alice')
        assert a != b

    def test_expired_session_rejected(self, auth_manager_factory):
        """Force the stored session to look stale and confirm validate_
        session rejects it without raising."""
        mgr, _ = auth_manager_factory()
        mgr.create_user('alice', 'StrongPw-1', role='admin')
        sid = mgr.create_session('alice')

        # Reach into the session store and rewrite the expiry to a moment
        # in the past. This is a deliberate white-box test of the timeout
        # path — without it nothing exercises the cleanup branch.
        with mgr._session_lock:
            for entry in mgr._sessions.values():
                entry['expires'] = time.time() - 10

        assert mgr.validate_session(sid) is None


# ---------------------------------------------------------------------------
# Local-auth toggle + has_any_users flag (setup-wizard gating)
# ---------------------------------------------------------------------------


class TestLocalAuthToggle:
    def test_default_is_disabled(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        assert mgr.is_local_auth_enabled() is False

    def test_enable_local_auth_flips_flag(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.enable_local_auth(True)
        assert mgr.is_local_auth_enabled() is True
        mgr.enable_local_auth(False)
        assert mgr.is_local_auth_enabled() is False

    def test_has_any_users_reports_false_on_empty(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        assert mgr.has_any_users() is False

    def test_has_any_users_reports_true_after_create(self, auth_manager_factory):
        mgr, _ = auth_manager_factory()
        mgr.create_user('first-admin', 'StrongPw-12345', role='admin')
        assert mgr.has_any_users() is True
