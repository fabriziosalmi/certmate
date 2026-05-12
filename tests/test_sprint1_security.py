"""Sprint 1 (security hardening) — pure unit tests.

Covers:
- modules.core.settings.validate_settings_post — strict whitelist
- modules.core.settings.diff_settings_keys
- modules.core.auth.AuthManager.domain_matches_scope
- modules.core.auth.AuthManager._normalize_allowed_domains
- AuthManager.create_api_key with allowed_domains
- AuthManager.authenticate_api_token propagating allowed_domains into
  request.current_user shape

No Docker; runs in-process.
"""

import pytest
from unittest.mock import MagicMock

from modules.core.settings import (
    PUBLIC_SETTINGS_WRITABLE_KEYS,
    SETTINGS_REJECT_KEYS,
    SECRET_MASK_SENTINEL,
    validate_settings_post,
    diff_settings_keys,
    _strip_masked_values,
)
from modules.core.auth import AuthManager


# --- POST /api/settings whitelist ------------------------------------------

class TestValidateSettingsPost:
    def test_accepts_safe_fields(self):
        payload = {'email': 'a@b.c', 'dns_provider': 'cloudflare'}
        filtered, rejected, unknown = validate_settings_post(payload)
        assert filtered == payload
        assert rejected == []
        assert unknown == []

    def test_rejects_api_bearer_token(self):
        payload = {'email': 'a@b.c', 'dns_provider': 'cf',
                   'api_bearer_token': 'cm_steal'}
        filtered, rejected, unknown = validate_settings_post(payload)
        assert 'api_bearer_token' not in filtered
        assert 'api_bearer_token' in rejected

    def test_rejects_deploy_hooks(self):
        # Deploy hooks via /api/settings would be an RCE injection vector.
        payload = {'email': 'a@b.c', 'dns_provider': 'cf',
                   'deploy_hooks': {'global_hooks': [{'command': 'rm -rf /'}]}}
        filtered, rejected, unknown = validate_settings_post(payload)
        assert 'deploy_hooks' not in filtered
        assert 'deploy_hooks' in rejected

    def test_rejects_users_and_api_keys(self):
        payload = {'email': 'a@b.c', 'dns_provider': 'cf',
                   'users': {'attacker': {}}, 'api_keys': {'x': {}}}
        filtered, rejected, unknown = validate_settings_post(payload)
        assert filtered == {'email': 'a@b.c', 'dns_provider': 'cf'}
        assert sorted(rejected) == ['api_keys', 'users']

    def test_rejects_local_auth_enabled(self):
        payload = {'email': 'a@b.c', 'dns_provider': 'cf',
                   'local_auth_enabled': False}
        filtered, rejected, _ = validate_settings_post(payload)
        assert 'local_auth_enabled' in rejected

    def test_flags_unknown_keys(self):
        payload = {'email': 'a@b.c', 'foobar_field': 1}
        filtered, rejected, unknown = validate_settings_post(payload)
        assert unknown == ['foobar_field']
        assert 'foobar_field' not in filtered

    def test_non_dict_payload_raises(self):
        with pytest.raises(ValueError):
            validate_settings_post(['a', 'b'])

    def test_writable_keys_are_disjoint_from_reject_keys(self):
        # Defense in depth: a key must not appear in both lists.
        assert PUBLIC_SETTINGS_WRITABLE_KEYS.isdisjoint(SETTINGS_REJECT_KEYS)

    def test_writable_keys_cover_setup_wizard_payload(self):
        # Regression guard: the setup wizard MUST be able to POST these.
        wizard_payload_keys = {
            'email', 'dns_provider', 'dns_providers',
            'auto_renew', 'setup_completed',
        }
        assert wizard_payload_keys.issubset(PUBLIC_SETTINGS_WRITABLE_KEYS)


class TestMaskedSentinelStripping:
    """The GET endpoint masks secret-named fields with '********'. A
    round-trip POST must NOT overwrite the real on-disk value with the
    placeholder. These tests pin the contract.
    """

    def test_top_level_mask_stripped(self):
        filtered, rejected, unknown = validate_settings_post({
            'email': 'a@b.c',
            'dns_provider': 'cloudflare',
            'api_bearer_token': SECRET_MASK_SENTINEL,
        })
        assert 'api_bearer_token' not in filtered
        assert 'api_bearer_token' not in rejected  # NOT a rejection — it's a no-op

    def test_nested_mask_collapses_empty_dict(self):
        # When every nested field is masked, the outer key disappears so
        # atomic_update isn't asked to write {}.
        cleaned = _strip_masked_values({
            'dns_providers': {
                'cloudflare': {'api_token': SECRET_MASK_SENTINEL},
            }
        })
        assert cleaned == {}

    def test_nested_mask_preserves_real_values(self):
        cleaned = _strip_masked_values({
            'dns_providers': {
                'cloudflare': {
                    'api_token': SECRET_MASK_SENTINEL,
                    'email': 'admin@example.com',
                }
            }
        })
        assert cleaned == {
            'dns_providers': {'cloudflare': {'email': 'admin@example.com'}}
        }

    def test_non_dict_input_returned_unchanged(self):
        assert _strip_masked_values('foo') == 'foo'
        assert _strip_masked_values(None) is None
        assert _strip_masked_values([1, 2]) == [1, 2]

    def test_real_token_value_still_rejected(self):
        # Defense: the strip is for masks only. A real token value still
        # has to go through the dedicated rotation flow.
        filtered, rejected, _ = validate_settings_post({
            'email': 'a@b.c',
            'dns_provider': 'cf',
            'api_bearer_token': 'cm_evil_real_token_value',
        })
        assert 'api_bearer_token' in rejected
        assert 'api_bearer_token' not in filtered


class TestNoOpEchoSilentDrop:
    """When `current` is supplied, fields whose incoming value matches the
    on-disk value are silently dropped — regardless of which list they
    fall under. This is what makes GET-then-POST-back behave like 'save
    only what changed'.
    """

    def test_unchanged_writable_field_dropped(self):
        current = {'email': 'a@b.c', 'dns_provider': 'cloudflare'}
        filtered, _, _ = validate_settings_post(
            {'email': 'a@b.c', 'dns_provider': 'cloudflare'},
            current=current,
        )
        assert filtered == {}

    def test_changed_writable_field_kept(self):
        current = {'email': 'old@b.c', 'dns_provider': 'cloudflare'}
        filtered, _, _ = validate_settings_post(
            {'email': 'new@b.c', 'dns_provider': 'cloudflare'},
            current=current,
        )
        assert filtered == {'email': 'new@b.c'}

    def test_unchanged_reject_field_not_rejected(self):
        # If a round-trip echoes 'deploy_hooks' unchanged, that's not a
        # mutation attempt — silently drop it instead of 400ing.
        current = {'deploy_hooks': {'global_hooks': []}, 'email': 'a@b.c'}
        filtered, rejected, _ = validate_settings_post(
            {'deploy_hooks': {'global_hooks': []}, 'email': 'a@b.c'},
            current=current,
        )
        assert rejected == []
        assert filtered == {}

    def test_changed_reject_field_still_rejected(self):
        current = {'deploy_hooks': {'global_hooks': []}}
        filtered, rejected, _ = validate_settings_post(
            {'deploy_hooks': {'global_hooks': [{'command': 'rm -rf /'}]}},
            current=current,
        )
        assert 'deploy_hooks' in rejected
        assert filtered == {}

    def test_unchanged_users_dict_silently_dropped(self):
        # The web UI doesn't send 'users' but the integration test fixture
        # round-trips the full GET response. The reject list must not 400
        # on this case (atomic_update would protect them anyway).
        current = {'users': {}, 'email': 'a@b.c'}
        filtered, rejected, _ = validate_settings_post(
            {'users': {}, 'email': 'a@b.c'},
            current=current,
        )
        assert rejected == []

    def test_without_current_old_strict_behavior(self):
        # Backward-compat: when callers don't supply `current`, no-op
        # detection is disabled. Reject-list fields still 400 immediately.
        filtered, rejected, _ = validate_settings_post(
            {'email': 'a@b.c', 'deploy_hooks': {}}
        )
        assert 'deploy_hooks' in rejected


class TestDiffSettingsKeys:
    def test_detects_changed_keys(self):
        assert diff_settings_keys({'a': 1}, {'a': 2}) == ['a']

    def test_detects_added_keys(self):
        assert diff_settings_keys({}, {'b': 1}) == ['b']

    def test_detects_removed_keys(self):
        assert diff_settings_keys({'c': 1}, {}) == ['c']

    def test_ignores_unchanged_keys(self):
        assert diff_settings_keys({'a': 1, 'b': 2}, {'a': 1, 'b': 2}) == []

    def test_returns_sorted(self):
        assert diff_settings_keys({'z': 1}, {'z': 2, 'a': 3, 'm': 4}) == ['a', 'm', 'z']

    def test_handles_non_dict_inputs_gracefully(self):
        assert diff_settings_keys(None, {'a': 1}) == []
        assert diff_settings_keys({'a': 1}, None) == []


# --- AuthManager.domain_matches_scope ---------------------------------------

class TestDomainMatchesScope:
    def test_none_scope_allows_everything(self):
        assert AuthManager.domain_matches_scope('any.example.com', None) is True

    def test_empty_scope_denies_everything(self):
        # An explicit empty list means a deliberately locked-out key.
        assert AuthManager.domain_matches_scope('any.example.com', []) is False

    def test_exact_match(self):
        assert AuthManager.domain_matches_scope('foo.com', ['foo.com']) is True
        assert AuthManager.domain_matches_scope('bar.com', ['foo.com']) is False

    def test_case_insensitive(self):
        assert AuthManager.domain_matches_scope('FOO.com', ['foo.com']) is True
        assert AuthManager.domain_matches_scope('foo.com', ['FOO.COM']) is True

    def test_wildcard_matches_subdomain(self):
        assert AuthManager.domain_matches_scope('a.foo.com', ['*.foo.com']) is True

    def test_wildcard_matches_multi_level_subdomain(self):
        # CertMate uses the LE-style wildcard meaning: "any depth below".
        assert AuthManager.domain_matches_scope('a.b.foo.com', ['*.foo.com']) is True

    def test_wildcard_does_not_match_apex(self):
        # *.foo.com must NOT match foo.com — apex needs its own pattern.
        assert AuthManager.domain_matches_scope('foo.com', ['*.foo.com']) is False

    def test_wildcard_does_not_match_overlapping_string(self):
        # 'barfoo.com' must not match '*.foo.com'.
        assert AuthManager.domain_matches_scope('barfoo.com', ['*.foo.com']) is False

    def test_multi_pattern_or_semantics(self):
        scope = ['foo.com', '*.example.org']
        assert AuthManager.domain_matches_scope('foo.com', scope) is True
        assert AuthManager.domain_matches_scope('x.example.org', scope) is True
        assert AuthManager.domain_matches_scope('nope.net', scope) is False

    def test_invalid_domain_input_denied(self):
        assert AuthManager.domain_matches_scope(None, ['foo.com']) is False
        assert AuthManager.domain_matches_scope('', ['foo.com']) is False


class TestNormalizeAllowedDomains:
    def test_none_passthrough(self):
        assert AuthManager._normalize_allowed_domains(None) == (None, None)

    def test_empty_list_passthrough(self):
        # Locked-out keys are a valid configuration choice.
        assert AuthManager._normalize_allowed_domains([]) == ([], None)

    def test_lowercases_and_trims(self):
        out, err = AuthManager._normalize_allowed_domains(
            ['  Foo.COM ', '*.BAR.net'])
        assert err is None
        assert out == ['foo.com', '*.bar.net']

    def test_dedupes(self):
        out, err = AuthManager._normalize_allowed_domains(
            ['foo.com', 'FOO.com', 'foo.com'])
        assert err is None
        assert out == ['foo.com']

    def test_rejects_invalid_pattern(self):
        out, err = AuthManager._normalize_allowed_domains(['not a domain'])
        assert out is None
        assert 'Invalid' in err

    def test_rejects_non_list(self):
        out, err = AuthManager._normalize_allowed_domains('foo.com')
        assert out is None
        assert 'list' in err.lower()

    def test_rejects_non_string_entries(self):
        out, err = AuthManager._normalize_allowed_domains([42])
        assert out is None
        assert 'string' in err.lower()


# --- API key creation + authentication with allowed_domains ------------------

@pytest.fixture
def settings_store():
    return {
        'local_auth_enabled': False,
        'users': {},
        'api_bearer_token': 'legacy_token_for_test',
        'api_keys': {},
    }


@pytest.fixture
def auth(settings_store):
    sm = MagicMock()
    sm.load_settings.side_effect = lambda: settings_store
    sm.save_settings.side_effect = lambda s, reason: True

    def _update(mutator, reason="auto_save"):
        s = sm.load_settings()
        mutator(s)
        return sm.save_settings(s, reason)
    sm.update.side_effect = _update
    return AuthManager(sm)


class TestCreateKeyWithAllowedDomains:
    def test_create_with_scope(self, auth):
        ok, result = auth.create_api_key(
            'CI', role='operator', allowed_domains=['*.ci.example.com'])
        assert ok is True
        assert result['allowed_domains'] == ['*.ci.example.com']

    def test_create_without_scope_is_unrestricted(self, auth):
        ok, result = auth.create_api_key('Unscoped', role='operator')
        assert ok is True
        assert result['allowed_domains'] is None

    def test_create_with_empty_scope_locks_key(self, auth):
        ok, result = auth.create_api_key(
            'Locked', role='operator', allowed_domains=[])
        assert ok is True
        assert result['allowed_domains'] == []

    def test_create_with_invalid_scope_fails(self, auth):
        ok, msg = auth.create_api_key(
            'Bad', role='operator', allowed_domains=['not a domain'])
        assert ok is False
        assert 'Invalid' in msg

    def test_listing_returns_allowed_domains(self, auth):
        auth.create_api_key('K1', role='viewer',
                            allowed_domains=['foo.com', '*.bar.com'])
        listed = auth.list_api_keys()
        assert len(listed) == 1
        entry = next(iter(listed.values()))
        assert entry['allowed_domains'] == ['foo.com', '*.bar.com']


class TestAuthenticatePropagatesScope:
    def test_scoped_token_sets_allowed_domains_on_user(self, auth):
        ok, created = auth.create_api_key(
            'CI', role='operator', allowed_domains=['*.app.example.com'])
        token = created['token']
        user = auth.authenticate_api_token(token)
        assert user is not None
        assert user['role'] == 'operator'
        assert user['allowed_domains'] == ['*.app.example.com']

    def test_unscoped_token_has_no_allowed_domains(self, auth):
        ok, created = auth.create_api_key('Open', role='admin')
        user = auth.authenticate_api_token(created['token'])
        assert user is not None
        assert user.get('allowed_domains') is None

    def test_legacy_token_has_no_allowed_domains(self, auth, settings_store):
        # Legacy api_bearer_token must keep working unconditionally.
        user = auth.authenticate_api_token('legacy_token_for_test')
        assert user is not None
        assert user['role'] == 'admin'
        assert user.get('allowed_domains') is None


class TestUserCanAccessDomain:
    def test_unrestricted_user_can_access_anything(self, auth):
        user = {'username': 'admin', 'role': 'admin'}  # no allowed_domains
        assert auth.user_can_access_domain(user, 'any.example.com') is True

    def test_scoped_user_blocked_outside_scope(self, auth):
        user = {'username': 'ci_key', 'role': 'operator',
                'allowed_domains': ['*.app.example.com']}
        assert auth.user_can_access_domain(user, 'other.com') is False
        assert auth.user_can_access_domain(user, 'app.example.com') is False  # apex

    def test_scoped_user_allowed_inside_scope(self, auth):
        user = {'username': 'ci_key', 'role': 'operator',
                'allowed_domains': ['*.app.example.com']}
        assert auth.user_can_access_domain(user, 'a.app.example.com') is True

    def test_none_user_denied(self, auth):
        assert auth.user_can_access_domain(None, 'x.com') is False
