"""
Unit tests for scoped API key management.
These run without Docker — they mock the settings manager.
"""

import pytest
from unittest.mock import MagicMock, patch
from modules.core.auth import AuthManager, ROLE_HIERARCHY


@pytest.fixture
def settings_store():
    """Shared mutable settings dict."""
    return {
        'local_auth_enabled': False,
        'users': {},
        'api_bearer_token': 'legacy_test_token_abc123',
        'api_keys': {},
    }


@pytest.fixture
def auth(settings_store):
    """AuthManager with mocked settings."""
    sm = MagicMock()
    sm.load_settings.side_effect = lambda: settings_store
    sm.save_settings.side_effect = lambda s, reason: True
    return AuthManager(sm)


class TestCreateApiKey:
    def test_creates_key_with_cm_prefix(self, auth):
        ok, result = auth.create_api_key('Test Key', role='viewer')
        assert ok is True
        assert result['token'].startswith('cm_')
        assert len(result['token']) == 43  # cm_ + 40 hex

    def test_returns_id_and_metadata(self, auth):
        ok, result = auth.create_api_key('My Key', role='operator', created_by='admin')
        assert ok is True
        assert 'id' in result
        assert result['name'] == 'My Key'
        assert result['role'] == 'operator'
        assert result['token_prefix'] == result['token'][:7]

    def test_stores_hashed_token(self, auth, settings_store):
        ok, result = auth.create_api_key('Hash Test', role='viewer')
        assert ok is True
        key_data = settings_store['api_keys'][result['id']]
        assert key_data['token_hash'].startswith('sha256:')
        assert result['token'] not in key_data['token_hash']

    def test_duplicate_name_fails(self, auth):
        auth.create_api_key('Dup', role='viewer')
        ok, err = auth.create_api_key('Dup', role='admin')
        assert ok is False
        assert 'already exists' in err

    def test_duplicate_name_ok_if_revoked(self, auth):
        ok1, result1 = auth.create_api_key('Reuse', role='viewer')
        auth.revoke_api_key(result1['id'])
        ok2, result2 = auth.create_api_key('Reuse', role='admin')
        assert ok2 is True

    def test_invalid_role_fails(self, auth):
        ok, err = auth.create_api_key('Bad Role', role='superadmin')
        assert ok is False

    def test_empty_name_fails(self, auth):
        ok, err = auth.create_api_key('', role='viewer')
        assert ok is False

    def test_long_name_fails(self, auth):
        ok, err = auth.create_api_key('x' * 65, role='viewer')
        assert ok is False

    def test_expiration_stored(self, auth, settings_store):
        ok, result = auth.create_api_key('Expiring', role='viewer', expires_at='2099-12-31T00:00:00')
        assert ok is True
        key_data = settings_store['api_keys'][result['id']]
        assert key_data['expires_at'] == '2099-12-31T00:00:00'


class TestListApiKeys:
    def test_list_excludes_token_hash(self, auth):
        auth.create_api_key('Listed', role='viewer')
        keys = auth.list_api_keys()
        for key_id, data in keys.items():
            assert 'token_hash' not in data

    def test_list_includes_is_expired(self, auth, settings_store):
        ok, result = auth.create_api_key('Past', role='viewer', expires_at='2020-01-01T00:00:00')
        keys = auth.list_api_keys()
        assert keys[result['id']]['is_expired'] is True

    def test_list_non_expired(self, auth, settings_store):
        ok, result = auth.create_api_key('Future', role='viewer', expires_at='2099-01-01T00:00:00')
        keys = auth.list_api_keys()
        assert keys[result['id']]['is_expired'] is False

    def test_empty_list(self, auth):
        keys = auth.list_api_keys()
        assert keys == {}


class TestRevokeApiKey:
    def test_revoke_sets_flag(self, auth, settings_store):
        ok, result = auth.create_api_key('Revokable', role='operator')
        rok, msg = auth.revoke_api_key(result['id'])
        assert rok is True
        assert settings_store['api_keys'][result['id']]['revoked'] is True
        assert 'revoked_at' in settings_store['api_keys'][result['id']]

    def test_revoke_nonexistent_fails(self, auth):
        ok, msg = auth.revoke_api_key('nonexistent-uuid')
        assert ok is False
        assert 'not found' in msg

    def test_revoke_already_revoked_fails(self, auth):
        ok, result = auth.create_api_key('Double Revoke', role='viewer')
        auth.revoke_api_key(result['id'])
        ok2, msg = auth.revoke_api_key(result['id'])
        assert ok2 is False
        assert 'already revoked' in msg


class TestAuthenticateApiToken:
    def test_legacy_token_returns_admin(self, auth):
        result = auth.authenticate_api_token('legacy_test_token_abc123')
        assert result is not None
        assert result['role'] == 'admin'
        assert result['username'] == 'api_user'

    def test_scoped_key_returns_correct_role(self, auth):
        ok, key = auth.create_api_key('Scoped', role='operator')
        result = auth.authenticate_api_token(key['token'])
        assert result is not None
        assert result['role'] == 'operator'
        assert 'api_key:Scoped' in result['username']

    def test_revoked_key_returns_none(self, auth):
        ok, key = auth.create_api_key('Revoked', role='admin')
        token = key['token']
        auth.revoke_api_key(key['id'])
        result = auth.authenticate_api_token(token)
        assert result is None

    def test_expired_key_returns_none(self, auth):
        ok, key = auth.create_api_key('Expired', role='viewer', expires_at='2020-01-01T00:00:00')
        result = auth.authenticate_api_token(key['token'])
        assert result is None

    def test_invalid_token_returns_none(self, auth):
        result = auth.authenticate_api_token('cm_invalid_token_that_does_not_exist')
        assert result is None

    def test_updates_last_used(self, auth, settings_store):
        ok, key = auth.create_api_key('Usage', role='viewer')
        assert settings_store['api_keys'][key['id']]['last_used_at'] is None
        auth.authenticate_api_token(key['token'])
        assert settings_store['api_keys'][key['id']]['last_used_at'] is not None


class TestValidateApiToken:
    def test_legacy_token_valid(self, auth):
        assert auth.validate_api_token('legacy_test_token_abc123') is True

    def test_scoped_token_valid(self, auth):
        ok, key = auth.create_api_key('Valid', role='viewer')
        assert auth.validate_api_token(key['token']) is True

    def test_invalid_token(self, auth):
        assert auth.validate_api_token('completely_wrong') is False
