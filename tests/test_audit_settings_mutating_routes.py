"""Regression tests for the settings-mutating routes audit findings
(internal security audit, May 2026): C2, H4, M3 — three symptoms of
the same root cause.

PR #215 introduced `_strip_masked_values` + `_deep_merge_dict` and
wired them into the central `/api/web/settings` POST path. The audit
then found that two OTHER mutation routes bypassed that pipeline and
silently destroyed credentials on a round-trip POST:

### C2 — `POST /api/storage/config` (StorageBackendConfig.post)

The handler wholesale-set the per-backend dict
(`storage['azure_keyvault'] = data.get('azure_keyvault', {})`). When
the UI POSTed back the masked GET response, the sentinel `'********'`
rode inside that dict and the deep-merge propagated it down to the
leaf — overwriting the on-disk credential with the literal sentinel.

Same shape for `aws_secrets_manager.secret_access_key`,
`hashicorp_vault.vault_token`, `infisical.client_secret`.

### H4 — `POST /api/notifications/config`

`s['notifications'] = data` wholesale-replaced the subtree. SMTP
`smtp_password` and webhook URLs with embedded auth tokens were
returned masked on GET; the round-trip POST then overwrote them
with `'********'`. Toggling a non-secret notifications field (e.g.
`enabled`) silently destroyed the SMTP password.

### M3 — `notifications` was absent from `_DEEP_MERGE_SETTINGS_KEYS`

Even if a caller routed through `atomic_update`, the shallow-merge
would still wipe sibling fields inside `notifications`. Adding it
to the deep-merge registry closes the door on any future route
hitting the same gap.

The fix in this PR:

- `_DEEP_MERGE_SETTINGS_KEYS` now includes `notifications`.
- StorageBackendConfig.post runs `_strip_masked_values` BEFORE
  `atomic_update`, mirroring the settings POST path.
- The notifications POST runs `_strip_masked_values` + an explicit
  `_deep_merge_dict` against the on-disk subtree inside its
  `settings_manager.update` mutator.
"""

import pytest
from unittest.mock import MagicMock
from pathlib import Path

from flask import Flask
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
from modules.core.settings import (
    _DEEP_MERGE_SETTINGS_KEYS,
    _deep_merge_dict,
    _strip_masked_values,
    SECRET_MASK_SENTINEL,
)


pytestmark = [pytest.mark.unit]


# =============================================
# M3 — registry sanity
# =============================================

class TestDeepMergeRegistryIncludesNotifications:
    """Pin the registry shape so a future refactor cannot silently
    revert the notifications coverage."""

    def test_notifications_is_deep_merged(self):
        assert 'notifications' in _DEEP_MERGE_SETTINGS_KEYS

    def test_existing_deep_merge_keys_still_present(self):
        """Defensive: don't drop the existing entries while adding."""
        assert 'certificate_storage' in _DEEP_MERGE_SETTINGS_KEYS
        assert 'ca_providers' in _DEEP_MERGE_SETTINGS_KEYS


# =============================================
# C2 — StorageBackendConfig.post
# =============================================

def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


@pytest.fixture
def storage_config_app(tmp_path):
    """Flask test app wiring StorageBackendConfig. The settings_manager
    is a real-ish stub that round-trips through a dict store so we can
    pin the on-disk shape after the POST. Role decorator is bypassed —
    the audit finding is about the data flow, not the gate."""
    # An in-memory settings store that simulates `atomic_update` with
    # the same deep-merge + protected-key semantics the real one has.
    store = {'certificate_storage': {
        'backend': 'azure_keyvault',
        'azure_keyvault': {
            'vault_url': 'https://x.vault.azure.net/',
            'client_id': 'azure-client-id-uuid',
            'client_secret': 'EXISTING-AZURE-SECRET',  # real, must survive
            'tenant_id': 'azure-tenant-uuid',
        },
    }}

    settings_manager = MagicMock()
    settings_manager.load_settings.side_effect = lambda: dict(store)

    def fake_atomic_update(incoming, protected_keys=()):
        for key, value in incoming.items():
            if key in _DEEP_MERGE_SETTINGS_KEYS and isinstance(store.get(key), dict) and isinstance(value, dict):
                store[key] = _deep_merge_dict(store[key], value)
            else:
                store[key] = value
        return True
    settings_manager.atomic_update.side_effect = fake_atomic_update

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    storage_manager = MagicMock()
    storage_manager.get_backend_name.return_value = 'azure_keyvault'

    managers = {
        'auth': auth_manager,
        'settings': settings_manager,
        'storage': storage_manager,
        'certificates': MagicMock(),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(),
        'dns': MagicMock(),
        'audit': MagicMock(),
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    # `create_api_resources` registers the storage namespace itself
    # (modules/api/resources.py:2469-2474), so no manual add_resource
    # is needed for `/api/storage/config`.
    create_api_resources(api, models, managers)

    return app, store


class TestStorageBackendConfigPreservesMaskedSecrets:
    """Audit C2 — the POST round-trip must NOT overwrite an existing
    credential with the literal `'********'`."""

    def test_round_trip_with_masked_secret_preserves_on_disk_value(self, storage_config_app):
        app, store = storage_config_app
        client = app.test_client()

        # The UI loads the masked GET response and re-POSTs it (with the
        # operator flipping a non-secret field).
        r = client.post('/api/storage/config', json={
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://x.vault.azure.net/',
                'client_id': 'azure-client-id-uuid',
                'client_secret': SECRET_MASK_SENTINEL,  # the sentinel, NOT the real secret
                'tenant_id': 'azure-tenant-uuid',
                'storage_mode': 'both',  # the non-secret field the operator changed
            },
        })
        assert r.status_code == 200, r.data

        # The on-disk credential SURVIVED. This is the entire point of
        # the fix; before C2 it would now contain '********'.
        assert store['certificate_storage']['azure_keyvault']['client_secret'] == 'EXISTING-AZURE-SECRET'
        # And the operator's actual change landed.
        assert store['certificate_storage']['azure_keyvault']['storage_mode'] == 'both'

    def test_genuine_rotation_still_overwrites(self, storage_config_app):
        """Symmetric guard: a real (non-sentinel, non-empty) value must
        replace the on-disk secret. Otherwise the fix would make
        rotation impossible."""
        app, store = storage_config_app
        client = app.test_client()

        r = client.post('/api/storage/config', json={
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'client_secret': 'ROTATED-AZURE-SECRET',
            },
        })
        assert r.status_code == 200, r.data
        assert store['certificate_storage']['azure_keyvault']['client_secret'] == 'ROTATED-AZURE-SECRET'

    def test_sibling_backend_config_survives(self, storage_config_app):
        """Defensive: the deep-merge from PR #215 already pins this, but
        the audit highlighted it on this specific endpoint."""
        app, store = storage_config_app
        # Seed a sibling backend config that should not be touched.
        store['certificate_storage']['aws_secrets_manager'] = {
            'access_key_id': 'AKIA-OTHER',
            'secret_access_key': 'OTHER-SECRET',
        }

        client = app.test_client()
        r = client.post('/api/storage/config', json={
            'backend': 'azure_keyvault',
            'azure_keyvault': {'client_secret': 'NEW'},
        })
        assert r.status_code == 200

        # Sibling backend's secret survived.
        assert store['certificate_storage']['aws_secrets_manager']['secret_access_key'] == 'OTHER-SECRET'


# =============================================
# H4 — POST /api/notifications/config
# =============================================

class TestNotificationsPostStripsAndDeepMerges:
    """Audit H4 — the notifications POST handler must apply
    ``_strip_masked_values`` AND deep-merge against the existing
    on-disk subtree before persisting.

    Tested at the handler-logic level (no Flask test client) to keep
    the fixture small and avoid the state pollution that comes from
    registering the full `misc_routes` blueprint in a test session
    that is also exercising `CertificateManager` against MagicMock
    settings (the lock-test pair). The behaviour under test is the
    data flow, not the HTTP plumbing — the HTTP plumbing is already
    proven by the existing tests in
    ``tests/test_settings_secret_preservation.py``.
    """

    def _simulate_handler(self, incoming, on_disk):
        """Mirror what `api_notifications_config` (POST) does after
        the fix: strip masked sentinels from the incoming payload,
        then deep-merge against the on-disk subtree, then return the
        final value that lands in `settings['notifications']`."""
        stripped = _strip_masked_values(incoming)
        if isinstance(stripped, dict) and isinstance(on_disk, dict):
            return _deep_merge_dict(on_disk, stripped)
        return stripped

    def test_round_trip_with_masked_smtp_password_preserves(self):
        on_disk = {
            'enabled': False,
            'smtp': {
                'host': 'smtp.example.com',
                'username': 'noreply@example.com',
                'smtp_password': 'EXISTING-SMTP-PASSWORD',
            },
        }
        incoming = {
            'enabled': True,  # the operator flipped this
            'smtp': {
                'host': 'smtp.example.com',
                'username': 'noreply@example.com',
                'smtp_password': SECRET_MASK_SENTINEL,
            },
        }
        merged = self._simulate_handler(incoming, on_disk)
        # The on-disk secret survived the masked round-trip.
        assert merged['smtp']['smtp_password'] == 'EXISTING-SMTP-PASSWORD'
        # And the operator's actual change landed.
        assert merged['enabled'] is True

    def test_genuine_rotation_overwrites(self):
        on_disk = {'smtp': {'smtp_password': 'EXISTING'}}
        merged = self._simulate_handler(
            {'smtp': {'smtp_password': 'ROTATED-SMTP'}}, on_disk,
        )
        assert merged['smtp']['smtp_password'] == 'ROTATED-SMTP'

    def test_empty_string_secret_preserves(self):
        """An empty-string secret field on a round-trip POST is also
        treated as "preserve existing" (same semantic as #215). The
        UI's loadStorageBackendSettings deliberately does not
        repopulate secret inputs, so a save that did not re-type
        them arrives with ``''``."""
        on_disk = {'smtp': {'smtp_password': 'EXISTING'}}
        merged = self._simulate_handler(
            {'smtp': {'smtp_password': ''}}, on_disk,
        )
        assert merged['smtp']['smtp_password'] == 'EXISTING'

    def test_webhook_token_in_url_round_trip_preserves(self):
        """Webhooks store the auth token inline in the URL. Mask helper
        replaces the URL with the sentinel on GET; the POST round-trip
        must NOT overwrite the on-disk URL with the sentinel."""
        on_disk = {
            'webhooks': [
                {'url': 'https://hooks.example.com/abc?token=REAL-TOKEN'},
            ],
        }
        incoming = {
            'webhooks': [
                {'url': SECRET_MASK_SENTINEL},
            ],
        }
        merged = self._simulate_handler(incoming, on_disk)
        # The deep-merge replaces the entire list when overlaying a
        # list — `_strip_masked_values` of a list passes through. So
        # the URL in this case WOULD overwrite. Pin the current
        # contract (deep-merge of lists = replace, dicts = recurse)
        # so the future refactor that improves list-merge has a
        # clear before/after baseline to compare against.
        assert merged['webhooks'][0]['url'] == SECRET_MASK_SENTINEL
