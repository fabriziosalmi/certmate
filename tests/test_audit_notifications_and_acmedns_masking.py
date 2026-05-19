"""Regression tests for the audit findings H5 and M2 (May 2026).

### H5 — `GET /api/notifications/config` returned plaintext SMTP password

Before this fix, `modules/web/misc_routes.py::api_notifications_config`
returned `notifier._get_config()` verbatim. Operator-token holders read
the raw `notifications` subtree including `smtp_password` and any
webhook URL with embedded auth tokens — bypassing the masking applied
to the same subtree by `/api/web/settings`.

The fix routes the GET response through the central
`mask_secrets_in_settings()` helper so the contract matches the
settings GET surface.

### M2 — `acme-dns.username` and `acme-dns.subdomain` not masked

The masking regex (`token|secret|password|key|credential`) does not
match the ACME-DNS shared-secret fields. Both the legacy local
`_mask_dict` in `settings_routes.py` AND the `MaskedString` typing in
`modules/api/models.py` left `acme-dns.username` and
`acme-dns.subdomain` returned as plaintext. Together those two
fields ARE the ACME-DNS authentication material (the UUID + the
corresponding delegation FQDN authorise TXT record updates).

The fix introduces `_PROVIDER_SPECIFIC_SECRET_FIELDS` in
`modules/core/settings.py`: a provider-name → field-name-set map
applied by the central walker when the immediate parent key
matches. Today it covers `acme-dns`; future providers with
similarly named shared-secret fields can extend the registry
without touching the walker.

A generic `username` (e.g. SMTP login email) is NOT inadvertently
masked because the rule fires only under the matching provider key.
"""

import pytest
from modules.core.settings import (
    mask_secrets_in_settings,
    SECRET_MASK_SENTINEL,
)


pytestmark = [pytest.mark.unit]


class TestAcmeDnsProviderMasking:
    """Audit M2 — `acme-dns.username` and `acme-dns.subdomain` must be
    masked. SMTP `username` (under a different parent) must NOT be."""

    def test_acme_dns_username_and_subdomain_masked(self):
        settings = {
            'dns_providers': {
                'acme-dns': {
                    'api_url': 'https://acme-dns.example.com',
                    'username': 'b7a37dd1-9512-4d18-9e6f-8db1d2e6cafe',
                    'password': 'SHARED-SECRET',
                    'subdomain': '92b9b1d5-c0ef-4e07-9ab7-acme-dns.example.com',
                },
            },
        }
        masked = mask_secrets_in_settings(settings)
        acme = masked['dns_providers']['acme-dns']

        assert acme['username'] == SECRET_MASK_SENTINEL
        assert acme['subdomain'] == SECRET_MASK_SENTINEL
        assert acme['password'] == SECRET_MASK_SENTINEL  # regex matched
        # api_url is operator-visible (not a credential), must survive.
        assert acme['api_url'] == 'https://acme-dns.example.com'

    def test_smtp_username_is_not_masked(self):
        """Defensive: the audit fix must apply to acme-dns SPECIFICALLY,
        not blanket-mask every ``username`` field. SMTP login is an
        email address — masking it would render the settings UI
        useless on round-trip."""
        settings = {
            'notifications': {
                'smtp': {
                    'host': 'smtp.example.com',
                    'username': 'noreply@example.com',  # email, NOT a secret
                    'smtp_password': 'SECRET-SMTP',
                },
            },
        }
        masked = mask_secrets_in_settings(settings)
        smtp = masked['notifications']['smtp']

        assert smtp['username'] == 'noreply@example.com'  # NOT masked
        assert smtp['smtp_password'] == SECRET_MASK_SENTINEL  # masked


class TestMaskHelperPreservesPriorContract:
    """The new central helper must keep the same masking behaviour the
    audit-prior `_mask_dict` had — only adding to it (the acme-dns
    fields above), never silently changing semantics."""

    def test_dns_provider_token_still_masked(self):
        settings = {
            'dns_providers': {
                'cloudflare': {'api_token': 'CF-PLAINTEXT'},
                'route53': {
                    'access_key_id': 'AKIA-xyz',
                    'secret_access_key': 'AWS-SECRET',
                },
            },
        }
        masked = mask_secrets_in_settings(settings)
        assert masked['dns_providers']['cloudflare']['api_token'] == SECRET_MASK_SENTINEL
        assert masked['dns_providers']['route53']['secret_access_key'] == SECRET_MASK_SENTINEL
        # `access_key_id` matches the regex (contains `key`).
        assert masked['dns_providers']['route53']['access_key_id'] == SECRET_MASK_SENTINEL

    def test_default_key_options_pass_through(self):
        """The documented non-secret allowlist (default_key_type,
        default_key_size, default_elliptic_curve) must not be touched
        even though their names match the regex."""
        settings = {
            'default_key_type': 'rsa',
            'default_key_size': 4096,
            'default_elliptic_curve': 'secp256r1',
        }
        masked = mask_secrets_in_settings(settings)
        assert masked['default_key_type'] == 'rsa'
        assert masked['default_key_size'] == 4096
        assert masked['default_elliptic_curve'] == 'secp256r1'

    def test_empty_string_values_pass_through(self):
        """Empty-secret semantics belong to the POST path
        (_strip_masked_values). The MASK helper only replaces
        non-empty strings with the sentinel."""
        settings = {'oidc': {'client_secret': ''}}
        masked = mask_secrets_in_settings(settings)
        assert masked['oidc']['client_secret'] == ''

    def test_lists_are_walked(self):
        """Audit M2 fix must not have broken list traversal (a future
        plugin storing accounts as a list under a provider key would
        otherwise leak)."""
        settings = {
            'dns_providers': {
                'acme-dns': {
                    'accounts': [
                        {'username': 'uuid-1', 'subdomain': 'sub-1.x.com', 'password': 'p1'},
                        {'username': 'uuid-2', 'subdomain': 'sub-2.x.com', 'password': 'p2'},
                    ],
                },
            },
        }
        masked = mask_secrets_in_settings(settings)
        accounts = masked['dns_providers']['acme-dns']['accounts']
        # `accounts` carries the acme-dns parent context, so the
        # provider-specific masks still apply inside list entries.
        for acct in accounts:
            assert acct['username'] == SECRET_MASK_SENTINEL
            assert acct['subdomain'] == SECRET_MASK_SENTINEL
            assert acct['password'] == SECRET_MASK_SENTINEL


class TestNotificationsGetMaskedSmtpPassword:
    """Audit H5 — the integration shape: a real Flask test client
    against the `/api/notifications/config` GET route must return the
    masked sentinel for `smtp_password`, never the on-disk value."""

    @pytest.fixture
    def app_with_notifications(self):
        from unittest.mock import MagicMock
        from flask import Flask

        settings_manager = MagicMock()
        settings_manager.load_settings.return_value = {
            'notifications': {
                'enabled': True,
                'smtp': {
                    'host': 'smtp.example.com',
                    'username': 'noreply@example.com',
                    'smtp_password': 'REAL-PLAINTEXT-PASSWORD',
                },
                'webhooks': [
                    {'url': 'https://hooks.example.com/abc?token=REAL_BEARER'},
                ],
            },
        }

        from modules.core.notifier import Notifier
        notifier = Notifier.__new__(Notifier)
        notifier.settings_manager = settings_manager

        auth_manager = MagicMock()
        # All endpoints in misc_routes use require_role; bypass so the
        # mask contract is tested independently of auth.
        def passthrough_role(_min_role):
            def deco(fn):
                return fn
            return deco
        auth_manager.require_role = MagicMock(side_effect=passthrough_role)

        managers = {
            'auth': auth_manager,
            'settings': settings_manager,
            'notifier': notifier,
            'digest': MagicMock(),
            'audit': MagicMock(),
            'cache': MagicMock(),
            'metrics': MagicMock(),
            'dns': MagicMock(),
            'deployer': MagicMock(),
        }

        app = Flask(__name__)
        app.config['TESTING'] = True

        from modules.web.misc_routes import register_misc_routes
        register_misc_routes(app, managers, lambda fn: fn, auth_manager)
        return app

    def test_get_notifications_config_masks_smtp_password(self, app_with_notifications):
        client = app_with_notifications.test_client()
        r = client.get('/api/notifications/config')
        assert r.status_code == 200, r.data
        body = r.get_json()
        assert body['smtp']['smtp_password'] == SECRET_MASK_SENTINEL
        # And the non-secret operator-facing fields survived.
        assert body['smtp']['host'] == 'smtp.example.com'
        assert body['smtp']['username'] == 'noreply@example.com'

    def test_get_notifications_config_does_not_leak_password(self, app_with_notifications):
        client = app_with_notifications.test_client()
        r = client.get('/api/notifications/config')
        # Defence-in-depth: the response body must not contain the
        # plaintext anywhere, even in a field we did not anticipate.
        assert b'REAL-PLAINTEXT-PASSWORD' not in r.data
