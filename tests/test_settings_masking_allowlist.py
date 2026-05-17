"""Regression test for the settings UI bug where ``default_key_type``
came back as ``'********'`` from ``GET /api/web/settings`` because the
masking regex on the route matched the ``key`` substring in the field
name. The masked placeholder did not match any ``<option>`` in the
``<select>``, so the dropdown rendered empty on every page reload.

The fix is an explicit allowlist of non-secret fields whose names
happen to contain "key". This test pins the contract: those three
fields come through unmasked, while genuine secrets keep being
masked.
"""

from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.web.settings_routes import register_settings_routes


pytestmark = [pytest.mark.unit]


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


def _build_app(settings_payload):
    app = Flask(__name__)
    app.secret_key = 'test'

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = settings_payload

    register_settings_routes(
        app,
        managers={},
        require_web_auth=lambda f: f,
        auth_manager=auth_manager,
        settings_manager=settings_manager,
        dns_manager=MagicMock(),
    )
    return app


def test_default_key_shape_fields_are_not_masked():
    """The three certificate-key-shape defaults must come through
    literally — they are public configuration, not credentials.
    Without the allowlist the dropdown on the Settings page renders
    empty on reload because '********' has no matching <option>."""
    app = _build_app({
        'default_key_type': 'ecdsa',
        'default_key_size': 2048,
        'default_elliptic_curve': 'secp384r1',
    })
    client = app.test_client()

    r = client.get('/api/web/settings')
    assert r.status_code == 200
    body = r.get_json()
    assert body['default_key_type'] == 'ecdsa'
    assert body['default_key_size'] == 2048
    assert body['default_elliptic_curve'] == 'secp384r1'


def test_genuine_secrets_are_still_masked():
    """The allowlist must not weaken masking of real credentials —
    every field whose name matches the regex and holds a non-empty
    string value still becomes '********'."""
    app = _build_app({
        'api_bearer_token': 'real-bearer-token-value',
        'cloudflare_token': 'real-cf-token',
        'secret_key_material': 'real-secret',
        'admin_password': 'real-password',
        'aws_credential': 'real-credential',
        'private_key': 'real-private-key',
    })
    client = app.test_client()

    r = client.get('/api/web/settings')
    assert r.status_code == 200
    body = r.get_json()
    for field in (
        'api_bearer_token',
        'cloudflare_token',
        'secret_key_material',
        'admin_password',
        'aws_credential',
        'private_key',
    ):
        assert body[field] == '********', f'{field} leaked through masking'


def test_nested_secrets_are_still_masked():
    """The masking recurses into nested dicts — the dns_providers
    block is the most common case where credentials live."""
    app = _build_app({
        'default_key_type': 'rsa',
        'dns_providers': {
            'cloudflare': {
                'accounts': {
                    'production': {'api_token': 'cf-prod-token'},
                },
            },
        },
    })
    client = app.test_client()

    r = client.get('/api/web/settings')
    body = r.get_json()
    assert body['default_key_type'] == 'rsa'  # allowlist still applies
    assert (
        body['dns_providers']['cloudflare']['accounts']['production']['api_token']
        == '********'
    )


def test_empty_string_values_pass_through_unmasked():
    """The existing behaviour: empty-string secrets are not masked
    (the `and d[k]` guard). The allowlist must not change this."""
    app = _build_app({
        'api_bearer_token': '',
        'default_key_type': '',
    })
    client = app.test_client()

    r = client.get('/api/web/settings')
    body = r.get_json()
    assert body['api_bearer_token'] == ''
    assert body['default_key_type'] == ''
