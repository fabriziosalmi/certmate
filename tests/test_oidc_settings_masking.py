"""Masking + reject-list coverage for the new ``oidc`` settings block.

The bulk GET /api/web/settings must mask ``oidc.client_secret`` via the
existing `_mask_dict` recursion (no per-OIDC code path needed) and the
bulk POST must refuse to mutate the ``oidc`` key — the dedicated
/api/auth/oidc/settings endpoint is the only legitimate write path.
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


def test_oidc_client_secret_is_masked_in_bulk_get():
    """The recursive ``_mask_dict`` pass in settings_routes.py already
    matches the regex (``secret``), so the OIDC client_secret comes
    back as the sentinel without any oidc-specific code path."""
    app = _build_app({
        'oidc': {
            'enabled': True,
            'provider_name': 'KeycloakProd',
            'issuer_url': 'https://idp.example.com',
            'client_id': 'cm-test',
            'client_secret': 'real-secret-value',
            'scopes': ['openid', 'email'],
        },
    })
    client = app.test_client()
    r = client.get('/api/web/settings')
    assert r.status_code == 200
    body = r.get_json()
    assert body['oidc']['client_secret'] == '********'
    # Non-secret fields keep their real values.
    assert body['oidc']['enabled'] is True
    assert body['oidc']['provider_name'] == 'KeycloakProd'
    assert body['oidc']['client_id'] == 'cm-test'
    assert body['oidc']['scopes'] == ['openid', 'email']


def test_oidc_empty_client_secret_is_not_masked():
    """An empty string isn't a credential — masking must not lie and
    claim a secret exists where there isn't one (would surface as a
    real ``********`` sentinel being POSTed back and persisted)."""
    app = _build_app({
        'oidc': {
            'enabled': False,
            'client_secret': '',
        },
    })
    client = app.test_client()
    body = client.get('/api/web/settings').get_json()
    assert body['oidc']['client_secret'] == ''


def test_oidc_key_is_in_reject_list():
    """Defense-in-depth: confirm ``oidc`` is in SETTINGS_REJECT_KEYS so
    the bulk POST validator surfaces it as 'rejected', not silently
    accepted or unknown."""
    from modules.core.settings import SETTINGS_REJECT_KEYS
    assert 'oidc' in SETTINGS_REJECT_KEYS


def test_oidc_block_rejected_by_validate_settings_post():
    """Direct call to the validator — the same gate both the web
    blueprint and the RESTX API endpoint run before persisting."""
    from modules.core.settings import validate_settings_post

    filtered, rejected, unknown = validate_settings_post(
        {'oidc': {'enabled': True, 'client_secret': 'sneaked-in'}},
        current={'oidc': {'enabled': False, 'client_secret': ''}},
    )
    assert 'oidc' not in filtered
    assert 'oidc' in rejected
    assert 'oidc' not in unknown
