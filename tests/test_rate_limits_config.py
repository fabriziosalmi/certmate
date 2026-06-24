"""Configurable API rate limits (#319).

Two layers:
1. RateLimitConfig reads per-endpoint overrides and the on/off toggle LIVE from
   settings['rate_limits'], sanitising bad values so a malformed entry can never
   disable a limit or crash a lookup.
2. The admin route PUT /api/settings/rate-limits validates and persists them.
"""
import json
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.rate_limit import RateLimitConfig

pytestmark = [pytest.mark.unit]


def _config(settings_dict):
    sm = MagicMock()
    sm.load_settings.return_value = settings_dict
    return RateLimitConfig(settings_manager=sm)


# --- RateLimitConfig: live settings overrides -----------------------------

def test_defaults_when_no_settings_manager():
    cfg = RateLimitConfig()
    assert cfg.get_limit('default') == 100
    assert cfg.get_limit('certificate_create') == 30
    assert cfg.is_enabled() is True


def test_override_changes_effective_limit():
    cfg = _config({'rate_limits': {'limits': {'certificate_create': 500}}})
    assert cfg.get_limit('certificate_create') == 500
    # untouched keys keep their default
    assert cfg.get_limit('default') == 100


def test_enabled_toggle():
    assert _config({'rate_limits': {'enabled': False}}).is_enabled() is False
    assert _config({'rate_limits': {'enabled': True}}).is_enabled() is True
    assert _config({}).is_enabled() is True  # default on


@pytest.mark.parametrize('bad', [0, -5, 'abc', None, 1.5])
def test_malformed_override_ignored_falls_back_to_default(bad):
    cfg = _config({'rate_limits': {'limits': {'default': bad}}})
    # A non-positive / non-int value must never override the default away.
    assert cfg.get_limit('default') == 100


def test_unknown_override_key_ignored():
    cfg = _config({'rate_limits': {'limits': {'not_a_real_endpoint': 9}}})
    assert cfg.get_limit('default') == 100


def test_live_reread_picks_up_change():
    sm = MagicMock()
    sm.load_settings.return_value = {'rate_limits': {'limits': {'default': 100}}}
    cfg = RateLimitConfig(settings_manager=sm)
    assert cfg.get_limit('default') == 100
    sm.load_settings.return_value = {'rate_limits': {'limits': {'default': 999}}}
    assert cfg.get_limit('default') == 999  # no restart, no re-instantiation


def test_settings_read_failure_is_swallowed():
    sm = MagicMock()
    sm.load_settings.side_effect = RuntimeError('disk gone')
    cfg = RateLimitConfig(settings_manager=sm)
    assert cfg.get_limit('default') == 100
    assert cfg.is_enabled() is True


# --- PUT/GET /api/settings/rate-limits route ------------------------------

def _passthrough_role(_min_role):
    def deco(fn):
        return fn
    return deco


@pytest.fixture
def route_client(tmp_path):
    settings_path = tmp_path / "settings.json"

    def _read():
        return json.loads(settings_path.read_text()) if settings_path.exists() else {}

    def _update(mutator, reason="auto_save"):
        doc = _read()
        mutator(doc)
        settings_path.write_text(json.dumps(doc, indent=2))
        return True

    settings_manager = MagicMock()
    settings_manager.load_settings.side_effect = _read
    settings_manager.update.side_effect = _update

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_role)

    managers = {"auth": auth_manager, "settings": settings_manager, "audit": MagicMock()}

    app = Flask(__name__)
    app.config["TESTING"] = True
    from modules.web.misc_routes import register_misc_routes
    register_misc_routes(app, managers, lambda fn: fn, auth_manager)
    return app.test_client(), settings_path


def test_get_returns_defaults_and_enabled(route_client):
    client, _ = route_client
    r = client.get('/api/settings/rate-limits')
    assert r.status_code == 200
    body = r.get_json()
    assert body['enabled'] is True
    assert body['limits']['default'] == 100
    assert body['defaults']['certificate_create'] == 30


def test_put_persists_and_get_reflects(route_client):
    client, settings_path = route_client
    r = client.put('/api/settings/rate-limits',
                   json={'enabled': True, 'limits': {'certificate_create': 500}})
    assert r.status_code == 200
    # persisted on disk
    disk = json.loads(settings_path.read_text())['rate_limits']
    assert disk['limits']['certificate_create'] == 500
    # GET reflects the override merged over defaults
    body = client.get('/api/settings/rate-limits').get_json()
    assert body['limits']['certificate_create'] == 500
    assert body['limits']['default'] == 100


def test_put_disable(route_client):
    client, settings_path = route_client
    r = client.put('/api/settings/rate-limits', json={'enabled': False, 'limits': {}})
    assert r.status_code == 200
    assert json.loads(settings_path.read_text())['rate_limits']['enabled'] is False


def test_put_rejects_unknown_key(route_client):
    client, _ = route_client
    r = client.put('/api/settings/rate-limits', json={'limits': {'bogus': 5}})
    assert r.status_code == 400


@pytest.mark.parametrize('bad', [0, -1, 100001, 'x', None])
def test_put_rejects_bad_value(route_client, bad):
    client, _ = route_client
    r = client.put('/api/settings/rate-limits', json={'limits': {'default': bad}})
    assert r.status_code == 400
