"""End-to-end route test for the masked webhook-secret fix.

This proves the fix works THROUGH the real Flask POST route
``/api/notifications/config`` (modules/web/misc_routes.py::api_notifications_config),
not just the ``_restore_masked_list_secrets`` helper in isolation.

It drives the REAL route + REAL ``Notifier`` + REAL settings pipeline
(``_strip_masked_values`` -> ``_deep_merge_dict`` -> ``_restore_masked_list_secrets``)
via the Flask test client, and verifies the result by reading the
ON-DISK settings JSON after each POST.

Auth pattern mirrors tests/test_audit_notifications_and_acmedns_masking.py:
``require_role`` is bypassed with a passthrough decorator so the test pins
the data flow (the masking/restore contract), not the RBAC gate — which is
already covered by the e2e admin-session tests in
tests/test_notifications_routes.py.

Backing store: a real settings.json on a tmp path. The ``settings_manager``
stub's ``load_settings``/``update`` read+write that file using the same
read -> mutate -> persist contract as the real
``modules.core.settings.SettingsManager.update`` (settings.py:515), so an
assertion that reads the file back is genuinely reading on-disk state.
"""

import json
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.notifier import Notifier
from modules.core.settings import SECRET_MASK_SENTINEL

pytestmark = [pytest.mark.unit]

MASK = SECRET_MASK_SENTINEL  # '********'

CHAT_URL = 'https://chat.googleapis.com/v1/spaces/SPACE/messages?key=example&token=secret'


def _passthrough_role(_min_role):
    def deco(fn):
        return fn
    return deco


@pytest.fixture
def route_client(tmp_path):
    """Real route + real Notifier over an on-disk settings.json.

    Returns ``(client, settings_path, seed)`` where ``client`` is a Flask
    test client bound to the real ``/api/notifications/config`` route,
    ``settings_path`` is the file on disk, and ``seed(dict)`` writes the
    full settings document to disk.
    """
    settings_path = tmp_path / "settings.json"

    def _read_disk():
        if not settings_path.exists():
            return {}
        return json.loads(settings_path.read_text())

    def _write_disk(doc):
        settings_path.write_text(json.dumps(doc, indent=2))

    def seed(doc):
        _write_disk(doc)

    settings_manager = MagicMock()
    # Real Notifier._get_config() calls load_settings()['notifications'].
    settings_manager.load_settings.side_effect = _read_disk

    def _update(mutator, reason="auto_save"):
        # Mirror SettingsManager.update: read -> mutate in place -> persist.
        doc = _read_disk()
        mutator(doc)
        _write_disk(doc)
        return True

    settings_manager.update.side_effect = _update

    # Real Notifier wired to the on-disk-backed settings manager.
    notifier = Notifier(settings_manager, data_dir=str(tmp_path))

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_role)
    auth_manager.require_session_role = MagicMock(
        side_effect=_passthrough_role)

    managers = {
        "auth": auth_manager,
        "settings": settings_manager,
        "notifier": notifier,
        "digest": MagicMock(),
        "audit": MagicMock(),
        "cache": MagicMock(),
        "metrics": MagicMock(),
        "dns": MagicMock(),
        "deployer": MagicMock(),
    }

    app = Flask(__name__)
    app.config["TESTING"] = True

    from modules.web.misc_routes import register_misc_routes
    register_misc_routes(app, managers, lambda fn: fn, auth_manager)

    return app.test_client(), settings_path, seed


def _disk_webhooks(settings_path):
    doc = json.loads(settings_path.read_text())
    return doc["notifications"]["channels"]["webhooks"]


@pytest.mark.parametrize('url', [
    'http://chat.googleapis.com/v1/spaces/SPACE/messages',
    'https://chat.googleapis.com.evil.example/hook',
    'https://evil.example/hook',
])
def test_google_chat_refuses_wrong_destination_on_save(route_client, url):
    client, settings_path, seed = route_client
    seed({'notifications': {'channels': {'webhooks': []}}})
    r = client.post('/api/notifications/config', json={'channels': {'webhooks': [
        {'type': 'google_chat', 'name': 'ops', 'url': url, 'enabled': True},
    ]}})
    assert r.status_code == 400
    assert 'Google Chat' in r.get_json()['error']
    assert _disk_webhooks(settings_path) == []


def test_google_chat_masked_save_validates_saved_url_without_losing_it(route_client):
    client, settings_path, seed = route_client
    seed({'notifications': {'channels': {'webhooks': [
        {'type': 'google_chat', 'name': 'ops', 'url': CHAT_URL, 'enabled': True},
    ]}}})
    masked = client.get('/api/notifications/config').get_json()['channels']['webhooks'][0]
    assert masked['url'] == MASK
    masked['enabled'] = False
    r = client.post('/api/notifications/config', json={'channels': {'webhooks': [masked]}})
    assert r.status_code == 200, r.get_json()
    assert _disk_webhooks(settings_path)[0]['url'] == CHAT_URL
    assert _disk_webhooks(settings_path)[0]['enabled'] is False


def test_google_chat_unmatched_mask_is_not_accepted_on_save(route_client):
    client, settings_path, seed = route_client
    seed({'notifications': {'channels': {'webhooks': [
        {'type': 'google_chat', 'name': 'ops', 'url': CHAT_URL},
    ]}}})
    r = client.post('/api/notifications/config', json={'channels': {'webhooks': [
        {'type': 'google_chat', 'name': 'renamed', 'url': MASK},
    ]}})
    assert r.status_code == 400
    assert _disk_webhooks(settings_path)[0]['name'] == 'ops'


def test_google_chat_refuses_invalid_button_url_on_save(route_client):
    client, settings_path, seed = route_client
    seed({'notifications': {'channels': {'webhooks': []}}})
    r = client.post('/api/notifications/config', json={'channels': {'webhooks': [
        {'type': 'google_chat', 'name': 'ops', 'url': CHAT_URL,
         'certmate_url': 'javascript:alert(1)'},
    ]}})
    assert r.status_code == 400
    assert 'CertMate URL' in r.get_json()['error']
    assert _disk_webhooks(settings_path) == []


def _seed_one_webhook(seed, token="REAL-TOKEN", **extra):
    wh = {
        "name": "ops",
        "type": "generic",
        "url": "https://hooks.example.com/ops",
        "token": token,
        "priority": "low",
        "enabled": True,
    }
    wh.update(extra)
    seed({
        "notifications": {
            "enabled": True,
            "events": ["certificate_renewed"],
            "channels": {"webhooks": [wh]},
        }
    })


# ---------------------------------------------------------------------------
# (1)+(2) GET returns the token masked as '********'
# ---------------------------------------------------------------------------
def test_get_masks_real_webhook_token(route_client):
    client, settings_path, seed = route_client
    _seed_one_webhook(seed, token="REAL-TOKEN")

    r = client.get("/api/notifications/config")
    assert r.status_code == 200, r.data
    body = r.get_json()
    wh = body["channels"]["webhooks"][0]

    # (2) the token comes back MASKED, never the real value.
    assert wh["token"] == MASK
    assert b"REAL-TOKEN" not in r.data
    # Non-secret fields survive the GET so the UI can re-render them.
    # The webhook url is a credential (incoming-webhook URL) and is masked (#16).
    assert wh["url"] == MASK
    assert wh["priority"] == "low"


# ---------------------------------------------------------------------------
# (3)+(4) POST the masked config back verbatim + a non-secret edit:
#         the on-disk token is STILL the real value, not the sentinel.
# ---------------------------------------------------------------------------
def test_masked_round_trip_preserves_on_disk_token(route_client):
    client, settings_path, seed = route_client
    _seed_one_webhook(seed, token="REAL-TOKEN")

    # The UI loads the masked GET response...
    got = client.get("/api/notifications/config").get_json()
    masked_wh = got["channels"]["webhooks"][0]
    assert masked_wh["token"] == MASK  # precondition: UI holds the sentinel

    # ...flips a non-secret field (priority) and re-POSTs verbatim.
    masked_wh["priority"] = "high"
    masked_wh["enabled"] = False
    r = client.post("/api/notifications/config", json={
        "enabled": True,
        "events": ["certificate_renewed"],
        "channels": {"webhooks": [masked_wh]},
    })
    assert r.status_code == 200, r.data

    # (4) ON DISK: the real token SURVIVED the masked round-trip.
    disk_wh = _disk_webhooks(settings_path)[0]
    assert disk_wh["token"] == "REAL-TOKEN"
    assert disk_wh["token"] != MASK
    # The operator's non-secret edits landed.
    assert disk_wh["priority"] == "high"
    assert disk_wh["enabled"] is False


# ---------------------------------------------------------------------------
# (5) A re-typed token persists (rotation still works).
# ---------------------------------------------------------------------------
def test_retyped_token_persists(route_client):
    client, settings_path, seed = route_client
    _seed_one_webhook(seed, token="REAL-TOKEN")

    got = client.get("/api/notifications/config").get_json()
    wh = got["channels"]["webhooks"][0]
    wh["token"] = "NEW-TOKEN"  # operator re-typed a fresh secret

    r = client.post("/api/notifications/config", json={
        "enabled": True,
        "channels": {"webhooks": [wh]},
    })
    assert r.status_code == 200, r.data

    disk_wh = _disk_webhooks(settings_path)[0]
    assert disk_wh["token"] == "NEW-TOKEN"


# ---------------------------------------------------------------------------
# (6) A brand-new webhook arriving with a masked token: the field is
#     DROPPED, never persisted as the literal sentinel.
# ---------------------------------------------------------------------------
def test_new_webhook_with_masked_token_drops_the_field(route_client):
    client, settings_path, seed = route_client
    # Seed an EXISTING (different) webhook so the prior list is non-empty;
    # the new one must still not borrow a secret it has no business holding.
    _seed_one_webhook(seed, token="REAL-TOKEN")

    # A brand-new webhook (distinct identity) the UI somehow sent masked.
    new_wh = {
        "name": "fresh",
        "type": "generic",
        "url": "https://hooks.example.com/fresh",
        "token": MASK,
        "priority": "low",
        "enabled": True,
    }
    # Keep the existing one (re-typed token so it's unambiguous) + the new one.
    r = client.post("/api/notifications/config", json={
        "enabled": True,
        "channels": {"webhooks": [
            {
                "name": "ops", "type": "generic",
                "url": "https://hooks.example.com/ops",
                "token": "REAL-TOKEN", "priority": "low", "enabled": True,
            },
            new_wh,
        ]},
    })
    assert r.status_code == 200, r.data

    disk = _disk_webhooks(settings_path)
    fresh = next(w for w in disk if w["name"] == "fresh")
    # The sentinel was NOT persisted; with no prior secret to restore, the
    # field is dropped entirely.
    assert fresh.get("token") != MASK
    assert "token" not in fresh
    # Non-secret fields on the new webhook still landed.
    assert fresh["url"] == "https://hooks.example.com/fresh"
    assert fresh["priority"] == "low"
