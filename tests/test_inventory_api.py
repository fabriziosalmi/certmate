"""In-process tests for the inventory API + page routes (#471).

Boots the real app (auth is in setup-mode bypass = admin) and exercises
GET /api/inventory, GET/POST /api/inventory/config, POST /api/inventory/scan,
and the /inventory page route. The inventory manager wired by the factory is
populated directly, then read back through the HTTP surface.
"""

from pathlib import Path

import pytest

from modules.core.factory import create_app

pytestmark = [pytest.mark.unit]


@pytest.fixture
def app_container(tmp_path, monkeypatch):
    project_root = tmp_path / "certmate"
    module_dir = project_root / "modules" / "core"
    module_dir.mkdir(parents=True)
    fake_factory_file = module_dir / "factory.py"
    fake_factory_file.write_text("# test path anchor\n")
    monkeypatch.setattr("modules.core.factory.__file__", str(fake_factory_file))
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("TESTING", "true")
    application, container = create_app()
    assert Path(container.cert_dir).resolve().is_relative_to(tmp_path)
    return application, container


@pytest.fixture
def client(app_container):
    application, _ = app_container
    return application.test_client()


@pytest.fixture
def inventory(app_container):
    _, container = app_container
    return container.managers['cert_inventory']


# --- routing --------------------------------------------------------------- #

def test_routes_resolve(app_container):
    application, _ = app_container
    adapter = application.url_map.bind('localhost')
    assert adapter.match('/api/inventory', method='GET')[0] == 'inventory_inventory_list'
    assert adapter.match('/api/inventory/config', method='GET')[0] == 'inventory_inventory_config'
    assert adapter.match('/api/inventory/scan', method='POST')[0] == 'inventory_inventory_scan'
    # The page route is registered (rendering is asserted separately, since the
    # path-anchored fixture relocates the app root away from templates/).
    assert adapter.match('/inventory', method='GET')[0] == 'inventory_page'


def test_inventory_template_exists():
    # templates/ lives at the repo root, two levels up from tests/.
    tpl = Path(__file__).resolve().parent.parent / 'templates' / 'inventory.html'
    assert tpl.exists()
    text = tpl.read_text()
    assert '{% extends "base.html" %}' in text
    assert 'inventory.js' in text


# --- GET /api/inventory ---------------------------------------------------- #

def test_inventory_list_empty(client):
    resp = client.get('/api/inventory')
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['certificates'] == []
    assert body['summary']['total'] == 0


def test_inventory_list_reflects_records(client, inventory):
    inventory.record_observation(
        fingerprint='fp1', host='a.example.com', port=443, source='issued',
        managed=True, managed_domain='example.com', subject_cn='a.example.com',
        not_after='2099-01-01T00:00:00Z',
    )
    inventory.record_certificate(
        {'fingerprint_sha256': 'fp2', 'subject_cn': 'shadow.example.com',
         'not_after': '2099-01-01T00:00:00Z'},
        source='ct-log',
    )
    resp = client.get('/api/inventory')
    body = resp.get_json()
    assert body['summary']['total'] == 2
    assert body['summary']['issued'] == 1
    assert body['summary']['discovered'] == 1
    groups = {c['fingerprint']: c['group'] for c in body['certificates']}
    assert groups == {'fp1': 'issued', 'fp2': 'discovered'}


def test_inventory_list_managed_filter(client, inventory):
    inventory.record_observation(fingerprint='m', host='h', port=443,
                                 source='issued', managed=True)
    inventory.record_observation(fingerprint='u', host='h2', port=443,
                                 source='probed', managed=False)
    resp = client.get('/api/inventory?managed=true')
    fps = [c['fingerprint'] for c in resp.get_json()['certificates']]
    assert fps == ['m']


# --- config + scan --------------------------------------------------------- #

def test_config_get_and_post(client):
    resp = client.get('/api/inventory/config')
    assert resp.status_code == 200
    assert 'discovery' in resp.get_json()
    assert 'ct_monitoring' in resp.get_json()

    resp = client.post('/api/inventory/config', json={
        'discovery': {'enabled': True, 'endpoints': ['a.example.com:8443']},
    })
    assert resp.status_code == 200
    disc = resp.get_json()['discovery']
    assert disc['enabled'] is True
    assert disc['endpoints'] == ['a.example.com:8443']


def test_config_post_rejects_bad_endpoint(client):
    resp = client.post('/api/inventory/config', json={
        'discovery': {'enabled': True, 'endpoints': ['host:notaport']},
    })
    assert resp.status_code == 400


def test_scan_runs_and_returns_summaries(client):
    # Nothing configured -> both sub-jobs are no-ops but the endpoint succeeds.
    resp = client.post('/api/inventory/scan')
    assert resp.status_code == 200
    body = resp.get_json()
    assert 'discovery' in body
    assert 'ct_monitoring' in body
