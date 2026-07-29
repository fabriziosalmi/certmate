"""In-process tests for the adopt API (#472): GET plan, POST adopt, the
unavailable/404 branches, and a success path with a stubbed issuance."""

from pathlib import Path

import pytest

from modules.core.factory import create_app

pytestmark = [pytest.mark.unit]


@pytest.fixture
def app_container(tmp_path, monkeypatch):
    project_root = tmp_path / "certmate"
    module_dir = project_root / "modules" / "core"
    module_dir.mkdir(parents=True)
    (module_dir / "factory.py").write_text("# test path anchor\n")
    monkeypatch.setattr("modules.core.factory.__file__", str(module_dir / "factory.py"))
    monkeypatch.setenv("FLASK_ENV", "testing")
    monkeypatch.setenv("TESTING", "true")
    application, container = create_app()
    assert Path(container.cert_dir).resolve().is_relative_to(tmp_path)
    return application, container


@pytest.fixture
def client(app_container):
    return app_container[0].test_client()


@pytest.fixture
def container(app_container):
    return app_container[1]


def _record_discovered(container, fingerprint='fp', cn='example.com'):
    inv = container.managers['cert_inventory']
    inv.record_certificate(
        {'fingerprint_sha256': fingerprint, 'subject_cn': cn,
         'san_dns': [cn], 'key': {'type': 'RSA', 'size': 2048},
         'not_after': '2099-01-01T00:00:00Z'},
        source='ct-log',
    )
    return inv


# --- routing / read -------------------------------------------------------- #

def test_route_resolves(app_container):
    adapter = app_container[0].url_map.bind('localhost')
    endpoint, _ = adapter.match('/api/inventory/abc/adopt', method='GET')
    assert endpoint == 'inventory_inventory_adopt'


def test_adopt_info_404_for_unknown(client):
    assert client.get('/api/inventory/nope/adopt').status_code == 404


def test_adopt_info_unavailable_without_dns(client, container):
    _record_discovered(container)
    resp = client.get('/api/inventory/fp/adopt')
    assert resp.status_code == 200
    plan = resp.get_json()
    assert plan['domain'] == 'example.com'
    assert plan['available'] is False   # fresh app has no DNS creds/email


# --- adopt (POST) ---------------------------------------------------------- #

def test_adopt_post_404_for_unknown(client):
    assert client.post('/api/inventory/nope/adopt').status_code == 404


def test_adopt_post_400_when_unavailable(client, container):
    _record_discovered(container)
    resp = client.post('/api/inventory/fp/adopt')
    assert resp.status_code == 400
    assert resp.get_json()['code'] == 'ADOPTION_UNAVAILABLE'


def test_adopt_post_success_marks_managed(client, container):
    inv = _record_discovered(container)

    # Stub DNS (feasible) and issuance so no real certbot runs. The handler
    # resolves both from container.managers at request time.
    settings_manager = container.managers['settings']
    settings_manager.update(lambda s: s.__setitem__('email', 'a@b.com'), 'seed')

    class _FakeDNS:
        settings_manager = container.managers['settings']

        def suggest_dns_provider_for_domain(self, domain, settings=None):
            return 'cloudflare', 90

        def get_available_providers(self):
            return [{'name': 'cloudflare', 'configured': True}]

    calls = {}

    class _FakeService:
        def create(self, **kwargs):
            calls.update(kwargs)
            return {'domain': kwargs['domain'], 'status': 'issued'}

    container.managers['dns'] = _FakeDNS()
    container.managers['cert_service'] = _FakeService()

    resp = client.post('/api/inventory/fp/adopt')
    assert resp.status_code == 201, resp.get_json()
    body = resp.get_json()
    assert body['status'] == 'adopted'
    assert body['domain'] == 'example.com'

    # Issuance was invoked with the derived parameters...
    assert calls['domain'] == 'example.com'
    assert calls['dns_provider'] == 'cloudflare'
    assert calls['key_type'] == 'rsa'
    # ...and the inventory record is now flagged managed + linked.
    rec = inv.get('fp')
    assert rec['managed'] is True
    assert rec['managed_domain'] == 'example.com'


def test_adopt_post_issuance_valueerror_is_400(client, container):
    _record_discovered(container)
    container.managers['settings'].update(
        lambda s: s.__setitem__('email', 'a@b.com'), 'seed')

    class _FakeDNS:
        settings_manager = container.managers['settings']

        def suggest_dns_provider_for_domain(self, domain, settings=None):
            return 'cloudflare', 90

        def get_available_providers(self):
            return [{'name': 'cloudflare', 'configured': True}]

    class _BoomService:
        def create(self, **kwargs):
            raise ValueError('DNS credentials invalid')

    container.managers['dns'] = _FakeDNS()
    container.managers['cert_service'] = _BoomService()

    resp = client.post('/api/inventory/fp/adopt')
    assert resp.status_code == 400
    assert 'DNS credentials invalid' in resp.get_json()['error']
    # The record must NOT be marked managed when issuance failed.
    assert container.managers['cert_inventory'].get('fp')['managed'] is False
