"""In-process tests for the crypto readiness report API + page (#473)."""

from pathlib import Path

import pytest

from modules.core.factory import create_app

pytestmark = [pytest.mark.unit]


@pytest.fixture
def app_container(tmp_path, monkeypatch):
    module_dir = tmp_path / "certmate" / "modules" / "core"
    module_dir.mkdir(parents=True)
    (module_dir / "factory.py").write_text("# anchor\n")
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
def inventory(app_container):
    return app_container[1].managers['cert_inventory']


def test_routes_resolve(app_container):
    adapter = app_container[0].url_map.bind('localhost')
    assert adapter.match('/api/inventory/crypto-report', method='GET')[0] \
        == 'inventory_inventory_crypto_report'
    assert adapter.match('/inventory/crypto-report', method='GET')[0] == 'crypto_report_page'


def test_json_report(client, inventory):
    inventory.record_observation(
        fingerprint='fp', host='h', port=443, source='probed',
        key={'type': 'RSA', 'size': 2048}, signature_algorithm='sha256WithRSAEncryption',
    )
    resp = client.get('/api/inventory/crypto-report')
    assert resp.status_code == 200
    body = resp.get_json()
    assert body['total'] == 1
    assert body['quantum_vulnerable'] == 1
    assert body['generated_at']


def test_csv_download(client, inventory):
    inventory.record_observation(
        fingerprint='fp', host='h', port=443, source='probed',
        key={'type': 'RSA', 'size': 2048}, signature_algorithm='sha256WithRSAEncryption',
    )
    resp = client.get('/api/inventory/crypto-report?format=csv')
    assert resp.status_code == 200
    assert resp.mimetype == 'text/csv'
    assert 'attachment' in resp.headers.get('Content-Disposition', '')
    assert b'subject_cn' in resp.data


def test_report_template_exists():
    tpl = Path(__file__).resolve().parent.parent / 'templates' / 'crypto_report.html'
    assert tpl.exists()
    assert '{% extends "base.html" %}' in tpl.read_text()
