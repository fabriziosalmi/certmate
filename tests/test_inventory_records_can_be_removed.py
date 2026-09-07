"""A discovered certificate must be removable from the inventory (#634).

Reported by a user: add a domain to the discovery configuration, scan, then
remove the domain again — "xxx.yy is still in list down below and cant be
removed".

That is not a filtering bug. `CertInventory` had no delete of any kind
and the API exposed no DELETE route, so the inventory was append-only: taking a
domain out of the discovery configuration stops future scans from finding it,
but every row already recorded stays forever. An operator cleaning up after a
mistaken scan, a decommissioned host, or a domain that was never theirs had no
way to do it short of deleting inventory.db.

Two properties are worth pinning beyond "the row goes away":

* the `endpoints` rows must go with it. The schema declares `ON DELETE CASCADE`,
  which SQLite ignores unless `PRAGMA foreign_keys` is ON per connection — it is
  (`_connect`), and `test_deleting_a_record_takes_its_endpoints_with_it` fails
  loudly if that ever regresses, since orphan endpoint rows would silently
  accumulate against a fingerprint that no longer exists.
* deleting one record must not disturb its neighbours, which is the assertion
  that a `DELETE` missing its WHERE clause would trip.
"""
from pathlib import Path

import pytest

from modules.core.cert_inventory import CertInventory
from modules.core.factory import create_app

pytestmark = [pytest.mark.unit]


CERT_A = {
    'fingerprint_sha256': 'aaa', 'subject_cn': 'gone.example.com',
    'san_dns': ['gone.example.com'], 'key': {'type': 'RSA', 'size': 2048},
    'not_after': '2099-01-01T00:00:00Z',
}
CERT_B = {
    'fingerprint_sha256': 'bbb', 'subject_cn': 'kept.example.com',
    'san_dns': ['kept.example.com'], 'key': {'type': 'RSA', 'size': 2048},
    'not_after': '2099-01-01T00:00:00Z',
}


@pytest.fixture
def inventory(tmp_path):
    inv = CertInventory(str(tmp_path))
    inv.record_certificate(CERT_A, source='ct-log')
    inv.record_certificate(CERT_B, source='ct-log')
    return inv


# ---------------------------------------------------------------------------
# The manager
# ---------------------------------------------------------------------------

def test_a_discovered_record_can_be_deleted(inventory):
    """The reported case."""
    assert inventory.get('aaa') is not None, 'nothing to delete'

    assert inventory.delete('aaa') is True
    assert inventory.get('aaa') is None, (
        'the record survived deletion and stays in the inventory list'
    )


def test_deleting_one_record_leaves_the_others_alone(inventory):
    """A DELETE that lost its WHERE clause would empty the inventory."""
    inventory.delete('aaa')

    assert inventory.get('bbb') is not None, 'deleting one record removed another'
    assert inventory.count() == 1


def test_deleting_a_record_takes_its_endpoints_with_it(tmp_path):
    """ON DELETE CASCADE is declared, but SQLite honours it only when
    PRAGMA foreign_keys is ON for the connection. If that regresses, endpoint
    rows outlive their certificate and accumulate invisibly."""
    inv = CertInventory(str(tmp_path))
    inv.record_certificate(CERT_A, source='probed')
    inv.record_observation(fingerprint='aaa', host='host.example.com', port=443)

    record = inv.get('aaa')
    assert record['endpoints'], 'this test needs an endpoint to orphan'

    inv.delete('aaa')

    with inv._read_conn() as conn:
        orphans = conn.execute(
            "SELECT COUNT(*) FROM endpoints WHERE fingerprint = ?", ('aaa',)
        ).fetchone()[0]
    assert orphans == 0, (
        f'{orphans} endpoint rows outlived their certificate — '
        'PRAGMA foreign_keys is not enabled on this connection'
    )


def test_deleting_an_unknown_fingerprint_reports_false(inventory):
    """So the route can answer 404 instead of pretending it removed something."""
    assert inventory.delete('does-not-exist') is False
    assert inventory.count() == 2


def test_a_deleted_record_can_be_rediscovered(inventory):
    """Deletion forgets an observation; it is not a blocklist. A domain still
    in the discovery configuration will legitimately come back on the next
    scan, and the operator needs that to be true rather than surprising."""
    inventory.delete('aaa')
    inventory.record_certificate(CERT_A, source='ct-log')

    assert inventory.get('aaa') is not None


# ---------------------------------------------------------------------------
# The route
# ---------------------------------------------------------------------------

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


def test_delete_route_removes_the_record(client, container):
    inv = container.managers['cert_inventory']
    inv.record_certificate(CERT_A, source='ct-log')

    resp = client.delete('/api/inventory/aaa')

    assert resp.status_code == 200, resp.get_json()
    assert inv.get('aaa') is None


def test_delete_route_404s_for_an_unknown_fingerprint(client, container):
    resp = client.delete('/api/inventory/nope')
    assert resp.status_code == 404


def test_delete_route_is_registered_with_the_delete_verb(app_container):
    """url_map is the source of truth; a resource added under the wrong path
    would leave the UI button calling nothing."""
    app, _ = app_container
    rules = {
        str(r): sorted(r.methods - {'HEAD', 'OPTIONS'})
        for r in app.url_map.iter_rules()
        if str(r) == '/api/inventory/<string:fingerprint>'
    }
    assert rules, 'no /api/inventory/<fingerprint> rule is registered'
    assert 'DELETE' in rules['/api/inventory/<string:fingerprint>']


def test_every_inline_handler_the_table_emits_is_actually_exported():
    """The Forget button reaches the DOM as
    `onclick="InventoryPage.forgetFromEl(this)"`. If the function is not on the
    exported object the button is inert and clicking it raises in the console —
    a failure no server-side test can see, and the reason the reported bug
    would look unfixed.
    """
    import re

    js = Path('static/js/inventory.js').read_text()

    called = set(re.findall(r'InventoryPage\.([A-Za-z_]\w*)\s*\(', js))
    assert 'forgetFromEl' in called, (
        'the Forget button is not wired to a handler at all'
    )

    exported_block = js[js.index('window.InventoryPage'):]
    exported_block = exported_block[:exported_block.index('};')]
    exported = set(re.findall(r'(\w+)\s*:', exported_block))

    missing = called - exported
    assert not missing, (
        f'inventory.js calls InventoryPage.{sorted(missing)} from generated '
        f'markup but does not export it — those buttons do nothing'
    )


def test_the_new_route_does_not_swallow_its_sibling_paths(app_container):
    """`/<string:fingerprint>` sits at the same depth as `/config`, `/scan` and
    `/crypto-report`. Werkzeug weights static segments above converters so
    those still win, but the cost of being wrong is that the whole inventory
    settings page starts answering "certificate not found" — so it is matched,
    not reasoned about.
    """
    app, _ = app_container
    adapter = app.url_map.bind('localhost')

    expected = {
        ('/api/inventory/config', 'GET'): 'inventory_inventory_config',
        ('/api/inventory/scan', 'POST'): 'inventory_inventory_scan',
        ('/api/inventory/crypto-report', 'GET'): 'inventory_inventory_crypto_report',
        ('/api/inventory/abc123', 'DELETE'): 'inventory_inventory_record',
        ('/api/inventory/abc123/adopt', 'POST'): 'inventory_inventory_adopt',
    }
    for (path, method), endpoint in expected.items():
        matched, _args = adapter.match(path, method=method)
        assert matched == endpoint, (
            f'{method} {path} resolved to {matched}, not {endpoint}'
        )
