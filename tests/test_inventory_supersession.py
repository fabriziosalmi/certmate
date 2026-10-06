"""A renewed certificate's predecessor is marked superseded, hidden by default, and never forgotten (#1044).

After a renewal the inventory holds two certificates for one host: the old one with its last
sighting and the new one with today's. That is the inventory working: it is a history by
fingerprint on purpose, and it is how "a renewed certificate that was never deployed" is caught
(the endpoint still serves the old one). Forgetting the old certificate as soon as a newer one
exists would erase exactly that case, and a rule "same name means replaced" collides with #854
(a public and a private certificate can share a name, and neither is the old one).

What an operator wants is for the list to tell the certificates in use from the ones that are
not any more. The data is stored: every endpoint records when it last served each certificate. A
certificate is SUPERSEDED when it has at least one endpoint and, at every endpoint it was seen
on, a different certificate has been seen more recently. This file pins that definition, the API
that carries it (the default answer is unchanged and gains a flag; `include_superseded=false`
leaves them out), and the page that hides them until asked.
"""
import json
import subprocess
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from modules.core.inventory_view import build_inventory_view, superseded_fingerprints

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
NOW = datetime(2026, 10, 2, 12, 0, 0)


def _at(days_ago):
    return (NOW - timedelta(days=days_ago)).replace(microsecond=0).isoformat() + 'Z'


def _record(fingerprint, *endpoints, **extra):
    """endpoints: (host, port, days_ago) triples."""
    base = {'fingerprint': fingerprint, 'subject_cn': f'{fingerprint}.example.test', 'san_dns': [],
            'not_after': _at(-60), 'managed': False, 'source': 'probed', 'revocation': None,
            'endpoints': [{'host': h, 'port': p, 'first_seen': _at(d + 30), 'last_seen': _at(d)}
                          for h, p, d in endpoints]}
    base.update(extra)
    return base


# --------------------------------------------------------------------------
# The definition.
# --------------------------------------------------------------------------

def test_the_old_certificate_of_a_renewed_host_is_superseded():
    records = [_record('old', ('shop.example.test', 443, 30)), _record('new', ('shop.example.test', 443, 1))]
    assert superseded_fingerprints(records) == {'old'}


def test_a_certificate_still_served_on_any_endpoint_is_never_superseded():
    """Replaced on one host and still current on another: not superseded."""
    records = [
        _record('old', ('a.example.test', 443, 30), ('b.example.test', 443, 1)),
        _record('new', ('a.example.test', 443, 1)),
    ]
    assert superseded_fingerprints(records) == set()


def test_replaced_on_every_endpoint_is_superseded():
    records = [
        _record('old', ('a.example.test', 443, 30), ('b.example.test', 443, 40)),
        _record('new', ('a.example.test', 443, 1), ('b.example.test', 443, 2)),
    ]
    assert superseded_fingerprints(records) == {'old'}


def test_a_certificate_with_no_endpoint_is_never_superseded():
    """Found in a CT log, or issued here and never probed: nothing to compare."""
    records = [_record('ct'), _record('also-served', ('a.example.test', 443, 5))]
    assert superseded_fingerprints(records) == set()


def test_a_chain_of_renewals_leaves_only_the_latest_current():
    records = [_record('first', ('a.example.test', 443, 90)), _record('second', ('a.example.test', 443, 45)),
               _record('third', ('a.example.test', 443, 1))]
    assert superseded_fingerprints(records) == {'first', 'second'}


def test_two_certificates_last_seen_at_the_same_instant_are_both_current():
    records = [_record('rsa', ('a.example.test', 443, 3)), _record('ecdsa', ('a.example.test', 443, 3))]
    assert superseded_fingerprints(records) == set()


def test_another_port_is_another_endpoint():
    """The same host on 443 and on 8443 are two endpoints: replacing the certificate on one says
    nothing about the other."""
    records = [_record('old', ('a.example.test', 443, 30), ('a.example.test', 8443, 30)),
               _record('new', ('a.example.test', 443, 1))]
    assert superseded_fingerprints(records) == set()


def test_host_names_compare_case_insensitively():
    records = [_record('old', ('Shop.Example.Test', 443, 30)), _record('new', ('shop.example.test', 443, 1))]
    assert superseded_fingerprints(records) == {'old'}


@pytest.mark.parametrize('stamp', [None, '', 'not-a-date'])
def test_a_last_seen_that_cannot_be_read_is_never_evidence_of_replacement(stamp):
    """Neither the unreadable certificate nor the one compared with it is marked on a guess."""
    old = _record('old', ('a.example.test', 443, 30))
    old['endpoints'][0]['last_seen'] = stamp
    new = _record('new', ('a.example.test', 443, 1))
    assert superseded_fingerprints([old, new]) == set()
    new['endpoints'][0]['last_seen'] = stamp
    assert superseded_fingerprints([old, new]) == set()


def test_an_endpoint_that_alternates_marks_whichever_it_served_earlier():
    """A rollout across a load balancer: the latest sighting decides, and the next scan corrects it.
    Documented behaviour, not a bug: "has since been seen serving a different certificate"."""
    records = [_record('a', ('lb.example.test', 443, 1)), _record('b', ('lb.example.test', 443, 5))]
    assert superseded_fingerprints(records) == {'b'}


def test_the_whole_inventory_is_what_decides_not_the_filtered_list():
    """A newer certificate that a source filter would hide still replaced the old one: the set is
    worked out before filtering, and handed to the view."""
    old = _record('old', ('a.example.test', 443, 30), source='probed')
    new = _record('new', ('a.example.test', 443, 1), source='imported')
    everything = superseded_fingerprints([old, new])
    view = build_inventory_view([old], now=NOW, superseded=everything)
    assert [c['superseded'] for c in view['certificates']] == [True]
    # Computed from the filtered list alone it would have said the opposite: the trap this avoids.
    assert build_inventory_view([old], now=NOW)['certificates'][0]['superseded'] is False


# --------------------------------------------------------------------------
# The view.
# --------------------------------------------------------------------------

def _renewal():
    return [_record('old', ('a.example.test', 443, 30), not_after=_at(-3)),
            _record('new', ('a.example.test', 443, 1), not_after=_at(-80))]


def test_every_certificate_carries_the_flag_and_the_summary_the_count():
    view = build_inventory_view(_renewal(), now=NOW)
    assert {c['fingerprint']: c['superseded'] for c in view['certificates']} == {'old': True, 'new': False}
    assert view['summary']['superseded'] == 1 and view['summary']['total'] == 2


def test_leaving_them_out_leaves_them_out_of_the_summary_too():
    """The cards describe what the list shows: the old certificate expiring in three days is not an
    alarm once something else serves the host."""
    shown = build_inventory_view(_renewal(), now=NOW)
    hidden = build_inventory_view(_renewal(), now=NOW, include_superseded=False)
    assert [c['fingerprint'] for c in hidden['certificates']] == ['new']
    assert hidden['summary']['total'] == 1
    assert shown['summary']['expiry']['7'] == 1 and hidden['summary']['expiry']['7'] == 0
    assert hidden['summary']['superseded'] == 1, 'it says how many were left out'


def test_a_record_without_a_fingerprint_is_neither_a_crash_nor_superseded():
    """The rest of the view reads records with `.get`; a malformed one degrades, it does not raise in a
    dashboard handler (a fixture of another test found this)."""
    odd = {'subject_cn': 'x', 'endpoints': [{'host': 'a.example.test', 'port': 443, 'last_seen': _at(1)}]}
    view = build_inventory_view([odd], now=NOW)
    assert view['certificates'][0]['superseded'] is False and view['summary']['superseded'] == 0


def test_an_inventory_with_nothing_superseded_is_unchanged_apart_from_the_flag():
    records = [_record('only', ('a.example.test', 443, 1))]
    view = build_inventory_view(records, now=NOW, include_superseded=False)
    assert [c['fingerprint'] for c in view['certificates']] == ['only']
    assert view['summary']['superseded'] == 0


# --------------------------------------------------------------------------
# The API, on the real inventory (SQLite), through the real app.
# --------------------------------------------------------------------------

@pytest.fixture
def app_container(tmp_path, monkeypatch):
    from modules.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    anchor = root / 'factory.py'
    anchor.write_text('# test path anchor\n')
    monkeypatch.setattr('modules.factory.__file__', str(anchor))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    return create_app()


@pytest.fixture
def client(app_container):
    return app_container[0].test_client()


@pytest.fixture
def inventory(app_container):
    return app_container[1].managers['cert_inventory']


def _observe(inventory, fingerprint, host, days_ago, **extra):
    when = (datetime.utcnow() - timedelta(days=days_ago)).replace(microsecond=0)
    inventory.record_observation(
        fingerprint=fingerprint, host=host, port=443, subject_cn=host, issuer_cn='CA', serial=fingerprint,
        not_after=(datetime.utcnow() + timedelta(days=60)).isoformat() + 'Z', key={'type': 'RSA', 'size': 2048},
        san_dns=[host], observed_at=when.isoformat() + 'Z', **extra)


def _renewed(inventory):
    _observe(inventory, 'aa' * 32, 'shop.example.test', 30)
    _observe(inventory, 'bb' * 32, 'shop.example.test', 1)


def test_the_default_answer_still_lists_everything_and_gains_the_flag(client, inventory):
    _renewed(inventory)
    body = client.get('/api/inventory').get_json()
    assert {c['fingerprint'][:2]: c['superseded'] for c in body['certificates']} == {'aa': True, 'bb': False}
    assert body['summary']['total'] == 2 and body['summary']['superseded'] == 1


@pytest.mark.parametrize('value', ['false', 'False', '0', 'no', 'off'])
def test_include_superseded_false_leaves_them_out(client, inventory, value):
    _renewed(inventory)
    body = client.get(f'/api/inventory?include_superseded={value}').get_json()
    assert [c['fingerprint'][:2] for c in body['certificates']] == ['bb']
    assert body['summary']['total'] == 1 and body['summary']['superseded'] == 1


@pytest.mark.parametrize('value', ['true', '1', 'yes', '', 'anything'])
def test_anything_else_keeps_them(client, inventory, value):
    _renewed(inventory)
    body = client.get(f'/api/inventory?include_superseded={value}').get_json()
    assert len(body['certificates']) == 2


def test_the_flag_does_not_depend_on_another_filter(client, inventory):
    """`source=probed` hides the newer, imported certificate; the old one is superseded all the same."""
    _observe(inventory, 'aa' * 32, 'shop.example.test', 30, source='probed')
    _observe(inventory, 'bb' * 32, 'shop.example.test', 1, source='imported')
    body = client.get('/api/inventory?source=probed').get_json()
    assert [(c['fingerprint'][:2], c['superseded']) for c in body['certificates']] == [('aa', True)]
    assert client.get('/api/inventory?source=probed&include_superseded=false').get_json()['certificates'] == []


def test_a_certificate_still_served_elsewhere_stays(client, inventory):
    _observe(inventory, 'aa' * 32, 'a.example.test', 30)
    _observe(inventory, 'aa' * 32, 'b.example.test', 1)
    _observe(inventory, 'bb' * 32, 'a.example.test', 1)
    body = client.get('/api/inventory?include_superseded=false').get_json()
    assert len(body['certificates']) == 2 and body['summary']['superseded'] == 0


def test_nothing_is_deleted(client, inventory):
    _renewed(inventory)
    client.get('/api/inventory?include_superseded=false')
    assert inventory.count() == 2


def test_the_crypto_report_leaves_them_out_on_request_so_it_agrees_with_the_list(client, inventory):
    """The readiness cards sit beside the list. A toggle that changed the list and not the cards
    would show 5 certificates and count 8 (found in a browser, not by the tests above)."""
    _renewed(inventory)
    everything = client.get('/api/inventory/crypto-report').get_json()
    current = client.get('/api/inventory/crypto-report?include_superseded=false').get_json()
    assert everything['total'] == 2 and current['total'] == 1
    assert client.get('/api/inventory/crypto-report?include_superseded=false&format=csv').status_code == 200


def test_the_operations_declare_their_parameters_so_a_gate_can_see_them(client):
    """GET /api/inventory has no response schema in the OpenAPI document, so a new field on its answer
    is seen by no gate; the parameter is the part that can be, once it is declared."""
    spec = client.get('/api/swagger.json').get_json()
    params = {p['name']: p for p in spec['paths']['/inventory']['get'].get('parameters', [])}
    assert {'managed', 'source', 'include_superseded'} <= set(params), params
    assert params['include_superseded']['type'] == 'boolean'
    report = {p['name'] for p in spec['paths']['/inventory/crypto-report']['get'].get('parameters', [])}
    assert {'format', 'include_superseded'} <= report, report


# --------------------------------------------------------------------------
# The page, executed: the real static/js/inventory.js in node, with a fake DOM.
# --------------------------------------------------------------------------

HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const els = {};
function el(id) {
  if (!els[id]) els[id] = { id, value: '', checked: false, textContent: '', innerHTML: '',
    getAttribute() { return null; }, classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } } };
  return els[id];
}
const payloads = JSON.parse(process.env.PAYLOADS);
const urls = [];
const context = {
  window: {}, console, Promise,
  // The page registers the actions its controls name when it loads.
  CertMate: {globalActions() {}, actions() {}},
  document: { getElementById: el, addEventListener() {}, querySelectorAll() { return []; } },
  fetch(url) {
    urls.push(url);
    const body = url.includes('include_superseded=false') ? payloads.hidden : payloads.shown;
    return Promise.resolve({ ok: true, json: () => Promise.resolve(body) });
  },
};
context.window = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/js/inventory.js', 'utf8'), context);
const page = context.InventoryPage;
(async () => {
  const out = {};
  page.load(); page.toggleSuperseded(); await new Promise(r => setTimeout(r, 20));
  out.loadUrls = urls.slice();
  out.hiddenUrl = urls.find(u => !u.includes('crypto'));
  out.hiddenBody = el('inventoryBody').innerHTML;
  out.hiddenCount = el('invCount').textContent;
  el('invSuperseded').checked = true;
  urls.length = 0;
  page.toggleSuperseded(); await new Promise(r => setTimeout(r, 20));
  out.toggleUrls = urls.slice();
  out.shownUrl = urls.find(u => u.startsWith('/api/inventory') && !u.includes('crypto'));
  out.shownBody = el('inventoryBody').innerHTML;
  out.shownCount = el('invCount').textContent;
  out.exported = Object.keys(page);
  console.log(JSON.stringify(out));
})();
"""


def _page_run(node, shown, hidden):
    done = subprocess.run([node, '-e', HARNESS], cwd=REPO, capture_output=True, text=True, timeout=60,
                          env={'PATH': '/usr/bin:/bin', 'PAYLOADS': json.dumps({'shown': shown, 'hidden': hidden})})
    assert done.returncode == 0, done.stderr + done.stdout
    return json.loads(done.stdout.strip().splitlines()[-1])


def _api_view(include):
    return build_inventory_view(_renewal(), now=NOW, include_superseded=include)


def test_the_page_hides_superseded_certificates_until_asked(node):
    result = _page_run(node, _api_view(True), _api_view(False))

    assert result['hiddenUrl'] == '/api/inventory?include_superseded=false'
    assert 'new.example.test' in result['hiddenBody'] and 'old.example.test' not in result['hiddenBody']
    assert result['hiddenCount'] == '1 of 1 · 1 superseded hidden'

    assert result['shownUrl'] == '/api/inventory'
    # The one control moves the list and the readiness cards together, in both directions.
    assert '/api/inventory/crypto-report?include_superseded=false' in result['loadUrls']
    assert sorted(result['toggleUrls']) == ['/api/inventory', '/api/inventory/crypto-report']
    assert 'old.example.test' in result['shownBody'] and 'new.example.test' in result['shownBody']
    assert result['shownBody'].count('>superseded<') == 1, 'only the superseded certificate wears the badge'
    assert result['shownCount'] == '2 of 2'


def test_an_inventory_that_is_entirely_superseded_says_so(node):
    only_old = [_record('old', ('a.example.test', 443, 30)), _record('new', ('a.example.test', 443, 1))]
    nothing_shown = build_inventory_view(only_old, now=NOW, include_superseded=False)
    nothing_shown['certificates'] = []        # every certificate left out
    nothing_shown['summary']['superseded'] = 2
    result = _page_run(node, _api_view(True), nothing_shown)
    assert 'has been superseded' in result['hiddenBody'] and 'Show superseded' in result['hiddenBody']
    assert 'Inventory is empty' not in result['hiddenBody']
    assert result['hiddenCount'] == '0 of 0 · 2 superseded hidden'


def test_the_toggle_is_in_the_template():
    template = (REPO / 'templates' / 'inventory.html').read_text(encoding='utf-8')
    assert 'id="invSuperseded"' in template and 'data-change="InventoryPage.toggleSuperseded"' in template
