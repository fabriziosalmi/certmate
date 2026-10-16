"""The inventory table sorts by its columns, like the other tables do.

The dashboard's certificate list and the client-certificate list sort when a
header is clicked: ascending, then descending, with the arrow and `aria-sort`
following. `/inventory` had plain headers, so an estate of a few hundred
discovered certificates could only be read in the order the API happened to
return them — the one list where "what expires first" or "everything one
issuer signed" is the question.

What the sort promises, checked against the real static/js/inventory.js run in
node with a fake DOM:

* nothing moves until a header is clicked (the control);
* expiry orders by the date, not by the badge text;
* the key column orders numerically, so `RSA 2048` precedes `RSA 4096`;
* endpoints orders by how many there are;
* a record with nothing for the column sorts last in both directions, rather
  than heading the list as a block of dashes;
* sorting applies to what the filters left, and a filter applies to the
  sorted list.

And, as text, the wiring a sort needs to announce itself: each header's
`inv-sort-th-*` / `inv-sort-icon-*` ids, a comparator branch for every field a
header sends, and the action registered so the click reaches it.
"""
import json
import re
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit]

REPO = Path(__file__).resolve().parent.parent
TEMPLATE = (REPO / 'templates' / 'inventory.html').read_text(encoding='utf-8')
SCRIPT = (REPO / 'static' / 'js' / 'inventory.js').read_text(encoding='utf-8')


def _thead():
    start = TEMPLATE.index('id="inv-sort-th-subject"')
    start = TEMPLATE.rindex('<thead', 0, start)
    return TEMPLATE[start:TEMPLATE.index('</thead>', start)]


def _sortable_fields():
    """Never empty: the tests that loop over it would pass on nothing."""
    fields = re.findall(r"""data-click="InventoryPage\.sortBy" data-args='\["(\w+)"\]'""", _thead())
    assert len(fields) == 6, f'expected six sortable headers, found {fields}'
    return fields


# --- the wiring, as text ---------------------------------------------------

def test_every_column_but_the_actions_is_sortable():
    assert _sortable_fields() == ['subject', 'issuer', 'expiry', 'key', 'source', 'endpoints']


def test_every_sortable_header_has_the_ids_the_sort_code_looks_up():
    """sortBy finds the glyph and the aria-sort target by id. A field whose ids
    do not match sorts correctly and silently stops announcing itself."""
    thead = _thead()
    for field in _sortable_fields():
        assert f'id="inv-sort-th-{field}"' in thead, field
        assert f'id="inv-sort-icon-{field}"' in thead, field
    assert thead.count('aria-sort="none"') == 6


def test_the_comparator_knows_every_field_a_header_sends():
    """A header wired to a field sortValue does not handle returns null for
    every row: the click lands, the arrow moves, nothing reorders."""
    body = SCRIPT[SCRIPT.index('function sortValue'):]
    body = body[:body.index('\n    }\n')]
    for field in _sortable_fields():
        assert f"field === '{field}'" in body, f'the {field} header sorts by nothing'


def test_the_action_is_registered_for_the_click_to_reach():
    registered = SCRIPT[SCRIPT.index('CertMate.globalActions('):]
    assert "'InventoryPage.sortBy'" in registered
    assert re.search(r'sortBy: sortBy', SCRIPT)


def test_the_header_and_the_rows_have_the_same_number_of_cells():
    columns = len(re.findall(r'<th\b', _thead()))
    row = SCRIPT[SCRIPT.index("return '<tr class=\"hover:bg-hover\">'"):]
    row = row[:row.index("+ '</tr>'")]
    assert row.count('<td') == columns == 7


# --- the behaviour, in node ------------------------------------------------

HARNESS = r"""
const fs = require('fs'), vm = require('vm');
const els = {};
function el(id) {
  if (!els[id]) els[id] = { id, value: '', checked: false, textContent: '', innerHTML: '', className: '',
    attrs: {}, getAttribute(n) { return this.attrs[n] || null; }, setAttribute(n, v) { this.attrs[n] = v; },
    classList: { toggle() {}, add() {}, remove() {}, contains() { return false; } } };
  return els[id];
}
const payload = JSON.parse(process.env.PAYLOAD);
const steps = JSON.parse(process.env.STEPS);
const context = {
  window: {}, console, Promise,
  CertMate: {globalActions() {}, actions() {}},
  document: {
    getElementById: el, addEventListener() {},
    querySelectorAll(sel) {
      const prefix = (sel.match(/\^="([^"]+)"/) || [])[1] || '';
      return Object.values(els).filter(e => prefix && e.id.startsWith(prefix));
    },
  },
  fetch() { return Promise.resolve({ ok: true, json: () => Promise.resolve(payload) }); },
};
context.window = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync('static/js/inventory.js', 'utf8'), context);
const page = context.InventoryPage;
const order = () => [...el('inventoryBody').innerHTML.matchAll(/font-medium text-foreground">([^ <]+)/g)].map(m => m[1]);
(async () => {
  // Every header exists before the page sorts, as it does in the template.
  for (const f of ['subject', 'issuer', 'expiry', 'key', 'source', 'endpoints']) {
    el('inv-sort-th-' + f); el('inv-sort-icon-' + f);
  }
  page.load(); await new Promise(r => setTimeout(r, 20));
  const out = { initial: order(), body: el('inventoryBody').innerHTML, steps: [] };
  for (const step of steps) {
    if (step.search !== undefined) { el('invSearch').value = step.search; page.render(); }
    else { page.sortBy(step.sort); }
    out.steps.push({
      order: order(),
      ariaSort: el('inv-sort-th-' + (step.sort || 'subject')).getAttribute('aria-sort'),
      icon: el('inv-sort-icon-' + (step.sort || 'subject')).className,
      othersAria: ['subject', 'issuer', 'expiry', 'key', 'source', 'endpoints']
        .filter(f => f !== step.sort).map(f => el('inv-sort-th-' + f).getAttribute('aria-sort')),
    });
  }
  console.log(JSON.stringify(out));
})();
"""


def _record(cn, **more):
    base = {'fingerprint': cn, 'subject_cn': cn, 'issuer_cn': 'R3', 'not_after': '2027-01-01T00:00:00Z',
            'expiry_status': 'ok', 'days_until_expiry': 90, 'key': {'type': 'RSA', 'size': 2048},
            'source': 'probed', 'managed': False, 'san_dns': [], 'endpoints': [], 'group': 'discovered'}
    base.update(more)
    return base


# The API's order, deliberately matching no column.
RECORDS = [
    _record('charlie', issuer_cn='ZeroSSL', not_after='2026-11-01T00:00:00Z',
            key={'type': 'RSA', 'size': 4096}, source='issued',
            endpoints=[{'host': 'c', 'port': 443}, {'host': 'c', 'port': 8443}]),
    _record('alpha', issuer_cn=None, issuer=None, not_after=None,
            key=None, source='ct-log', endpoints=[]),
    _record('delta', issuer_cn='R3', not_after='2026-10-20T00:00:00Z',
            key={'type': 'EC', 'curve': 'secp256r1'}, source='probed',
            endpoints=[{'host': 'd', 'port': 443}]),
    _record('bravo', issuer_cn='E5', not_after='2027-06-01T00:00:00Z',
            key={'type': 'RSA', 'size': 2048}, source='imported',
            endpoints=[{'host': 'b', 'port': 1}, {'host': 'b', 'port': 2}, {'host': 'b', 'port': 3}]),
]


def _run(node, steps, records=None):
    payload = {'certificates': RECORDS if records is None else records, 'summary': {}}
    done = subprocess.run([node, '-e', HARNESS], cwd=REPO, capture_output=True, text=True, timeout=60,
                          env={'PATH': '/usr/bin:/bin', 'PAYLOAD': json.dumps(payload),
                               'STEPS': json.dumps(steps)})
    assert done.returncode == 0, done.stderr + done.stdout
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_nothing_moves_until_a_header_is_clicked(node):
    """CONTROL: the page looks exactly as it did before this change."""
    assert _run(node, [])['initial'] == ['charlie', 'alpha', 'delta', 'bravo']


def test_a_header_sorts_ascending_then_descending(node):
    out = _run(node, [{'sort': 'subject'}, {'sort': 'subject'}])

    first, second = out['steps']
    assert first['order'] == ['alpha', 'bravo', 'charlie', 'delta']
    assert first['ariaSort'] == 'ascending' and 'fa-sort-up' in first['icon']
    assert second['order'] == ['delta', 'charlie', 'bravo', 'alpha']
    assert second['ariaSort'] == 'descending' and 'fa-sort-down' in second['icon']


def test_another_header_resets_the_one_before(node):
    out = _run(node, [{'sort': 'subject'}, {'sort': 'source'}])

    assert out['steps'][1]['ariaSort'] == 'ascending'
    assert set(out['steps'][1]['othersAria']) == {'none'}, 'only one column says it is sorted'


def test_expiry_orders_by_the_date_and_unknown_goes_last_both_ways(node):
    out = _run(node, [{'sort': 'expiry'}, {'sort': 'expiry'}])

    assert out['steps'][0]['order'] == ['delta', 'charlie', 'bravo', 'alpha']
    assert out['steps'][1]['order'] == ['bravo', 'charlie', 'delta', 'alpha']


def test_an_empty_issuer_goes_last_both_ways(node):
    out = _run(node, [{'sort': 'issuer'}, {'sort': 'issuer'}])

    assert out['steps'][0]['order'][-1] == 'alpha'
    assert out['steps'][1]['order'][-1] == 'alpha'
    assert out['steps'][0]['order'][:3] == ['bravo', 'delta', 'charlie']   # E5, R3, ZeroSSL


def test_the_key_column_orders_numerically_and_keyless_goes_last(node):
    out = _run(node, [{'sort': 'key'}])

    # EC secp256r1, RSA 2048, RSA 4096 — and no key at the bottom.
    assert out['steps'][0]['order'] == ['delta', 'bravo', 'charlie', 'alpha']


def test_endpoints_orders_by_how_many(node):
    out = _run(node, [{'sort': 'endpoints'}, {'sort': 'endpoints'}])

    assert out['steps'][0]['order'] == ['alpha', 'delta', 'charlie', 'bravo']
    assert out['steps'][1]['order'] == ['bravo', 'charlie', 'delta', 'alpha']


def test_sorting_and_filtering_compose(node):
    """The sort is of what the filters left, and survives a new filter."""
    out = _run(node, [{'sort': 'subject'}, {'sort': 'subject'}, {'search': 'l'}])

    # 'l' is in alpha, charlie (ZeroSSL) and delta, not in bravo or its issuer E5.
    assert out['steps'][2]['order'] == ['delta', 'charlie', 'alpha']


# --- the endpoints cell lists every endpoint on hover ----------------------

def _endpoints_cell(body, cn):
    """The <td> holding the endpoints of the row whose subject is `cn`."""
    at = body.index('font-medium text-foreground">' + cn)
    row = body[body.rindex('<tr', 0, at):]
    row = row[:row.index('</tr>')]
    return re.findall(r'<td[^>]*>(.*?)</td>', row, re.S)[5]


def test_hovering_the_endpoints_lists_every_one(node):
    """"+2" said how many, not which. The title now holds all of them, one per
    line, the first included so the tooltip reads as the whole list."""
    records = [_record('multi', endpoints=[{'host': 'formacion.example.test', 'port': 443},
                                           {'host': 'b.example.test', 'port': 8443},
                                           {'host': 'c.example.test', 'port': 443}])]
    cell = _endpoints_cell(_run(node, [], records)['body'], 'multi')

    title = re.search(r'title="([^"]*)"', cell).group(1)
    assert title.split('\n') == ['formacion.example.test:443', 'b.example.test:8443', 'c.example.test:443']
    assert '>+2<' in cell, 'the count is still shown'


def test_screen_readers_get_the_list_too(node):
    """A title is not reliably announced, so the rest of the list is also in
    the cell as visually hidden text, and the bare "+2" is hidden from them."""
    records = [_record('multi', endpoints=[{'host': 'a.example.test', 'port': 443},
                                           {'host': 'b.example.test', 'port': 443}])]
    cell = _endpoints_cell(_run(node, [], records)['body'], 'multi')

    assert '<span class="sr-only">, b.example.test:443</span>' in cell
    assert 'aria-hidden="true">+1<' in cell


def test_a_single_endpoint_has_nothing_to_reveal(node):
    """CONTROL: the cell already shows everything, so no tooltip, no help cursor."""
    records = [_record('single', endpoints=[{'host': 'a.example.test', 'port': 443}])]
    cell = _endpoints_cell(_run(node, [], records)['body'], 'single')

    assert 'a.example.test:443' in cell
    assert 'title=' not in cell and 'cursor-help' not in cell


def test_an_endpoint_name_cannot_break_out_of_the_tooltip(node):
    """Endpoint names come from discovery configuration and CT logs. A quote
    in one must not end the title attribute and start markup of its own."""
    records = [_record('hostile', endpoints=[{'host': 'a.example.test', 'port': 443},
                                             {'host': 'x" onmouseover="alert(1)', 'port': 1}])]
    cell = _endpoints_cell(_run(node, [], records)['body'], 'hostile')

    assert 'onmouseover="' not in cell
    assert '&quot;' in cell
