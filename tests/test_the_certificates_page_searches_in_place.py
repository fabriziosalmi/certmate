"""The Certificates page searches its own list, in place (#1385).

The list had no search field of its own: the command palette was the one place
certificates were searched, and it takes you to one certificate. A user with many
certificates asked for the other thing, to see every certificate that matches,
in the list, next to the status chips and the tags.

The field looks at what the palette finds a certificate by (name, or address for
an IP certificate, the host it is served at, every other name it covers, tags
and note), so the two never disagree about what matches. It narrows the table
before the list is paged, combines with the other filters, and is cleared with them.
"""
import re
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
JS = ROOT / 'static/js'


def test_search_narrows_the_list_in_place(node):
    script = r"""
const fs = require('fs');
global.window = global;
global.setTimeout = () => 0; global.clearTimeout = () => {}; global.setInterval = () => 0;
global.localStorage = {getItem() { return null; }, setItem() {}};
const list = {innerHTML: '', children: [1], querySelectorAll() { return []; }, querySelector() { return null; }};
const searchBox = {value: ''};
const elements = {
  createCertForm: {addEventListener() {}}, certificatesList: list, certificateSearch: searchBox,
  certificatePageSummary: {textContent: ''}, certificatePreviousPage: {}, certificateNextPage: {}
};
const head = {style: {}};
global.document = {addEventListener() {}, getElementById(id) { return elements[id] || null; },
  querySelector(selector) { return selector === '#certificatesTable thead' ? head : null; },
  querySelectorAll() { return []; }};
eval(fs.readFileSync(process.argv[1], 'utf8'));
CertMate.actions = () => {}; CertMate.globalActions = () => {};
const source = fs.readFileSync(process.argv[2], 'utf8').replace(/\}\)\(\);\s*$/, `
window.setTestCertificates = certs => { allCertificates = certs; filterCertificates(); };
window.testTag = setTagFilter;
window.testStatus = setStatusFilter;
checkVisibleDeployments = () => {};
})();`);
eval(source);

// 60 certificates, three of them different in what a search can find them by.
const certs = Array.from({length: 60}, (_, i) => ({domain: `host${String(i).padStart(3, '0')}.example.com`,
  exists: true, expired: false, days_until_expiry: 90, san_domains: [], tags: [], notes: ''}));
certs[10].san_domains = ['www.shop.example.net'];
certs[20].tags = ['loadbalancer'];
certs[30].notes = 'Ticket 1234';
certs[40].domain = 'ip-203-0-113-5'; certs[40].ip_address = '203.0.113.5';
certs[50].host = 'internal.service.lan';

function check(ok, msg) { if (!ok) throw Error(msg); }
function rows() { return (list.innerHTML.match(/data-row-domain=/g) || []).length; }
function shows(domain) { return list.innerHTML.includes(`data-row-domain="${domain}"`); }
window.setTestCertificates(certs);
check(rows() === 25, 'Setup: the first page should be 25 rows');

window.setCertificateSearch('host007');
check(rows() === 1 && shows('host007.example.com'), 'A name fragment does not narrow the list to its match');

window.setCertificateSearch('  HOST00  ');
check(rows() === 10, 'The query is not trimmed and case-folded (host000 to host009 expected)');

window.setCertificateSearch('shop.example.net');
check(rows() === 1 && shows('host010.example.com'), 'A SAN does not find its certificate');

window.setCertificateSearch('loadbalancer');
check(rows() === 1 && shows('host020.example.com'), 'A tag does not find its certificate');

window.setCertificateSearch('1234');
check(rows() === 1 && shows('host030.example.com'), 'A note does not find its certificate');

window.setCertificateSearch('203.0.113.5');
check(rows() === 1 && shows('ip-203-0-113-5'), 'An IP certificate is not found by its address');

window.setCertificateSearch('service.lan');
check(rows() === 1 && shows('host050.example.com'), 'The host a certificate is served at does not find it');

window.setCertificateSearch('nothing-matches-this');
check(rows() === 0, 'A query with no match should leave no rows');
check(list.innerHTML.includes('data-empty-state'), 'No empty state for a search with no match');

window.setCertificateSearch('');
check(rows() === 25, 'Clearing the search does not bring the whole list back');

// It narrows before paging, and a new query starts at the first page: from page two,
// a query that still leaves several pages must show the first of them, not the second.
window.changeCertificatePage(1);
check(shows('host025.example.com') && !shows('host000.example.com'), 'Setup: page two');
window.setCertificateSearch('host0');
check(shows('host000.example.com') && !shows('host025.example.com'),
  'A search made on page two did not go back to page one');
window.setCertificateSearch('host059');
check(rows() === 1 && shows('host059.example.com'), 'A match that lies on the last page is not reachable');

// It combines with the tag filter, and "clear filters" clears it with them.
window.setCertificateSearch('host0');
window.testTag('loadbalancer');
check(rows() === 1 && shows('host020.example.com'), 'The search does not combine with the tag filter');
searchBox.value = 'host0';
window.clearFilters();
check(searchBox.value === '' && rows() === 25, 'Clear filters left the search in place');
"""
    result = subprocess.run([node, '-e', script, str(JS / 'certmate.js'), str(JS / 'dashboard.js')],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_the_page_has_a_labelled_search_field_wired_to_the_action():
    template = (ROOT / 'templates/index.html').read_text()

    field = re.search(r'<input[^>]*id="certificateSearch"[^>]*>', template)
    assert field, 'the Certificates page has no search field'
    assert 'data-input="setCertificateSearch"' in field.group(0)
    assert 'data-pass="value"' in field.group(0)
    assert re.search(r'<label for="certificateSearch"', template), 'the field has no label'


def test_the_action_the_field_names_is_one_the_page_may_call():
    dashboard = (JS / 'dashboard.js').read_text()

    assert re.search(r"CertMate\.globalActions\(\[[^\]]*'setCertificateSearch'", dashboard, re.S)
    assert 'window.setCertificateSearch = setCertificateSearch' in dashboard
