"""Pagination bounds rendering and automatic deployment checks.

The certificate lists have no search field of their own: the ⌘K palette is the
one place certificates are searched (the redesign's decision, recorded in the
templates), so the same query cannot give two answers.
"""

import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


def test_certificate_navigation(node):
    js = Path(__file__).resolve().parent.parent / 'static/js'
    script = r"""
const fs = require('fs');
global.window = global;
const callbacks = new Map(); let timer = 0;
global.setTimeout = fn => { callbacks.set(++timer, fn); return timer; };
global.clearTimeout = id => callbacks.delete(id);
global.setInterval = () => 0;
let savedSize;
global.localStorage = {getItem() { return null; }, setItem(key, value) { savedSize = value; }};
const list = {innerHTML: '', children: [1], querySelectorAll() { return []; }, querySelector() { return null; }};
const elements = {
  createCertForm: {addEventListener() {}}, certificatesList: list,
  certificatePageSummary: {textContent: ''},
  certificatePreviousPage: {}, certificateNextPage: {}
};
const head = {style: {}};
global.document = {addEventListener() {}, getElementById(id) { return elements[id] || null; },
  querySelector(selector) { return selector === '#certificatesTable thead' ? head : null; },
  querySelectorAll() { return []; }};
eval(fs.readFileSync(process.argv[1], 'utf8'));
const actions = {};
CertMate.actions = values => Object.assign(actions, values);
CertMate.globalActions = () => {};
const source = fs.readFileSync(process.argv[2], 'utf8').replace(/\}\)\(\);\s*$/, `
window.setTestCertificates = certs => { allCertificates = certs; filterCertificates(); };
window.testTag = setTagFilter;
window.testChecks = () => { allCertificates.forEach(c => c.exists = true); checkVisibleDeployments(); };
window.clearDeploymentCache = () => deploymentCache.clear();
window.checked = [];
window.counted = [];
checkDeploymentStatus = domain => {
  window.checked.push(domain);
  deploymentCache.set(domain, {deployed: true, certificate_match: true});
  return Promise.resolve();
};
// What the Deployed card would show, from the same cache the real one reads.
updateDeploymentStats = () => {
  window.counted.push(allCertificates.filter(c => c.exists && deploymentCache.get(c.domain)).length);
};
})();`);
eval(source);
const certs = Array.from({length: 63}, (_, i) => ({domain: `host${String(i).padStart(3, '0')}.example.com`,
  exists: false, san_domains: i === 62 ? ['special.example.net'] : [],
  tags: i >= 60 ? ['production'] : [], notes: i === 61 ? 'ticket 1234' : ''}));
function check(ok, msg) { if (!ok) throw Error(msg); }
function rows() { return (list.innerHTML.match(/data-row-domain=/g) || []).length; }
window.setTestCertificates(certs);
check(rows() === 25 && elements.certificatePageSummary.textContent === '1\u201325 of 63', 'First page not bounded');
check(elements.certificatePreviousPage.disabled && !elements.certificateNextPage.disabled, 'Navigation state wrong');
window.changeCertificatePage(1);
check(rows() === 25 && list.innerHTML.includes('host025') && !list.innerHTML.includes('host000'), 'Second page wrong');
window.changeCertificatePage(1);
check(rows() === 13 && elements.certificateNextPage.disabled, 'Last page wrong');
window.testTag('production');
check(rows() === 3, 'Tag filter not combined');
window.clearFilters();
window.changeCertificatePageSize({value: '50'});
check(rows() === 50 && elements.certificatePageSummary.textContent === '1\u201350 of 63', 'Page size not applied');
check(savedSize === '50', 'Page size preference not saved');
window.changeCertificatePageSize({value: '5000'});
check(rows() === 50, 'Invalid page size accepted');
window.changeCertificatePage(1);
window.setTestCertificates(certs.slice(0, 2));
check(rows() === 2 && elements.certificatePageSummary.textContent === '1\u20132 of 2', 'Page not clamped after deletion');
window.changeCertificatePageSize({value: '25'});
window.setTestCertificates(certs);
window.sortCertificates('domain');
check(rows() === 25 && list.innerHTML.includes('host062') && !list.innerHTML.includes('host000'),
  'Sort not applied before pagination');
window.sortCertificates('domain');
async function settle() { for (let i = 0; i < 20; i++) await Promise.resolve(); }
// Fire pending timers oldest first, as the browser would, up to `limit` of them.
async function runTimers(limit) {
  let fired = 0;
  while (callbacks.size && (limit === undefined || fired < limit)) {
    const [id, fn] = callbacks.entries().next().value;
    callbacks.delete(id); fn(); fired++; await settle();
  }
}
const page = n => Array.from({length: 25}, (_, i) => `host${String(i + 25 * n).padStart(3, '0')}.example.com`);
(async () => {
  window.testChecks();
  await runTimers();
  check(window.checked.length === 63 && new Set(window.checked).size === 63,
    'Not every certificate was checked exactly once');
  check(page(0).every(d => window.checked.indexOf(d) < 25), 'The page on screen was not checked first');
  check(window.counted[window.counted.length - 1] === 63, 'The Deployed card does not count the whole list');

  // Everything is cached: another page asks nothing again, and the card is still whole.
  window.checked = [];
  const counts = window.counted.length;
  window.changeCertificatePage(1);
  await runTimers();
  check(window.checked.length === 0, 'Cached certificates were asked again');
  check(window.counted.length > counts && window.counted[window.counted.length - 1] === 63,
    'The card was not recomputed over the whole list');

  // After a cache clear, a page shown during a pass restarts it with its own rows first.
  window.clearDeploymentCache(); window.checked = [];
  window.changeCertificatePage(-1);
  await runTimers(1);
  check(window.checked.length === 3, 'Probe batch is not bounded');
  window.changeCertificatePage(1);
  await runTimers();
  check(page(1).every(d => window.checked.indexOf(d) >= 3 && window.checked.indexOf(d) < 28),
    'The page shown during the pass was not checked next');
  check(window.checked.length === 63 && new Set(window.checked).size === 63,
    'The restarted pass did not reach every certificate exactly once');
  check(window.counted[window.counted.length - 1] === 63, 'The card does not count the whole list after a clear');
})().catch(e => { console.error(e); process.exitCode = 1; });
"""
    result = subprocess.run([node, '-e', script, str(js / 'certmate.js'),
                             str(js / 'dashboard.js')], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_client_certificate_navigation_filters_without_refetching(node):
    js = Path(__file__).resolve().parent.parent / 'static/js'
    script = r"""
const fs = require('fs');
global.window = global;
global.localStorage = {getItem() { return null; }, setItem() {}};
const body = {innerHTML: '', querySelectorAll() { return []; }};
const elements = {certTableBody: body, clientCertificatePageSummary: {},
  clientCertificatePreviousPage: {}, clientCertificateNextPage: {}};
global.document = {addEventListener() {}, querySelectorAll() { return []; },
  getElementById(id) { return elements[id] || null; }};
eval(fs.readFileSync(process.argv[1], 'utf8'));
const actions = {}; CertMate.actions = values => Object.assign(actions, values);
CertMate.globalActions = () => {};
const certs = Array.from({length: 63}, (_, i) => ({identifier: String(i),
  common_name: `client${String(i).padStart(3, '0')}`, email: `user${i}@example.com`,
  cert_usage: i === 62 ? 'vpn' : 'api-mtls', revoked: i === 61,
  created_at: '2026-01-01', expires_at: '2027-01-01'}));
let requests = 0;
global.fetch = () => { requests++; return Promise.resolve({json: () => Promise.resolve({certificates: certs})}); };
const source = fs.readFileSync(process.argv[2], 'utf8').replace(/\}\)\(\);\s*$/,
  'window.testLoad = ccLoadCertificates; })();');
eval(source);
const rows = () => (body.innerHTML.match(/data-cc-id=/g) || []).length;
function check(ok, msg) { if (!ok) throw Error(msg); }
window.testLoad().then(() => {
  check(rows() === 25 && elements.clientCertificatePageSummary.textContent === '1\u201325 of 63',
    'Initial client page not bounded');
  actions.ccChangePage(2);
  check(rows() === 13 && elements.clientCertificateNextPage.disabled, 'Last client page wrong');
  window.ccSetStatusFilter('active'); window.ccSetUsageFilter('vpn');
  check(rows() === 1 && requests === 1, 'Client filters refetch instead of using loaded data');
  window.ccSetUsageFilter(''); actions.ccChangePageSize({value: '50'});
  check(rows() === 50, 'Client page size wrong');
  window.ccSortCertificates('common_name');
  check(body.innerHTML.includes('client000'), 'Client sort not applied before pagination');
  window.ccSetStatusFilter('revoked');
  check(rows() === 1 && body.innerHTML.includes('client061'), 'Revoked client filter wrong');
  window.ccSetUsageFilter('vpn');
  check(rows() === 0 && body.innerHTML.includes('No matching client certificates'), 'Empty filtered view incorrect');
}).catch(e => {console.error(e); process.exitCode = 1;});
"""
    result = subprocess.run([node, '-e', script, str(js / 'certmate.js'),
                             str(js / 'client-certs.js')], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_the_certificate_lists_have_no_search_field_of_their_own():
    templates = Path(__file__).resolve().parent.parent / 'templates'
    for name in ('index.html', 'partials/_client_certs.html'):
        assert 'type="search"' not in (templates / name).read_text(encoding='utf-8'), name

