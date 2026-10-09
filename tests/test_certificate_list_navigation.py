"""Search and pagination bound rendering and automatic deployment checks."""

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
  certificateSearch: {value: ''}, certificatePageSummary: {textContent: ''},
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
window.testChecks = () => { visibleCertificates.forEach(c => c.exists = true); checkVisibleDeployments(); };
window.checked = [];
checkDeploymentStatus = domain => { window.checked.push(domain); return Promise.resolve(); };
updateDeploymentStats = () => {};
})();`);
eval(source);
const certs = Array.from({length: 63}, (_, i) => ({domain: `host${String(i).padStart(3, '0')}.example.com`,
  exists: false, san_domains: i === 62 ? ['special.example.net'] : [],
  tags: i >= 60 ? ['production'] : [], notes: i === 61 ? 'ticket 1234' : ''}));
function check(ok, msg) { if (!ok) throw Error(msg); }
function rows() { return (list.innerHTML.match(/data-row-domain=/g) || []).length; }
window.setTestCertificates(certs);
check(rows() === 25 && elements.certificatePageSummary.textContent === '1–25 of 63', 'First page not bounded');
check(elements.certificatePreviousPage.disabled && !elements.certificateNextPage.disabled, 'Navigation state wrong');
actions.changeCertificatePage(1);
check(rows() === 25 && list.innerHTML.includes('host025') && !list.innerHTML.includes('host000'), 'Second page wrong');
actions.changeCertificatePage(1);
check(rows() === 13 && elements.certificateNextPage.disabled, 'Last page wrong');
actions.searchCertificates({value: 'SPECIAL'});
check(rows() === 1 && list.innerHTML.includes('host062'), 'Search misses SAN on another page');
actions.searchCertificates({value: 'ticket 1234'});
check(rows() === 1 && list.innerHTML.includes('host061'), 'Search misses notes');
actions.searchCertificates({value: ''});
window.testTag('production');
check(rows() === 3, 'Tag filter not combined');
window.clearFilters();
actions.changeCertificatePageSize({value: '50'});
check(rows() === 50 && elements.certificatePageSummary.textContent === '1–50 of 63', 'Page size not applied');
check(savedSize === '50', 'Page size preference not saved');
actions.changeCertificatePageSize({value: '5000'});
check(rows() === 50, 'Invalid page size accepted');
actions.changeCertificatePage(1);
window.setTestCertificates(certs.slice(0, 2));
check(rows() === 2 && elements.certificatePageSummary.textContent === '1–2 of 2', 'Page not clamped after deletion');
actions.changeCertificatePageSize({value: '25'});
window.setTestCertificates(certs);
window.sortCertificates('domain');
check(rows() === 25 && list.innerHTML.includes('host062') && !list.innerHTML.includes('host000'), 'Sort not applied before pagination');
window.sortCertificates('domain');
window.testChecks();
const pending = Array.from(callbacks.values()).pop(); pending();
Promise.resolve().then(() => Promise.resolve()).then(() => {
  check(window.checked.length === 3, 'Probe batch is not bounded');
  actions.searchCertificates({value: 'not-found'});
  const scheduled = Array.from(callbacks.values());
  scheduled.forEach(fn => fn());
  check(window.checked.length === 3, 'Obsolete page continued checking off-screen certificates');
}).catch(e => { console.error(e); process.exitCode = 1; });
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
  check(rows() === 25 && elements.clientCertificatePageSummary.textContent === '1–25 of 63', 'Initial client page not bounded');
  actions.ccChangePage(2);
  check(rows() === 13 && elements.clientCertificateNextPage.disabled, 'Last client page wrong');
  actions.ccSearchCertificates({value: 'USER62@EXAMPLE.COM'});
  check(rows() === 1 && body.innerHTML.includes('client062'), 'Client email search misses another page');
  actions.ccSearchCertificates({value: ''});
  window.ccSetStatusFilter('active'); window.ccSetUsageFilter('vpn');
  check(rows() === 1 && requests === 1, 'Client filters refetch instead of using loaded data');
  window.ccSetUsageFilter(''); actions.ccChangePageSize({value: '50'});
  check(rows() === 50, 'Client page size wrong');
  window.ccSortCertificates('common_name');
  check(body.innerHTML.includes('client000'), 'Client sort not applied before pagination');
  window.ccSetStatusFilter('revoked');
  check(rows() === 1 && body.innerHTML.includes('client061'), 'Revoked client filter wrong');
  actions.ccSearchCertificates({value: 'missing'});
  check(rows() === 0 && body.innerHTML.includes('No matching client certificates'), 'Empty filtered view incorrect');
}).catch(e => {console.error(e); process.exitCode = 1;});
"""
    result = subprocess.run([node, '-e', script, str(js / 'certmate.js'),
                             str(js / 'client-certs.js')], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
