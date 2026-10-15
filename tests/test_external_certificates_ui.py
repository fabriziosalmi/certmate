"""The dashboard's side of external certificates (#1159), with the real dashboard.js.

What is sent is the part a browser test cannot see well: an external import
carries the three files and ``external: true`` and nothing about a renewal, and
a replacement carries the three files and the earlier-expiry choice to
``/api/certificates/<domain>/replace``. Each runs the shipped submit handler in
node over a small DOM double, as test_certificate_import_ui.py does for the
import a CA renews. tests/test_ui_external_certificates.py drives the same
screens in a browser.
"""
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

JS = Path(__file__).resolve().parent.parent / 'static/js'

HARNESS = r"""
const fs = require('fs');
global.window = global;
global.localStorage = {getItem() { return null; }};
global.setInterval = () => 0;
const classes = () => {
  const values = new Set();
  return {toggle(name, enabled) { if (enabled === undefined) enabled = !values.has(name);
      if (enabled) values.add(name); else values.delete(name); },
    add(...names) { names.forEach(name => values.add(name)); },
    remove(...names) { names.forEach(name => values.delete(name)); },
    contains(name) { return values.has(name); }};
};
const make = () => ({value: '', disabled: false, checked: false, dataset: {}, textContent: '',
  classList: classes(), innerHTML: 'Create', setAttribute() {}, addEventListener() {}, focus() { focused = this.id; }});
let focused = null;
const elements = {};
['createCertForm', 'importExistingCertificate', 'importAutoRenew', 'importRenewalCa', 'importRenewalExternal',
 'importAutoRenewOption', 'certificateImportFiles', 'drawerTitle', 'drawerSubtitle',
 'createCertFormContainer', 'importCertificateFile', 'importChainFile', 'importPrivateKeyFile',
 'domain', 'ca_provider_select', 'ca_account_id', 'challenge_type_select', 'dns_provider_select',
 'account_select', 'dns_alias_domain', 'cert_acme_profile', 'cert_csr', 'san_entry',
 'certificateImportMode', 'wildcard-cert', 'advanced-options', 'reissue-edit-banner',
 'importCertificateFileName', 'importChainFileName', 'importPrivateKeyFileName',
 'importCertificatePreview', 'importCertificatePreviewStatus', 'importCertificatePreviewNames',
 'importCertificatePreviewCN', 'importCertificatePreviewSAN',
 'detailDomain', 'certReplaceSection', 'replaceCertificateFile', 'replaceChainFile', 'replacePrivateKeyFile',
 'replaceAllowEarlierExpiry', 'replaceCertificateSubmit'].forEach(id => {
   elements[id] = make(); elements[id].id = id;
});
elements.importAutoRenew.checked = true;
elements.importRenewalCa.checked = true;
// A control the page had disabled before any mode: it must come back disabled.
elements.ca_account_id.disabled = true;
const dropZones = ['importCertificateFile', 'importChainFile', 'importPrivateKeyFile'].map(id => {
  const input = elements[id];
  Object.defineProperty(input, 'value', {get() { return ''; }, set(value) { if (!value) input.files = []; }});
  return {dataset: {}, classList: classes(), contains() { return false; },
    querySelector() { return input; }, addEventListener() {}};
});
global.openCreateCertForm = () => {};
const button = make(); const form = elements.createCertForm;
const issuanceOnly = [elements.domain, elements.cert_csr, elements.san_entry, elements['wildcard-cert']];
const issuanceSections = [{classList: classes(), querySelectorAll() { return issuanceOnly; }}];
const renewalSource = [elements.ca_provider_select, elements.ca_account_id, elements.challenge_type_select,
  elements.dns_provider_select, elements.account_select, elements.dns_alias_domain, elements.cert_acme_profile];
const renewalSections = [{classList: classes(), querySelectorAll() { return renewalSource; }}];
const advanced = {classList: classes()};
const inputs = Object.values(elements).concat(button);
form.querySelector = () => button;
form.querySelectorAll = selector => selector === '[data-issuance-only]' ? issuanceSections
  : selector === '[data-renewal-source]' ? renewalSections
  : selector === '[data-external-hidden]' ? [advanced] : inputs;
let submit;
form.addEventListener = (event, fn) => { if (event === 'submit') submit = fn; };
const replaceControls = [elements.replaceCertificateFile, elements.replaceChainFile, elements.replacePrivateKeyFile,
  elements.replaceAllowEarlierExpiry, elements.replaceCertificateSubmit];
elements.certReplaceSection.querySelectorAll = () => replaceControls;
global.document = {addEventListener() {}, querySelectorAll(selector) {
    return selector === '[data-import-dropzone]' ? dropZones : [];
  },
  getElementById(id) { return elements[id] || null; }};
// The repository's own scripts, run as the page runs them; nothing else is evaluated.
eval(fs.readFileSync(process.argv[1], 'utf8'));
CertMate.globalActions = () => {};
const messages = []; CertMate.toast = message => messages.push(message);
let reloaded = 0; let closed = 0;
const source = fs.readFileSync(process.argv[2], 'utf8').replace(/\}\)\(\);\s*$/, `
loadCertificates = () => { reloaded++; };
clearCreateFormAfterSubmit = () => {};
closeCertDetail = () => { closed++; };
toggleDnsProviderVisibility = () => {};
})();`);
eval(source);
function check(ok, message) { if (!ok) throw Error(message); }
const calls = [];
let answer = {ok: true, body: {domain: 'ext.example.com'}};
global.fetch = (url, options) => {
  if (url.endsWith('/import/preview')) {
    return Promise.resolve({ok: true, json: async () => ({common_names: [], sans: [], validated: false})});
  }
  calls.push({url, payload: JSON.parse(options.body)});
  return Promise.resolve({ok: answer.ok, json: () => Promise.resolve(answer.body)});
};
const pem = (name, i) => [{name: name + '.pem', size: 50,
  text: () => Promise.resolve(['CERT PEM', 'CHAIN PEM', 'PRIVATE PEM'][i])}];
async function settle() { for (let i = 0; i < 12; i++) await Promise.resolve(); }
"""


def _run(node, body):
    result = subprocess.run([node, '-e', HARNESS + body, str(JS / 'certmate.js'), str(JS / 'dashboard.js')],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_an_external_import_sends_the_files_and_nothing_about_a_renewal(node):
    _run(node, r"""
async function run() {
  ['importCertificateFile', 'importChainFile', 'importPrivateKeyFile'].forEach((id, i) => {
    elements[id].files = pem(id, i);
  });
  elements.importExistingCertificate.checked = true;
  window.toggleCertificateImport();
  check(renewalSource.every(el => el.id === 'ca_account_id' ? el.disabled : !el.disabled),
    'An import a CA renews lost its renewal source');
  elements.importRenewalCa.checked = false;
  elements.importRenewalExternal.checked = true;
  window.toggleCertificateImport();
  check(renewalSections[0].classList.contains('hidden') && renewalSource.every(el => el.disabled),
    'The renewal source of an external import is still there');
  check(elements.importAutoRenewOption.classList.contains('hidden'), 'Auto-renew offered for an external import');
  check(advanced.classList.contains('hidden'), 'Advanced options shown for an external import');
  check(issuanceOnly.every(el => el.disabled), 'Issuance-only inputs enabled in an external import');
  // Values a previous form left behind are not sent either.
  elements.ca_provider_select.value = 'sectigo';
  elements.challenge_type_select.value = 'dns-01';
  elements.dns_provider_select.value = 'cloudflare';
  elements.cert_acme_profile.value = 'tlsserver';
  elements.importAutoRenew.checked = true;
  const event = {preventDefault() {}, target: form};
  await Promise.all([submit(event), submit(event)]);
  check(calls.length === 1 && calls[0].url === '/api/certificates/import', 'External import not sent once');
  const keys = Object.keys(calls[0].payload).sort().join();
  check(keys === 'certificate,chain,external,private_key', 'External import sent ' + keys);
  check(calls[0].payload.external === true, 'external is not true');
  check(messages.some(m => m.includes('will not renew it')), 'Success does not say it is not renewed');
  // Back to the form a CA renews, with each control as it was.
  check(!elements.importExistingCertificate.checked && elements.importRenewalCa.checked &&
    !elements.importRenewalExternal.checked, 'The form did not return to a CA renewal');
  check(!renewalSections[0].classList.contains('hidden') && !advanced.classList.contains('hidden') &&
    !elements.importAutoRenewOption.classList.contains('hidden'), 'Sections stayed hidden');
  check(renewalSource.every(el => el.id === 'ca_account_id' ? el.disabled : !el.disabled),
    'A control did not get its state back');
  check(issuanceOnly.every(el => !el.disabled), 'Issuance controls not restored');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""")


def test_switching_between_the_two_renewals_gives_each_control_its_state_back(node):
    _run(node, r"""
elements.importExistingCertificate.checked = true;
window.toggleCertificateImport();
for (let i = 0; i < 2; i++) {
  elements.importRenewalCa.checked = false; elements.importRenewalExternal.checked = true;
  window.toggleCertificateImport();
  check(renewalSource.every(el => el.disabled), 'External left a renewal control enabled');
  elements.importRenewalCa.checked = true; elements.importRenewalExternal.checked = false;
  window.toggleCertificateImport();
  check(renewalSource.every(el => el.id === 'ca_account_id' ? el.disabled : !el.disabled),
    'Back to a CA renewal, a control is not as it was');
  check(issuanceOnly.every(el => el.disabled), 'Issuance-only inputs enabled while importing');
}
// Leaving the import straight from external restores both kinds of section.
elements.importRenewalCa.checked = false; elements.importRenewalExternal.checked = true;
window.toggleCertificateImport();
elements.importExistingCertificate.checked = false;
window.toggleCertificateImport();
check(issuanceOnly.every(el => !el.disabled), 'Issuance controls not restored after an external import');
check(renewalSource.every(el => el.id === 'ca_account_id' ? el.disabled : !el.disabled),
  'Renewal controls not restored after an external import');
""")


def test_a_replacement_sends_the_files_to_its_certificate(node):
    _run(node, r"""
async function run() {
  elements.detailDomain.textContent = 'ext.example.com';
  ['replaceCertificateFile', 'replaceChainFile', 'replacePrivateKeyFile'].forEach((id, i) => {
    elements[id].files = pem(id, i);
  });
  await Promise.all([window.submitReplaceCertificate('ext.example.com'),
                     window.submitReplaceCertificate('ext.example.com')]);
  check(calls.length === 1, 'Replacement not sent exactly once');
  check(calls[0].url === '/api/certificates/ext.example.com/replace', 'Wrong URL ' + calls[0].url);
  const body = calls[0].payload;
  check(body.certificate === 'CERT PEM' && body.chain === 'CHAIN PEM' && body.private_key === 'PRIVATE PEM',
    'Bundle missing');
  check(body.allow_earlier_expiry === false, 'Earlier expiry accepted without asking');
  check(closed === 1 && reloaded === 1, 'A replacement did not close the panel and reload the list');
  check(messages.some(m => m.includes('Deploy hooks run as for a renewal')), 'Success not reported');

  elements.replaceAllowEarlierExpiry.checked = true;
  await window.submitReplaceCertificate('ext.example.com');
  check(calls[1].payload.allow_earlier_expiry === true, 'The earlier-expiry choice was not sent');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""")


def test_an_earlier_expiry_refusal_points_at_the_box(node):
    _run(node, r"""
async function run() {
  ['replaceCertificateFile', 'replaceChainFile', 'replacePrivateKeyFile'].forEach((id, i) => {
    elements[id].files = pem(id, i);
  });
  answer = {ok: false, body: {code: 'REPLACEMENT_EXPIRES_EARLIER',
    error: 'The uploaded certificate expires before the one ext.example.com serves. ' +
           'Send allow_earlier_expiry: true if that is intended.'}};
  await window.submitReplaceCertificate('ext.example.com');
  check(messages.some(m => m.includes('Tick "Accept a certificate that expires before this one"')),
    'The refusal named the API field instead of the box');
  check(focused === 'replaceAllowEarlierExpiry', 'The box was not focused');
  check(replaceControls.every(el => !el.disabled), 'Controls stayed disabled after a refusal');
  check(closed === 0 && reloaded === 0, 'A refusal closed the panel');

  answer = {ok: false, body: {code: 'NAMES_ALREADY_MANAGED',
    error: 'These names are already covered by a certificate CertMate manages: taken.example.com'}};
  await window.submitReplaceCertificate('ext.example.com');
  check(messages.some(m => m.includes('taken.example.com')), 'Another refusal was not shown as sent');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""")


def test_a_replacement_without_its_three_files_is_not_sent(node):
    _run(node, r"""
async function run() {
  elements.replaceCertificateFile.files = pem('cert', 0);
  elements.replaceChainFile.files = [];
  elements.replacePrivateKeyFile.files = pem('key', 2);
  await window.submitReplaceCertificate('ext.example.com');
  elements.replaceChainFile.files = [{name: 'big.pem', size: 65537, text: () => Promise.resolve('x')}];
  await window.submitReplaceCertificate('ext.example.com');
  check(calls.length === 0, 'An incomplete or oversized bundle was sent');
  check(messages.filter(m => m.includes('Select all three PEM files')).length === 2, 'Not explained');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
""")
