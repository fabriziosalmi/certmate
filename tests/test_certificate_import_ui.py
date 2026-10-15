"""Exercise the real dashboard import submit handler with a small DOM double."""
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit


def test_import_form_sends_files_and_source_without_issuing(node):
    js = Path(__file__).resolve().parent.parent / 'static/js'
    script = r"""
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
const make = () => ({value: '', disabled: false, checked: false, dataset: {},
  classList: classes(), innerHTML: 'Create', setAttribute() {}, addEventListener() {}});
const elements = {};
 ['createCertForm', 'importExistingCertificate', 'importAutoRenew', 'importRenewalCa', 'importRenewalExternal',
 'importAutoRenewOption', 'certificateImportFiles', 'drawerTitle', 'drawerSubtitle',
 'createCertFormContainer', 'importCertificateFile', 'importChainFile', 'importPrivateKeyFile',
 'domain', 'ca_provider_select', 'ca_account_id', 'challenge_type_select', 'dns_provider_select',
 'account_select', 'dns_alias_domain', 'cert_acme_profile', 'cert_csr', 'san_entry',
 'certificateImportMode', 'wildcard-cert', 'advanced-options', 'reissue-edit-banner',
 'importCertificateFileName', 'importChainFileName', 'importPrivateKeyFileName',
 'importCertificatePreview', 'importCertificatePreviewStatus', 'importCertificatePreviewNames',
 'importCertificatePreviewCN', 'importCertificatePreviewSAN'].forEach(id => {
   elements[id] = make(); elements[id].id = id;
  });
elements.importAutoRenew.checked = true;
elements.importRenewalCa.checked = true;
const dropZones = ['importCertificateFile', 'importChainFile', 'importPrivateKeyFile'].map(id => {
  const input = elements[id];
  const handlers = {};
  Object.defineProperty(input, 'value', {get() { return ''; }, set(value) { if (!value) input.files = []; }});
  input.addEventListener = (event, handler) => handlers['input:' + event] = handler;
   return {handlers, dataset: {}, classList: classes(), contains() { return false; },
    querySelector() { return input; }, addEventListener(event, handler) { handlers[event] = handler; }};
});
global.openCreateCertForm = () => {};
const button = make(); const form = elements.createCertForm;
const sourceOnly = [elements.domain, elements.cert_csr, elements.san_entry];
const sections = [{classList: classes(), querySelectorAll() { return sourceOnly; }}];
// The renewal source stays in place for an import a CA renews.
const renewalSource = [elements.ca_provider_select, elements.ca_account_id, elements.challenge_type_select,
  elements.dns_provider_select, elements.account_select, elements.dns_alias_domain, elements.cert_acme_profile];
const renewalSections = [{classList: classes(), querySelectorAll() { return renewalSource; }}];
const externalHidden = [{classList: classes()}];
const inputs = Object.values(elements).concat(button);
form.querySelector = () => button;
form.querySelectorAll = selector => selector === '[data-issuance-only]' ? sections
  : selector === '[data-renewal-source]' ? renewalSections
  : selector === '[data-external-hidden]' ? externalHidden : inputs;
let submit;
form.addEventListener = (event, fn) => { if (event === 'submit') submit = fn; };
global.document = {addEventListener() {}, querySelectorAll(selector) {
    return selector === '[data-import-dropzone]' ? dropZones : [];
  },
  getElementById(id) { return elements[id] || null; }};
eval(fs.readFileSync(process.argv[1], 'utf8'));
CertMate.globalActions = () => {};
const messages = []; CertMate.toast = message => messages.push(message);
const source = fs.readFileSync(process.argv[2], 'utf8').replace(/\}\)\(\);\s*$/, `
loadCertificates = () => {};
clearCreateFormAfterSubmit = () => {};
allCertificates = [{domain: 'existing.example.com', challenge_type: 'http-01', ca_provider: 'letsencrypt'}];
closeCertDetail = () => {};
setSanDomains = () => {};
toggleDnsProviderVisibility = () => {};
updateCAProviderInfo = () => {};
updateDnsAliasHelp = () => {};
updateAccountSelection = () => {};
})();`);
eval(source);
function check(ok, message) { if (!ok) throw Error(message); }
const calls = [];
const previews = [];
let fail = false;
global.fetch = (url, options) => {
  if (url.endsWith('/import/preview')) {
    const body = JSON.parse(options.body); previews.push(body);
    return Promise.resolve({ok: true, json: async () => ({common_names: ['import.example.com'],
      sans: ['import.example.com', 'other.example.com'], validated: !!(body.chain && body.private_key)})});
  }
  calls.push({url, payload: JSON.parse(options.body)});
    return Promise.resolve({ok: !fail,
      json: () => Promise.resolve(fail ? {error: 'Bad chain'} : {domain: 'import.example.com'})});
};
function selectFiles(size = 50) {
  ['importCertificateFile', 'importChainFile', 'importPrivateKeyFile'].forEach((id, i) => {
    elements[id].files = [{name: id + '.pem', size, text: () => Promise.resolve(['CERT PEM', 'CHAIN PEM', 'PRIVATE PEM'][i])}];
  });
  elements.importExistingCertificate.checked = true;
  window.toggleCertificateImport();
}
async function run() {
  selectFiles();
  const chainFiles = elements.importChainFile.files;
  const keyFiles = elements.importPrivateKeyFile.files;
  elements.importChainFile.files = []; elements.importPrivateKeyFile.files = [];
  dropZones[0].handlers['input:change']();
  for (let i = 0; i < 12; i++) await Promise.resolve();
  check(Object.keys(previews[0]).join() === 'certificate', 'Partial selection sent more than the public certificate');
  check(dropZones[0].dataset.state === 'selected' && dropZones[0].classList.contains('bg-warning-surface') &&
    dropZones[1].dataset.state === 'empty', 'Selected file was not yellow while other tiles stayed empty');
  elements.importChainFile.files = chainFiles; elements.importPrivateKeyFile.files = keyFiles;
  dropZones.forEach((zone, i) => {
    const input = zone.querySelector();
    const file = input.files[0];
    const event = {preventDefault() {}, dataTransfer: {files: [file]}};
    zone.handlers.dragover(event);
    zone.handlers.drop(event);
    check(input.files[0] === file && elements[input.id + 'Name'].textContent === file.name,
      'Dropped file not selected or displayed');
    const before = input.files;
    zone.handlers.drop({...event, dataTransfer: {files: [file, file]}});
    zone.handlers.drop({...event, dataTransfer: {files: [{size: 65537}]}});
    check(input.files === before, 'Invalid drop replaced the selected file');
    input.disabled = true;
    zone.handlers.drop({...event, dataTransfer: {files: [{name: 'ignored.pem', size: 10}]}});
    check(input.files === before, 'Disabled tile accepted a drop');
    input.disabled = false;
    input.files = [{...file, name: 'picked-' + i + '.pem'}];
    zone.handlers['input:change']();
    check(elements[input.id + 'Name'].textContent === 'picked-' + i + '.pem',
      'File picker selection not displayed');
  });
  for (let i = 0; i < 12; i++) await Promise.resolve();
  check(previews.some(body => body.chain === 'CHAIN PEM' && body.private_key === 'PRIVATE PEM'),
    'Complete selection did not validate the whole bundle');
  check(dropZones.every(zone => zone.dataset.state === 'valid' && zone.classList.contains('bg-success-surface')),
    'Matching bundle did not turn all three tiles green');
  check(elements.importCertificatePreviewCN.textContent === 'import.example.com' &&
    elements.importCertificatePreviewSAN.textContent.includes('other.example.com'), 'CN/SAN preview missing');
  const normalFetch = global.fetch;
  const pendingPreviews = [];
  global.fetch = () => new Promise(resolve => pendingPreviews.push(resolve));
  const certificateZone = dropZones[0];
  certificateZone.handlers['input:change']();
  for (let i = 0; i < 4; i++) await Promise.resolve();
  certificateZone.handlers['input:change']();
  for (let i = 0; i < 4; i++) await Promise.resolve();
  const previewResponse = name => ({ok: true, json: async () => ({common_names: [name], sans: [], validated: true})});
  pendingPreviews[1](previewResponse('latest.example.com'));
  for (let i = 0; i < 8; i++) await Promise.resolve();
  pendingPreviews[0](previewResponse('stale.example.com'));
  for (let i = 0; i < 8; i++) await Promise.resolve();
  check(elements.importCertificatePreviewCN.textContent === 'latest.example.com', 'Stale preview replaced current identity');
  certificateZone.handlers['input:change']();
  for (let i = 0; i < 4; i++) await Promise.resolve();
  window.resetCertificateImport();
  pendingPreviews[2](previewResponse('cancelled.example.com'));
  for (let i = 0; i < 8; i++) await Promise.resolve();
  check(elements.importCertificatePreviewCN.textContent === '', 'Cancelled preview left certificate identity visible');
  check(dropZones.every(zone => zone.dataset.state === 'empty'), 'Cancelled preview left green tiles');
  global.fetch = normalFetch;
  selectFiles();
  global.fetch = () => Promise.resolve({ok: false, json: async () => ({error: 'Private key does not match the certificate'})});
  dropZones[2].handlers['input:change']();
  for (let i = 0; i < 12; i++) await Promise.resolve();
  check(dropZones.every(zone => zone.dataset.state === 'selected' && !zone.classList.contains('bg-success-surface')),
    'Mismatched bundle turned green');
  check(elements.importCertificatePreviewStatus.textContent.includes('does not match'), 'Mismatch error not displayed');
  global.fetch = normalFetch;
  elements.domain.value = 'IMPORT.EXAMPLE.COM';
  elements.ca_provider_select.value = 'sectigo';
  elements.ca_account_id.value = 'paid';
  elements.challenge_type_select.value = 'prevalidated';
  elements.dns_provider_select.value = 'cloudflare';
  elements.account_select.value = 'dns-prod';
  elements.cert_csr.value = 'OLD CSR';
  check(sourceOnly.every(el => el.disabled), 'Issuance-only inputs still enabled');
  check(renewalSource.every(el => !el.disabled) && !renewalSections[0].classList.contains('hidden'),
    'An import a CA renews lost its renewal source');
  const event = {preventDefault() {}, target: form};
  await Promise.all([submit(event), submit(event)]);
  check(calls.length === 1 && calls[0].url === '/api/certificates/import', 'Import issued or double-submitted');
  const body = calls[0].payload;
  check(body.certificate === 'CERT PEM' && body.chain === 'CHAIN PEM' && body.private_key === 'PRIVATE PEM', 'Missing bundle');
  check(body.auto_renew === true, 'Default import did not enable auto-renew');
  check(!body.domain && body.ca_account_id === 'paid', 'Names should be derived; source missing');
  check(!body.dns_provider && !body.account_id && !body.csr && !body.async, 'Import contains issuance-only fields');
  check(!elements.importExistingCertificate.checked && sourceOnly.every(el => !el.disabled), 'Issuance controls not restored');
  ['importCertificateFile', 'importChainFile', 'importPrivateKeyFile'].forEach(id => {
    check(elements[id].disabled && !elements[id].required && elements[id].value === '', 'Private upload not reset');
    check(elements[id + 'Name'].textContent === 'Drop or click', 'Filename not reset');
  });
  selectFiles(); fail = true;
  elements.importAutoRenew.checked = false;
  await submit(event);
  check(calls[calls.length - 1].payload.auto_renew === false, 'Import did not send auto-renew opt-out');
  check(elements.importExistingCertificate.checked && !elements.importPrivateKeyFile.disabled, 'Error prevents retry');
  check(messages.includes('Bad chain'), 'Validation error not shown');
  selectFiles(65537);
  const count = calls.length;
  await submit(event);
  check(calls.length === count, 'Oversized file was uploaded');
  window.resetCertificateImport();
  check(!elements.importExistingCertificate.checked, 'Cancel leaves import active');
  check(sourceOnly.every(el => !el.disabled), 'Cancel leaves issuance controls disabled');

  let complete;
  let started;
  const requestStarted = new Promise(resolve => started = resolve);
  global.fetch = (url, options) => {
    calls.push({url, payload: JSON.parse(options.body)});
    started();
    return new Promise(resolve => complete = resolve);
  };
  selectFiles();
  const pending = submit(event);
  await requestStarted;
  const domainBeforeEdit = elements.domain.value;
  const buttonBeforeEdit = button.innerHTML;
  window.startEditReissue('existing.example.com');
  check(elements.domain.value === domainBeforeEdit && button.innerHTML === buttonBeforeEdit,
    'Pending import allowed the edit form to replace the active form');
  check(messages.includes('Wait for the current certificate operation to finish before editing.'),
    'Busy edit did not explain why it was blocked');
  complete({ok: false, json: async () => ({error: 'Bad chain'})});
  await pending;
  window.startEditReissue('existing.example.com');
  check(!elements.importExistingCertificate.checked, 'Edit after failure still submits an import');
  check(elements.domain.value === 'existing.example.com' && elements.domain.readOnly,
    'Edit after failure did not select the existing certificate');
  check(button.innerHTML.includes('Reissue Certificate') && sourceOnly.every(el => !el.disabled),
    'Edit after failure did not restore the reissue controls');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run([node, '-e', script, str(js / 'certmate.js'),
                             str(js / 'dashboard.js')], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
