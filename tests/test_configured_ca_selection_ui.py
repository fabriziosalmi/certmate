"""The issuance form lists configured CAs and accounts for the selected CA."""

import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit


def test_ca_and_account_selection(node):
    root = Path(__file__).resolve().parent.parent / 'static' / 'js'
    script = r"""
const fs = require('fs');
global.window = global;
global.document = { addEventListener() {}, getElementById(id) { return elements[id] || null; } };
global.setInterval = () => 0;
const select = () => ({value: '', options: [], replaceChildren() { this.options = []; this.value = ''; },
    add(option) { this.options.push(option); }, querySelector() { return null; }});
global.Option = function(label, value) { this.textContent = label; this.value = value; };
const hidden = { add() {}, remove() {}, toggle() {} };
const elements = {
    ca_provider_select: select(), ca_account_id: select(),
    createCertForm: {addEventListener() {}},
    'ca-account-container': {classList: hidden},
    'ca-provider-info': {classList: hidden},
    challenge_type_select: {value: '', querySelector() { return null; }},
    'dns-provider-container': {style: {display: ''}}
};
const settings = {
    default_ca: 'letsencrypt',
    default_ca_accounts: {sectigo: 'bertrand'},
    ca_providers: {letsencrypt: {email: 'le@example.com'},
        sectigo: {accounts: {scm: {email: 'ops@example.com', acme_url: 'https://acme.example.com',
            eab_kid: 'kid', eab_hmac: '********'}, bertrand: {name: 'Bertrand',
            email: 'b@example.com', acme_url: 'https://acme.example.com',
            eab_kid: 'kid-2', eab_hmac: '********'}}}, zerossl: {}}
};
global.fetch = () => Promise.resolve({ok: true, json: () => Promise.resolve(settings)});
eval(fs.readFileSync(process.argv[1], 'utf8'));
eval(fs.readFileSync(process.argv[2], 'utf8'));
window.loadCAProviders().then(() => {
    const ca = elements.ca_provider_select;
    if (ca.options.map(o => o.value).join(',') !== ',letsencrypt,sectigo') throw Error('Unconfigured CA offered');
    if (ca.options[0].textContent !== "Global default: Let's Encrypt — le@example.com")
        throw Error('Global default CA account not identified');
    ca.value = 'sectigo'; window.updateCAProviderInfo();
    if (elements.ca_account_id.options.map(o => o.value).join(',') !== ',scm,bertrand' ||
        elements.ca_account_id.options[0].textContent !== 'Default for Sectigo: Bertrand')
        throw Error('Sectigo default and accounts missing');
    ca.value = 'letsencrypt'; window.updateCAProviderInfo();
    if (elements.ca_account_id.options.length !== 2 || elements.ca_account_id.options[1].value !== 'default')
        throw Error('Account from another CA was retained');
    settings.default_ca = 'sectigo';
    ca.value = '';
    return window.loadCAProviders();
}).then(() => {
    if (elements.ca_provider_select.value !== '' ||
        elements.ca_account_id.options.map(o => o.value).join(',') !== ',scm,bertrand' ||
        elements.ca_provider_select.options[0].textContent !== 'Global default: Sectigo — Bertrand')
        throw Error('Default CA account not offered');
}).catch(error => { console.error(error); process.exitCode = 1; });
"""
    result = subprocess.run([node, '-e', script, str(root / 'certmate.js'),
                             str(root / 'dashboard.js')], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_add_opens_ca_account_modal_without_changing_default(node):
    settings_js = Path(__file__).resolve().parent.parent / 'static/js/settings.js'
    script = r"""
const fs = require('fs');
global.window = global;
global.CertMate = {escapeHtml: String};
const type = {value: '', options: [{value: '', textContent: 'Choose a type'},
    {value: 'sectigo', textContent: 'Sectigo'}]};
const panels = {};
const modal = {classList: {remove(key) { this.opened = key === 'hidden'; }}};
const nameField = {value: '', classList: {classes: {}, toggle(key, on) { this.classes[key] = on; }}};
const elements = {'add-ca-type': type, 'caAccountModal': modal,
    'ca-account-name': nameField, 'default-ca': {value: 'letsencrypt'},
    'ca-test-hint': {textContent: ''}};
global.document = {
    addEventListener() {},
    getElementById(id) {
        if (elements[id]) return elements[id];
        if (id.endsWith('-config')) return panels[id] || (panels[id] = {
            style: {}, querySelectorAll() { return []; }});
        if (id.startsWith('sectigo-')) return elements[id] || (elements[id] = {value: ''});
        return null;
    },
    createTextNode(text) { return {textContent: text}; },
    createElement(tag) { return {tag, children: [], appendChild(child) { this.children.push(child); },
        addEventListener(event, fn) { this[event] = fn; }}; }
};
eval(fs.readFileSync(process.argv[1], 'utf8'));
window.openCAAccountModal();
if (!modal.classList.opened) throw Error('Add did not open the modal');
if (nameField.disabled || nameField.classList.classes['opacity-60']) throw Error('New account name is disabled');
type.value = 'sectigo'; window.selectCAAccountType();
if (panels['sectigo-config'].style.display !== 'block') throw Error('Added CA editor is hidden');
if (elements['default-ca'].value !== 'letsencrypt') throw Error('Add changed the default CA');
window.openCAAccountModal('sectigo', 'default');
if (!nameField.disabled || !nameField.classList.classes['opacity-60'] ||
    !nameField.classList.classes['cursor-not-allowed']) throw Error('Existing account name is not greyed out');
"""
    result = subprocess.run([node, '-e', script, str(settings_js)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
