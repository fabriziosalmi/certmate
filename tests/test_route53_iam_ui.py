"""The Route53 account form asks for keys only in access-key mode."""

import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit


def test_route53_account_modal_switches_authentication_fields(node):
    settings_js = Path(__file__).resolve().parent.parent / 'static/js/settings.js'
    script = r"""
const fs = require('fs');
global.window = global;
global.CertMate = {globalActions() {}, actions() {}, escapeHtml: s => String(s), formatTime: () => '12:00'};
global.setTimeout = () => 0;
const mode = {value: 'access_keys', addEventListener(event, callback) { this.onchange = callback; }};
const field = () => ({required: true, parentElement: {classList: {
    toggle(name, enabled) { this.hidden = enabled; }
}}});
const key = field(), secret = field();
const fields = {innerHTML: '', querySelector(selector) {
    return {'[name="auth_mode"]': mode, '[name="access_key_id"]': key,
            '[name="secret_access_key"]': secret}[selector] || null;
}};
const modal = {dataset: {}, classList: {remove() {}}, querySelector() { return null; }};
const elements = {addAccountModal: modal, 'addAccountModal-title': {textContent: ''},
    'modal-provider-fields': fields, 'account-name': {value: ''},
    'account-description': {value: ''}, 'set-as-default': {checked: false},
    settingsDebugOutput: {appendChild() {}, scrollHeight: 0}};
global.document = {activeElement: null, body: {style: {}}, addEventListener() {},
    getElementById(id) { return elements[id] || null; }, createElement() { return {}; }};
eval(fs.readFileSync(process.argv[1], 'utf8'));
window.showAddAccountModal('route53');
if (!fields.innerHTML.includes('AWS credentials / IAM role') || !key.required || !secret.required)
    throw Error('Access-key form is incomplete');
mode.value = 'iam_role'; mode.onchange();
if (key.required || secret.required || !key.parentElement.classList.hidden ||
    !secret.parentElement.classList.hidden) throw Error('IAM mode still requires access keys');
"""
    result = subprocess.run([node, '-e', script, str(settings_js)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_clearing_role_arn_is_sent_to_the_account_api(node):
    settings_js = Path(__file__).resolve().parent.parent / 'static/js/settings.js'
    script = r"""
const fs = require('fs');
global.window = global;
global.CertMate = {globalActions() {}, actions() {}, escapeHtml: s => String(s), formatTime: () => '12:00'};
global.FormData = class {get(key) { return {
    'edit-provider-name': 'route53', 'edit-account-id': 'prod',
    name: 'prod', description: '', set_as_default: ''}[key]; }};
const elements = {editAccountForm: {}, 'edit-modal-provider-fields': {
    querySelectorAll() { return [{name: 'assume_role_arn', value: ''}]; }},
    settingsDebugOutput: {appendChild() {}, scrollHeight: 0}};
global.document = {addEventListener() {}, createElement() { return {}; },
    getElementById(id) { return elements[id] || null; }};
let sent;
global.fetch = (url, options) => {
    sent = {url, body: JSON.parse(options.body)};
    return new Promise(() => {});
};
eval(fs.readFileSync(process.argv[1], 'utf8'));
window.saveEditAccount();
if (sent.url !== '/api/dns/route53/accounts/prod' || sent.body.assume_role_arn !== '')
    throw Error('Cleared role ARN was not submitted');
"""
    result = subprocess.run([node, '-e', script, str(settings_js)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr


def test_legacy_route53_form_updates_the_default_account_not_provider_root(node):
    settings_js = Path(__file__).resolve().parent.parent / 'static/js/settings.js'
    script = r"""
const fs = require('fs');
global.window = global;
global.CertMate = {globalActions() {}, actions() {}, escapeHtml: s => String(s), formatTime: () => '12:00'};
const values = {default_ca: 'letsencrypt', dns_provider: 'route53',
    challenge_type: 'dns-01', route53_auth_mode: 'iam_role',
    route53_region: 'eu-west-3', route53_assume_role_arn: ''};
global.FormData = class {get(key) { return values[key] || ''; }};
const legacy = {style: {display: 'block'}};
const elements = {
    'route53-legacy-config': legacy,
    route53_auth_mode: {value: 'iam_role'},
    route53_assume_role_arn: {value: 'arn:aws:iam::123456789012:role/old'},
    'storage-backend': {value: 'local_filesystem'},
    'storage-cert-dir': {value: 'certificates'},
    pfx_password: {value: ''},
    settingsDebugOutput: {appendChild() {}, scrollHeight: 0}
};
global.document = {getElementById(id) { return elements[id] || null; },
    querySelectorAll() { return []; }, addEventListener() {}, createElement() { return {}; }};
const code = fs.readFileSync(process.argv[1], 'utf8').replace(/\}\)\(\);\s*$/,
    'window.__test = (settings) => { isLoading = false; currentSettings = settings; form = {}; }; ' +
    'window.__save = saveSettings; window.__populateLegacy = populateLegacyProviderFields; })();');
eval(code);
window.__populateLegacy('route53', {auth_mode: 'iam_role', assume_role_arn: ''});
if (elements.route53_assume_role_arn.value !== '') throw Error('Reload restored a stale ARN');
const settings = {setup_completed: true, api_bearer_token_hash: 'stored',
    email: 'ops@example.com', ca_providers: {letsencrypt: {email: 'ops@example.com'}},
    dns_providers: {route53: {accounts: {default: {auth_mode: 'iam_role',
        assume_role_arn: 'arn:aws:iam::123456789012:role/old'}}}}};
let sent;
global.fetch = (url, options) => {sent = JSON.parse(options.body); return new Promise(() => {});};
window.__test(settings);
window.__save();
if (sent.dns_providers.route53.accounts.default.auth_mode !== 'iam_role' ||
    sent.dns_providers.route53.accounts.default.assume_role_arn !== '' ||
    'auth_mode' in sent.dns_providers.route53) throw Error('Legacy fields missed the account');
legacy.style.display = 'none'; window.__test(settings); window.__save();
if (sent.dns_providers) throw Error('Hidden legacy form overwrote a multi-account setup');
"""
    result = subprocess.run([node, '-e', script, str(settings_js)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
