"""The prevalidated challenge is available when the effective CA is Sectigo."""

import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit


HARNESS = r"""
const fs = require('fs');
const option = { hidden: true, disabled: true };
const challenge = {
  value: 'prevalidated',
  querySelector: selector => selector === 'option[value="prevalidated"]' ? option : null,
};
const ca = {value: 'sectigo'};
const dns = {style: {display: ''}};
const form = {addEventListener() {}};
global.CertMate = {escapeHtml: s => s};
global.window = {};
global.setInterval = () => 0;
global.document = {
  addEventListener() {},
  getElementById(id) {
    return {'challenge_type_select': challenge, 'ca_provider_select': ca,
            'dns-provider-container': dns, 'createCertForm': form}[id] || null;
  },
};
eval(fs.readFileSync(process.argv[1], 'utf8'));
function check(condition, message) { if (!condition) throw new Error(message); }
window.toggleDnsProviderVisibility();
check(!option.hidden && !option.disabled, 'Sectigo prevalidated option unavailable');
check(dns.style.display === 'none', 'DNS provider displayed for prevalidated');
ca.value = 'letsencrypt';
window.toggleDnsProviderVisibility();
check(option.hidden && option.disabled, 'prevalidated option available to another CA');
check(challenge.value === '', 'stale prevalidated selection survived CA change');
check(dns.style.display === '', 'DNS configuration remained hidden for another CA');
"""


def test_sectigo_only_prevalidated_selection(node):
    js = Path(__file__).resolve().parent.parent / 'static/js/dashboard.js'
    result = subprocess.run([node, '-e', HARNESS, str(js)],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
