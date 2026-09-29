"""A certificate with no private key is never counted or shown as Valid (#966).

The dashboard decided "Valid" from the expiry alone, so a certificate restored
from a share-safe backup, with no key anywhere, read "Valid" with a green
padlock: the one state that cannot serve TLS looked like the healthy one. The
list reports `reissue_required` since contract 2.28; the stats tiles, the
Valid filter, the row and the detail panel now read it.

These run the shipped `updateStats` in node against a minimal DOM, so they
measure the numbers the browser shows rather than the source text.
"""
import json
import pathlib
import re
import shutil
import subprocess

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
DASHBOARD = (REPO / 'static' / 'js' / 'dashboard.js').read_text(encoding='utf-8')


def _function(name):
    match = re.search(r'\n    function ' + name + r'\(.*?\n    \}\n', DASHBOARD, re.S)
    assert match, f'{name} not found in dashboard.js'
    return match.group(0)


def _stats(certificates):
    node = shutil.which('node')
    if not node:
        pytest.skip('node is not available')
    script = (
        "var tiles = {innerHTML: ''}; var chips = {};\n"
        "var document = {getElementById: function (id) { return id === 'statsCards' ? tiles : null; },\n"
        "  querySelector: function (sel) { var k = sel.match(/\"(\\w+)\"/)[1];\n"
        "    return chips[k] = chips[k] || {textContent: ''}; }};\n"
        "var CertMate = {escapeHtml: function (s) { return String(s); }};\n"
        + _function('lifeKnown') + _function('hasExpired') + _function('lostItsKey')
        + _function('updateStats')
        + "updateStats(" + json.dumps(certificates) + ");\n"
        "var text = tiles.innerHTML.replace(/<[^>]+>/g, ' ').replace(/\\s+/g, ' ').trim();\n"
        "var out = {}; Object.keys(chips).forEach(function (k) { out[k] = chips[k].textContent; });\n"
        "console.log(JSON.stringify({tiles: text, chips: out}));"
    )
    result = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _cert(domain, *, keyless=False, days=79):
    return {'domain': domain, 'exists': True, 'expired': False,
            'days_until_expiry': days, 'reissue_required': keyless}


def test_a_keyless_certificate_is_not_counted_as_valid():
    out = _stats([_cert('ok.example.com'), _cert('lost.example.com', keyless=True)])
    assert '1 Valid' in out['tiles'], out
    assert out['chips'].get('valid') in (1, '1'), out


def test_the_attention_tile_names_the_keyless_ones():
    out = _stats([_cert('ok.example.com'), _cert('lost.example.com', keyless=True)])
    assert '1 No key' in out['tiles'], out


def test_an_expired_certificate_still_takes_the_attention_tile():
    """Expired is the more urgent state; the keyless one still leaves Valid."""
    expired = dict(_cert('old.example.com'), expired=True, days_until_expiry=-2)
    out = _stats([expired, _cert('lost.example.com', keyless=True)])
    assert '1 Expired' in out['tiles'] and '0 Valid' in out['tiles'], out


def test_without_keyless_certificates_nothing_changes():
    out = _stats([_cert('a.example.com'), _cert('b.example.com', days=10)])
    assert '1 Valid' in out['tiles'] and '1 Expiring' in out['tiles'], out
    assert 'No key' not in out['tiles']


def test_the_row_and_the_detail_panel_read_the_same_field():
    """The two renderers that used to say Valid read `lostItsKey` too, and
    the valid filter excludes it. Read from the source because both build DOM
    for a live page; the numbers above are measured in node."""
    assert DASHBOARD.count('lostItsKey(cert)') >= 4
    assert "var keylessRow = lostItsKey(cert);" in DASHBOARD
    assert "var keylessDetail = lostItsKey(cert);" in DASHBOARD
