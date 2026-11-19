"""The Valid counter and filter follow the renewal rule, as the rows do.

Since #1429 a certificate's state comes from `expiry_status`, the server's
renewal rule: a row reads "Expiring" when renewal is due and "Valid" otherwise,
and so do the Expiring counter and filter. (Since #1511, P25, "Expiring" is two
states, "Overdue" and "Due", each with its counter and filter chip.) The Valid counter and the Valid
filter kept a fixed "more than 30 days left". So a 47-day certificate with 20
days left, which the rule calls healthy, had a green Valid badge and was counted
nowhere: twelve Valid rows under "Valid 7, Expiring 0, Expired 0". And a
certificate whose renewal is due with more than 30 days left (a long-lived one,
or one renewing early) was counted twice, Valid and Expiring.

These run the shipped functions in node, as test_a_certificate_with_no_key_is_never_valid.py
does, so they measure the numbers the browser shows.
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


def _helpers():
    names = ['lifeKnown', 'hasExpired', 'isExpiring', 'lostItsKey', 'isOverdue', 'isDue']
    if re.search(r'\n    function isValid\(', DASHBOARD):
        names.append('isValid')
    return ''.join(_function(n) for n in names)


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
        + _helpers() + _function('updateStats')
        + "updateStats(" + json.dumps(certificates) + ");\n"
        "var out = {}; Object.keys(chips).forEach(function (k) { out[k] = Number(chips[k].textContent); });\n"
        "console.log(JSON.stringify(out));"
    )
    result = subprocess.run([node, '-e', script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def _cert(domain, days, status=None):
    cert = {'domain': domain, 'exists': True, 'expired': False, 'days_until_expiry': days,
            'reissue_required': False}
    if status:
        cert['expiry_status'] = status
    return cert


def test_a_certificate_the_rule_calls_healthy_is_counted_valid_at_twenty_days():
    """A 47-day certificate with 20 days left: renewal is not due yet."""
    out = _stats([_cert('short.example.com', 20, 'ok')])
    assert out == {'all': 1, 'valid': 1, 'overdue': 0, 'due': 0, 'expired': 0}, out


def test_a_certificate_due_for_renewal_is_not_also_counted_valid():
    """Renewal due with 40 days left: Due only, not Valid as well."""
    out = _stats([_cert('long.example.com', 40, 'warning')])
    assert out == {'all': 1, 'valid': 0, 'overdue': 0, 'due': 1, 'expired': 0}, out


def test_every_certificate_is_counted_exactly_once():
    """With known lives and keys, the three counters add up to the total."""
    certs = [_cert('a.example.com', 80, 'ok'), _cert('b.example.com', 20, 'ok'),
             _cert('c.example.com', 12, 'ok'), _cert('d.example.com', 5, 'critical'),
             _cert('e.example.com', 40, 'warning'), _cert('f.example.com', 3, 'ok'),
             dict(_cert('g.example.com', -1, 'expired'), expired=True)]
    out = _stats(certs)
    assert out['valid'] + out['overdue'] + out['due'] + out['expired'] == out['all'] == len(certs), out
    assert out == {'all': 7, 'valid': 4, 'overdue': 1, 'due': 1, 'expired': 1}, out


def test_an_older_server_without_expiry_status_keeps_the_thirty_days():
    """An answer from before contract 2.62 has no expiry_status: 30 days stays the line."""
    out = _stats([_cert('old-a.example.com', 20), _cert('old-b.example.com', 45)])
    assert out == {'all': 2, 'valid': 1, 'overdue': 0, 'due': 1, 'expired': 0}, out


def test_the_valid_filter_and_the_valid_counter_are_one_rule():
    """The filter builds DOM for a live page, so it is read from the source:
    it must use the same function as the counter, not a threshold of its own."""
    assert re.search(r'\n    function isValid\(', DASHBOARD), 'no isValid() in dashboard.js'
    assert 'days_until_expiry > 30' not in DASHBOARD
    stats = _function('updateStats')
    assert 'certificates.filter(isValid)' in stats
    assert 'var isValid = ' not in DASHBOARD and 'matchesStatus = isValid(cert);' in DASHBOARD
