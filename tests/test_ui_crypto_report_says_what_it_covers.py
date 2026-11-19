"""The printable crypto readiness report says what it covers and colours a
count the way Inventory does.

UX perception audit, 2026-11-18 (P44): on an estate of 14 ECDSA P-256
certificates the report painted every row and the "Acceptable 14" card in the
warning colour, "Weak 0" red and "Modern 0" green, while Inventory showed the
same numbers neutral (#939: zero is neutral, Acceptable is never coloured). The
API's per-class explanation (NIST IR 8547) was never shown, the header printed
"Generated 2026-11-18T00:11:52.579662Z", and the intro promised "every managed
and discovered certificate" while the client certificates were not in it.

The report is answered in the browser (page.route) from the real
build_crypto_report, so both pages read the same numbers and the instance
needs no certificates.
"""
import json
import os
import re

import pytest

from modules.core.crypto_report import build_crypto_report
from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
GENERATED = '2026-11-18T00:11:52.579662Z'


def _record(n, key, sig='ecdsa-with-SHA256'):
    return {'fingerprint': f'{n:064x}', 'subject_cn': f'site{n}.example.test', 'key': key,
            'signature_algorithm': sig, 'managed': True, 'source': 'issued',
            'not_after': '2027-02-01T00:00:00Z'}


P256 = {'type': 'ECDSA', 'curve': 'secp256r1'}
ESTATES = {
    # The audited instance: every certificate acceptable, weak and modern zero.
    'all-acceptable': [_record(n, P256) for n in range(14)],
    # One of each, so a non-zero weak and modern count is coloured on both pages.
    'mixed': [_record(1, P256), _record(2, {'type': 'RSA', 'size': 1024}, 'sha256WithRSAEncryption'),
              _record(3, {'type': 'Ed25519'}, 'ed25519')],
}


def _answered(page, report):
    page.route('**/api/inventory/crypto-report**', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps(report))
        if route.request.method == 'GET' else route.continue_())


def _colour(page, selector):
    return page.eval_on_selector(selector, 'el => getComputedStyle(el).color')


def _report_card(label):
    return f'#reportSummary > div:has(> div:text-is("{label}")) > div:nth-child(2)'


@pytest.mark.parametrize('estate', sorted(ESTATES))
def test_the_report_colours_each_count_as_inventory_does(browser_page, estate):
    page = browser_page
    report = build_crypto_report(ESTATES[estate], generated_at=GENERATED)
    _answered(page, report)

    page.goto(f'{BASE_URL}/inventory', wait_until='networkidle')
    page.wait_for_function("document.getElementById('cryptoWeak').textContent.trim() !== '\\u2013'")
    inventory = {label: _colour(page, f'#{node}') for label, node in (
        ('Weak', 'cryptoWeak'), ('Acceptable', 'cryptoAcceptable'),
        ('Modern', 'cryptoModern'), ('Quantum-vulnerable', 'cryptoQuantum'))}

    page.goto(f'{BASE_URL}/inventory/crypto-report', wait_until='networkidle')
    page.wait_for_selector('#reportBody:not(.invisible)')
    foreground = _colour(page, '#reportRoot h1')
    on_report = {label: _colour(page, _report_card(label)) for label in inventory}
    assert on_report == inventory, (estate, on_report, inventory)
    by_class = report['by_classification']
    for label, key in (('Weak', 'weak'), ('Modern', 'modern')):
        if by_class[key] == 0:
            assert on_report[label] == foreground, f'{label} 0 is coloured: {on_report[label]}'
    assert on_report['Acceptable'] == foreground

    # A row the report calls acceptable reads like the card: not as a warning.
    rows = page.locator('#reportAssets tr')
    for i in range(rows.count()):
        cell = rows.nth(i).locator('td').nth(3)
        if cell.inner_text().strip() == 'acceptable':
            assert cell.evaluate('el => getComputedStyle(el).color') == foreground


def test_the_report_says_what_it_covers_explains_each_class_and_dates_itself_in_words(browser_page):
    page = browser_page
    report = build_crypto_report(ESTATES['mixed'], generated_at=GENERATED)
    _answered(page, report)
    page.goto(f'{BASE_URL}/inventory/crypto-report', wait_until='networkidle')
    page.wait_for_selector('#reportBody:not(.invisible)')

    text = page.inner_text('#reportRoot')
    lowered = text.lower()
    assert 'server certificates' in lowered
    assert 'client certificates are not' in lowered, text[:600]

    # The explanation the API carries for each class present is on the page.
    for note in {asset['deprecation'] for asset in report['assets']}:
        assert note in text, f'not shown: {note}'

    meta = page.inner_text('#reportMeta')
    assert not re.search(r'T\d{2}:\d{2}:\d{2}', meta), meta
    assert '2026' in meta and 'Nov' in meta, meta

    crumb = page.locator('nav[aria-label="Breadcrumb"] a[href="/inventory"]')
    assert crumb.count() == 1 and crumb.is_visible()
    page.emulate_media(media='print')
    assert not crumb.is_visible(), 'the breadcrumb prints'
    page.emulate_media(media='screen')
