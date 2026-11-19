"""Playwright browser tests for the certificate inventory pages (#471-#473).

Renders the real /inventory dashboard and /inventory/crypto-report report in a
browser against the running container, exercising the page JS (which fetches the
inventory + crypto-report APIs and reveals the admin config panel via
/api/auth/me — the container runs in setup-mode bypass = admin).
"""

import json
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

from playwright.sync_api import expect  # noqa: E402

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"


class TestInventoryPage:
    def test_nav_to_inventory(self, browser_page):
        browser_page.goto(BASE_URL)
        browser_page.click('a[href="/inventory"]')
        browser_page.wait_for_url("**/inventory")
        expect(browser_page.locator("nav[aria-label='Breadcrumb']")).to_contain_text("Inventory")

    def test_inventory_renders_without_js_errors(self, browser_page):
        errors = []
        browser_page.on("pageerror", lambda e: errors.append(str(e)))
        browser_page.goto(f"{BASE_URL}/inventory")
        browser_page.wait_for_load_state("networkidle")
        # Summary cards + crypto readiness panel are present.
        expect(browser_page.locator("#summaryCards")).to_be_visible()
        expect(browser_page.locator("#cryptoQuantum")).to_be_visible()
        # The list finishes loading, not a spinner stuck forever: the guidance
        # when the inventory holds nothing, one row per certificate otherwise.
        # Since contract 2.68 it holds the certificates CertMate manages, so on
        # the shared instance what it holds depends on the tests before this.
        expect(browser_page.locator("#invPlaceholder")).to_have_count(0)
        listed = browser_page.request.get(
            f"{BASE_URL}/api/inventory?include_superseded=false").json()["certificates"]
        if listed:
            expect(browser_page.locator("#inventoryBody tr")).to_have_count(len(listed))
        else:
            expect(browser_page.locator("#inventoryBody")).to_contain_text("Inventory is empty")
        assert errors == [], f"JS errors on /inventory: {errors}"

    def test_admin_config_panel_revealed(self, browser_page):
        # Container runs in setup-mode (admin bypass), so the admin-only config
        # panel and Scan-now button must become visible after /api/auth/me.
        browser_page.goto(f"{BASE_URL}/inventory")
        browser_page.wait_for_load_state("networkidle")
        expect(browser_page.locator("#configPanel")).to_be_visible()
        expect(browser_page.locator("#scanNowBtn")).to_be_visible()

    def test_crypto_report_page_renders(self, browser_page):
        errors = []
        browser_page.on("pageerror", lambda e: errors.append(str(e)))
        browser_page.goto(f"{BASE_URL}/inventory/crypto-report")
        browser_page.wait_for_load_state("networkidle")
        expect(browser_page.locator("#reportRoot")).to_contain_text("Cryptographic Readiness Report")
        expect(browser_page.locator("#reportSummary")).to_contain_text("Total")
        assert errors == [], f"JS errors on /inventory/crypto-report: {errors}"


# UX perception audit, 2026-11-18 (P48). Since #1505 the Managed count is the
# certificates CertMate holds, recorded at startup and on each issuance or
# renewal. Forget was offered on those rows too, and a forgotten one came back
# on neither "Scan now" nor a reload: Managed fell to 13 of 14 until a restart.
# A managed row has no Forget now; a discovered one keeps it, asked in the
# page's own dialog with what really happens next. The list is answered in the
# browser (page.route), so nothing is removed from the instance.
_MANAGED = {
    'fingerprint': 'aa' * 32, 'subject_cn': 'held.example.test', 'issuer_cn': 'Test CA',
    'managed': True, 'managed_domain': 'held.example.test', 'source': 'issued', 'group': 'issued',
    'expiry_status': 'ok', 'days_until_expiry': 80, 'not_after': '2027-02-01T00:00:00Z',
    'key': {'type': 'ECDSA', 'curve': 'secp256r1'}, 'endpoints': [], 'san_dns': ['held.example.test'],
}
_DISCOVERED = dict(_MANAGED, fingerprint='bb' * 32, subject_cn='found.example.test', managed=False,
                   managed_domain=None, source='probed', group='discovered',
                   endpoints=[{'host': 'found.example.test', 'port': 443}], san_dns=['found.example.test'])


def _inventory_answered(page, deleted):
    def answer(route):
        request = route.request
        path = request.url.split('?')[0]
        if request.method == 'GET' and path.endswith('/api/inventory'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps(
                {'certificates': [_MANAGED, _DISCOVERED], 'summary': {'superseded': 0}}))
        if request.method == 'DELETE' and '/api/inventory/' in path:
            deleted.append(path.rsplit('/', 1)[1])
            return route.fulfill(status=200, content_type='application/json',
                                 body=json.dumps({'status': 'deleted'}))
        return route.continue_()
    page.route('**/api/inventory**', answer)


def test_a_managed_certificate_cannot_be_forgotten_and_a_discovered_one_is_asked_in_the_page(browser_page):
    page = browser_page
    native = []
    page.on('dialog', lambda dialog: (native.append(dialog.message), dialog.dismiss()))
    deleted = []
    _inventory_answered(page, deleted)
    page.goto(f"{BASE_URL}/inventory", wait_until='networkidle')
    page.wait_for_selector('#inventoryBody tr:has-text("found.example.test")')

    held = page.locator('#inventoryBody tr', has_text='held.example.test')
    found = page.locator('#inventoryBody tr', has_text='found.example.test')
    assert held.locator('button:has-text("Forget")').count() == 0, \
        'a certificate CertMate manages is offered Forget'
    assert found.locator('button:has-text("Forget")').count() >= 1

    found.locator('button:has-text("Forget")').filter(visible=True).first.click()
    page.wait_for_timeout(300)
    assert native == [], f'a native dialog asked instead of the page: {native}'
    dialog = page.get_by_role('alertdialog')
    expect(dialog).to_be_visible()
    text = dialog.inner_text()
    # What it says must hold for a discovered certificate: it comes back when a
    # sweep or the CT poll finds it again, which needs the endpoint or domain
    # still configured (and, for the CT log, the certificate still valid).
    assert 'found.example.test' in text
    assert 'not touched' in text
    assert 'Discovery configuration' in text
    dialog.get_by_role('button', name='Forget').click()
    page.wait_for_timeout(500)
    assert deleted == [_DISCOVERED['fingerprint']]
