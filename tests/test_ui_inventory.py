"""Playwright browser tests for the certificate inventory pages (#471-#473).

Renders the real /inventory dashboard and /inventory/crypto-report report in a
browser against the running container, exercising the page JS (which fetches the
inventory + crypto-report APIs and reveals the admin config panel via
/api/auth/me — the container runs in setup-mode bypass = admin).
"""

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
        # Empty inventory shows its guidance, not a spinner stuck forever.
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
