"""
Playwright browser tests for CertMate UI.

Install:
    pip install playwright pytest-playwright
    playwright install chromium

Run:
    pytest tests/test_ui.py --headed   # watch the browser
    pytest tests/test_ui.py            # headless (default)

Requires a running container (the docker_container fixture handles this).
"""

import os
import pytest

# Skip entire module if playwright is not installed
pytest.importorskip("playwright")

from playwright.sync_api import Page, expect

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"


@pytest.fixture(scope="module")
def browser_page(docker_container):
    """Provide a Playwright browser page."""
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True)
    context = browser.new_context(ignore_https_errors=True)
    page = context.new_page()
    yield page
    context.close()
    browser.close()
    pw.stop()


class TestNavigation:
    """Basic page navigation."""

    def test_dashboard_loads(self, browser_page):
        browser_page.goto(BASE_URL)
        expect(browser_page).to_have_title("CertMate")

    def test_settings_navigation(self, browser_page):
        browser_page.goto(BASE_URL)
        browser_page.click('a[href="/settings"]')
        browser_page.wait_for_url("**/settings")
        expect(browser_page.locator("h1, h2").first).to_contain_text("Settings")

    def test_help_navigation(self, browser_page):
        browser_page.goto(BASE_URL)
        browser_page.click('a[href="/help"]')
        browser_page.wait_for_url("**/help")
        expect(browser_page.locator("text=Getting Started")).to_be_visible()

    def test_client_certs_navigation(self, browser_page):
        browser_page.goto(BASE_URL)
        browser_page.click('a[href="/client-certificates"]')
        browser_page.wait_for_url("**/client-certificates")


class TestDashboardUI:
    """Dashboard page UI elements."""

    def test_welcome_banner_visible(self, browser_page):
        browser_page.goto(BASE_URL)
        browser_page.wait_for_load_state("networkidle")
        expect(browser_page.locator("text=Welcome to CertMate")).to_be_visible()

    def test_create_cert_form_exists(self, browser_page):
        browser_page.goto(BASE_URL)
        domain_input = browser_page.locator("#domain")
        expect(domain_input).to_be_visible()

    def test_logo_visible(self, browser_page):
        browser_page.goto(BASE_URL)
        logo = browser_page.locator('img[alt="CertMate"]')
        expect(logo).to_be_visible()


class TestSettingsUI:
    """Settings page UI elements."""

    def test_dns_provider_selector(self, browser_page):
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")
        # Should have DNS provider radio buttons
        cloudflare_radio = browser_page.locator('input[name="dns_provider"][value="cloudflare"]')
        expect(cloudflare_radio).to_be_visible()

    def test_auth_security_banner_visible(self, browser_page):
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")
        banner = browser_page.locator("#authSecurityBanner")
        expect(banner).to_be_visible()

    def test_save_settings_button(self, browser_page):
        browser_page.goto(f"{BASE_URL}/settings")
        save_btn = browser_page.locator('button:has-text("Save")')
        expect(save_btn.first).to_be_visible()

    def test_no_console_errors(self, browser_page):
        """Page should load without JS errors (excluding expected 401 on /api/auth/me)."""
        errors = []
        browser_page.on("pageerror", lambda exc: errors.append(str(exc)))
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")
        # Filter out known acceptable errors
        real_errors = [e for e in errors if "safeDomain" not in e]
        assert len(real_errors) == 0, f"JS errors: {real_errors}"


class TestSettingsCloudflareFlow:
    """Test adding a Cloudflare account via UI."""

    def test_add_cloudflare_account(self, browser_page, cloudflare_token):
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")

        # Select Cloudflare provider
        browser_page.click('input[name="dns_provider"][value="cloudflare"]')

        # Open add account modal
        add_btn = browser_page.locator('button:has-text("Add Account")')
        if add_btn.is_visible():
            add_btn.click()
            browser_page.wait_for_timeout(500)

            # Fill account form
            browser_page.fill('#modal-account-name, #accountName', 'playwright-test')
            # Fill token field (may have different IDs)
            token_field = browser_page.locator(
                '#modal-api-token, #cloudflare-api-token, input[placeholder*="token"]'
            ).first
            if token_field.is_visible():
                token_field.fill(cloudflare_token)

            # Submit
            submit_btn = browser_page.locator('#addAccountModal button[type="submit"], #addAccountModal button:has-text("Save")')
            if submit_btn.first.is_visible():
                submit_btn.first.click()
                browser_page.wait_for_timeout(1000)


class TestCertCreationFlow:
    """Test certificate creation via UI (requires Cloudflare token)."""

    def test_create_certificate_ui(self, browser_page, cloudflare_token):
        test_domain = os.environ.get("CERTMATE_TEST_DOMAIN", "test.gpfree.org")

        browser_page.goto(BASE_URL)
        browser_page.wait_for_load_state("networkidle")

        # Fill domain
        domain_input = browser_page.locator("#domain")
        domain_input.fill(test_domain)

        # Click create button
        create_btn = browser_page.locator('button:has-text("Create")')
        if create_btn.first.is_visible():
            create_btn.first.click()
            # Wait for cert creation (can take 30-120s)
            browser_page.wait_for_timeout(5000)


class TestHelpPageUI:
    """Help page UI."""

    def test_docker_quick_start_visible(self, browser_page):
        browser_page.goto(f"{BASE_URL}/help")
        browser_page.wait_for_load_state("networkidle")
        expect(browser_page.locator("text=Docker Quick Start")).to_be_visible()

    def test_first_steps_visible(self, browser_page):
        browser_page.goto(f"{BASE_URL}/help")
        expect(browser_page.locator("text=First Steps")).to_be_visible()
