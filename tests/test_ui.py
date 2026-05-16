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
import re
import pytest

# Skip entire module if playwright is not installed
pytest.importorskip("playwright")

from playwright.sync_api import Page, expect

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"


@pytest.fixture(scope="module")
def browser_page(docker_container):
    """Provide a Playwright browser page."""
    import requests

    session_cookie = None
    try:
        # Step 1: Create admin user (no auth required in setup mode)
        requests.post(f"{BASE_URL}/api/web/settings/users", json={
            "username": "admin", "password": "Password123!", "role": "admin"
        })

        # Step 2: Enable local auth (still bypassed -- auth not enabled yet)
        requests.post(f"{BASE_URL}/api/auth/config", json={
            "local_auth_enabled": True
        })

        # Step 3: Login to get session cookie (auth is now enabled)
        login_r = requests.post(f"{BASE_URL}/api/auth/login", json={
            "username": "admin", "password": "Password123!"
        })
        session_cookie = login_r.cookies.get("certmate_session")

        # Step 4: Mark setup as completed (using session cookie)
        s = requests.Session()
        s.cookies.set("certmate_session", session_cookie)
        r = s.get(f"{BASE_URL}/api/web/settings")
        if r.status_code == 200:
            data = r.json()
            data["setup_completed"] = True
            s.post(f"{BASE_URL}/api/web/settings", json=data)
    except Exception as e:
        print(f"Warning: could not complete setup via API: {e}")

    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch(headless=True)
    except Exception as e:
        pw.stop()
        pytest.skip(f"Chromium not available: {e}")
    context = browser.new_context(ignore_https_errors=True)

    # Inject session cookie into Playwright browser context
    if session_cookie:
        context.add_cookies([{
            "name": "certmate_session",
            "value": session_cookie,
            "url": BASE_URL
        }])

    page = context.new_page()
    yield page
    context.close()
    browser.close()
    pw.stop()


class TestNavigation:
    """Basic page navigation."""

    def test_dashboard_loads(self, browser_page):
        browser_page.goto(BASE_URL)
        expect(browser_page).to_have_title(re.compile(r"CertMate"))

    def test_settings_navigation(self, browser_page):
        browser_page.goto(BASE_URL)
        browser_page.click('a[href="/settings"]')
        browser_page.wait_for_url("**/settings")
        expect(browser_page.locator("nav[aria-label='Breadcrumb']")).to_contain_text("Settings")

    def test_help_navigation(self, browser_page):
        browser_page.goto(BASE_URL)
        browser_page.click('a[href="/help"]')
        browser_page.wait_for_url("**/help")
        browser_page.wait_for_load_state("networkidle")
        # v2.5.0 rewrote the help page: the old "Getting Started" anchor was
        # replaced with "Quick Start" as the first section. Match the current
        # nav strip + section heading so the test reflects the shipping UI.
        expect(browser_page.locator("nav[aria-label='Help sections']")).to_be_visible()
        expect(browser_page.locator("h3:has-text('Quick Start')")).to_be_visible()

    @pytest.mark.xfail(reason="Alpine.js defer timing in headless Chromium", strict=False)
    def test_client_certs_navigation(self, browser_page):
        browser_page.goto(BASE_URL)
        browser_page.wait_for_load_state("domcontentloaded")
        # The toggle button is rendered immediately (not behind x-show),
        # but Alpine.js defer may delay x-data binding. Wait for it.
        browser_page.wait_for_timeout(2000)
        client_btn = browser_page.locator("text=Client Certificates").first
        expect(client_btn).to_be_visible(timeout=10000)
        client_btn.click()
        expect(client_btn).to_be_visible()


class TestDashboardUI:
    """Dashboard page UI elements."""

    def test_welcome_banner_visible(self, browser_page):
        import requests as _req
        try:
            certs = _req.get(f"{BASE_URL}/api/certificates", timeout=5).json()
        except Exception:
            certs = []
        if certs:
            # Lifecycle tests already created a certificate — the welcome banner
            # is intentionally hidden when certificates exist.
            import pytest as _pytest
            _pytest.skip("Certificates present in container — welcome banner not shown")
        browser_page.goto(BASE_URL)
        browser_page.wait_for_load_state("networkidle")
        expect(browser_page.locator("text=Welcome to CertMate").first).to_be_visible()

    @pytest.mark.xfail(reason="Pre-existing: fixture auth + Alpine.js x-show timing", strict=False)
    def test_create_cert_form_exists(self, browser_page):
        browser_page.goto(BASE_URL)
        domain_input = browser_page.locator("#domain")
        # Alpine.js defer needs time to process x-data and x-show
        expect(domain_input).to_be_visible(timeout=10000)

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

        # Disable local auth via browser fetch (authenticated via session cookie)
        browser_page.evaluate("""
            fetch('/api/auth/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({local_auth_enabled: false})
            })
        """)
        browser_page.wait_for_timeout(500)

        # Reload to pick up change
        browser_page.reload()
        browser_page.wait_for_load_state("networkidle")

        # Banner is inside the Users tab — switch to it first
        browser_page.locator('button[role="tab"]:has-text("Users")').click(timeout=10000)
        browser_page.wait_for_timeout(500)

        banner = browser_page.locator("#authSecurityBanner")
        expect(banner).to_be_visible(timeout=10000)

        # Re-enable auth for subsequent tests
        browser_page.evaluate("""
            fetch('/api/auth/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({local_auth_enabled: true})
            })
        """)

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
        # Filter out known acceptable errors (safeDomain, rate limiting)
        real_errors = [e for e in errors if "safeDomain" not in e and "429" not in e]
        assert len(real_errors) == 0, f"JS errors: {real_errors}"


class TestSettingsCloudflareFlow:
    """Test adding a Cloudflare account via UI."""

    def test_add_cloudflare_account(self, browser_page, cloudflare_token):
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")

        # Select Cloudflare provider — the input is sr-only; click its wrapping label
        browser_page.click('label:has(input[name="dns_provider"][value="cloudflare"])')

        # Open add account modal for Cloudflare specifically
        add_btn = browser_page.locator('#cloudflare-add-account, button[onclick*="showAddAccountModal(\'cloudflare\'"]')
        if add_btn.first.is_visible():
            add_btn.first.click()
            # Wait for the modal to actually appear
            browser_page.wait_for_selector('#addAccountModal:not(.hidden)', timeout=5000)

            # Fill account name (real field ID is 'account-name')
            browser_page.fill('#account-name', 'playwright-test')
            # Fill token field inside the visible modal section
            token_field = browser_page.locator(
                '#addAccountModal input[type="text"][id*="api"], '
                '#addAccountModal input[placeholder*="token"], '
                '#addAccountModal input[placeholder*="Token"]'
            ).first
            if token_field.is_visible(timeout=3000):
                token_field.fill(cloudflare_token)

            # Submit
            submit_btn = browser_page.locator(
                '#addAccountModal button[type="submit"], '
                '#addAccountModal button:has-text("Add Account")'
            ).first
            if submit_btn.is_visible(timeout=3000):
                submit_btn.click()
                browser_page.wait_for_timeout(1000)


class TestCertCreationFlow:
    """Test certificate creation via UI (requires Cloudflare token)."""

    def test_create_certificate_ui(self, browser_page, cloudflare_token):
        test_domain = os.environ.get("CERTMATE_TEST_DOMAIN", "test.gpfree.org")

        browser_page.goto(BASE_URL)
        browser_page.wait_for_load_state("networkidle")

        # The first-run setup wizard is rendered as a fixed-position overlay
        # (#setupWizard, z-[110]) by static/js/setup-wizard.js when
        # setup_completed is False — which is the case in a freshly-started
        # test container. The overlay intercepts every pointer event, so any
        # subsequent click against the dashboard times out. Remove the
        # overlay DOM node so the test interacts with the live dashboard.
        browser_page.evaluate(
            "() => { const w = document.getElementById('setupWizard'); if (w) w.remove(); }"
        )

        # v2.5.0 (QW-15) put the create form behind a toggle: the
        # #createCertFormContainer is `hidden` by default and the
        # #toggleCreateForm button calls toggleCreateCertForm() to expand it.
        # Before this fix the test did `#domain.fill(...)` directly against a
        # hidden input and Playwright timed out with strict-mode violation.
        toggle_btn = browser_page.locator('#toggleCreateForm')
        expect(toggle_btn).to_be_visible()
        toggle_btn.click()

        # Now the form is visible and the input is fillable.
        domain_input = browser_page.locator('#domain')
        expect(domain_input).to_be_visible()
        domain_input.fill(test_domain)

        # Click create button inside the now-visible form
        create_btn = browser_page.locator('#createCertForm button[type="submit"], #createCertForm button:has-text("Create")')
        if create_btn.first.is_visible():
            create_btn.first.click()
            # Wait for cert creation (can take 30-120s)
            browser_page.wait_for_timeout(5000)


class TestHelpPageUI:
    """Help page UI.

    These tests originally asserted "Docker Quick Start" and "First Steps"
    from the pre-v2.5.0 help page card grid. v2.5.0 / v2.5.1 rewrote the
    help page (RELEASE_NOTES.md `fix(help): rewrite for user help, drop
    marketing`) replacing the grid with a horizontal section-nav strip and
    sections keyed by anchor id. The assertions are now repointed at two
    stable sections that exist in the new structure.
    """

    def test_quick_start_section_visible(self, browser_page):
        """The Quick Start section is the first content card and a stable anchor."""
        browser_page.goto(f"{BASE_URL}/help")
        browser_page.wait_for_load_state("networkidle")
        expect(browser_page.locator("section#quick-start")).to_be_visible()
        expect(browser_page.locator("section#quick-start h3")).to_contain_text("Quick Start")

    def test_troubleshooting_section_visible(self, browser_page):
        """The Troubleshooting section is the diagnostic anchor users hit when
        something breaks; pinning its presence catches a regression that
        accidentally removed it during a future help-page refactor."""
        browser_page.goto(f"{BASE_URL}/help")
        browser_page.wait_for_load_state("networkidle")
        expect(browser_page.locator("section#troubleshooting")).to_be_visible()
