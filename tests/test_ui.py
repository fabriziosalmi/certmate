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

# Skip the module if playwright is not installed — unless the environment
# declares that a browser MUST be available (#414). CI sets
# CERTMATE_UI_REQUIRE_BROWSER=1, so a runner missing playwright or its system
# libraries fails the job instead of skipping every test and reporting green.
from tests.conftest import _REQUIRE_BROWSER


if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError(
            "playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1"
        )
else:
    pytest.importorskip("playwright")

from playwright.sync_api import Page, expect

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"


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
        # DNS provider cards live in the DNS tab; the default tab is General,
        # so open the DNS tab first.
        browser_page.locator('button[role="tab"][aria-label="DNS"]').click(timeout=10000)
        browser_page.wait_for_timeout(300)
        # The radio itself is sr-only (visually hidden); assert its visible
        # wrapping card instead of the input.
        cloudflare_card = browser_page.locator(
            'label:has(input[name="dns_provider"][value="cloudflare"])')
        expect(cloudflare_card).to_be_visible(timeout=5000)

    def test_auth_security_banner_visible(self, browser_page):
        """Disabling local auth on an instance where it is the only credential
        is refused (409) since #581: it would put the instance back into setup
        mode, where every endpoint answers an anonymous caller as admin. So the
        'authentication is disabled' banner must NOT appear, the toggle must
        stay on, and the refusal must say why. (Before #581 this test disabled
        auth and asserted the banner; that path is now the guarded one.)"""
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")

        result = browser_page.evaluate("""
            async () => {
                const r = await fetch('/api/auth/config', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({local_auth_enabled: false})
                });
                return {status: r.status, body: await r.json()};
            }
        """)
        assert result["status"] == 409, result
        assert "setup mode" in (result["body"].get("hint") or ""), result

        # Reload: the door stayed closed, so no banner.
        browser_page.reload()
        browser_page.wait_for_load_state("networkidle")
        browser_page.locator('button[role="tab"]:has-text("Users")').click(timeout=10000)
        browser_page.wait_for_timeout(500)
        expect(browser_page.locator("#authSecurityBanner")).to_be_hidden()

        still_on = browser_page.evaluate("""
            async () => { const r = await fetch('/api/auth/config'); return (await r.json()); }
        """)
        assert still_on.get("local_auth_enabled") is True, still_on

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


class TestCAAndChallengeToggles:
    """Regression tests for issue #226: CA provider config panels and the
    HTTP-01 challenge toggle."""

    def test_google_ca_panel_shows_when_selected(self, browser_page):
        """Selecting Google Trust Services in the CA tab reveals the CA-side
        config panel. Regression: it shared id="google-config" with the DNS-tab
        Google panel, so getElementById matched the DNS one (rendered first)
        and the CA panel stayed hidden (#226)."""
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")

        # Switch to the CA tab — the label text is hidden on small viewports,
        # so target the stable aria-label.
        browser_page.locator('button[role="tab"][aria-label="CA"]').click(timeout=10000)
        browser_page.wait_for_timeout(300)

        browser_page.select_option('#default-ca', 'google')
        browser_page.wait_for_timeout(300)

        expect(browser_page.locator('#google-ca-config')).to_be_visible(timeout=5000)
        # The DNS-tab Google panel is a distinct element and stays hidden.
        expect(browser_page.locator('#google-config')).to_be_hidden()

    def test_http01_hides_dns_config_panels(self, browser_page):
        """Choosing HTTP-01 hides both the provider picker and the per-provider
        config panels. Regression: the panels are siblings of the picker, so a
        previously selected DNS config lingered under HTTP-01 (#226)."""
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")

        # The DNS challenge/provider controls live in the DNS tab; the default
        # tab is General, so open the DNS tab first.
        browser_page.locator('button[role="tab"][aria-label="DNS"]').click(timeout=10000)
        browser_page.wait_for_timeout(300)

        # Select a provider so its config panel shows.
        browser_page.click('label:has(input[name="dns_provider"][value="cloudflare"])')
        browser_page.wait_for_timeout(300)
        expect(browser_page.locator('#cloudflare-config')).to_be_visible(timeout=5000)

        # Switch to HTTP-01 — picker and config panels must both disappear.
        browser_page.click('label:has(input[name="challenge_type"][value="http-01"])')
        browser_page.wait_for_timeout(300)
        expect(browser_page.locator('#dns-provider-section')).to_be_hidden()
        expect(browser_page.locator('#dns-config-section')).to_be_hidden()
        expect(browser_page.locator('#cloudflare-config')).to_be_hidden()

        # Switching back to DNS-01 restores them.
        browser_page.click('label:has(input[name="challenge_type"][value="dns-01"])')
        browser_page.wait_for_timeout(300)
        expect(browser_page.locator('#dns-provider-section')).to_be_visible()
        expect(browser_page.locator('#dns-config-section')).to_be_visible()


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


class TestDnsAccountSelector:
    """#563 — with several accounts on one DNS provider, the create form has
    to offer them. The selector existed in the markup but never appeared:
    the loader read ``data.accounts`` off a response that is a plain list,
    so every certificate went to the default account regardless of zone."""

    def test_account_selector_lists_the_configured_accounts(self, browser_page):
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")
        browser_page.evaluate("""
            async () => {
                for (const [id, name] of [['zone-a', 'Zone A'], ['zone-b', 'Zone B']]) {
                    const r = await fetch('/api/dns/cloudflare/accounts/' + id, {
                        method: 'PUT',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({name: name, api_token: 'test-token-' + id})
                    });
                    if (!r.ok) throw new Error('PUT account ' + id + ' -> ' + r.status);
                }
            }
        """)

        browser_page.goto(BASE_URL)
        expect(browser_page.locator("#domain")).to_be_visible(timeout=10000)
        browser_page.select_option("#dns_provider_select", "cloudflare")

        container = browser_page.locator("#account-selection-container")
        expect(container).to_be_visible(timeout=10000)
        select = browser_page.locator("#account_select")
        # "Use default account" + the two configured ones (+ whatever account
        # the default settings already carry for the provider).
        values = select.locator("option").evaluate_all("els => els.map(e => e.value)")
        assert "" in values and "zone-a" in values and "zone-b" in values, values
        expect(select).to_contain_text("Zone A")
        expect(select).to_contain_text("Zone B")

        # Pick the non-default one and make sure the value that would be
        # posted is its account_id, not a label.
        browser_page.select_option("#account_select", "zone-b")
        assert browser_page.eval_on_selector("#account_select", "el => el.value") == "zone-b"

        # Another provider with no accounts: the selector hides again.
        browser_page.select_option("#dns_provider_select", "hetzner")
        expect(container).to_be_hidden()


class TestClientCertListKeepsItsFilter:
    """#562 / #561 — the client list opens on Active, keeps that view across
    a refresh (the post-revoke reload used to snap back to All), remembers
    it across page loads, and the details panel offers the .pfx bundle the
    API has served since v2.24.0 but the UI never exposed."""

    @staticmethod
    def _drop_wizard(page):
        # The first-run wizard is a fixed overlay (#setupWizard, z-[110]) that
        # intercepts every click on a fresh container; other tests remove it
        # the same way.
        page.evaluate(
            "() => { const w = document.getElementById('setupWizard'); if (w) w.remove(); }")

    def _open_client_tab(self, page):
        page.goto(BASE_URL)
        page.wait_for_load_state("domcontentloaded")
        # The server/client segmented control is Alpine-bound; give the
        # deferred x-data a moment, then switch to the client view.
        client_btn = page.locator("#certViewClientBtn")
        expect(client_btn).to_be_visible(timeout=10000)
        page.wait_for_timeout(1000)
        self._drop_wizard(page)
        client_btn.click()
        expect(client_btn).to_have_attribute("aria-pressed", "true", timeout=10000)
        page.wait_for_timeout(800)

    def test_active_is_the_view_and_it_survives_refresh_and_reload(self, browser_page):
        browser_page.goto(f"{BASE_URL}/settings")
        browser_page.wait_for_load_state("networkidle")
        ids = browser_page.evaluate("""
            async () => {
                const out = [];
                for (const cn of ['filter-keep-a', 'filter-keep-b']) {
                    const r = await fetch('/api/client-certs/create', {
                        method: 'POST', headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({common_name: cn, cert_usage: 'api-mtls', days_valid: 30})
                    });
                    if (!r.ok) throw new Error('create ' + cn + ' -> ' + r.status);
                    const body = await r.json();
                    out.push(body.identifier || (body.certificate && body.certificate.identifier));
                }
                return out;
            }
        """)
        assert len(ids) == 2 and all(ids), ids
        browser_page.evaluate("localStorage.removeItem('cm.clientTab.filters')")

        self._open_client_tab(browser_page)
        active_chip = browser_page.locator('[data-cc-status-chip="active"]')
        expect(active_chip).to_have_attribute("aria-pressed", "true")
        # Assert on our two identifiers, not on a global count: the container
        # is session-scoped and other tests may leave certificates behind.

        def row(identifier):
            return browser_page.locator(
                '#certTableBody button[data-cc-action="details"][data-id="%s"]' % identifier)
        expect(row(ids[0])).to_be_visible(timeout=10000)
        expect(row(ids[1])).to_be_visible(timeout=10000)

        # Revoke one through the API and refresh the way the Revoke button
        # does: the view must still be Active, with one row fewer.
        browser_page.evaluate("""
            async (id) => {
                const r = await fetch('/api/client-certs/' + id + '/revoke', {
                    method: 'POST', headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({reason: 'test'})
                });
                if (!r.ok) throw new Error('revoke -> ' + r.status);
                window.ccRefresh();
            }
        """, ids[0])
        expect(row(ids[0])).to_have_count(0, timeout=10000)
        expect(row(ids[1])).to_be_visible()
        expect(active_chip).to_have_attribute("aria-pressed", "true")

        # Remembered across a page load.
        self._drop_wizard(browser_page)
        browser_page.locator('[data-cc-status-chip="revoked"]').click()
        expect(row(ids[0])).to_be_visible(timeout=10000)
        expect(row(ids[1])).to_have_count(0)
        self._open_client_tab(browser_page)
        expect(browser_page.locator('[data-cc-status-chip="revoked"]')).to_have_attribute("aria-pressed", "true")
        expect(row(ids[0])).to_be_visible(timeout=10000)
        expect(row(ids[1])).to_have_count(0)

        # The details panel has the PKCS#12 button next to crt/key/csr.
        self._drop_wizard(browser_page)
        row(ids[0]).click()
        pfx = browser_page.locator('button[onclick="downloadCertFile(\'pfx\')"]')
        expect(pfx).to_be_visible(timeout=5000)


class TestAuthDisabledBanner:
    """The 'authentication is disabled' banner depends on one HTTP answer
    (settings.js: fetch('/api/auth/config') → show when local_auth_enabled is
    false), not on server state. Intercepting that route keeps the banner
    covered without putting the instance into a state the guard now refuses
    (#581) and without the old test's re-enable dance."""

    def test_banner_shows_when_local_auth_is_reported_off(self, browser_page):
        browser_page.route(
            "**/api/auth/config",
            lambda route: route.fulfill(
                status=200, content_type="application/json",
                body='{"local_auth_enabled": false, "has_users": true}'),
        )
        try:
            browser_page.goto(f"{BASE_URL}/settings")
            browser_page.wait_for_load_state("networkidle")
            browser_page.locator('button[role="tab"]:has-text("Users")').click(timeout=10000)
            expect(browser_page.locator("#authSecurityBanner")).to_be_visible(timeout=10000)
        finally:
            # browser_page is module-scoped: the stub must not outlive this
            # test whatever happens above, or the "banner hidden" assertion
            # elsewhere in the module turns red for a reason three screens away.
            browser_page.unroute("**/api/auth/config")


class TestDeliberateNoAuthToggle:
    """#587 — the local-auth toggle on a local-only instance: the first request
    is refused (409), the UI asks with the one-way-door wording, confirming
    repeats the request with the flag and authentication is off; cancelling
    leaves it on. Re-enabled at the end for the tests after this one."""

    def _open_users_tab(self, page):
        page.goto(f"{BASE_URL}/settings")
        page.wait_for_load_state("networkidle")
        page.evaluate("() => { const w = document.getElementById('setupWizard'); if (w) w.remove(); }")
        page.locator('button[role="tab"]:has-text("Users")').click(timeout=10000)
        page.wait_for_timeout(400)

    def test_cancel_keeps_auth_on_and_confirm_turns_it_off(self, browser_page):
        self._open_users_tab(browser_page)
        # The toggle's state arrives from /api/auth/config asynchronously;
        # wait for it rather than reading it the instant the tab opens.
        expect(browser_page.locator("#localAuthToggle")).to_be_checked(timeout=10000)

        # Cancel: the 409 arrives, the dialog shows, nothing changes.
        browser_page.evaluate("document.getElementById('localAuthToggle').click()")
        dialog_confirm = browser_page.locator('[data-action="confirm"]')
        expect(dialog_confirm).to_be_visible(timeout=10000)
        expect(browser_page.get_by_text("Run without authentication?")).to_be_visible()
        browser_page.locator('[data-action="cancel"]').click()
        browser_page.wait_for_timeout(500)
        assert browser_page.evaluate("""
            async () => (await (await fetch('/api/auth/config')).json()).local_auth_enabled
        """) is True
        expect(browser_page.locator("#localAuthToggle")).to_be_checked(timeout=5000)

        # Confirm: the request is repeated with the flag and auth goes off.
        try:
            browser_page.evaluate("document.getElementById('localAuthToggle').click()")
            expect(dialog_confirm).to_be_visible(timeout=10000)
            dialog_confirm.click()
            browser_page.wait_for_timeout(800)
            assert browser_page.evaluate("""
                async () => (await (await fetch('/api/auth/config')).json()).local_auth_enabled
            """) is False
            expect(browser_page.locator("#authSecurityBanner")).to_be_visible(timeout=5000)
        finally:
            # Re-enable for the tests after this one (never needs the flag).
            browser_page.evaluate("""
                async () => { await fetch('/api/auth/config', {method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({local_auth_enabled: true})}); }
            """)
        assert browser_page.evaluate("""
            async () => (await (await fetch('/api/auth/config')).json()).local_auth_enabled
        """) is True
