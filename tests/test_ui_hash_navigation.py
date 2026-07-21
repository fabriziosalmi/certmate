"""The settings tabs and the dashboard view must follow the URL fragment.

Behavioural counterpart to the source-level guards in
test_frontend_state_regressions.py, for #425.

Eleven command-palette entries point at ``/settings#<tab>``. Assigning
``location.href`` to a fragment-only change does not reload the page, and both
templates read ``location.hash`` exactly once in ``x-data`` — so choosing
"API Keys" while already on /settings changed the URL and then visibly did
nothing. These tests drive a real browser and assert the panel actually
changes, which is the part a static check cannot prove.
"""

import os

import pytest


pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"


def _panel_visible(page, tab):
    return page.locator(f"#settings-panel-{tab}").is_visible()


def test_settings_tabs_follow_a_hash_change_without_a_reload(browser_page):
    page = browser_page
    page.goto(f"{BASE_URL}/settings#general", wait_until="networkidle")
    page.wait_for_timeout(400)
    assert _panel_visible(page, "general")

    # Exactly what the command palette does now: a fragment-only navigation.
    page.evaluate("window.location.hash = '#apikeys'")
    page.wait_for_timeout(400)

    assert _panel_visible(page, "apikeys"), \
        "the panel ignored the hash change — the palette entry would do nothing"
    assert not _panel_visible(page, "general")


def test_a_second_hash_change_keeps_working(browser_page):
    """Guards against a one-shot listener."""
    page = browser_page
    page.goto(f"{BASE_URL}/settings#general", wait_until="networkidle")
    page.wait_for_timeout(300)

    for tab in ("dns", "backup", "general"):
        page.evaluate(f"window.location.hash = '#{tab}'")
        page.wait_for_timeout(350)
        assert _panel_visible(page, tab), f"stopped following the hash at #{tab}"


def test_the_dashboard_switches_to_the_client_view_on_hash(browser_page):
    page = browser_page
    page.goto(f"{BASE_URL}/", wait_until="networkidle")
    page.wait_for_timeout(400)

    page.evaluate("window.location.hash = '#client'")
    page.wait_for_timeout(500)

    assert page.locator("#certViewClientBtn").get_attribute("aria-pressed") == "true" \
        or page.locator("#clientCertsSection, #client-certs-section").count() > 0, \
        "the dashboard ignored #client"
