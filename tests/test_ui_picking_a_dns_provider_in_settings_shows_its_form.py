"""Picking a DNS provider in Settings brings its configuration into view.

UX perception audit, 2026-11-18 (P18): on a phone, Settings > DNS lays the
providers out two to a row, so the selected provider's configuration opens two
screens below the tile. Tapping Route53 only checked the tile: the page did not
move (scrollY 0), and its configuration heading was at y 2278 of a 3418 px
page. The section is now scrolled into view when a provider is picked with the
pointer (arrow keys in the group still move only the selection).

Nothing is saved: the test only picks a tile.
"""
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError(
            "playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1"
        )
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
IN_VIEW = """sel => {
    const r = document.querySelector(sel).getBoundingClientRect();
    return r.height > 0 && r.top >= 0 && r.bottom <= window.innerHeight;
}"""


@pytest.fixture
def phone(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(
        viewport={'width': 360, 'height': 740}, is_mobile=True, has_touch=True)
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    context.close()


def _dns_tab(page):
    page.goto(f'{BASE_URL}/settings#dns', wait_until='networkidle')
    tile = page.locator('label:has(input[name="dns_provider"][value="route53"])')
    tile.wait_for(state='visible', timeout=10000)
    return tile


def test_tapping_a_provider_scrolls_its_configuration_into_view(phone):
    tile = _dns_tab(phone)
    tile.scroll_into_view_if_needed()
    assert not phone.evaluate(f"() => ({IN_VIEW})('#route53-config h4')")
    tile.tap()
    phone.wait_for_function(f"() => ({IN_VIEW})('#route53-config h4')", timeout=3000)


def test_arrow_keys_in_the_group_do_not_scroll_the_page(phone):
    """CONTROL: moving through the tiles with the keyboard keeps the group in view."""
    _dns_tab(phone)
    radio = phone.locator('input[name="dns_provider"][value="cloudflare"]')
    radio.focus()
    before = phone.evaluate('() => window.scrollY')
    phone.keyboard.press('ArrowRight')
    phone.wait_for_timeout(800)
    assert phone.evaluate("() => document.activeElement.value") == 'route53'
    assert phone.evaluate('() => window.scrollY') == before
