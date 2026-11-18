"""Each "Settings → X" link on the Help page opens tab X, and the Help search
finds the sections for client certificates, the ACME server, Inventory and the
crypto readiness report.

UX perception audit of v2.58.0, P47 and P46. "Settings → DNS" and
"Settings → CA" linked to /settings, which opens General: the tab is the URL's
fragment. The four features had no section at all, so the search found
nothing for them. The text of Help against the code is
tests/test_help_says_what_the_product_does.py; this is the page in a browser.
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


@pytest.fixture
def page(browser_page, ui_session_cookie):
    # 1280 wide: the Settings side menu, with its tabs, is shown from lg up.
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    context.close()


def _settings_links(page):
    page.goto(f'{BASE_URL}/help', wait_until='networkidle')
    links = page.evaluate("""() => {
        const seen = new Set();
        return Array.from(document.querySelectorAll('main a[href^="/settings"]'))
            .map(a => [a.getAttribute('href'), a.textContent.trim()])
            .filter(([href, text]) => text.startsWith('Settings → ') && !seen.has(href + text) && seen.add(href + text));
    }""")
    return links


def test_help_has_settings_links_to_follow(page):
    assert len(_settings_links(page)) >= 8


def test_each_settings_link_in_help_opens_the_tab_it_names(page):
    wrong = []
    for href, text in _settings_links(page):
        named = text.split('→')[1].strip()
        page.goto(f'{BASE_URL}/help', wait_until='networkidle')
        page.locator(f'main a[href="{href}"]', has_text=text).first.click()
        page.wait_for_url(f'**{href}')
        page.wait_for_function("() => document.querySelector('[role=tab][aria-selected=true]')")
        selected = page.locator('[role=tab][aria-selected=true]').first
        label = selected.get_attribute('aria-label')
        panel = selected.get_attribute('id').replace('settings-tab-', 'settings-panel-')
        visible = page.locator(f'#{panel}').is_visible()
        if label != named or not visible:
            wrong.append(f'"{text}" ({href}) opened "{label}" (panel visible: {visible})')
    assert not wrong, 'Help links that open another tab than the one they name:\n' + '\n'.join(wrong)


@pytest.mark.parametrize('term,section', [
    ('client certificate', 'client-certificates'),
    ('EAB key', 'acme-server'),
    ('Show superseded', 'inventory'),
    ('quantum', 'crypto-readiness'),
])
def test_help_search_finds_the_section_for_the_feature(page, term, section):
    page.goto(f'{BASE_URL}/help', wait_until='networkidle')
    chip = page.locator(f'nav[aria-label="Help sections"] a[href="#{section}"]')
    assert chip.count() == 1, f'no chip for #{section}'
    page.fill('#helpSearch', term)
    # The search is debounced by 200 ms.
    page.wait_for_function(
        "id => !document.getElementById(id).classList.contains('hidden') "
        "&& document.querySelectorAll('[data-help-section].hidden').length > 0",
        arg=section, timeout=5000)
    assert page.locator(f'section#{section}').is_visible()
    assert page.locator('#noHelpResults').is_hidden()
