"""Settings Save says why it did not save, and stays in view.

Found by the UX perception audit of 2026-11-18 (P07, P29). One form holds the
DNS, CA, General and Storage tabs. With the renewal threshold at 0 on General,
Save pressed on DNS did nothing: the browser could not show its message on a
hidden tab, so there was no request, no toast and no tab change, only a
console line. The Save bar was marked sticky but was the only child of its
wrapper, so it scrolled away with the page: on a phone it sat about 1200 px
below the threshold field, and a bar stuck at bottom 0 would have been under
the fixed bottom nav.

The invalid save sends nothing, so the shared instance is not written.
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
THRESHOLD = '#renewal_threshold_days'


def _context(browser_page, ui_session_cookie, width, height):
    context = browser_page.context.browser.new_context(viewport={'width': width, 'height': height})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    return context


def _open(page, tab):
    page.goto(f'{BASE_URL}/settings#{tab}', wait_until='networkidle')
    page.wait_for_function("() => typeof window.CertMate.unsavedSettings === 'function'")
    page.wait_for_selector(f'#settings-panel-{tab}', state='visible')


def test_a_save_blocked_by_a_field_on_another_tab_goes_there_and_says_so(browser_page, ui_session_cookie):
    context = _context(browser_page, ui_session_cookie, 1280, 900)
    page = context.new_page()
    try:
        _open(page, 'general')
        page.fill(THRESHOLD, '0')
        page.evaluate("() => { location.hash = 'dns'; }")
        page.wait_for_selector('#settings-panel-dns', state='visible')
        page.wait_for_selector('#settings-panel-general', state='hidden')

        writes = []
        page.on('request', lambda r: writes.append(r.url)
                if r.method != 'GET' and '/api/web/settings' in r.url else None)
        page.click('#saveBtn')

        toast = page.locator('#cm-toasts').get_by_text('Nothing was saved', exact=False)
        toast.first.wait_for(state='visible', timeout=5000)
        text = toast.first.inner_text()
        assert 'Certificate Renewal Threshold' in text, text
        assert 'General' in text, text

        page.wait_for_selector('#settings-panel-general', state='visible')
        assert page.evaluate('() => location.hash') == '#general'
        assert page.evaluate('() => document.activeElement && document.activeElement.id') == 'renewal_threshold_days'
        # One message per press of Save, not one per invalid field.
        assert toast.count() == 1, toast.all_inner_texts()
        page.wait_for_timeout(300)
        assert writes == [], writes
    finally:
        context.close()


@pytest.mark.parametrize('width,height', [(360, 740), (1280, 800)])
def test_save_stays_in_view_while_a_long_tab_scrolls(browser_page, ui_session_cookie, width, height):
    context = _context(browser_page, ui_session_cookie, width, height)
    page = context.new_page()
    try:
        _open(page, 'general')
        page.evaluate("(sel) => document.querySelector(sel).scrollIntoView({block: 'center'})", THRESHOLD)
        page.mouse.wheel(0, 300)
        page.wait_for_timeout(200)
        box = page.evaluate("""() => {
            const save = document.getElementById('saveBtn').getBoundingClientRect();
            const nav = document.getElementById('bottomTabBar');
            const navTop = nav && getComputedStyle(nav).display !== 'none'
                ? nav.getBoundingClientRect().top : window.innerHeight;
            return {top: save.top, bottom: save.bottom, navTop: navTop,
                    scrollY: window.scrollY, height: window.innerHeight,
                    pageHeight: document.documentElement.scrollHeight};
        }""")
        assert box['scrollY'] > 0, box
        # Not resting at the end of the form: the page goes on below it.
        assert box['pageHeight'] - box['scrollY'] - box['height'] > 50, box
        assert box['top'] >= 0, box
        assert box['bottom'] <= box['navTop'], box
        assert box['bottom'] <= box['height'], box
    finally:
        context.close()
