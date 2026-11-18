"""The command palette tells assistive technology which result is highlighted,
keeps keyboard focus inside itself while it is open, and on a touch screen
offers a Cancel button instead of key hints.

UX perception audit, 2026-11-18:

- P36. The search input had no combobox role and the results were plain divs,
  so a screen reader user arrowing through results heard nothing and could not
  know what Enter would open; the highlighted row was shown only by colour.
  Tab moved focus to the page behind the open palette (25 of 25 Tabs landed
  outside it), although the dialog says aria-modal="true".
- P57. At 360x740 on a touch screen the footer said "navigate / select / esc
  close", keys a phone does not have, and there was no visible way to close
  the palette except guessing that a tap on the backdrop does it. The "Crypto
  Audit Report" entry had no icon: fa-shield-halved is not in the bundled
  Font Awesome 6.0.0.

The certificate list is given in the browser (page.route), as in
tests/test_ui_a_failed_job_toast_leads_with_the_cause.py.
"""
import json
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

CERTS = [
    {'domain': f'site{i}.example.test', 'exists': True, 'expired': False,
     'days_until_expiry': days, 'tags': [], 'san_domains': [f'site{i}.example.test']}
    for i, days in enumerate((80, 44, 20))
]

# Queries that between them list every entry the palette has without
# certificates: an icon that draws nothing is found wherever it is.
EVERY_ENTRY = ('', 'settings', 'certificate', 'deploy', 'user', 'api', 'sso',
               'backup', 'new', 'dark', 'alerts', 'documentation', 'activity')

PHONE = {'viewport': {'width': 360, 'height': 740}, 'has_touch': True, 'is_mobile': True}
TABLET = {'viewport': {'width': 1024, 'height': 768}, 'has_touch': True, 'is_mobile': True}
DESKTOP = {'viewport': {'width': 1280, 'height': 900}}


def _context(browser_page, cookie, device):
    context = browser_page.context.browser.new_context(**device)
    context.add_cookies([{'name': 'certmate_session', 'value': cookie, 'url': BASE_URL}])
    return context


def _stub_certificates(page):
    page.route('**/api/certificates', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps(CERTS)))
    page.route('**/api/client-certs', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps({'certificates': []})))


@pytest.fixture
def make_page(browser_page, ui_session_cookie):
    contexts = []

    def make(device):
        context = _context(browser_page, ui_session_cookie, device)
        contexts.append(context)
        page = context.new_page()
        _stub_certificates(page)
        page.goto(f'{BASE_URL}/', wait_until='networkidle')
        return page

    yield make
    for context in contexts:
        context.close()


def _open_with_keys(page):
    page.keyboard.press('Control+k')
    page.wait_for_selector('#cmdPalette:not(.hidden) #cmdPaletteInput', state='visible')
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'cmdPaletteInput'")


def _open_with_the_search_button(page):
    page.get_by_role('button', name='Open search').tap()
    page.wait_for_selector('#cmdPalette:not(.hidden) #cmdPaletteInput', state='visible')


def _type(page, query):
    page.fill('#cmdPaletteInput', query)


def _wait_for_certificates(page):
    page.wait_for_function(
        "() => document.getElementById('cmdPaletteResults').innerText.includes('site2.example.test')",
        timeout=10000)


def _highlighted(page):
    """What the input says is highlighted, read the way assistive technology does."""
    return page.evaluate("""() => {
        const input = document.getElementById('cmdPaletteInput');
        const id = input.getAttribute('aria-activedescendant');
        const option = id ? document.getElementById(id) : null;
        const list = document.getElementById(input.getAttribute('aria-controls') || '');
        return {
            role: input.getAttribute('role'),
            expanded: input.getAttribute('aria-expanded'),
            listRole: list ? list.getAttribute('role') : null,
            id: id,
            optionRole: option ? option.getAttribute('role') : null,
            optionSelected: option ? option.getAttribute('aria-selected') : null,
            optionInList: !!(option && list && list.contains(option)),
            optionText: option ? option.textContent.replace(/\\s+/g, ' ').trim() : null,
            selectedCount: list ? list.querySelectorAll('[role=option][aria-selected=true]').length : 0,
        };
    }""")


def _status(page):
    return page.evaluate("""() => {
        const live = document.querySelector('#cmdPalette [role=status], #cmdPalette [aria-live]');
        return live ? live.textContent.trim() : null;
    }""")


def test_arrowing_down_names_the_highlighted_certificate_to_assistive_technology(make_page):
    page = make_page(DESKTOP)
    _open_with_keys(page)
    _type(page, 'site')
    _wait_for_certificates(page)
    page.keyboard.press('ArrowDown')
    seen = _highlighted(page)
    assert seen['role'] == 'combobox', seen
    assert seen['expanded'] == 'true', seen
    assert seen['listRole'] == 'listbox', seen
    assert seen['optionRole'] == 'option', seen
    assert seen['optionInList'], seen
    assert seen['optionSelected'] == 'true', seen
    assert seen['selectedCount'] == 1, seen
    assert 'site1.example.test' in seen['optionText'], seen
    page.keyboard.press('ArrowUp')
    assert 'site0.example.test' in _highlighted(page)['optionText']


def test_the_number_of_results_is_announced(make_page):
    page = make_page(DESKTOP)
    _open_with_keys(page)
    _type(page, 'site')
    _wait_for_certificates(page)
    page.wait_for_function(
        "() => { const l = document.querySelector('#cmdPalette [role=status]');"
        " return l && l.textContent.trim() === '3 results'; }", timeout=5000)
    _type(page, 'nothing-matches-this')
    page.wait_for_function(
        "() => document.querySelector('#cmdPalette [role=status]').textContent.trim() === 'No results'",
        timeout=5000)
    assert _highlighted(page)['id'] is None
    assert _highlighted(page)['expanded'] == 'false'


def _focus(page):
    return page.evaluate("""() => ({
        open: !document.getElementById('cmdPalette').classList.contains('hidden'),
        inside: document.getElementById('cmdPalette').contains(document.activeElement),
        focus: document.activeElement ? (document.activeElement.id || document.activeElement.tagName) : null,
    })""")


def test_tab_does_not_leave_focus_on_the_page_behind_the_palette(make_page):
    page = make_page(DESKTOP)
    _open_with_keys(page)
    for key in ['Tab'] * 6 + ['Shift+Tab'] * 6:
        page.keyboard.press(key)
        where = _focus(page)
        assert where['inside'] or not where['open'], (key, where)


@pytest.mark.parametrize('spot', ['group-header', 'no-results'])
def test_tab_stays_in_the_palette_after_a_click_on_a_spot_that_takes_no_focus(make_page, spot):
    """A click on a group header or on the "No results found" line leaves
    focus on the body, outside the palette; Tab from there still lands in it
    (review of P36: Tab 1 went to the skip link, Tab 2 to the logo)."""
    page = make_page(DESKTOP)
    _open_with_keys(page)
    if spot == 'group-header':
        _type(page, 'site')
        _wait_for_certificates(page)
        page.click('#cmdPaletteResults [id^=cmdPaletteGroup-]:text-is("Server Certificates")')
    else:
        _type(page, 'nothing-matches-this')
        page.click('#cmdPaletteResults :text("No results found")')
    assert _focus(page)['open'], 'the click closed the palette'
    for key in ['Tab'] * 3 + ['Shift+Tab'] * 3:
        page.keyboard.press(key)
        where = _focus(page)
        assert where['inside'] or not where['open'], (key, where)


def _visible_text(page):
    return page.inner_text('#cmdPalette [role=dialog]').lower()


def _visible_key_hints(page):
    return page.evaluate("""() => [...document.querySelectorAll('#cmdPalette kbd')]
        .filter(k => k.getClientRects().length > 0).map(k => k.textContent)""")


@pytest.mark.parametrize('device', [PHONE, TABLET], ids=['phone-360', 'touch-tablet-1024'])
def test_on_a_touch_screen_the_palette_shows_a_cancel_button_and_no_key_hints(make_page, device):
    page = make_page(device)
    assert page.evaluate("matchMedia('(hover: none)').matches") is True
    _open_with_the_search_button(page)
    text = _visible_text(page)
    for hint in ('esc close', 'navigate'):
        assert hint not in text, (hint, text)
    assert _visible_key_hints(page) == [], _visible_key_hints(page)
    cancel = page.get_by_role('button', name='Cancel')
    assert cancel.is_visible()
    box = cancel.bounding_box()
    assert box['width'] >= 44 and box['height'] >= 44, box
    cancel.tap()
    page.wait_for_selector('#cmdPalette', state='hidden', timeout=3000)


def test_with_a_keyboard_and_mouse_the_palette_keeps_its_key_hints(make_page):
    page = make_page(DESKTOP)
    _open_with_keys(page)
    text = _visible_text(page)
    assert 'navigate' in text and 'esc close' in text, text
    assert 'ESC' in _visible_key_hints(page)
    assert page.get_by_role('button', name='Cancel').is_visible() is False


def test_every_entry_in_the_palette_draws_its_icon(make_page):
    page = make_page(PHONE)
    _open_with_the_search_button(page)
    blank, seen = set(), set()
    for query in EVERY_ENTRY:
        _type(page, query)
        rows = page.evaluate("""() => [...document.querySelectorAll('#cmdPaletteResults .cmd-result')].map(r => ({
            label: r.querySelector('.text-sm').textContent,
            before: getComputedStyle(r.querySelector('i'), '::before').content,
        }))""")
        for row in rows:
            if row['label'].endswith('.example.test'):
                continue
            seen.add(row['label'])
            if row['before'] in ('none', 'normal', '""', ''):
                blank.add(row['label'])
    assert len(seen) >= 23, sorted(seen)
    assert not blank, sorted(blank)


_PLACEHOLDER_FITS = """() => {
    const input = document.getElementById('cmdPaletteInput');
    const style = getComputedStyle(input);
    const ctx = document.createElement('canvas').getContext('2d');
    ctx.font = style.font;
    const room = input.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
    return {placeholder: input.placeholder, needs: Math.ceil(ctx.measureText(input.placeholder).width), room: room};
}"""


@pytest.mark.parametrize('device', [
    PHONE,
    {'viewport': {'width': 390, 'height': 844}, 'has_touch': True, 'is_mobile': True},
    {'viewport': {'width': 414, 'height': 896}, 'has_touch': True, 'is_mobile': True},
    TABLET,
    DESKTOP,
], ids=['phone-360', 'phone-390', 'phone-414', 'touch-tablet-1024', 'desktop-1280'])
def test_the_search_placeholder_is_not_cut_off(make_page, device):
    """Review of P57: at 360 and 390 the Cancel button left the input 212 and
    242 px, and "Search pages, settings, certificates..." needs about 246,
    so it read "Search pages, settings, certifica"."""
    page = make_page(device)
    if device.get('has_touch'):
        _open_with_the_search_button(page)
    else:
        _open_with_keys(page)
    seen = page.evaluate(_PLACEHOLDER_FITS)
    assert seen['placeholder'].startswith('Search'), seen
    assert seen['needs'] <= seen['room'], seen


def test_a_wide_screen_keeps_the_full_search_placeholder(make_page):
    page = make_page(DESKTOP)
    _open_with_keys(page)
    assert page.get_attribute('#cmdPaletteInput', 'placeholder') == 'Search pages, settings, certificates...'
    assert page.get_attribute('#cmdPaletteInput', 'aria-label') == 'Search pages, settings, certificates'
