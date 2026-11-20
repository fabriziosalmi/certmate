"""Every app page opens in one frame (UX perception audit, #1511, P67).

The pages used four frames. The dashboard's first card had no breadcrumb;
Settings, Activity and Inventory had theirs in the header of a card;
Notifications sat in a narrower container (max-w-5xl), so its card started
128 px to the right of the others at 1440 px; Help had its breadcrumb outside
any card, and the crypto report had a frame of its own. Now every page is in
the same max-w-7xl container, and its first card carries the breadcrumb and
the page's actions in its header (templates/partials/_page_header.html).

The first content card is found the way a person sees it, not by a marker the
fix added: the first element in <main> that is on screen and has a border or a
shadow.
"""
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER, BASE_URL

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError(
            "playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1"
        )
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

_TEMPLATES = os.path.join(os.path.dirname(__file__), '..', 'templates')

# Every page of the app a signed-in person reaches. /#client and /#acme are the
# dashboard's other two views (/client-certificates redirects to /#client), and
# /__forbidden is the 403 page an operator gets for /settings, served here from
# the template (see _forbidden_page).
PAGES = ['/', '/#client', '/#acme', '/settings', '/activity', '/inventory', '/notifications', '/help',
         '/inventory/crypto-report', '/__forbidden']

FIRST_CARD = """() => {
    const main = document.querySelector('main');
    const shown = el => {
        for (let e = el; e && e !== main; e = e.parentElement) {
            const st = getComputedStyle(e);
            if (st.display === 'none' || st.visibility === 'hidden' || parseFloat(st.opacity) === 0
                || st.position === 'fixed') return false;
        }
        const r = el.getBoundingClientRect();
        return r.width > 0 && r.height > 0;
    };
    const boxed = el => {
        const st = getComputedStyle(el);
        return st.boxShadow !== 'none' || parseFloat(st.borderTopWidth) > 0 || parseFloat(st.borderLeftWidth) > 0;
    };
    const card = [...main.querySelectorAll('*')].find(el => shown(el) && boxed(el));
    if (!card) return null;
    const box = card.getBoundingClientRect();
    const crumb = [...card.querySelectorAll('nav[aria-label="Breadcrumb"]')].find(shown) || null;
    const header = card.firstElementChild;
    const controls = header ? [...header.querySelectorAll('a, button, input, select, nav')].filter(shown) : [];
    return {
        tag: card.tagName, left: Math.round(box.left), width: Math.round(box.width),
        crumb: crumb ? crumb.innerText.replace(/\\s+/g, ' ').trim() : null,
        crumbCut: crumb ? crumb.scrollWidth > crumb.clientWidth + 1 : null,
        outside: controls.filter(c => {
            const r = c.getBoundingClientRect();
            return r.left < box.left - 0.5 || r.right > box.right + 0.5;
        }).map(c => c.tagName + ' ' + (c.getAttribute('aria-label') || c.innerText || c.id).trim().slice(0, 30)),
        // A button or link whose words broke onto a second line: one of its
        // text runs is drawn on two lines. (An icon or a count beside the
        // words sits at another height on the same line, so the runs are
        // measured one at a time.)
        wrapped: controls.filter(c => c.tagName === 'A' || c.tagName === 'BUTTON').filter(c => {
            const walker = document.createTreeWalker(c, NodeFilter.SHOW_TEXT);
            for (let node = walker.nextNode(); node; node = walker.nextNode()) {
                if (!node.textContent.trim()) continue;
                const range = document.createRange();
                range.selectNodeContents(node);
                const tops = [...range.getClientRects()].filter(b => b.width > 0).map(b => b.top);
                if (tops.length && Math.max(...tops) - Math.min(...tops) > 2) return true;
            }
            return false;
        }).map(c => c.innerText.trim().slice(0, 30)),
        screen: document.documentElement.clientWidth,
        scroll: document.documentElement.scrollWidth,
    };
}"""


def _forbidden_page():
    """The page an operator gets for /settings, rendered from 403.html.

    The instance under test is signed in as its admin, who never gets it, and
    adding a viewer to it would change what every other test sees.
    """
    from flask import Flask, render_template

    app = Flask(__name__, template_folder=_TEMPLATES)
    app.secret_key = 'test'
    with app.test_request_context('/settings'):
        return render_template('403.html', required_role='admin', current_role='viewer')


@pytest.fixture
def frames(browser_page, ui_session_cookie):
    browser = browser_page.context.browser
    forbidden = _forbidden_page()
    contexts = []

    def run(width):
        context = browser.new_context(viewport={'width': width, 'height': 900})
        contexts.append(context)
        context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
        page = context.new_page()
        page.route(f'{BASE_URL}/__forbidden', lambda route: route.fulfill(
            status=403, content_type='text/html; charset=utf-8', body=forbidden))
        seen = {}
        for path in PAGES:
            # A fresh load each time: /#client to /#acme alone is a fragment change.
            page.goto('about:blank')
            page.goto(f'{BASE_URL}{path}', wait_until='networkidle')
            page.wait_for_timeout(300)
            seen[path] = page.evaluate(FIRST_CARD)
        return seen

    yield run
    for context in contexts:
        context.close()


def test_every_page_starts_with_a_card_at_the_same_left_edge_with_its_breadcrumb_in_it(frames):
    seen = frames(1440)
    missing = {path: card for path, card in seen.items() if not card}
    assert not missing, f'no card on: {missing}'
    edges = {path: (card['left'], card['width']) for path, card in seen.items()}
    assert len(set(edges.values())) == 1, f'the first card does not start at one edge: {edges}'
    no_crumb = {path: card['tag'] for path, card in seen.items() if not card['crumb']}
    assert not no_crumb, f'no breadcrumb inside the first card: {no_crumb}'


def test_on_a_phone_no_page_header_is_cut(frames):
    seen = frames(390)
    faults = {}
    for path, card in seen.items():
        if not card or not card['crumb']:
            faults[path] = 'no card with a breadcrumb'
        elif card['crumbCut'] or card['outside'] or card['wrapped'] or card['scroll'] > card['screen']:
            faults[path] = card
    assert not faults, f'at 390 px: {faults}'


def test_the_crypto_report_prints_as_a_plain_sheet_without_its_header(browser_page):
    """The report is printed. In its card it must still print as it did
    before it had one: no breadcrumb or buttons, no card shadow, and the
    title at the sheet's edge rather than inset by the card's padding."""
    page = browser_page
    page.goto(f'{BASE_URL}/inventory/crypto-report', wait_until='networkidle')
    page.wait_for_selector('#reportBody:not(.invisible)')
    page.emulate_media(media='print')
    try:
        seen = page.evaluate("""() => {
            const root = document.getElementById('reportRoot');
            const shown = sel => [...root.querySelectorAll(sel)].filter(e => e.getClientRects().length).length;
            const shadows = [...root.querySelectorAll('*')]
                .filter(e => e.getClientRects().length && getComputedStyle(e).boxShadow !== 'none')
                .map(e => e.tagName + '.' + String(e.className).slice(0, 40));
            const edge = root.getBoundingClientRect().left + parseFloat(getComputedStyle(root).paddingLeft);
            const title = root.querySelector('h1').getBoundingClientRect().left;
            return {navs: shown('nav'), buttons: shown('button, a.btn'), shadows, inset: Math.round(title - edge)};
        }""")
    finally:
        page.emulate_media(media='screen')
    assert seen == {'navs': 0, 'buttons': 0, 'shadows': [], 'inset': 0}, seen
