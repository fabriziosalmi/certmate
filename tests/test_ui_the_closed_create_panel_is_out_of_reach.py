"""The create panel is out of reach while it is closed.

The panel is always in the page: closing it moves it out of sight, it is not
removed. Out of sight is not out of reach. With the panel closed, Tab still
walked through every control in it, on a control nobody could see, and a
screen reader was offered a dialog called "New certificate" that was not open.

Pinned in a browser, with the keys a person presses, because the question is
where the browser puts focus and what it hands to assistive technology. Neither
can be read off the markup: both depend on styles, on attributes set from
script, and on a focus call the page makes a third of a second after opening.

The two tests that open it and use it are the control, and they pass with or
without the change: a panel nobody can reach when it is closed is easy to build
by making it unreachable when it is open too.
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

PANEL = 'createCertFormContainer'
OPENER = 'button[title="New certificate"]'
# More presses than the dashboard has stops, however many certificates the
# modules before this one left in the list; the walk ends when it comes round.
MOST_PRESSES = 1500

# Where focus is, as a person would find it: which element, whether it is in
# the panel, and whether it is the thing on screen at its own position.
_FOCUS = """() => {
    const panel = document.getElementById('PANEL');
    const el = document.activeElement;
    if (!el || el === document.body) return null;
    window.__stops = window.__stops || 0;
    if (!el.dataset.stop) el.dataset.stop = String(++window.__stops);
    // The first box, not the bounding one: a link that wraps over two lines
    // has a bounding box whose middle is the text around it.
    const box = el.getClientRects()[0] || el.getBoundingClientRect();
    const top = document.elementFromPoint(
        box.left + box.width / 2, box.top + box.height / 2);
    return {
        stop: Number(el.dataset.stop),
        name: el.tagName.toLowerCase() + (el.id ? '#' + el.id : ''),
        in_panel: panel.contains(el),
        on_screen: top === el || el.contains(top),
        is_opener: el.matches('OPENER'),
    };
}""".replace('PANEL', PANEL).replace('OPENER', OPENER)


@pytest.fixture(scope="module")
def _loaded(browser_page):
    """The dashboard, loaded once, and what it was like before anything ran.

    Loaded once because every load spends the rate limit the UI modules share.
    Measured here, and not in the tests, because the panel a test finds is the
    one the tests before it left: after one open and close the page has put
    itself right, and a test of "as loaded" would be reading that instead.
    """
    page = browser_page
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); }"
        " catch (e) {}")
    page.goto(BASE_URL, wait_until="networkidle")
    page.wait_for_selector(OPENER, state='visible')
    assert not _is_open(page)
    first = {'dialogs': _dialogs(page), 'stops': _walk(page)}
    first['script_focus'] = page.evaluate(
        "() => { document.getElementById('domain').focus();"
        " const landed = document.activeElement.id;"
        " document.activeElement.blur(); return landed; }")
    return page, first


@pytest.fixture(scope="module")
def as_loaded(_loaded):
    return _loaded[1]


@pytest.fixture
def dashboard(_loaded):
    """The page with the panel closed, the way a person closes it: a call to
    the page's own close function here would hand the next test a panel that
    has already been put right."""
    page = _loaded[0]
    yield page
    if _is_open(page):
        page.keyboard.press('Escape')
        page.wait_for_function(
            f"() => document.getElementById('{PANEL}')"
            ".classList.contains('translate-x-full')")
    page.evaluate(
        "() => { if (document.activeElement) document.activeElement.blur(); }")
    page.wait_for_timeout(400)


def _is_open(page):
    return page.evaluate(
        f"() => !document.getElementById('{PANEL}')"
        ".classList.contains('translate-x-full')")


def _focus(page):
    return page.evaluate(_FOCUS)


def _walk(page):
    """Press Tab until focus comes back to a control it has already been on."""
    stops = []
    for _ in range(MOST_PRESSES):
        page.keyboard.press('Tab')
        here = _focus(page)
        if here is None:
            continue
        if any(seen['stop'] == here['stop'] for seen in stops):
            return stops
        stops.append(here)
    raise AssertionError(
        f'{MOST_PRESSES} presses of Tab never came back to a control already '
        f'visited; the walk cannot say it saw the whole page')


def _tab_to_opener(page):
    for _ in range(MOST_PRESSES):
        page.keyboard.press('Tab')
        here = _focus(page)
        if here and here['is_opener']:
            return
    raise AssertionError('Tab never reached the "New certificate" button')


def _dialogs(page):
    """The dialogs the browser hands to assistive technology, by name."""
    session = page.context.new_cdp_session(page)
    try:
        nodes = session.send('Accessibility.getFullAXTree')['nodes']
    finally:
        session.detach()
    return [(node.get('name') or {}).get('value', '') for node in nodes
            if not node.get('ignored')
            and (node.get('role') or {}).get('value') == 'dialog']


def test_tab_does_not_stop_inside_the_closed_panel(as_loaded):
    stops = as_loaded['stops']

    # A walk that never left the first control would agree with anything.
    assert any(stop['is_opener'] for stop in stops), (
        'the walk did not reach the button that opens the panel, so it did '
        'not cross the page')
    inside = [stop['name'] for stop in stops if stop['in_panel']]
    assert inside == [], (
        f'Tab stopped on {len(inside)} controls of a panel that is closed: '
        f'{inside}')


def test_a_script_cannot_put_focus_in_the_closed_panel(as_loaded):
    """The page itself focuses the first field a moment after opening."""
    assert as_loaded['script_focus'] != 'domain'


def test_the_closed_panel_is_not_announced(as_loaded):
    assert as_loaded['dialogs'] == []


def test_the_keyboard_opens_it_stays_in_it_and_gets_back_out(dashboard):
    _tab_to_opener(dashboard)
    dashboard.keyboard.press('Enter')
    dashboard.wait_for_function(
        "() => document.activeElement && document.activeElement.id === 'domain'")
    assert _is_open(dashboard)
    assert _dialogs(dashboard) == ['New certificate']

    dashboard.keyboard.type('reach.example.test')
    assert dashboard.input_value('#domain') == 'reach.example.test'

    for _ in range(8):
        dashboard.keyboard.press('Tab')
        here = _focus(dashboard)
        assert here and here['in_panel'], f'Tab left the open panel: {here}'
        assert here['on_screen'], f'Tab stopped on a hidden control: {here}'

    dashboard.keyboard.press('Escape')
    dashboard.wait_for_function(
        "() => document.activeElement"
        f" && document.activeElement.matches('{OPENER}')")
    assert not _is_open(dashboard)


def test_closed_again_it_is_out_of_reach_again(dashboard):
    """The state it loads in is not the only closed state."""
    dashboard.click(OPENER)
    dashboard.wait_for_function(
        "() => document.activeElement && document.activeElement.id === 'domain'")
    assert _dialogs(dashboard) == ['New certificate']
    dashboard.keyboard.press('Escape')
    dashboard.wait_for_function(
        "() => document.activeElement"
        f" && document.activeElement.matches('{OPENER}')")

    assert _dialogs(dashboard) == []
    inside = [stop['name'] for stop in _walk(dashboard) if stop['in_panel']]
    assert inside == []


def test_the_pointer_opens_it_and_its_controls_answer(dashboard):
    dashboard.click(OPENER)
    dashboard.wait_for_function(
        "() => document.activeElement && document.activeElement.id === 'domain'")
    assert _is_open(dashboard)
    dashboard.click('#drawerTypeClient')
    dashboard.wait_for_selector('#commonName', state='visible')
    dashboard.click('#commonName')
    dashboard.keyboard.type('alice')
    assert dashboard.input_value('#commonName') == 'alice'


def test_closing_before_the_first_field_is_focused_leaves_focus_outside(dashboard):
    """Opening focuses the first field a third of a second later; a person who
    closes sooner than that must not be sent into the panel they just closed."""
    _tab_to_opener(dashboard)
    dashboard.keyboard.press('Enter')
    dashboard.keyboard.press('Escape')
    dashboard.wait_for_timeout(700)

    assert not _is_open(dashboard)
    here = _focus(dashboard)
    assert here and here['is_opener'], f'focus ended on {here}'
