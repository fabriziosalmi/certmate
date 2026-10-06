"""A control names what it does, and one listener does it.

The markup had an event-handler attribute on some hundred and fifty controls.
Each now carries a name (`data-click`, `data-change`, `data-input`), and one
listener in static/js/certmate.js looks it up among the actions the page
registered. tests/test_no_markup_carries_script.py checks the markup and the
registry as text; this is what text cannot say, in a browser with a real mouse
and a real keyboard.

**The listener.** A handler attribute lived on its element and ran there. One
listener on the document has to decide whose event it is, and three of those
decisions used to be the handler's own code: a click on a button inside a
clickable row is the button's (it called `event.stopPropagation()`), a dialog's
backdrop closes it only when the click is on the backdrop itself (it compared
`event.target` with `this`), and a row that acts as a button answers Enter and
Space (it had an `onkeydown`). They are tried on markup made for the purpose,
with actions that only record how they were called.

**The pages.** Every control on every page and every Settings tab names an
action that is registered there, which is what a control that does nothing
would get wrong. Then the dashboard is used: a row, the dialog it opens, and
the buttons a script builds into that dialog with the certificate's name as
their argument.
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


def _certificate(domain, **more):
    return dict({'domain': domain, 'exists': True, 'days_left': 60, 'expiry_date': '2026-12-04 10:00:00',
                 'expires_at': '2026-12-04T10:00:00Z', 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt',
                 'auto_renew': True, 'san_domains': [], 'has_private_key': True}, **more)


CERTIFICATES = [_certificate('alpha.example.test'), _certificate('beta.example.test', days_left=5)]

# Markup made for the listener, in a corner of the page and above everything.
PLAYGROUND = """() => {
    window.__calls = [];
    const seen = (value) => (value instanceof Event ? '<event ' + value.type + '>'
        : value instanceof Element ? '<' + value.id + '>' : value);
    CertMate.actions({'playground.record': function () {
        window.__calls.push(Array.from(arguments).map(seen));
    }});
    const box = document.createElement('div');
    box.id = 'playground';
    box.style.cssText = 'position:fixed;top:0;left:0;z-index:2147483647;background:#fff;color:#000;padding:8px;'
        + 'font:14px sans-serif';
    box.innerHTML = `
      <button type="button" id="pg-plain" data-click="playground.record">plain</button>
      <button type="button" id="pg-args" data-click="playground.record" data-args='["a", 2, true, null]'>args</button>
      <button type="button" id="pg-passed" data-click="playground.record" data-args='["x"]'
              data-pass="el,event">passed</button>
      <input type="checkbox" id="pg-box" data-change="playground.record" data-pass="checked">
      <input type="text" id="pg-text" data-input="playground.record" data-pass="value">
      <div id="pg-row" data-click="playground.record" data-args='["row"]' tabindex="0" role="button"
           style="padding:6px;border:1px solid #999">
        <span id="pg-text-in-row">a row</span>
        <button type="button" id="pg-button-in-row">a button with a listener of its own</button>
        <button type="button" id="pg-action-in-row" data-click="playground.record" data-args='["inner"]'>an action</button>
      </div>
      <div id="pg-backdrop" data-click="playground.record" data-args='["backdrop"]' data-self
           style="padding:16px;background:#ddd">
        <p id="pg-card" style="margin:0;background:#fff;padding:6px">the dialog</p>
      </div>
      <a href="#pg-went" id="pg-link" data-click="playground.record" data-args='["link"]'>a link</a>
      <button type="button" id="pg-unknown" data-click="playground.nothing">unknown</button>`;
    document.body.appendChild(box);
    document.getElementById('pg-button-in-row').addEventListener('click', () => window.__calls.push(['its own']));
}"""


@pytest.fixture(scope="module")
def page(browser_page):
    page = browser_page
    page.emulate_media(reduced_motion='reduce')
    page.said = []

    def heard(message):
        # What a script said. A request that failed is not that: the two
        # certificates of this module exist nowhere, and the page asks about
        # them. Nor is a request the browser dropped because the test left the
        # page while it was out: the settings page asks for its backups three
        # seconds after it loads, which is when the walk below moves on.
        if message.type != 'error' or 'Failed to load resource' in message.text:
            return
        if 'TypeError: Failed to fetch' in message.text:
            return
        page.said.append(message.text)

    page.on('console', heard)
    page.on('pageerror', lambda error: page.said.append(f'uncaught: {error}'))
    page.route('**/api/certificates', lambda route: (
        route.fulfill(status=200, content_type='application/json', body=json.dumps(CERTIFICATES))
        if route.request.method == 'GET' else route.continue_()))
    return page


@pytest.fixture
def playground(page):
    page.goto(f'{BASE_URL}/help', wait_until="networkidle")
    page.evaluate(PLAYGROUND)
    del page.said[:]

    def calls():
        made = page.evaluate("() => window.__calls.splice(0)")
        return made
    return page, calls


def test_a_click_calls_the_action_with_its_arguments_as_data(playground):
    page, calls = playground
    page.click('#pg-plain')
    assert calls() == [[]]
    page.click('#pg-args')
    assert calls() == [['a', 2, True, None]]
    page.click('#pg-passed')
    assert calls() == [['x', '<pg-passed>', '<event click>']]


def test_change_and_input_pass_what_the_control_holds(playground):
    page, calls = playground
    page.click('#pg-box')
    page.click('#pg-box')
    assert calls() == [[True], [False]]
    page.click('#pg-text')
    page.keyboard.type('ab')
    assert calls() == [['a'], ['ab']]


def test_a_click_inside_a_row_is_the_rows_unless_it_is_on_a_control(playground):
    page, calls = playground
    page.click('#pg-text-in-row')
    assert calls() == [['row']]
    page.click('#pg-button-in-row')              # a button with a listener of its own
    assert calls() == [['its own']]
    page.click('#pg-action-in-row')              # a control with an action of its own
    assert calls() == [['inner']]


def test_a_row_answers_enter_and_space_and_a_button_is_not_called_twice(playground):
    page, calls = playground
    page.focus('#pg-row')
    page.keyboard.press('Enter')
    page.keyboard.press('Space')
    assert calls() == [['row'], ['row']]
    assert page.evaluate("() => window.scrollY") == 0       # Space did not scroll the page

    # A real button turns Enter into a click by itself. Once is enough.
    page.focus('#pg-plain')
    page.keyboard.press('Enter')
    assert calls() == [[]]
    # So does a link, and the key must be left to it: it also goes where it points.
    page.focus('#pg-link')
    page.keyboard.press('Enter')
    assert calls() == [['link']]
    assert page.evaluate("() => location.hash") == '#pg-went'
    # And a key on a button inside the row is the button's, not the row's.
    page.focus('#pg-button-in-row')
    page.keyboard.press('Enter')
    assert calls() == [['its own']]


def test_a_backdrop_acts_on_a_click_on_itself_only(playground):
    page, calls = playground
    page.click('#pg-card')
    assert calls() == []
    page.click('#pg-backdrop', position={'x': 4, 'y': 4})
    assert calls() == [['backdrop']]


def test_a_name_that_is_not_registered_runs_nothing_and_says_so(playground):
    page, calls = playground
    page.click('#pg-unknown')
    assert calls() == []
    assert any('playground.nothing' in said for said in page.said), page.said


def test_every_control_on_every_page_names_an_action_that_is_there(page):
    del page.said[:]
    seen = {}
    unknown = """() => Array.from(document.querySelectorAll('[data-click], [data-change], [data-input]')).map((el) => {
        const type = ['click', 'change', 'input'].find((t) => el.hasAttribute('data-' + t));
        const name = el.getAttribute('data-' + type);
        let args = true;
        try {
            if (el.hasAttribute('data-args')) args = Array.isArray(JSON.parse(el.getAttribute('data-args')));
        } catch (e) { args = false; }
        return {name, known: CertMate.hasAction(name), args};
    })"""
    for path in ('/', '/settings', '/inventory', '/activity', '/notifications', '/help', '/inventory/crypto-report'):
        page.goto(f'{BASE_URL}{path}', wait_until="networkidle")
        if path == '/settings':
            for tab in page.locator('[role=tab]').all():
                tab.click()
                page.wait_for_timeout(150)
        controls = page.evaluate(unknown)
        seen[path] = len(controls)
        wrong = sorted({control['name'] for control in controls if not control['known'] or not control['args']})
        assert wrong == [], f'{path}: {wrong}'
    # CONTROL: the pages were loaded and their controls were there to be asked.
    assert seen['/'] >= 30 and seen['/settings'] >= 40 and seen['/inventory'] >= 6, seen
    assert page.said == [], page.said


def test_the_dashboard_a_row_its_dialog_and_the_buttons_a_script_built(page):
    del page.said[:]
    page.goto(BASE_URL, wait_until="networkidle")
    row = page.locator('tr[data-row-domain="alpha.example.test"]')
    row.wait_for(state='visible')
    panel = page.locator('#certDetailPanel')

    def is_open():
        return page.evaluate("() => !document.getElementById('certDetailPanel').classList.contains('hidden')")

    # A literal argument in the template: each status chip passes its own.
    pressed = ("() => Array.from(document.querySelectorAll('[data-status-chip]'))"
               ".filter(c => c.getAttribute('aria-pressed') === 'true').map(c => c.getAttribute('data-status-chip'))")
    for status in ('expiring', 'valid', 'all'):
        page.click(f'[data-status-chip="{status}"]')
        assert page.evaluate(pressed) == [status]
    assert page.locator('tr[data-row-domain]:visible').count() == 2

    # The row opens its certificate; a button in the row does not.
    row.locator('button').first.click()
    assert not is_open()
    page.keyboard.press('Escape')
    row.locator('td').first.click()
    page.wait_for_function("() => document.getElementById('detailDomain').textContent.trim() === 'alpha.example.test'")
    assert is_open()

    # In the dialog: a click on its card keeps it (on the title, which is no
    # control), a button built by a script carries the certificate's name as
    # data. Closing takes a moment to show, so the look comes after it would have.
    page.click('#detailDomain')
    page.wait_for_timeout(600)
    assert is_open()
    panel.locator('button[title="Delete certificate"]').click()
    asked = page.locator('[role="alertdialog"]').filter(has_text='alpha.example.test')
    asked.wait_for(state='visible')
    asked.get_by_role('button', name='Cancel').click()      # it asks first; nothing is deleted
    asked.wait_for(state='hidden')

    if not is_open():
        row.locator('td').first.click()
    panel.locator('button[title="Edit & reissue"]').click()
    page.wait_for_function("() => document.getElementById('domain').value === 'alpha.example.test'")
    assert page.evaluate("() => document.getElementById('domain').readOnly") is True
    page.keyboard.press('Escape')
    page.wait_for_function(
        "() => document.getElementById('createCertFormContainer').classList.contains('translate-x-full')")

    # The backdrop of the dialog closes it, and the keyboard opens it again.
    row.locator('td').first.click()
    page.wait_for_function("() => !document.getElementById('certDetailPanel').classList.contains('hidden')")
    page.mouse.click(6, 6)                        # a corner: the backdrop, not the card
    page.wait_for_function("() => document.getElementById('certDetailPanel').classList.contains('hidden')")
    # Three closes come before this key (the edit button, Escape, the
    # backdrop). Each used to leave its own 200 ms timer, and one of them hid
    # the dialog this key opens when the steps above came close enough
    # together. tests/test_ui_a_dialog_reopened_while_it_closes_stays_open.py
    # is where that is held; here the key only has to do what a click does.
    row.press('Enter')
    try:
        page.wait_for_function(
            "() => !document.getElementById('certDetailPanel').classList.contains('hidden')", timeout=10000)
    except Exception:
        # What the page was like when the key did nothing, for whoever reads the failure.
        raise AssertionError('Enter on the row did not open its certificate: ' + json.dumps(page.evaluate("""() => ({
            focus: document.activeElement.tagName + '#' + document.activeElement.id + ' ' +
                (document.activeElement.getAttribute('data-row-domain') || ''),
            rows: Array.from(document.querySelectorAll('tr[data-row-domain]')).map(r => r.getAttribute('data-row-domain')),
            panel: document.getElementById('certDetailPanel').className.slice(-40),
            dialogs: Array.from(document.querySelectorAll('[role=dialog], [role=alertdialog]'))
                .filter(e => e.offsetParent !== null).map(e => e.id || e.getAttribute('aria-label')),
        })"""))) from None
    assert page.said == [], page.said
