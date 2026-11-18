"""The inventory's certificate list is not pushed below the fold by the domain
checks that are off, and a check that is on and has found nothing says so
whole on a phone.

UX perception audit, 2026-11-18 (P50): Domain registrations and Domain health
are off until an admin turns them on, and the page still drew each as a card
of zero counters over an empty table, about 210 px apiece. On a 1280 x 800
screen the certificate list, the reason for the page, started below the fold.
And the empty-state sentence sat in a table row inside a sideways scroll box:
on a phone the nine health columns made the row wider than the screen, and
the centred sentence was cut at both edges ("No names checked yet. Enable
Domain health i").

A check that is off is now one line saying so, with a way to turn it on for an
admin. A check that is on says what it has, and its empty state is a sentence
outside the scrolled table.

The checks' state is the instance's own (GET /api/inventory/config), set here
and put back after; the inventory and the checks' answers are given in the
browser (page.route).
"""
import json
import os

import pytest
import requests

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

CHECKS = ('domain_registration', 'domain_health')
PANELS = {'domain_registration': 'registrationsPanel', 'domain_health': 'domainHealthPanel'}
EMPTY = {'domain_registration': 'No domain registrations checked yet',
         'domain_health': 'No names checked yet'}


def _record(index):
    return {'fingerprint': f'{index:064x}', 'subject_cn': f'site{index}.example.test',
            'san_dns': [f'site{index}.example.test'], 'issuer_cn': 'Example CA', 'expiry_status': 'ok',
            'days_until_expiry': 60, 'not_after': '2027-01-01T10:00:00Z', 'key': {'type': 'EC', 'curve': 'P-256'},
            'source': 'probed', 'managed': False, 'group': 'discovered', 'endpoints': []}


INVENTORY = {'certificates': [_record(i) for i in range(3)],
             'summary': {'total': 3, 'issued': 0, 'discovered': 3, 'expiry': {'expired': 0, '7': 0, '30': 0, '90': 3}}}
NOTHING_YET = {
    '/api/inventory/domains': {'domains': [], 'summary': {'expiry': {}, 'by_status': {}}},
    '/api/inventory/health': {'names': [], 'summary': {'total': 0, 'by_status': {}}},
}


@pytest.fixture
def checks(ui_session_cookie):
    """Set the two checks on or off on the instance, and put them back after."""
    session = requests.Session()
    session.cookies.set('certmate_session', ui_session_cookie)
    headers = {'Origin': BASE_URL}
    before = session.get(f'{BASE_URL}/api/inventory/config', timeout=10)
    assert before.status_code == 200, before.text[:200]
    before = before.json()

    def set_checks(**on):
        body = {name: dict(before[name], enabled=on.get(name, False)) for name in CHECKS}
        answer = session.post(f'{BASE_URL}/api/inventory/config', json=body, headers=headers, timeout=10)
        assert answer.status_code == 200, answer.text[:200]
        now = session.get(f'{BASE_URL}/api/inventory/config', timeout=10).json()
        assert {name: now[name]['enabled'] for name in CHECKS} == {name: on.get(name, False) for name in CHECKS}

    yield set_checks
    # Every section the page's Save sends, as it was.
    restored = session.post(f'{BASE_URL}/api/inventory/config', json=before, headers=headers, timeout=10)
    assert restored.status_code == 200, restored.text[:200]
    assert session.get(f'{BASE_URL}/api/inventory/config', timeout=10).json() == before


@pytest.fixture
def open_inventory(browser_page, ui_session_cookie):
    contexts = []

    def run(width, height, phone=False):
        context = browser_page.context.browser.new_context(
            viewport={'width': width, 'height': height}, is_mobile=phone, has_touch=phone)
        contexts.append(context)
        context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
        page = context.new_page()

        def answer(route):
            path = '/' + route.request.url.split('?')[0].split('/', 3)[3]
            if route.request.method != 'GET':
                return route.continue_()
            if path == '/api/inventory':
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(INVENTORY))
            if path in NOTHING_YET:
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(NOTHING_YET[path]))
            return route.continue_()

        page.route('**/api/**', answer)
        page.goto(f'{BASE_URL}/inventory', wait_until='networkidle')
        page.wait_for_selector('#inventoryBody tr:has-text("site0.example.test")')
        page.wait_for_timeout(300)
        return page

    yield run
    for context in contexts:
        context.close()


def test_with_the_checks_off_the_certificate_list_starts_above_the_fold(checks, open_inventory):
    checks()
    page = open_inventory(1280, 800)
    first = page.locator('#inventoryBody tr').first.bounding_box()
    assert first['y'] + first['height'] <= 800, (
        f'the first certificate ends at {first["y"] + first["height"]:.0f} px, below an 800 px screen')
    for name, panel in PANELS.items():
        height = page.locator(f'#{panel}').bounding_box()['height']
        assert height <= 60, f'{name} is off and takes {height:.0f} px, not one line'
        assert 'off' in page.locator(f'#{panel}').inner_text().lower(), f'{name} does not say it is off'


@pytest.mark.parametrize('name', CHECKS)
def test_a_check_that_is_on_and_found_nothing_says_so_whole_on_a_phone(checks, open_inventory, name):
    checks(**{name: True})
    page = open_inventory(390, 844, phone=True)
    cut = page.evaluate("""([panel, text]) => {
        const node = [...document.querySelectorAll('#' + panel + ' *')].find(e =>
            e.checkVisibility() && [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.includes(text)));
        if (!node) return 'not drawn';
        const range = document.createRange(); range.selectNodeContents(node);
        const lines = [...range.getClientRects()];
        const width = document.documentElement.clientWidth;
        const clips = [];
        for (let a = node.parentElement; a; a = a.parentElement) {
            const style = getComputedStyle(a);
            if (style.overflowX !== 'visible') clips.push(a.getBoundingClientRect());
        }
        return lines.filter(l => l.left < 0 || l.right > width
                || clips.some(c => l.left < c.left - 0.5 || l.right > c.right + 0.5))
            .map(l => [Math.round(l.left), Math.round(l.right)]);
    }""", [PANELS[name], EMPTY[name]])
    assert cut == [], f'{name}: the empty-state sentence is cut on a 390 px phone (lines [left, right]): {cut}'


def test_an_admin_turns_a_check_on_from_its_line_and_the_section_opens(checks, open_inventory):
    """The control: the line that says "Off" leads to the switch, and a check
    turned on and saved there opens its section without a reload."""
    checks()
    page = open_inventory(1280, 800)
    panel = page.locator('#registrationsPanel')
    panel.get_by_role('button', name='Turn on in Discovery configuration').click()
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'cfgRegEnabled'")
    assert page.evaluate("() => document.querySelector('#configPanel details').open") is True
    page.check('#cfgRegEnabled')
    page.get_by_role('button', name='Save configuration').click()
    page.wait_for_function("() => document.getElementById('cfgMsg').textContent === 'Saved.'")
    page.wait_for_function(
        "t => document.getElementById('registrationsPanel').innerText.includes(t)", arg=EMPTY['domain_registration'])
    assert 'Off' not in panel.inner_text()
    assert page.locator('#domainHealthPanel').inner_text().count('Off') == 1
