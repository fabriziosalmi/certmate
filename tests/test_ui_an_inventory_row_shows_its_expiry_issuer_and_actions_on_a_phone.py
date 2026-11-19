"""On a phone an inventory row shows when the certificate expires, who issued
it, where it was found, and its actions, without a sideways scroll.

UX perception audit, 2026-11-18 (P11): at 390 px the inventory table kept its
seven columns, so the screen showed the subject and nothing else: the expiry,
the issuer and the Adopt and Forget buttons were past the right edge of a
scroll box with no visible scrollbar, and a tap on the row did nothing. Below
md the row now carries them under the subject, and the other columns start
at md.

Measured at both phone widths the finding names, 390 and 360 px. At 360 the
line of names under the subject was capped at 320 px (max-w-xs), so a
certificate with three or more names set the one column left at 352 px in a
328 px box: the list scrolled sideways again and the names were cut at the
edge of the box, with no ellipsis on screen.

The inventory is answered in the browser (page.route), so the instance's own
inventory, whatever the modules before this one left in it, does not matter.
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

DISCOVERED = {
    'fingerprint': 'aa' * 32, 'subject_cn': 'shop.example.test',
    'san_dns': ['shop.example.test', 'www.shop.example.test'], 'issuer_cn': 'Example Issuing CA R11',
    'expiry_status': 'critical', 'days_until_expiry': 5, 'not_after': '2026-11-23T10:00:00Z',
    'key': {'type': 'EC', 'curve': 'P-256'}, 'source': 'probed', 'managed': False, 'group': 'discovered',
    'endpoints': [{'host': 'shop.example.test', 'port': 443}, {'host': '10.0.0.4', 'port': 8443}]}
MANAGED = {
    'fingerprint': 'bb' * 32, 'subject_cn': 'api.example.test', 'san_dns': ['api.example.test'],
    'issuer_cn': 'Another Example Server CA', 'expiry_status': 'ok', 'days_until_expiry': 80,
    'not_after': '2027-02-06T10:00:00Z', 'key': {'type': 'RSA', 'size': 2048}, 'source': 'issued',
    'managed': True, 'group': 'issued', 'endpoints': []}
# Four names: the line under the subject reads three of them and "+1".
MANY_NAMES = {
    'fingerprint': 'cc' * 32, 'subject_cn': 'edge.example.test',
    'san_dns': ['api.example.test', 'www.api.example.test', 'eu.api.example.test', 'us.api.example.test'],
    'issuer_cn': 'Example Issuing CA R11', 'expiry_status': 'ok', 'days_until_expiry': 60,
    'not_after': '2027-01-17T10:00:00Z', 'key': {'type': 'EC', 'curve': 'P-256'}, 'source': 'probed',
    'managed': False, 'group': 'discovered', 'endpoints': [{'host': 'eu.api.example.test', 'port': 443}]}
INVENTORY = {'certificates': [DISCOVERED, MANAGED, MANY_NAMES],
             'summary': {'total': 3, 'issued': 1, 'discovered': 2,
                         'expiry': {'expired': 0, '7': 1, '30': 0, '90': 2}}}


@pytest.fixture(params=[390, 360], ids=['390px', '360px'])
def phone(request, browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(
        viewport={'width': request.param, 'height': 844}, is_mobile=True, has_touch=True)
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()

    def answer(route):
        if route.request.method == 'GET' and route.request.url.split('?')[0].endswith('/api/inventory'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps(INVENTORY))
        return route.continue_()

    page.route('**/api/**', answer)
    page.goto(f'{BASE_URL}/inventory', wait_until='networkidle')
    # The admin's Adopt and Forget buttons are drawn once the role is known.
    page.wait_for_selector('#inventoryBody button:has-text("Forget")', state='attached')
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


# Every element of a row that carries the text, with whether it is drawn and
# whether it lies inside the screen from left to right.
ON_SCREEN = """([row, text]) => {
    const width = document.documentElement.clientWidth;
    const tr = [...document.querySelectorAll('#inventoryBody tr')].find(t => t.innerText.startsWith(row));
    const found = [...tr.querySelectorAll('*')].filter(e =>
        [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.includes(text)));
    return found.map(e => { const b = e.getBoundingClientRect();
        return {shown: e.checkVisibility() && b.width > 0, inside: b.left >= 0 && b.right <= width,
                left: Math.round(b.left), right: Math.round(b.right)}; });
}"""


def test_the_inventory_list_does_not_scroll_sideways_on_a_phone(phone):
    sizes = phone.evaluate("""() => { const box = document.getElementById('inventoryBody').closest('.overflow-x-auto');
        return [box.scrollWidth, box.clientWidth]; }""")
    assert sizes[0] <= sizes[1], f'the inventory list scrolls sideways on a phone [content, box]: {sizes}'


def test_a_long_line_of_names_ends_inside_the_list_with_an_ellipsis(phone):
    """The names under the subject end inside the list's box, which clips them with no ellipsis
    of its own; what does not fit in the line is cut with an ellipsis."""
    line = phone.evaluate("""() => {
        const box = document.getElementById('inventoryBody').closest('.overflow-x-auto');
        const edge = Math.round(box.getBoundingClientRect().right);
        const tr = [...document.querySelectorAll('#inventoryBody tr')].find(t => t.innerText.startsWith('edge.example.test'));
        const div = [...tr.querySelectorAll('div')].find(d => d.textContent.startsWith('api.example.test, www.'));
        const b = div.getBoundingClientRect();
        return {right: Math.round(b.right), edge, cut: div.scrollWidth > div.clientWidth,
                ellipsis: getComputedStyle(div).textOverflow};
    }""")
    assert line['right'] <= line['edge'], f'the line of names ends past the edge of the list: {line}'
    assert not line['cut'] or line['ellipsis'] == 'ellipsis', f'the line of names is cut with no ellipsis: {line}'


@pytest.mark.parametrize('row, texts', [
    ('shop.example.test', ['5d', 'Example Issuing CA R11', 'probed', 'Adopt', 'Forget']),
    # A managed row has no Forget since P48 (test_ui_inventory.py says why).
    ('api.example.test', ['80d', 'Another Example Server CA', 'issued']),
])
def test_a_row_shows_its_expiry_issuer_source_and_actions_on_screen(phone, row, texts):
    for text in texts:
        seen = phone.evaluate(ON_SCREEN, [row, text])
        shown = [s for s in seen if s['shown']]
        assert shown, f'{row}: "{text}" is not drawn in the row: {seen}'
        assert all(s['inside'] for s in shown), f'{row}: "{text}" is past the edge of the screen: {shown}'


def test_a_rows_actions_answer_a_tap_on_a_phone(phone):
    """The control: the buttons on screen are the working ones. Forget asks in
    the page's own dialog since P48, not in a native one."""
    row = phone.locator('#inventoryBody tr', has_text='shop.example.test')
    row.get_by_role('button', name='Forget').locator('visible=true').tap()
    asked = phone.get_by_role('alertdialog')
    asked.wait_for()
    assert 'shop.example.test' in asked.inner_text(), asked.inner_text()
