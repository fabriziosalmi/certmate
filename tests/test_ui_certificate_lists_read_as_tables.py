"""The certificate lists read as tables: rows a screen reader can walk, a real
button on each name, and the row's actions beside it rather than inside it.

UX perception audit, 2026-11-18 (P13): every row of the server and client
lists was a `<tr role="button" tabindex="0" aria-label="View details for X">`.
A screen reader heard the table as a column of buttons, one per certificate,
with no cells to move through and the Renew, Download and More actions buttons
nested inside each of those buttons. The rows are native rows again; the name
in the first cell is a button that opens the certificate, and a click anywhere
else on the row still does, for the mouse.

What a screen reader is handed is read from the browser's own accessibility
tree (CDP Accessibility.getFullAXTree), the way
tests/test_ui_the_closed_create_panel_is_out_of_reach.py reads its dialogs:
the markup alone cannot say how Chrome exposes a row with a role on it.
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

SERVER = ['alpha.example.test', 'beta.example.test']
CLIENT = ['alice.example.test', 'bob.example.test']


def _certificate(domain, days):
    return {'domain': domain, 'exists': True, 'days_left': days, 'days_until_expiry': days,
            'expired': False, 'seconds_left': days * 86400,
            'expiry_date': '2027-01-01 10:00:00', 'expires_at': '2027-01-01T10:00:00Z',
            'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
            'san_domains': [], 'has_private_key': True}


def _client(cn, index):
    return {'identifier': f'cc-{index}', 'common_name': cn, 'email': f'{index}@example.test',
            'cert_usage': 'vpn', 'created_at': '2026-10-01T10:00:00Z',
            'expires_at': '2027-10-01T10:00:00Z', 'revoked': False}


def _answer(route):
    url = route.request.url.split('?')[0]
    if route.request.method != 'GET':
        return route.continue_()
    if url.endswith('/api/certificates'):
        body = [_certificate(SERVER[0], 60), _certificate(SERVER[1], 40)]
    elif url.endswith('/deployment-status'):
        body = {'deployed': True, 'reachable': True, 'certificate_match': True,
                'method': 'server', 'protocol': 'https-tls'}
    elif url.endswith('/api/client-certs'):
        body = {'certificates': [_client(cn, i) for i, cn in enumerate(CLIENT)]}
    elif url.endswith('/api/client-certs/stats'):
        body = {'total': 2, 'active': 2, 'revoked': 0, 'by_usage': {'vpn': 2}}
    else:
        return route.continue_()
    return route.fulfill(status=200, content_type='application/json', body=json.dumps(body))


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.emulate_media(reduced_motion='reduce')
    page.route('**/api/**', _answer)
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _tree(page):
    """The accessibility tree, as {id: node}, with the ignored nodes left in so
    a parent chain can be walked; `role` and `name` are plain strings."""
    session = page.context.new_cdp_session(page)
    try:
        nodes = session.send('Accessibility.getFullAXTree')['nodes']
    finally:
        session.detach()
    tree = {}
    for node in nodes:
        tree[node['nodeId']] = {
            'role': (node.get('role') or {}).get('value', ''),
            'name': (node.get('name') or {}).get('value', ''),
            'ignored': node.get('ignored', False),
            'parent': node.get('parentId'),
            'children': node.get('childIds', []),
        }
    return tree


def _ancestors(tree, node_id):
    parent = tree[node_id]['parent']
    while parent is not None and parent in tree:
        yield tree[parent]
        parent = tree[parent]['parent']


def _descendants(tree, node_id):
    for child in tree[node_id]['children']:
        if child in tree:
            yield tree[child]
            yield from _descendants(tree, child)


def _what_a_screen_reader_is_handed(page, names):
    """For each certificate name, the buttons of the row (role "row") that holds
    a "View details for <name>" button; and every button that sits inside
    another button, as [inner, outer] names."""
    tree = _tree(page)
    seen = {}
    nested = set()
    for node_id, node in tree.items():
        if node['ignored']:
            continue
        if node['role'] == 'row':
            buttons = [d['name'] for d in _descendants(tree, node_id)
                       if d['role'] == 'button' and not d['ignored']]
            for name in names:
                if f'View details for {name}' in buttons:
                    seen[name] = buttons
        if node['role'] == 'button':
            nested.update((node['name'], outer['name']) for outer in _ancestors(tree, node_id)
                          if outer['role'] == 'button' and not outer['ignored'])
    return seen, sorted(nested)


def _open_server_list(page):
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_function(
        "() => document.querySelectorAll('#certificatesList tr[data-row-domain]').length === 2")


def _open_client_list(page):
    page.goto(f'{BASE_URL}/#client', wait_until='networkidle')
    page.wait_for_function("() => document.querySelectorAll('#certTableBody tr[data-cc-id]').length === 2")


def test_the_server_list_is_rows_with_a_button_on_each_name(page):
    _open_server_list(page)
    seen, nested = _what_a_screen_reader_is_handed(page, SERVER)
    assert sorted(seen) == SERVER, f'rows with a "View details for" button on the name: {seen}'
    for name, buttons in seen.items():
        # The row's own actions are in the row, beside the name, not under it.
        assert f'Renew {name}' in buttons and f'More actions for {name}' in buttons, buttons
    assert nested == [], f'buttons inside buttons [inner, outer]: {nested}'


def test_the_client_list_is_rows_with_a_button_on_each_name(page):
    _open_client_list(page)
    seen, nested = _what_a_screen_reader_is_handed(page, CLIENT)
    assert sorted(seen) == CLIENT, f'rows with a "View details for" button on the name: {seen}'
    assert nested == [], f'buttons inside buttons [inner, outer]: {nested}'


def test_the_keyboard_opens_a_server_certificate_from_its_name(page):
    _open_server_list(page)
    name = page.get_by_role('button', name=f'View details for {SERVER[1]}')
    name.focus()
    page.keyboard.press('Enter')
    page.wait_for_function(
        "d => document.getElementById('detailDomain').textContent.trim() === d", arg=SERVER[1])
    # Closing gives the focus back to the name it was opened from.
    page.keyboard.press('Escape')
    page.wait_for_function(
        "d => document.activeElement && document.activeElement.getAttribute('aria-label') === 'View details for ' + d",
        arg=SERVER[1])


def test_a_click_elsewhere_on_a_server_row_still_opens_it(page):
    """For the mouse the whole row stays the target, and a button in it stays its own."""
    _open_server_list(page)
    row = page.locator(f'tr[data-row-domain="{SERVER[0]}"]')
    row.locator('td').nth(1).click()               # the status cell: no control there
    page.wait_for_function(
        "d => document.getElementById('detailDomain').textContent.trim() === d", arg=SERVER[0])


def test_the_keyboard_and_the_mouse_open_a_client_certificate(page):
    _open_client_list(page)
    page.get_by_role('button', name=f'View details for {CLIENT[0]}').focus()
    page.keyboard.press('Enter')
    title = page.locator('#certModalTitle')
    page.wait_for_function("() => !document.getElementById('certModal').classList.contains('hidden')")
    assert title.inner_text().strip() == CLIENT[0]
    page.keyboard.press('Escape')
    page.wait_for_function("() => document.getElementById('certModal').classList.contains('hidden')")
    # A click on the expiry cell, which holds no control, opens it too.
    page.locator('tr[data-cc-id="cc-1"] td').nth(4).click()
    page.wait_for_function("() => !document.getElementById('certModal').classList.contains('hidden')")
    assert title.inner_text().strip() == CLIENT[1]
