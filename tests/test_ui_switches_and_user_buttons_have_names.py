"""Every control on Settings > Users, Deploy and Notifications has a name a
screen reader can say, and the Users list works on a phone.

UX perception audit, 2026-11-18 (batch B9):

* P16. The Enable Local Authentication switch, the deploy hooks and
  notifications switches and each hook's own switch were announced as a
  checkbox with no name: the visible words were in a label that was not tied
  to them, and the empty label wrapping the input won over its title. Each
  user's Disable, Change email, Reset password and Delete were named by an
  icon-font glyph (U+F05E, U+F0E0, U+F084, U+F1F8), the same four on every row.
* P12. On a 360 px phone the user rows did not wrap: the second user's four
  buttons sat past the right edge of the list, with only a sideways scroll to
  find them, and the "Local Authentication" badge ran past its card.

Names are read from the browser's accessibility tree (CDP). The users and the
deploy configuration are answered in the browser (page.route); nothing is
written.
"""
import json
import os
import re

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
USERS = {'users': {
    'admin': {'role': 'admin', 'enabled': True, 'email': '', 'last_login': '2026-11-18T09:00:00Z'},
    'operator-maria': {'role': 'operator', 'enabled': True, 'email': 'maria.rossi@example.test',
                       'last_login': None},
    # An SSO username is often an address: no hyphen or space to break on.
    'giovanni.bianchi@example.com': {'role': 'viewer', 'enabled': True, 'email': '',
                                     'last_login': None},
}}
HOOK = {'id': 'h1', 'name': 'reload-lb', 'command': 'systemctl reload nginx', 'enabled': True,
        'timeout': 30, 'on_events': ['created', 'renewed']}
DEPLOY = {'enabled': True, 'global_hooks': [HOOK], 'domain_hooks': {'site.example.test': [dict(HOOK, id='h2')]},
          'targets': []}
PRIVATE_USE = re.compile('[-]')
LOADED = "() => !document.getElementById('userList').innerText.includes('Loading users')"


@pytest.fixture
def open_settings(browser_page, ui_session_cookie):
    contexts = []

    def make(width=1280, height=900):
        context = browser_page.context.browser.new_context(viewport={'width': width, 'height': height})
        contexts.append(context)
        context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
        page = context.new_page()

        def answer(route):
            request = route.request
            url = request.url.split('?')[0]
            if request.method == 'GET' and url.endswith('/api/users'):
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(USERS))
            if request.method == 'GET' and url.endswith('/api/deploy/config'):
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(DEPLOY))
            return route.continue_()
        page.route('**/api/**', answer)
        return page
    yield make
    for context in contexts:
        context.close()


def _focusable_names(page, panel):
    """(role, name) of each control in `panel` the accessibility tree exposes."""
    cdp = page.context.new_cdp_session(page)
    root = cdp.send('DOM.getDocument', {'depth': 0})['root']['nodeId']
    selector = ', '.join(f'{panel} {tag}' for tag in ('button', 'input', 'select', 'textarea', 'a[href]'))
    found = []
    for node_id in cdp.send('DOM.querySelectorAll', {'nodeId': root, 'selector': selector})['nodeIds']:
        node = cdp.send('Accessibility.getPartialAXTree', {'nodeId': node_id, 'fetchRelatives': False})['nodes'][0]
        if node.get('ignored'):
            continue
        found.append((node.get('role', {}).get('value'), node.get('name', {}).get('value', '')))
    return found


def _unnamed(found):
    return [(role, name) for role, name in found
            if not PRIVATE_USE.sub('', name).strip()]


def test_the_users_tab_names_the_switch_and_each_users_buttons(open_settings):
    page = open_settings()
    page.goto(f'{BASE_URL}/settings#users', wait_until='networkidle')
    page.wait_for_function(LOADED, timeout=10000)
    assert page.get_by_role('checkbox', name='Enable Local Authentication').count() == 1
    found = _focusable_names(page, '#settings-panel-users')
    assert _unnamed(found) == [], found
    names = [name for _, name in found]
    for wanted in ('Disable operator-maria', 'Change email of operator-maria',
                   'Reset password of operator-maria', 'Delete operator-maria',
                   'Set email of admin', 'Reset password of admin'):
        assert wanted in names, names


@pytest.mark.parametrize('tab,switch', [('deploy', 'Enable deploy hooks'),
                                        ('notifications', 'Enable notifications')])
def test_the_deploy_and_notifications_switches_have_names(open_settings, tab, switch):
    page = open_settings()
    page.goto(f'{BASE_URL}/settings#{tab}', wait_until='networkidle')
    page.wait_for_selector(f'#settings-panel-{tab}', state='visible', timeout=10000)
    assert page.get_by_role('checkbox', name=switch).count() == 1
    found = _focusable_names(page, f'#settings-panel-{tab}')
    unnamed = [item for item in _unnamed(found) if item[0] in ('checkbox', 'switch', 'button')]
    assert unnamed == [], found


def test_each_hook_switch_says_which_hook_it_turns_on(open_settings):
    page = open_settings()
    page.goto(f'{BASE_URL}/settings#deploy', wait_until='networkidle')
    page.wait_for_selector('#settings-panel-deploy', state='visible', timeout=10000)
    # Open the global and the per-domain hook lists.
    page.evaluate("""() => document.querySelectorAll('#settings-panel-deploy button').forEach(b => {
        const click = b.getAttribute('@click') || '';
        if (click === 'showGlobal = !showGlobal' || click === 'showDomain = !showDomain') b.click();
    })""")
    page.get_by_role('button', name='Test').first.wait_for(state='visible', timeout=5000)
    assert page.get_by_role('checkbox', name='Enable hook reload-lb', exact=True).count() == 2
    found = _focusable_names(page, '#settings-panel-deploy')
    unnamed = [item for item in _unnamed(found) if item[0] in ('checkbox', 'switch', 'button')]
    assert unnamed == [], found


def test_on_a_phone_every_user_action_is_inside_the_list(open_settings):
    page = open_settings(width=360, height=740)
    page.goto(f'{BASE_URL}/settings#users', wait_until='networkidle')
    page.wait_for_function(LOADED, timeout=10000)
    box = page.evaluate("""() => {
        const list = document.getElementById('userList');
        const r = list.getBoundingClientRect();
        const buttons = Array.from(list.querySelectorAll('button')).map(b => {
            const br = b.getBoundingClientRect();
            return {name: b.getAttribute('aria-label') || b.title, left: br.left, right: br.right};
        });
        const panel = document.getElementById('settings-panel-users').getBoundingClientRect();
        const badge = Array.from(document.querySelectorAll('#settings-panel-users span'))
            .find(s => s.innerText.trim() === 'Local Authentication').getBoundingClientRect();
        return {left: r.left, right: r.right, client: list.clientWidth, scroll: list.scrollWidth,
                buttons, panelRight: panel.right, badgeRight: badge.right};
    }""")
    assert len(box['buttons']) >= 6, box
    assert box['scroll'] <= box['client'], box
    past = [b for b in box['buttons'] if b['right'] > box['right'] + 0.5 or b['left'] < box['left'] - 0.5]
    assert past == [], box
    assert box['badgeRight'] <= box['panelRight'] + 0.5, box


def test_on_a_phone_a_long_username_wraps_inside_its_row(open_settings):
    """An address as username has no hyphen to break on: break-words did not
    let it shrink, and it ran past the list (cut, with the list's sideways
    scroll gone)."""
    page = open_settings(width=360, height=740)
    page.goto(f'{BASE_URL}/settings#users', wait_until='networkidle')
    page.wait_for_function(LOADED, timeout=10000)
    box = page.evaluate("""() => {
        const list = document.getElementById('userList');
        const r = list.getBoundingClientRect();
        const names = Array.from(list.querySelectorAll('span.font-medium')).map(s => {
            const b = s.getBoundingClientRect();
            return {name: s.innerText, right: b.right};
        });
        return {right: r.right, client: list.clientWidth, scroll: list.scrollWidth, names};
    }""")
    long_name = [n for n in box['names'] if n['name'].startswith('giovanni')]
    assert long_name, box
    assert box['scroll'] <= box['client'], box
    assert [n for n in box['names'] if n['right'] > box['right'] + 0.5] == [], box
