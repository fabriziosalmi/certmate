"""The pages work with the build of Alpine that evaluates without `eval`.

The Content-Security-Policy no longer carries 'unsafe-eval', and Alpine is
`@alpinejs/csp`: an expression in the markup is parsed, not compiled, and
reaches nothing outside its component. Some two dozen expressions said
something that build does not evaluate (`Object.keys(...)`, an arrow function,
two statements, a function of the page) and each became a method or a getter of
its component.

scripts/check_alpine_expressions.mjs proves every expression can be parsed and
names only what its component has. It cannot prove the method does what the
expression did. This does, in a browser, for each place that changed: the
control is used the way a person uses it, and what the page then shows is read
back. The answers of the server are fixed by the test, so the rows that only
exist when someone has data (a key with domains, a delivery, an execution) are
there to be rendered.

A mistake with this build is quiet: the element renders and does nothing, and
the only trace is a warning in the console. So the last test opens every page
and every Settings tab and fails on any such warning, and on anything the
policy had to block.
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

ANSWERS = {
    '/api/keys': {'keys': {
        'k1': {'name': 'ci', 'role': 'operator', 'token_prefix': 'cm_abc', 'revoked': False, 'is_expired': False,
               'created_at': '2026-09-01T10:00:00Z', 'last_used_at': '2026-10-01T08:00:00Z',
               'expires_at': '2027-01-01T00:00:00Z', 'allowed_domains': ['a.example.test', 'b.example.test'],
               'created_during_setup': True, 'setup_origin_confirmed_at': '2026-09-02T00:00:00Z',
               'setup_origin_confirmed_by': 'admin'},
        'k2': {'name': 'plain', 'role': 'viewer', 'token_prefix': 'cm_def', 'revoked': False, 'is_expired': False,
               'created_at': '2026-09-03T10:00:00Z'},
        'k3': {'name': 'locked', 'role': 'viewer', 'token_prefix': 'cm_ghi', 'revoked': False, 'is_expired': False,
               'created_at': '2026-09-04T10:00:00Z', 'allowed_domains': []}}},
    '/api/deploy/config': {'enabled': True, 'global_hooks': [], 'targets': [], 'domain_hooks': {
        'zeta.example.test': [{'id': 'h2', 'name': 'reload zeta', 'command': 'true', 'enabled': True,
                               'timeout': 30, 'on_events': ['renewed']}],
        'alpha.example.test': [{'id': 'h1', 'name': 'reload alpha', 'command': 'true', 'enabled': True,
                                'timeout': 30, 'on_events': ['renewed']}]}},
    '/api/deploy/history': [{'run_id': 'r1', 'timestamp': '2026-10-05T10:00:00Z', 'hook_id': 'h1',
                             'hook_name': 'reload alpha', 'domain': 'alpha.example.test', 'event': 'test',
                             'success': True, 'exit_code': 0, 'duration_ms': 12}],
    '/api/notifications/config': {'enabled': True, 'digest_enabled': True, 'events': [], 'channels': {
        'smtp': {'enabled': False, 'host': '', 'port': 587, 'username': '', 'password': '', 'from_address': '',
                 'to_addresses': [], 'use_tls': True},
        'webhooks': [
            {'enabled': True, 'name': 'ops', 'url': 'https://hooks.example.test/a', 'type': 'generic',
             'secret': '', 'events': [], 'headers': {'X-Env': 'prod'}},
            {'enabled': False, 'name': 'off', 'url': 'https://hooks.example.test/b', 'type': 'slack',
             'secret': '', 'events': []}]}},
    '/api/webhooks/deliveries': [{'timestamp': '2026-10-05T10:00:00Z', 'webhook_name': 'ops',
                                  'event': 'certificate_renewed', 'success': True, 'status_code': 200}],
    '/api/certificates': [
        {'domain': 'probed.example.test', 'exists': True, 'days_left': 60, 'deployment_port': 8443,
         'deployment_protocol': 'tls', 'deployment_host': ''},
        {'domain': 'plain.example.test', 'exists': True, 'days_left': 60}],
}

# What the browser said that nobody was shown: Alpine's warnings, uncaught
# errors, and what the policy blocked.
_WATCH = """() => {
    window.__blocked = [];
    document.addEventListener('securitypolicyviolation', (e) => window.__blocked.push(
        e.violatedDirective + ' ' + e.blockedURI + ' ' + (e.sourceFile || '').split('/').pop()));
}"""


class Heard:
    def __init__(self, page):
        self.said = []
        page.on('console', self._console)
        page.on('pageerror', lambda error: self.said.append(f'error: {error}'))

    def _console(self, message):
        if message.type in ('warning', 'error') and 'Alpine' in message.text:
            self.said.append(' '.join(message.text.split())[:200])


@pytest.fixture(scope="module")
def page(browser_page):
    """One page for the module, with the server's answers fixed for the GETs the
    Settings components make, and everything the browser complains of kept."""
    page = browser_page
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); } catch (e) {}")
    page.add_init_script(f'({_WATCH})()')
    page.emulate_media(reduced_motion='reduce')
    page.heard = Heard(page)
    page.asked = []

    def answer(route):
        request = route.request
        path = request.url.split(BASE_URL, 1)[-1].split('?', 1)[0]
        page.asked.append(f'{request.method} {path}')
        if request.method == 'GET' and path in ANSWERS:
            route.fulfill(status=200, content_type='application/json', body=json.dumps(ANSWERS[path]))
        else:
            route.continue_()

    page.route('**/api/**', answer)
    return page


@pytest.fixture(scope="module")
def settings(page):
    page.goto(f'{BASE_URL}/settings', wait_until="networkidle")
    page.wait_for_selector('#settings-tab-general', state='visible')
    return page


def _selected(page):
    return page.evaluate(
        "() => ({hash: location.hash, tabs: Array.from(document.querySelectorAll('[role=tab]'))"
        ".filter(t => t.getAttribute('aria-selected') === 'true').map(t => t.id)})")


def _open(page, tab):
    page.click(f'#settings-tab-{tab}')
    page.wait_for_selector(f'#settings-panel-{tab}', state='visible')
    return page.locator(f'#settings-panel-{tab}')


def test_a_tab_follows_the_click_the_keyboard_and_the_url(settings):
    page = settings
    assert _selected(page) == {'hash': '', 'tabs': ['settings-tab-general']}

    page.click('#settings-tab-deploy')
    assert _selected(page) == {'hash': '#deploy', 'tabs': ['settings-tab-deploy']}

    page.keyboard.press('ArrowRight')
    assert _selected(page) == {'hash': '#probe', 'tabs': ['settings-tab-probe']}
    page.keyboard.press('Home')
    assert _selected(page) == {'hash': '#general', 'tabs': ['settings-tab-general']}

    # The other direction: the URL changes under the page, as Back does.
    page.evaluate("() => { location.hash = '#oidc'; }")
    page.wait_for_function("() => document.getElementById('settings-tab-oidc').getAttribute('aria-selected') === 'true'")
    assert _selected(page) == {'hash': '#oidc', 'tabs': ['settings-tab-oidc']}


def test_the_keys_are_listed_with_their_dates_and_their_scope(settings):
    panel = _open(settings, 'apikeys')
    panel.get_by_text('cm_abc...').wait_for()
    text = ' '.join(panel.inner_text().split())

    assert 'No API keys created yet' not in text
    for prefix in ('cm_abc...', 'cm_def...', 'cm_ghi...'):
        assert prefix in text
    assert 'Created Sep 1, 2026' in text and 'Last used Oct 1, 2026' in text and 'Expires Jan 1, 2027' in text
    # A key with domains says how many and which; one with none is locked; one
    # without the restriction says nothing.
    assert '2 domains' in text and 'a.example.test, b.example.test' in text
    assert text.count('locked') >= 2            # the key's name and its badge
    assert panel.locator('[title^="Created during setup; confirmed by admin on Sep 2, 2026"]').count() == 1


def test_the_domains_with_hooks_are_counted_listed_in_order_and_the_history_opens(settings):
    page = settings
    panel = _open(page, 'deploy')
    toggle = panel.get_by_role('button', name='Domain-Specific Hooks')
    toggle.wait_for()
    assert '(2 domains)' in ' '.join(toggle.inner_text().split())

    toggle.click()
    panel.locator('h4 span', has_text='alpha.example.test').wait_for()
    assert panel.locator('h4 span').all_inner_texts() == ['alpha.example.test', 'zeta.example.test']

    history = panel.get_by_role('button', name='Recent Executions')
    row = panel.locator('[aria-label="View execution detail for reload alpha on alpha.example.test"]')
    assert 'GET /api/deploy/history' not in page.asked
    history.click()
    row.wait_for(state='visible')
    assert page.asked.count('GET /api/deploy/history') == 1
    history.click()                             # closing it asks nothing
    row.wait_for(state='hidden')
    assert page.asked.count('GET /api/deploy/history') == 1


def test_a_webhooks_headers_are_added_and_removed_and_the_deliveries_open(settings):
    page = settings
    panel = _open(page, 'notifications')
    webhooks = panel.get_by_role('button', name='Webhooks')
    webhooks.wait_for()
    assert '1 active' in ' '.join(webhooks.inner_text().split())     # two webhooks, one of them on

    webhooks.click()
    name = panel.locator('input[placeholder="Header name"]').first
    value = panel.locator('input[placeholder="Value"]').first
    name.wait_for(state='visible')

    def headers():
        return [field.input_value() for field in panel.locator('input[type="text"][disabled]').all()
                if field.is_visible()]

    assert headers() == ['X-Env', 'prod']
    add = name.locator('xpath=following-sibling::button')
    add.click()                                 # an empty name adds nothing
    assert headers() == ['X-Env', 'prod']

    name.fill('X-Team')
    value.fill('pki')
    add.click()
    assert headers() == ['X-Env', 'prod', 'X-Team', 'pki']
    assert (name.input_value(), value.input_value()) == ('', '')    # the two fields are emptied

    panel.locator('input[type="text"][disabled]').first.locator('xpath=following-sibling::button').click()
    assert headers() == ['X-Team', 'pki']

    panel.get_by_role('button', name='Recent Deliveries').click()
    row = panel.locator('tbody tr', has_text='ops')
    row.wait_for(state='visible')
    assert 'Oct 5, 2026' in row.inner_text() and 'renewed' in row.inner_text()
    assert page.asked.count('GET /api/webhooks/deliveries') == 1


def test_choosing_a_protocol_sets_it_and_closes_its_list(settings):
    page = settings
    panel = _open(page, 'probe')
    panel.get_by_text('probed.example.test').first.wait_for()

    def state():
        return page.evaluate(
            "() => { const d = Alpine.$data(document.querySelector('[x-data^=\"probeManager\"]'));"
            " return [d.addProtocol, d.addProtoOpen, d.editProtocol, d.editProtoOpen, d.editingDomain]; }")

    assert state() == ['https-tls', False, 'https-tls', False, None]
    add = panel.locator('[\\@click="addProtoOpen = !addProtoOpen"]')
    add.click()
    assert state()[:2] == ['https-tls', True]
    add.locator('xpath=following-sibling::div').get_by_role('button', name='SMTP').click()
    assert state()[:2] == ['smtp-starttls', False]
    assert 'SMTP' in add.inner_text()

    panel.locator('button[title*="dit"]').first.click()
    assert state()[2:] == ['tls', False, 'probed.example.test']
    edit = panel.locator('[\\@click="editProtoOpen = !editProtoOpen"]')
    edit.click()
    assert state()[3] is True
    edit.locator('xpath=following-sibling::div').get_by_role('button', name='HTTPS').click()
    assert state()[2:] == ['https-tls', False, 'probed.example.test']


def test_the_dashboard_opens_the_panel_and_loads_the_client_view(page):
    page.goto(BASE_URL, wait_until="networkidle")
    page.click('button[title="New certificate"]')
    page.wait_for_function(
        "() => !document.getElementById('createCertFormContainer').classList.contains('translate-x-full')")
    page.keyboard.press('Escape')

    del page.asked[:]
    page.click('#certViewClientBtn')
    page.wait_for_function("() => location.hash === '#client'")
    page.wait_for_function("() => Alpine.store('certs').view === 'client'")
    assert any('client-certs' in asked for asked in page.asked), page.asked

    # Asked for by the URL, with no click: the list still loads.
    del page.asked[:]
    page.goto(f'{BASE_URL}/#client', wait_until="networkidle")
    page.reload(wait_until="networkidle")
    assert page.evaluate("() => Alpine.store('certs').view") == 'client'
    assert page.get_attribute('#certViewClientBtn', 'aria-pressed') == 'true'
    assert any('client-certs' in asked for asked in page.asked), page.asked


def test_no_page_and_no_tab_leaves_a_warning_or_a_blocked_script(page):
    """Runs last: it also covers what the tests above did to the page."""
    tabs = 0
    for path in ('/settings', '/inventory', '/activity', '/notifications', '/help', '/'):
        page.goto(f'{BASE_URL}{path}', wait_until="networkidle")
        if path == '/settings':
            for tab in page.locator('[role=tab]').all():
                tab.click()
                page.wait_for_timeout(250)
                tabs += 1
        blocked = page.evaluate("() => window.__blocked")
        assert blocked == [], f'{path}: the policy blocked {blocked}'
    assert tabs >= 11, tabs                     # CONTROL: the tabs were opened
    assert page.heard.said == [], page.heard.said
