"""The actions on a certificate say what they do, and say what happened.

UX perception audit, 2026-11-18 (batch B11):

* P32. The detail panel's Deployment and Actions rows were nine bare 40 px
  pictograms, Delete eight pixels from "Show API command", and the list toolbar
  three more: the meaning lived in `title`, which a touch browser never shows.
  On a 360 px phone the row actions sat past the right edge of the table, with
  nothing saying they were there. Now each of those controls carries its word,
  Delete sits on a line of its own, the detail's deployment chips say what the
  probe found, and below `md` the row actions are not drawn: a tap on the row
  opens the panel that has them.
* P43. The client list's Refresh and each row's Renew drew the same glyph
  (U+F021), and "Check deployment now" was a near twin of Renew. One icon meant
  CA in one place and ACME in another, and the shield that marks CA in the
  Settings menu marked Challenge Type in the drawer.
* P51. "Run deploy hooks now" was offered and confirmed while deploy hooks were
  off, and a failed run's toast said only "0/1 succeeded" although the answer
  named the hook and carried its error.
* P52. When the browser tried a host and could not connect, its chip said
  "Browser: Not Checked", the same as a probe that never ran.
* P35. The row's More actions menu ignored the arrow keys, and Escape dropped
  focus on the page body.

The certificates, the deploy configuration and the deploy run are answered in
the browser (page.route), as in tests/test_ui_controls_name_their_actions.py.
The server half of P51 (a run that ran nothing is not a failure in Activity) is
tests/test_a_deploy_run_that_ran_nothing_is_not_a_failure.py.
"""
import json
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER
from tests.test_ui_text_is_readable import CONTRAST

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError(
            "playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1"
        )
else:
    pytest.importorskip("playwright")

from playwright.sync_api import TimeoutError as PlaywrightTimeout

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
DOMAIN = 'site0.example.test'


def _certificate(domain, **more):
    return dict({'domain': domain, 'exists': True, 'days_left': 60, 'days_until_expiry': 60,
                 'expired': False, 'seconds_left': 60 * 86400,
                 'expiry_date': '2027-01-01 10:00:00', 'expires_at': '2027-01-01T10:00:00Z',
                 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
                 'san_domains': [], 'has_private_key': True}, **more)


CERTIFICATES = [_certificate(DOMAIN), _certificate('site1.example.test'),
                _certificate('a-really-long-subdomain-name-for-testing.customer-env.example.io')]
CLIENT_CERTIFICATES = {'certificates': [
    {'identifier': f'c{i}', 'common_name': f'client{i}.example.test', 'email': f'user{i}@example.test',
     'cert_usage': 'vpn', 'created_at': '2026-10-01T10:00:00Z', 'expires_at': '2027-10-01T10:00:00Z',
     'revoked': False} for i in range(2)]}
DEPLOYED = {'deployed': True, 'reachable': True, 'certificate_match': True,
            'method': 'server', 'protocol': 'https-tls'}
UNREACHABLE = {'deployed': False, 'reachable': False, 'certificate_match': False,
               'method': 'https-tls', 'protocol': 'https-tls', 'probe_host': DOMAIN,
               'mismatch_reason': 'DNS resolution failed'}
HOOK = {'id': 'h1', 'name': 'reload-lb', 'command': 'ls /run/lb01-admin.sock', 'enabled': True,
        'timeout': 30, 'on_events': ['created', 'renewed']}
HOOKS_OFF = {'enabled': False, 'global_hooks': [], 'domain_hooks': {}, 'targets': []}
HOOKS_ON = {'enabled': True, 'global_hooks': [HOOK], 'domain_hooks': {}, 'targets': []}
STDERR = 'ls: /run/lb01-admin.sock: No such file or directory\n'
FAILED_RUN = {'ok': False, 'total': 1, 'succeeded': 0, 'failed': 1, 'results': [
    {'hook_id': 'h1', 'hook_name': 'reload-lb', 'domain': DOMAIN, 'event': 'manual',
     'exit_code': 1, 'stdout': '', 'stderr': STDERR, 'success': False, 'status': 'failed',
     'error': 'exit code 1: ' + STDERR.strip()}]}


@pytest.fixture
def open_page(browser_page, ui_session_cookie):
    """A new page at `width`, with the answers given; closed after the test."""
    contexts = []

    def make(width=1280, height=900, deployment=DEPLOYED, deploy_config=HOOKS_OFF, deploy_run=None,
             touch=False, scheme='light'):
        context = browser_page.context.browser.new_context(
            viewport={'width': width, 'height': height}, has_touch=touch, is_mobile=touch, color_scheme=scheme)
        contexts.append(context)
        context.add_init_script(CONTRAST)
        context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
        page = context.new_page()
        page.emulate_media(reduced_motion='reduce')
        page.runs = []

        def answer(route):
            request = route.request
            url = request.url.split('?')[0]
            if request.method == 'GET' and url.endswith('/api/certificates'):
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(CERTIFICATES))
            if request.method == 'GET' and url.endswith('/deployment-status'):
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(deployment))
            if request.method == 'GET' and url.endswith('/api/client-certs'):
                return route.fulfill(status=200, content_type='application/json',
                                     body=json.dumps(CLIENT_CERTIFICATES))
            if request.method == 'GET' and url.endswith('/api/deploy/config'):
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(deploy_config))
            if request.method == 'POST' and url.endswith('/deploy') and deploy_run is not None:
                page.runs.append(url)
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(deploy_run))
            return route.continue_()
        page.route('**/api/**', answer)
        # The browser's own probe of a host the server could not reach: no such host.
        page.route('https://*.example.test/**', lambda route: route.abort('namenotresolved'))
        page.route('https://*.example.io/**', lambda route: route.abort('namenotresolved'))
        return page

    yield make
    for context in contexts:
        context.close()


def _open_detail(page, domain=DOMAIN):
    page.goto(BASE_URL + '/', wait_until='networkidle')
    row = page.locator(f'tr[data-row-domain="{domain}"]')
    row.wait_for(state='visible', timeout=15000)
    row.locator('td').first.click()
    page.wait_for_function(
        "d => document.getElementById('detailDomain').textContent.trim() === d", arg=domain)
    return page.locator('#certDetailPanel')


SECTION_CONTROLS = """name => {
    const heading = [...document.querySelectorAll('#certDetailPanel h3')]
        .find(h => h.textContent.trim().toLowerCase() === name);
    if (!heading) return null;
    return [...heading.parentElement.querySelectorAll('button, a')]
        .filter(el => el.offsetParent !== null)
        .map(el => ({label: el.getAttribute('aria-label') || el.title, text: el.innerText.trim(),
                     parent: el.parentElement === heading.nextElementSibling}));
}"""


# --- P32 -------------------------------------------------------------------

def test_the_detail_actions_say_what_they_do_in_words(open_page):
    page = open_page()
    _open_detail(page)
    for section in ('deployment', 'actions'):
        controls = page.evaluate(SECTION_CONTROLS, section)
        assert controls, f'no {section} controls found'
        bare = [c['label'] for c in controls if not c['text']]
        assert bare == [], f'{section} controls with no word on them: {bare}'
    # CONTROL: the panel drew the actions of a managed certificate for an admin.
    labels = [c['label'] for c in page.evaluate(SECTION_CONTROLS, 'actions')]
    assert 'Renew certificate' in labels and 'Delete certificate' in labels, labels


def test_delete_is_set_apart_from_the_other_actions(open_page):
    page = open_page()
    panel = _open_detail(page)
    delete = panel.locator('button[aria-label="Delete certificate"]')
    download = panel.locator('button[aria-label="Download certificate"]')
    same_row = page.evaluate(
        "([a, b]) => a.parentElement === b.parentElement",
        [delete.element_handle(), download.element_handle()])
    assert not same_row, 'Delete sits in the same row as Download'
    gap = delete.bounding_box()['y'] - (download.bounding_box()['y'] + download.bounding_box()['height'])
    assert gap >= 8, f'Delete is {gap} px below the other actions'


def test_the_detail_deployment_chips_say_what_the_probe_found(open_page):
    page = open_page()
    panel = _open_detail(page)
    chip = panel.locator('[data-deployment-role="backend"]')
    page.wait_for_function(
        "() => (document.querySelector('#certDetailPanel [data-deployment-role=\"backend\"]').title || '')"
        ".startsWith('Server: Deployed')")
    assert 'Deployed' in chip.inner_text(), chip.inner_text()


@pytest.mark.parametrize('scheme', ['light', 'dark'])
@pytest.mark.parametrize('deployment', [DEPLOYED, UNREACHABLE], ids=['deployed', 'unreachable'])
def test_the_words_in_the_detail_are_readable(open_page, scheme, deployment):
    page = open_page(scheme=scheme, deployment=deployment)
    _open_detail(page)
    page.wait_for_function("() => !document.querySelector('#certDetailPanel .fa-spinner')", timeout=15000)
    page.wait_for_timeout(400)
    low = [t for t in page.evaluate("() => __contrast.texts()") if t[0]]
    assert low == [], f'{scheme}: text under AA: {low}'


def test_the_list_actions_say_what_they_do_in_words(open_page):
    for width in (1280, 360):
        page = open_page(width=width)
        page.goto(BASE_URL + '/', wait_until='networkidle')
        group = page.locator('[role="group"][aria-label="Certificate list actions"] button:visible')
        assert group.count() >= 3
        bare = [b.get_attribute('aria-label') for b in group.all() if not b.inner_text().strip()]
        assert bare == [], f'list actions with no word at {width} px: {bare}'


def test_no_row_action_is_past_the_edge_of_a_phone(open_page):
    page = open_page(width=360, height=740, touch=True)
    page.goto(BASE_URL + '/', wait_until='networkidle')
    page.locator(f'tr[data-row-domain="{DOMAIN}"]').wait_for(state='visible', timeout=15000)
    edge = page.evaluate("() => document.querySelector('#certificatesTable').parentElement"
                         ".getBoundingClientRect().right")
    assert edge <= 344.5, edge
    cut = page.evaluate("""edge => [...document.querySelectorAll('#certificatesTable button')]
        .filter(b => b.offsetParent !== null && b.getBoundingClientRect().right > edge + 0.5)
        .map(b => (b.getAttribute('aria-label') || b.title) + ' right ' + b.getBoundingClientRect().right)""", edge)
    assert cut == [], cut
    # CONTROL: the actions are still one tap away, in the panel the row opens.
    page.locator(f'tr[data-row-domain="{DOMAIN}"] td').first.tap()
    page.wait_for_function("() => !document.getElementById('certDetailPanel').classList.contains('hidden')")
    assert page.locator('#certDetailPanel button[aria-label="Renew certificate"]').is_visible()


# --- P43 -------------------------------------------------------------------

GLYPHS = """() => [...document.querySelectorAll('button, a')]
    .filter(el => el.offsetParent !== null && el.querySelector('i.fas'))
    .map(el => ({label: (el.getAttribute('aria-label') || el.title || '').trim(),
                 glyph: getComputedStyle(el.querySelector('i.fas'), '::before').content}))"""


def _glyphs(page, starts):
    return {g['glyph'] for g in page.evaluate(GLYPHS) if g['label'].startswith(starts)}


def test_refresh_and_renew_never_share_a_glyph_on_the_dashboard(open_page):
    page = open_page()
    _open_detail(page)
    refresh, renew = _glyphs(page, 'Refresh'), _glyphs(page, 'Renew')
    assert refresh and renew, page.evaluate(GLYPHS)
    assert not refresh & renew, (refresh, renew)
    # "Check deployment now" asks again where the certificate is served: the
    # same glyph as "Check all deployments", not a twin of Refresh or Renew.
    check = _glyphs(page, 'Check deployment now')
    assert check == _glyphs(page, 'Check all deployments'), (check, _glyphs(page, 'Check all deployments'))
    assert not check & (renew | refresh), (check, renew, refresh)


def test_refresh_and_renew_never_share_a_glyph_on_the_client_list(open_page):
    page = open_page()
    page.goto(BASE_URL + '/#client', wait_until='networkidle')
    page.locator('tr[data-cc-id="c0"]').wait_for(state='visible', timeout=15000)
    refresh, renew = _glyphs(page, 'Refresh'), _glyphs(page, 'Renew')
    assert refresh and renew, page.evaluate(GLYPHS)
    assert not refresh & renew, (refresh, renew)


def _icon(page, selector):
    return page.evaluate("s => getComputedStyle(document.querySelector(s), '::before').content", selector)


def test_one_icon_means_ca_and_another_means_acme(open_page):
    page = open_page()
    page.goto(BASE_URL + '/settings#ca', wait_until='networkidle')
    page.locator('#settings-panel-ca').wait_for(state='visible', timeout=15000)
    ca_nav = page.evaluate("""() => getComputedStyle(
        [...document.querySelectorAll('[role=tab]')].find(t => t.textContent.trim() === 'CA').querySelector('i'),
        '::before').content""")
    acme_nav = page.evaluate("""() => getComputedStyle(
        [...document.querySelectorAll('[role=tab]')].find(t => t.textContent.trim() === 'ACME').querySelector('i'),
        '::before').content""")
    ca_heading = _icon(page, '#settings-panel-ca h2 i')
    acme_heading = page.evaluate("""() => getComputedStyle([...document.querySelectorAll('h2')]
        .find(h => h.textContent.trim() === 'ACME server').querySelector('i'), '::before').content""")

    page.goto(BASE_URL + '/', wait_until='networkidle')
    ca_field = _icon(page, 'label[for="ca_provider_select"] i')
    challenge_field = _icon(page, 'label[for="challenge_type_select"] i')
    acme_view = _icon(page, '#certViewAcmeBtn i')

    assert {ca_nav, ca_heading, ca_field} == {ca_nav}, (ca_nav, ca_heading, ca_field)
    assert {acme_nav, acme_heading, acme_view} == {acme_nav}, (acme_nav, acme_heading, acme_view)
    assert ca_nav != acme_nav
    assert challenge_field not in (ca_nav, acme_nav), challenge_field


# --- P51 -------------------------------------------------------------------

def test_run_hooks_is_not_offered_while_deploy_hooks_are_off(open_page):
    page = open_page(deploy_config=HOOKS_OFF, deploy_run=FAILED_RUN)
    panel = _open_detail(page)
    run = panel.locator('button[aria-label="Run deploy hooks now"]')
    try:
        # The panel asks whether hooks are on when it opens; give it the moment.
        page.wait_for_function("() => document.querySelector("
                               "'#certDetailPanel button[aria-label=\"Run deploy hooks now\"]').disabled",
                               timeout=3000)
    except PlaywrightTimeout:
        pass
    assert run.is_disabled(), 'Run deploy hooks now is offered while deploy hooks are off'
    assert 'Settings' in (run.get_attribute('title') or ''), run.get_attribute('title')
    run.click(force=True)
    page.wait_for_timeout(300)
    assert page.locator('[role="alertdialog"]').count() == 0 or not page.locator('[role="alertdialog"]').is_visible()
    assert page.runs == []


def test_a_failed_hook_run_names_the_hook_and_its_error(open_page):
    page = open_page(deploy_config=HOOKS_ON, deploy_run=FAILED_RUN)
    panel = _open_detail(page)
    run = panel.locator('button[aria-label="Run deploy hooks now"]')
    page.wait_for_timeout(300)
    assert run.is_enabled()
    run.click()
    page.get_by_role('alertdialog').get_by_role('button', name='Run Hooks').click()
    page.wait_for_function(
        "() => document.getElementById('cm-toasts') && document.getElementById('cm-toasts').innerText"
        ".includes('Deploy hook')", timeout=10000)
    toast = page.inner_text('#cm-toasts')
    assert 'reload-lb' in toast and 'No such file or directory' in toast, toast
    assert len(page.runs) == 1


# A typed deploy target reports in its own shape (modules/core/deploy_targets.py
# run_targets): its name in `target`, its kind in `type`, its reason in
# `message`, and no hook_name, stderr or error. The refusal a CSR-only
# certificate gets before any target runs (modules/core/deployer.py) has no
# name at all.
TARGET_REASON = 'connection refused by lb01.internal:443'
FAILED_TARGET_RUN = {'ok': False, 'total': 1, 'succeeded': 0, 'failed': 1, 'results': [
    {'success': False, 'status_code': None, 'message': TARGET_REASON,
     'target': 'lb-webhook', 'type': 'webhook', 'domain': DOMAIN}]}
NO_KEY_REASON = (f'{DOMAIN} has no private key on this node: it was issued from a CSR and the key '
                 'stays on the device that generated it. Typed deploy targets publish the key with '
                 'the certificate, so use a shell hook that fetches only the certificate instead.')
NO_KEY_RUN = {'ok': False, 'total': 1, 'succeeded': 0, 'failed': 1, 'results': [
    {'success': False, 'target': None, 'type': None, 'domain': DOMAIN, 'status_code': None,
     'message': NO_KEY_REASON}]}


def _run_and_read_the_toast(open_page, deploy_run):
    page = open_page(deploy_config=HOOKS_ON, deploy_run=deploy_run)
    panel = _open_detail(page)
    run = panel.locator('button[aria-label="Run deploy hooks now"]')
    page.wait_for_timeout(300)
    run.click()
    page.get_by_role('alertdialog').get_by_role('button', name='Run Hooks').click()
    page.wait_for_function(
        "() => document.getElementById('cm-toasts') && document.getElementById('cm-toasts').innerText"
        ".includes('succeeded')", timeout=10000)
    assert len(page.runs) == 1
    return page.inner_text('#cm-toasts')


def test_a_failed_target_run_names_the_target_and_its_reason(open_page):
    toast = _run_and_read_the_toast(open_page, FAILED_TARGET_RUN)
    assert 'Deploy target lb-webhook failed' in toast, toast
    assert TARGET_REASON in toast, toast
    assert 'deploy hook' not in toast.lower(), toast


def test_a_target_refused_for_want_of_a_key_says_why(open_page):
    toast = _run_and_read_the_toast(open_page, NO_KEY_RUN)
    assert 'has no private key on this node' in toast, toast
    assert 'A deploy target failed' in toast, toast
    assert 'deploy hook' not in toast.lower(), toast


# --- P52 -------------------------------------------------------------------

def test_the_browser_chip_says_the_browser_could_not_connect(open_page):
    page = open_page(deployment=UNREACHABLE)
    page.goto(BASE_URL + '/', wait_until='networkidle')
    chip = page.locator(f'#certificatesList [data-deployment-domain="{DOMAIN}"][data-deployment-role="browser"]')
    chip.first.wait_for(state='attached', timeout=15000)
    # The server's answer is drawn after the browser's own try, so once the
    # server chip says Unreachable the browser chip has its answer too.
    page.wait_for_function(
        """d => [...document.querySelectorAll('#certificatesList [data-deployment-role="backend"]')]
              .some(c => c.getAttribute('data-deployment-domain') === d
                         && (c.title || '').startsWith('Server: Unreachable'))""", arg=DOMAIN, timeout=15000)
    title = chip.first.get_attribute('title')
    assert title.startswith('Browser: Could not connect'), title
    # CONTROL: the server chip says the server's own verdict.
    server = page.locator(f'#certificatesList [data-deployment-domain="{DOMAIN}"][data-deployment-role="backend"]')
    assert server.first.get_attribute('title').startswith('Server: Unreachable')


# --- P35 -------------------------------------------------------------------

def _active(page):
    return page.evaluate("""() => { const a = document.activeElement;
        return {tag: a.tagName, role: a.getAttribute('role'), text: (a.innerText || '').trim(),
                more: a.hasAttribute('data-more-domain') ? a.getAttribute('data-more-domain') : null}; }""")


def test_the_more_actions_menu_answers_the_arrow_keys_and_gives_focus_back(open_page):
    page = open_page()
    page.goto(BASE_URL + '/', wait_until='networkidle')
    trigger = page.locator(f'tr[data-row-domain="{DOMAIN}"] button[data-more-domain]')
    trigger.wait_for(state='visible', timeout=15000)
    trigger.focus()
    page.keyboard.press('Enter')
    menu = page.locator('[role="menu"]')
    menu.wait_for(state='visible')
    items = [t.strip() for t in menu.locator('[role="menuitem"]').all_inner_texts()]
    assert len(items) >= 3, items
    assert trigger.get_attribute('aria-expanded') == 'true'
    assert _active(page)['text'] == items[0]

    page.keyboard.press('ArrowDown')
    assert _active(page)['text'] == items[1]
    page.keyboard.press('End')
    assert _active(page)['text'] == items[-1]
    page.keyboard.press('ArrowDown')
    assert _active(page)['text'] == items[0]
    page.keyboard.press('ArrowUp')
    assert _active(page)['text'] == items[-1]
    page.keyboard.press('Home')
    assert _active(page)['text'] == items[0]
    assert page.evaluate('() => window.scrollY') == 0, 'the keys scrolled the page under the menu'

    page.keyboard.press('Escape')
    assert menu.count() == 0
    assert _active(page)['more'] == DOMAIN, _active(page)
    assert trigger.get_attribute('aria-expanded') == 'false'

    # Tab closes it too, and goes on from the button rather than from the page top.
    page.keyboard.press('Enter')
    menu.wait_for(state='visible')
    page.keyboard.press('Tab')
    assert menu.count() == 0
    assert trigger.get_attribute('aria-expanded') == 'false'
    after = page.evaluate("""d => { const t = document.querySelector('button[data-more-domain="' + d + '"]');
        const a = document.activeElement;
        return a !== document.body && !!(t.compareDocumentPosition(a) & Node.DOCUMENT_POSITION_FOLLOWING); }""", DOMAIN)
    assert after, _active(page)
