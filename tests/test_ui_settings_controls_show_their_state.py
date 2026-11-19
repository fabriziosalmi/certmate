"""Settings controls show their real state (UX perception audit #1511, batch B5).

P06  With no event chosen every event is sent, and the chips said nothing:
     all six drew grey, and clicking one to be sure it was sent narrowed the
     notifications to that one event. An empty list now draws every chip
     selected with "All events are sent"; a click deselects one.
P27  ACME read "On" and offered a directory URL as soon as the box was ticked,
     before Save, while /acme/ still answered 404; under ticked boxes the
     helpers began "Off, ...".
P61  A refused SSO save and a refused EAB key named the API key
     ("issuer_url", "allowed_identifiers") and marked no field.
P28  Switches that look alike save in different ways. Each one now says so:
     a control that writes at once carries "Applies immediately", a change
     that waits shows "Unsaved changes" next to the Save that saves it, and
     every Save names what it saves.

Every write is answered in the browser or refused by the server's own
validation, so the shared instance is left as it was.
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

EVENTS = ['certificate_created', 'certificate_renewed', 'certificate_deployed',
          'certificate_expiring', 'certificate_revoked', 'domain_expiring']


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.writes = []
    page.on('request', lambda r: page.writes.append((r.method, r.url)) if r.method != 'GET' else None)
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _open(page, tab):
    page.goto(f'{BASE_URL}/settings#{tab}', wait_until='networkidle')
    page.wait_for_function("() => typeof window.CertMate.unsavedSettings === 'function'")


def _answer_json(page, pattern, body, method=None, status=200, sent=None):
    """Answer `pattern` in the browser; other methods go to the server."""
    def handle(route):
        if method and route.request.method != method:
            return route.fallback()
        if sent is not None:
            sent.append(route.request.post_data_json)
        return route.fulfill(status=status, content_type='application/json', body=json.dumps(body))
    page.route(pattern, handle)


def _toast_text(page):
    page.wait_for_function("() => (document.getElementById('cm-toasts') || {}).innerText")
    return page.inner_text('#cm-toasts')


# ── P06 ──────────────────────────────────────────────────────────────

def _notifications(page, events):
    config = {'enabled': True, 'digest_enabled': True, 'events': events,
              'channels': {'smtp': {'enabled': False}, 'webhooks': []}}
    sent = []
    _answer_json(page, '**/api/notifications/config', config, method='GET')
    _answer_json(page, '**/api/notifications/config', {'message': 'saved'}, method='POST', sent=sent)
    _open(page, 'notifications')
    page.wait_for_selector('#settings-panel-notifications label:has(input[type=checkbox][value])', state='visible')
    return sent


def _chip(page, evt):
    return page.locator(f'#settings-panel-notifications input[type=checkbox][value="{evt}"]')


def _selected(page):
    return [evt for evt in EVENTS if _chip(page, evt).is_checked()]


def _click_chip(page, evt):
    page.locator(f'#settings-panel-notifications label:has(input[value="{evt}"])').click()


def _save_notifications(page, sent):
    before = len(sent)
    page.locator('#settings-panel-notifications button[data-saves]').click()
    page.wait_for_timeout(300)
    assert len(sent) == before + 1, 'the Save sent nothing'
    return sent[-1]['events']


def test_an_empty_event_list_draws_every_chip_selected_and_says_all_are_sent(page):
    sent = _notifications(page, [])
    panel = page.locator('#settings-panel-notifications')
    assert _selected(page) == EVENTS, 'with no filter every event is sent, so every chip must read selected'
    assert panel.get_by_text('All events are sent').is_visible()
    assert not panel.get_by_text('Only the selected events are sent').is_visible()
    # Nothing changed, so the Save keeps the list empty: every event.
    assert _save_notifications(page, sent) == []


def test_clicking_a_chip_deselects_it_and_says_only_the_selected_are_sent(page):
    sent = _notifications(page, [])
    panel = page.locator('#settings-panel-notifications')
    _click_chip(page, 'certificate_expiring')
    assert _selected(page) == [e for e in EVENTS if e != 'certificate_expiring']
    assert panel.get_by_text('Only the selected events are sent').is_visible()
    assert not panel.get_by_text('All events are sent').is_visible()
    saved = _save_notifications(page, sent)
    assert sorted(saved) == sorted(e for e in EVENTS if e != 'certificate_expiring'), \
        'the page shows five events selected, so the five are what is saved'


def test_selecting_every_chip_again_goes_back_to_all_events(page):
    sent = _notifications(page, [])
    _click_chip(page, 'certificate_expiring')
    _click_chip(page, 'certificate_expiring')
    assert _selected(page) == EVENTS
    assert page.locator('#settings-panel-notifications').get_by_text('All events are sent').is_visible()
    assert _save_notifications(page, sent) == [], 'all selected is saved as all, so a future event is not filtered away'


def test_a_saved_subset_draws_only_those_chips_and_the_last_one_stays(page):
    _notifications(page, ['certificate_renewed'])
    panel = page.locator('#settings-panel-notifications')
    assert _selected(page) == ['certificate_renewed']
    assert panel.get_by_text('Only the selected events are sent').is_visible()
    # Removing the last one would empty the list, which means every event.
    _click_chip(page, 'certificate_renewed')
    assert _selected(page) == ['certificate_renewed']


# ── P27 ──────────────────────────────────────────────────────────────

ACME_OFF = {'enabled': False, 'allow_http': False, 'eab_required': True, 'validity_days': 45,
            'allowed_identifiers': [], 'directory_url': f'{BASE_URL}/acme/directory', 'eab_keys': []}


def test_acme_reads_on_and_offers_its_url_only_once_saved(page):
    _answer_json(page, '**/api/acme/server', ACME_OFF, method='GET')
    _answer_json(page, '**/api/acme/server', dict(ACME_OFF, enabled=True), method='PATCH')
    _open(page, 'acme')
    page.wait_for_selector('#acmeEnabled', state='visible')
    badge = page.locator('#acmeState')
    assert badge.inner_text().strip() == 'Off'

    page.check('#acmeEnabled')
    assert badge.inner_text().strip() == 'Off', 'nothing is served until Save'
    assert not page.is_visible('#acmeDirectoryUrl'), 'an unsaved directory URL answers 404'
    options = page.locator('[data-unsaved-scope="ACME server"]')
    assert options.get_by_text('Unsaved changes').is_visible()
    helpers = page.evaluate("""() => [...document.querySelectorAll('[data-unsaved-scope="ACME server"] label')]
        .filter(l => l.querySelector('input[type=checkbox]:checked'))
        .map(l => l.querySelector('.text-muted').innerText.trim())""")
    assert len(helpers) == 2, helpers
    assert not [h for h in helpers if h.startswith('Off,')], helpers

    page.click('#acmeSave')
    page.wait_for_function("() => document.getElementById('acmeState').innerText.trim() === 'On'")
    assert page.is_visible('#acmeDirectoryUrl')
    assert not options.get_by_text('Unsaved changes').is_visible()


# ── P61 ──────────────────────────────────────────────────────────────

def test_a_refused_sso_save_names_and_marks_the_field(page):
    _open(page, 'oidc')
    page.wait_for_selector('#oidc-issuer-url', state='visible')
    panel = page.locator('#settings-panel-oidc')
    panel.locator('label:has-text("Enable OIDC/SSO") input[type=checkbox]').check()
    page.fill('#oidc-issuer-url', '')
    page.fill('#oidc-client-id', '')
    with page.expect_response(lambda r: r.url.endswith('/api/auth/oidc/settings') and r.request.method == 'POST') as answer:
        panel.locator('button[data-saves]').click()
    assert answer.value.status == 400
    toast = _toast_text(page)
    # Led by the label; the server's message follows as it was sent.
    assert 'Issuer URL: issuer_url is required when OIDC is enabled' in toast, toast
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'oidc-issuer-url'")
    assert page.get_attribute('#oidc-issuer-url', 'aria-invalid') == 'true'
    assert 'required' in panel.locator('label[for="oidc-issuer-url"]').inner_text()
    page.type('#oidc-issuer-url', 'h')
    assert page.get_attribute('#oidc-issuer-url', 'aria-invalid') is None, 'the mark goes once the field is edited'


def test_a_refused_eab_key_names_and_marks_the_field(page):
    _open(page, 'acme')
    page.wait_for_selector('#acmeKeyNames', state='visible')
    with page.expect_response(lambda r: r.url.endswith('/api/acme/eab-keys') and r.request.method == 'POST') as answer:
        page.click('#acmeCreateKey')
    assert answer.value.status == 400
    toast = _toast_text(page)
    assert 'Names and addresses it may order: allowed_identifiers must list' in toast, toast
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'acmeKeyNames'")
    assert page.get_attribute('#acmeKeyNames', 'aria-invalid') == 'true'


# ── P28 ──────────────────────────────────────────────────────────────

def _flip(page, selector):
    before = len(page.writes)
    page.locator(selector).click()
    page.wait_for_timeout(800)
    return page.writes[before:]


def _row_text(page, control):
    """The text of the smallest block around a control that holds its helper."""
    return page.evaluate("""sel => {
        let el = document.querySelector(sel);
        while (el && !(el.innerText || '').match(/\\S{2,}.*\\n.*\\S{2,}/s)) el = el.parentElement;
        return el ? el.innerText : '';
    }""", control)


def test_the_update_check_applies_at_once_says_so_and_is_not_left_unsaved(page):
    _answer_json(page, '**/api/web/update-check', {'enabled': True}, method='POST')
    _open(page, 'general')
    page.wait_for_selector('#update_check_enabled', state='visible')
    writes = _flip(page, '#update_check_enabled')
    assert [m for m, _ in writes] == ['POST'], writes
    assert 'Applies immediately' in _row_text(page, '#update_check_enabled')
    assert page.evaluate('() => window.CertMate.unsavedSettings()') == [], \
        'a change already saved must not ask before leaving'
    assert not page.locator('#formControls').get_by_text('Unsaved changes').is_visible()


def test_local_authentication_applies_at_once_and_says_so(page):
    _answer_json(page, '**/api/auth/config', {'message': 'Local authentication updated'}, method='POST')
    _open(page, 'users')
    page.wait_for_selector('label:has(#localAuthToggle)', state='visible')
    writes = _flip(page, 'label:has(#localAuthToggle)')
    assert [m for m, _ in writes] == ['POST'], writes
    assert 'Applies immediately' in page.inner_text('#localAuthToggleHint')


def test_a_deploy_target_switch_applies_at_once_and_says_so(page):
    target = {'id': 'audit-target', 'name': 'audit target', 'type': 'webhook', 'enabled': True,
              'events': {'created': True, 'renewed': True},
              'config': {'url': 'https://hooks.example.test/certmate', 'method': 'POST'}}
    config = {'enabled': True, 'global_hooks': [], 'domain_hooks': {}, 'targets': [target]}
    _answer_json(page, '**/api/deploy/config', config, method='GET')
    _answer_json(page, '**/api/deploy/config', config, method='POST')
    _open(page, 'deploy')
    page.locator('#deploy-targets > button').click()
    switch = 'label:has(input[aria-label="Enable target audit target"])'
    page.wait_for_selector(switch, state='visible')
    writes = _flip(page, switch)
    assert [m for m, _ in writes] == ['POST'], writes
    assert 'applies immediately' in page.inner_text('#deploy-targets').lower()
    assert 'deploy' not in page.evaluate('() => window.CertMate.unsavedSettings()')


@pytest.mark.parametrize('tab, control, save', [
    ('deploy', 'label:has(input[aria-label="Enable deploy hooks"])',
     '#settings-panel-deploy button[data-saves]:has-text("Deploy")'),
    ('notifications', 'label:has(input[aria-label="Enable notifications"])', '#settings-panel-notifications [data-saves]'),
    ('general', '#auto_renew', '#saveBtn'),
    ('acme', '#acmeEnabled', '#acmeSave'),
    ('oidc', '#settings-panel-oidc label:has-text("Enable OIDC/SSO") input', '#settings-panel-oidc [data-saves]'),
])
def test_a_switch_that_waits_for_save_shows_unsaved_beside_its_save(page, tab, control, save):
    _open(page, tab)
    page.wait_for_selector(control, state='visible')
    writes = _flip(page, control)
    assert writes == [], f'{control} wrote at once: {writes}'
    button = page.locator(save).last
    beside = button.locator('xpath=..')
    assert beside.get_by_text('Unsaved changes').is_visible(), \
        f'nothing beside {save} says a change waits for it'


def test_every_save_button_names_what_it_saves(page):
    labels = {}
    for tab in ('dns', 'general', 'storage', 'notifications', 'deploy', 'apikeys', 'oidc', 'acme'):
        _open(page, tab)
        page.wait_for_timeout(400)
        for text in page.evaluate("""() => [...document.querySelectorAll('#saveBtn, [data-saves]')]
                .filter(b => b.offsetParent !== null).map(b => b.innerText.trim())"""):
            labels[text] = tab
    assert labels, 'no Save button found'
    bare = [text for text in labels if not re.match(r'^Save \S', text)]
    assert not bare, f'Save buttons that do not say what they save: {bare}'
    assert 'Save Settings' not in labels, 'the main Save saves DNS, General and Storage, and says so'


# ── Review round: what the first fix still got wrong ─────────────────

def test_a_stored_entry_without_a_chip_is_not_counted_as_a_selected_one(page):
    """certificate_failed had a chip before #943. Deselecting the one chip of
    a list that also holds it would leave the failures only, silently."""
    sent = _notifications(page, ['certificate_created', 'certificate_failed'])
    assert _selected(page) == ['certificate_created']
    _click_chip(page, 'certificate_created')
    assert _selected(page) == ['certificate_created']
    assert 'certificate_created' in _save_notifications(page, sent)


def test_a_stored_list_with_no_chip_says_only_failures_are_sent_and_is_kept(page):
    sent = _notifications(page, ['certificate_failed'])
    panel = page.locator('#settings-panel-notifications')
    assert _selected(page) == []
    assert panel.get_by_text('No event is selected: only failures are sent.').is_visible()
    assert not panel.get_by_text('All events are sent').is_visible()
    assert _save_notifications(page, sent) == ['certificate_failed'], 'an untouched list is saved as it was'


def _refuse_eab(page, kid, field, message=None):
    message = message or (f"An EAB key called '{kid}' exists already; keys are never reused, so the accounts "
                          'each one enrolled stay attributable')
    body = {'error': message, 'code': 'ACME_EAB_KEY_EXISTS', 'field': field}
    _answer_json(page, '**/api/acme/eab-keys', body, method='POST', status=409)
    _open(page, 'acme')
    page.wait_for_selector('#acmeKeyNames', state='visible')
    page.fill('#acmeKeyNames', '*.lab.internal')
    page.fill('#acmeKeyKid', kid)
    page.click('#acmeCreateKey')
    return _toast_text(page)


# Messages that any rewrite of the key would change: the key as a whole word
# inside a typed value, both quote kinds in one value (Python's repr escapes
# the single quote), and a host the server puts in the message unquoted.
@pytest.mark.parametrize('kid, message', [
    ('kid', "An EAB key called 'kid' exists already; keys are never reused"),
    ('kid', 'An EAB key called \'it\\\'s "kid" kid\' exists already; keys are never reused'),
])
def test_the_server_message_is_shown_as_sent_after_the_label(page, kid, message):
    toast = _refuse_eab(page, kid, 'kid', message)
    assert 'Key identifier: ' + message in toast, toast


def test_an_unquoted_host_in_the_message_is_shown_as_sent(page):
    message = ('issuer_url.169.254.169.254.nip.io resolves to 169.254.169.254, a link-local or '
               'cloud-metadata address that is never a valid endpoint')
    _answer_json(page, '**/api/auth/oidc/settings', {'error': message, 'field': 'issuer_url'},
                 method='POST', status=400)
    _open(page, 'oidc')
    page.wait_for_selector('#oidc-issuer-url', state='visible')
    page.locator('#settings-panel-oidc button[data-saves]').click()
    toast = _toast_text(page)
    assert 'Issuer URL: ' + message in toast, toast
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'oidc-issuer-url'")


def test_the_field_marked_is_the_one_the_server_names(page):
    _refuse_eab(page, 'ipv6-lab', 'kid')
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'acmeKeyKid'")
    assert page.get_attribute('#acmeKeyKid', 'aria-invalid') == 'true'
    assert page.get_attribute('#acmeKeyNames', 'aria-invalid') is None


def test_a_refused_acme_option_is_named_and_marked(page):
    _open(page, 'acme')
    page.wait_for_selector('#acmeValidity', state='visible')
    page.fill('#acmeValidity', '0')
    with page.expect_response(lambda r: r.url.endswith('/api/acme/server') and r.request.method == 'PATCH') as answer:
        page.click('#acmeSave')
    assert answer.value.status == 400
    toast = _toast_text(page)
    assert 'Certificate validity: validity_days must be a whole number' in toast, toast
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'acmeValidity'")
    assert page.get_attribute('#acmeValidity', 'aria-invalid') == 'true'


def test_a_link_local_issuer_is_named_and_marked(page):
    _open(page, 'oidc')
    page.wait_for_selector('#oidc-issuer-url', state='visible')
    panel = page.locator('#settings-panel-oidc')
    panel.locator('label:has-text("Enable OIDC/SSO") input[type=checkbox]').check()
    page.fill('#oidc-issuer-url', 'https://169.254.169.254/realm')
    page.fill('#oidc-client-id', 'certmate')
    saved = lambda r: r.url.endswith('/api/auth/oidc/settings') and r.request.method == 'POST'  # noqa: E731
    with page.expect_response(saved) as answer:
        panel.locator('button[data-saves]').click()
    assert answer.value.status == 400
    assert 'Issuer URL' in _toast_text(page)
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'oidc-issuer-url'")
    assert page.get_attribute('#oidc-issuer-url', 'aria-invalid') == 'true'


def _deploy_with_a_target(page):
    target = {'id': 'audit-target', 'name': 'audit target', 'type': 'webhook', 'enabled': True,
              'events': {'created': True, 'renewed': True},
              'config': {'url': 'https://hooks.example.test/certmate', 'method': 'POST'}}
    config = {'enabled': True, 'global_hooks': [], 'domain_hooks': {}, 'targets': [target]}
    _answer_json(page, '**/api/deploy/config', config, method='GET')
    _open(page, 'deploy')
    page.locator('#deploy-targets > button').click()
    page.wait_for_selector('input[aria-label="Enable target audit target"]', state='attached')


def test_save_deploy_settings_leaves_an_unsaved_target_unsaved(page):
    _deploy_with_a_target(page)
    _answer_json(page, '**/api/deploy/config', {'message': 'saved'}, method='POST')
    page.locator('button[aria-label="Edit target audit target"]').click()
    page.fill('#webhook-target-editor input[aria-label="Target name"]', 'renamed target')
    assert 'deploy target' in page.evaluate('() => window.CertMate.unsavedSettings()')
    with page.expect_response(lambda r: r.url.endswith('/api/deploy/config') and r.request.method == 'POST'):
        page.locator('#settings-panel-deploy button[data-saves]:has-text("Save Deploy Settings")').click()
    page.wait_for_timeout(300)
    assert 'deploy target' in page.evaluate('() => window.CertMate.unsavedSettings()')
    assert page.locator('#webhook-target-editor').get_by_text('Unsaved changes').is_visible()


def test_a_refused_save_is_not_cleared_by_a_later_write(page):
    _answer_json(page, '**/api/notifications/config', {'error': 'refused'}, method='POST', status=400)
    _answer_json(page, '**/api/web/update-check', {'enabled': True}, method='POST')
    _open(page, 'notifications')
    page.locator('label:has(input[aria-label="Enable notifications"])').click()
    with page.expect_response(lambda r: r.url.endswith('/api/notifications/config') and r.request.method == 'POST'):
        page.locator('#settings-panel-notifications button[data-saves]').click()
    page.click('#settings-tab-general')
    page.wait_for_selector('#update_check_enabled', state='visible')
    with page.expect_response(lambda r: r.url.endswith('/api/web/update-check') and r.request.method == 'POST'):
        page.click('#update_check_enabled')
    page.wait_for_timeout(300)
    assert 'notifications' in page.evaluate('() => window.CertMate.unsavedSettings()'), \
        'the refused save saved nothing, and a later write elsewhere does not change that'


def test_an_edited_probe_shows_unsaved_until_save_probe(page):
    cert = {'domain': 'probe.example.test', 'deployment_host': 'probe.example.test',
            'deployment_port': 443, 'deployment_protocol': 'https-tls'}
    _answer_json(page, '**/api/certificates', [cert], method='GET')
    _answer_json(page, '**/api/certificates/probe.example.test', cert, method='PATCH')
    _open(page, 'probe')
    page.locator('button[title="Edit probe"]').click()
    page.fill('input[aria-label="Probe host"]', 'other.example.test')
    save = page.locator('button:has-text("Save Probe")')
    assert save.locator('xpath=..').get_by_text('Unsaved changes').is_visible()
    with page.expect_response(lambda r: r.request.method == 'PATCH'):
        save.click()
    page.wait_for_timeout(300)
    assert page.evaluate('() => window.CertMate.unsavedSettings()') == []


@pytest.mark.parametrize('tab, control', [
    ('general', '#auto_renew'),
    ('notifications', '#settings-panel-notifications label:has(input[value="certificate_renewed"])'),
])
def test_a_change_undone_is_not_unsaved(page, tab, control):
    if tab == 'notifications':
        _notifications(page, [])
    else:
        _open(page, tab)
    page.wait_for_selector(control, state='visible')
    page.locator(control).click()
    page.wait_for_timeout(100)
    assert page.evaluate('() => window.CertMate.unsavedSettings()') != []
    page.locator(control).click()
    page.wait_for_timeout(100)
    assert page.evaluate('() => window.CertMate.unsavedSettings()') == []
    markers = page.locator('[data-unsaved-marker]')
    assert all(not markers.nth(i).is_visible() for i in range(markers.count()))


def test_a_target_switch_that_could_not_be_sent_goes_back(page):
    _deploy_with_a_target(page)
    page.route('**/api/deploy/config',
               lambda route: route.abort('failed') if route.request.method == 'POST' else route.fallback())
    switch = page.locator('input[aria-label="Enable target audit target"]')
    assert switch.is_checked()
    page.locator('label:has(input[aria-label="Enable target audit target"])').click()
    page.wait_for_timeout(800)
    assert switch.is_checked(), 'nothing was saved, so the switch shows the target still on'


# ── Second review round ──────────────────────────────────────────────

SLOW_FETCH = """(() => {
    const [path, method, ms] = %s;
    const real = window.fetch;
    window.fetch = function (resource, options) {
        const url = typeof resource === 'string' ? resource : resource.url;
        const verb = ((options && options.method) || 'GET').toUpperCase();
        if (url.indexOf(path) !== -1 && verb === method) {
            const self = this, args = arguments;
            return new Promise(done => setTimeout(done, ms)).then(() => real.apply(self, args));
        }
        return real.apply(this, arguments);
    };
})()"""


def _slow(page, path, method, ms):
    """Hold fetch() calls to *path* with *method* for *ms* before they go out."""
    page.add_init_script(SLOW_FETCH % json.dumps([path, method, ms]))


def test_a_field_clicked_before_the_page_loaded_is_not_an_edit(page):
    def stored_threshold_21(route):
        settings = route.fetch().json()
        settings['renewal_threshold_days'] = 21
        return route.fulfill(status=200, content_type='application/json', body=json.dumps(settings))
    page.route('**/api/web/settings', lambda route: stored_threshold_21(route) if route.request.method == 'GET'
               else route.fallback())
    _slow(page, '/api/web/settings', 'GET', 3000)
    page.goto(f'{BASE_URL}/settings#general', wait_until='domcontentloaded')
    page.wait_for_selector('#renewal_threshold_days', state='visible')
    page.click('#renewal_threshold_days')
    assert page.input_value('#renewal_threshold_days') != '21', 'the click must come before the load'
    page.wait_for_function("() => document.querySelector('#renewal_threshold_days').value === '21'",
                           timeout=15000)
    page.wait_for_timeout(300)
    assert page.evaluate('() => window.CertMate.unsavedSettings()') == [], \
        'a click is no edit, and the value the page loaded is where the field starts'


# ── Third review round: a section takes no edits while its save is on its way

def _main_form_answered_in_the_browser(page):
    """The main form needs a CA email to save; the settings it reads carry one
    and its save is answered here, so the instance is not written."""
    def handle(route):
        if route.request.method == 'GET':
            answer = route.fetch()
            settings = answer.json()
            settings['email'] = settings.get('email') or 'ops@example.test'
            return route.fulfill(response=answer, body=json.dumps(settings))
        return route.fulfill(status=200, content_type='application/json', body=json.dumps({'message': 'saved'}))
    page.route('**/api/web/settings', handle)


def _open_general(page):
    _main_form_answered_in_the_browser(page)
    _slow(page, '/api/web/settings', 'POST', 2500)
    _open(page, 'general')
    page.wait_for_function("() => document.querySelector('#renewal_threshold_days').value !== ''")


def _open_acme(page):
    _answer_json(page, '**/api/acme/server', ACME_OFF, method='GET')
    _answer_json(page, '**/api/acme/server', ACME_OFF, method='PATCH')
    _slow(page, '/api/acme/server', 'PATCH', 2500)
    _open(page, 'acme')


def _open_oidc(page):
    _answer_json(page, '**/api/auth/oidc/settings', {'message': 'OIDC settings updated'}, method='POST')
    _slow(page, '/api/auth/oidc/settings', 'POST', 2500)
    _open(page, 'oidc')


def _open_notifications(page):
    _notifications(page, [])
    _slow(page, '/api/notifications/config', 'POST', 2500)
    page.reload(wait_until='networkidle')
    page.locator('button:has-text("Email (SMTP)")').click()


def _open_deploy(page):
    config = {'enabled': True, 'global_hooks': [], 'domain_hooks': {}, 'targets': []}
    _answer_json(page, '**/api/deploy/config', config, method='GET')
    _answer_json(page, '**/api/deploy/config', {'message': 'saved'}, method='POST')
    _slow(page, '/api/deploy/config', 'POST', 2500)
    _open(page, 'deploy')


SAVING = {
    'general': (_open_general, '#settingsForm', '#saveBtn', '#renewal_threshold_days', 'text'),
    'acme': (_open_acme, '[data-unsaved-scope="ACME server"]', '#acmeSave', '#acmeValidity', 'text'),
    'oidc': (_open_oidc, '#settings-panel-oidc', '#settings-panel-oidc button[data-saves]', '#oidc-issuer-url', 'text'),
    'notifications': (_open_notifications, '#settings-panel-notifications',
                      '#settings-panel-notifications button[data-saves]', 'input[aria-label="SMTP username"]', 'text'),
    'deploy': (_open_deploy, '#settings-panel-deploy', '#settings-panel-deploy button[data-saves]:has-text("Deploy")',
               'input[aria-label="Enable deploy hooks"]', 'checkbox'),
}


def _try_to_change(page, field, kind):
    if kind == 'text':
        page.focus(field)
        page.keyboard.type('77')
    else:
        page.locator(f'label:has({field})').click()


@pytest.mark.parametrize('section', list(SAVING))
def test_a_section_takes_no_edits_while_its_save_is_on_its_way(page, section):
    open_section, scope, save, field, kind = SAVING[section]
    open_section(page)
    page.wait_for_selector(field, state='attached')
    if kind == 'text':
        page.fill(field, '42')
    page.locator(save).click()
    busy = page.locator(scope).first
    assert busy.get_attribute('aria-busy') == 'true', 'the section says it is busy while its save is on its way'
    assert 'Saving' in page.locator(save).locator('xpath=..').inner_text()
    before = page.input_value(field) if kind == 'text' else page.is_checked(field)
    _try_to_change(page, field, kind)
    after = page.input_value(field) if kind == 'text' else page.is_checked(field)
    assert after == before, f'{section}: an edit was taken while the save was on its way'
    if kind == 'text':
        assert page.evaluate(f"() => document.activeElement === document.querySelector('{field}')"), \
            'focus stays where the user put it'
    page.wait_for_function(f"() => !document.querySelector('{scope}').hasAttribute('aria-busy')", timeout=15000)
    if kind == 'text':
        page.fill(field, '43')
        assert page.input_value(field) == '43', 'the field takes edits again once the save has settled'
    else:
        was = page.is_checked(field)
        page.locator(f'label:has({field})').click()
        assert page.is_checked(field) != was


def test_an_event_chip_takes_no_click_while_the_save_is_on_its_way(page):
    _open_notifications(page)
    page.locator('#settings-panel-notifications button[data-saves]').click()
    _click_chip(page, 'certificate_expiring')
    assert _selected(page) == EVENTS
    page.wait_for_function("() => !document.querySelector('#settings-panel-notifications').hasAttribute('aria-busy')",
                           timeout=15000)
    _click_chip(page, 'certificate_expiring')
    assert 'certificate_expiring' not in _selected(page)


def test_a_saved_sso_form_rebuilt_by_its_reload_reads_saved(page):
    """The SSO form is redrawn by the read after a save: its old controls are
    gone, and that is not a change."""
    _open_oidc(page)
    page.wait_for_selector('#oidc-issuer-url', state='visible')
    page.fill('#oidc-issuer-url', 'https://idp.example.test/realms/main')
    page.locator('#settings-panel-oidc button[data-saves]').click()
    page.focus('#oidc-issuer-url')
    page.keyboard.type('/x')
    page.wait_for_timeout(4500)
    assert page.evaluate('() => window.CertMate.unsavedSettings()') == []
    markers = page.locator('#settings-panel-oidc [data-unsaved-marker]')
    assert all(not markers.nth(i).is_visible() for i in range(markers.count()))
