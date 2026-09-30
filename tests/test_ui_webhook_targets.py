"""The webhook deploy target is configurable from Settings -> Deploy (#218).

What is pinned here is what a screenshot cannot show and the JS source does not
make obvious, in the browser, against the real page:

* **What reaches the wire.** Saving posts ONLY `targets`: a post that also carried
  `enabled`/`global_hooks` would overwrite them with whatever this page loaded. And
  it posts the list the server holds NOW with this one target changed, not the
  list the page loaded earlier, so an edit an API client made in between is not
  overwritten. Targets of another type pass through unchanged.
* **The decision about the key.** A template that names the private key makes the
  save impossible until the destination host is typed; a confirmation the server
  already holds for this host is not asked again; a different host asks again. The
  page never posts its own `delivery_consent`.
* **Operator input is text.** A target name with markup in it is shown, not run.
* **What the preview claims.** It comes from the real server, and it is not shown
  once the form has changed since.
"""
import json
import os
import uuid

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

CERT_ONLY = '{"name": "{{domain}}", "certificate": "{{fullchain}}"}'
WITH_KEY = '{"name": "{{domain}}", "certificate": "{{fullchain}}", "key": "{{privkey_pkcs8}}"}'

KUBERNETES = {
    'id': 'k8s-1', 'name': 'Cluster secret', 'type': 'kubernetes-secret', 'enabled': True,
    'domains': ['shop.example.com'], 'on_events': ['renewed'],
    'config': {'api_server': 'https://k8s.internal:6443', 'namespace': 'web',
               'secret_name': 'tls', 'token': 'k8s-token-not-to-be-touched'},
}


def _webhook(template=CERT_ONLY, consent_host=None, **overrides):
    target = {
        'id': 'wh-1', 'name': 'Load balancer', 'type': 'webhook', 'enabled': True,
        'domains': ['shop.example.com'], 'on_events': ['created', 'renewed'],
        'config': {'url': 'https://lb.internal:8443/api/certificate', 'method': 'POST',
                   'payload_template': template, 'auth_type': 'none', 'allow_internal': True,
                   'a_field_an_api_client_added': 'keep-me'},
    }
    if consent_host:
        target['delivery_consent'] = {'host': consent_host, 'by': 'admin', 'at': '2026-09-30T10:00:00Z'}
    target.update(overrides)
    return target


class FakeConfigServer:
    """Stands in for /api/deploy/config: GET returns `state`, POST applies the keys it carries.

    Applying only the keys that arrive is what the real endpoint does, which is why
    a test can tell a post that carried `enabled` from one that did not.
    """

    def __init__(self, targets=None, enabled=True):
        self.state = {'enabled': enabled, 'global_hooks': [], 'domain_hooks': {},
                      'targets': targets or []}
        self.posts = []

    def handle(self, route, request):
        if request.method == 'GET':
            route.fulfill(status=200, content_type='application/json', body=json.dumps(self.state))
            return
        body = json.loads(request.post_data or '{}')
        self.posts.append(body)
        self.state.update(body)
        route.fulfill(status=200, content_type='application/json',
                      body=json.dumps({'message': 'Deploy configuration saved'}))


@pytest.fixture(scope='module')
def page(browser_page):
    """One page for the whole module, in the logged-in context.

    Not a page per test, for a reason that is not about speed: opening Settings
    makes about a dozen calls to /api/*, the app allows 100 a minute per address,
    and this module has twenty tests. Navigating in each of them spent that
    allowance and turned the tests that follow (here and in other modules, which
    share the instance) into 429s that read as "the preview never appeared".
    So the page is opened once, and each test swaps the fake configuration
    endpoint and reloads the component.
    """
    fresh = browser_page.context.new_page()
    fresh.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); } catch (e) {}")
    yield fresh
    fresh.close()


_RELOAD = """async () => {
    const component = Alpine.$data(document.getElementById('deploy-targets'));
    component.cancel();
    await component.load();
    await new Promise(resolve => requestAnimationFrame(() => resolve()));
}"""


def _open(page, server=None, targets=None):
    """Settings -> Deploy -> Deploy Targets, expanded, against a fake config endpoint.

    The first call navigates; later ones keep the page and only point it at the
    new fake and reload the component (see the `page` fixture for why).
    """
    if server is None:
        server = FakeConfigServer(targets)
    page.unroute('**/api/deploy/config')
    page.route('**/api/deploy/config', server.handle)
    if getattr(page, '_webhook_targets_open', False):
        page.evaluate(_RELOAD)
        return server
    page.goto(f'{BASE_URL}/settings')
    page.click('#settings-tab-deploy')
    page.wait_for_selector('#settings-panel-deploy', state='visible')
    page.locator('#deploy-targets > button').click()
    page.wait_for_selector('#deploy-targets >> text=A target hands the certificate')
    page._webhook_targets_open = True
    return server


def _fill_new_target(page, template=CERT_ONLY, url='https://lb.internal:8443/api/certificate'):
    page.locator('#deploy-targets button:has-text("Add Webhook Target")').click()
    page.wait_for_selector('#webhook-target-editor')
    page.fill('[aria-label="Target name"]', 'Load balancer')
    page.fill('[aria-label="Target domains"]', 'Shop.Example.com\nshop.example.com, api.example.com')
    page.fill('[aria-label="Target URL"]', url)
    page.fill('[aria-label="Target payload template"]', template)


def _save_and_capture(page):
    with page.expect_request(lambda r: r.method == 'POST' and '/api/deploy/config' in r.url) as posted:
        page.locator('#webhook-target-editor button:has-text("Save target")').click()
    return json.loads(posted.value.post_data)


# --------------------------------------------------------------------------
# What reaches the wire
# --------------------------------------------------------------------------

def test_saving_posts_only_targets_and_normalises_what_was_typed(page):
    server = _open(page)
    _fill_new_target(page)
    body = _save_and_capture(page)

    assert list(body) == ['targets'], (
        f'the save carried {sorted(body)}: a post with `enabled` or `global_hooks` would overwrite '
        f'those with whatever this page loaded')
    target = body['targets'][0]
    assert target['type'] == 'webhook' and target['enabled'] is True
    assert target['domains'] == ['shop.example.com', 'api.example.com'], (
        'domains are split on lines and commas, lower-cased and de-duplicated')
    assert target['on_events'] == ['created', 'renewed']
    assert 'acknowledge_key_delivery_to' not in target['config'], (
        'a certificate-only target has nothing to confirm')
    assert 'delivery_consent' not in target
    # The page reloads the list after a save; once the row is there the server has applied the post.
    page.wait_for_selector('[data-target-row]')
    assert server.state['targets'][0]['config']['payload_template'] == CERT_ONLY


def test_a_save_writes_the_list_the_server_holds_now_not_the_one_the_page_loaded(page):
    """An API client adds a target after this page loaded. Saving here must keep it."""
    server = _open(page)
    page.locator('#deploy-targets button:has-text("Add Webhook Target")').wait_for()
    added_meanwhile = _webhook(id='added-by-api', name='Added by an API client')
    server.state['targets'].append(added_meanwhile)

    _fill_new_target(page)
    body = _save_and_capture(page)

    ids = [t['id'] for t in body['targets']]
    assert 'added-by-api' in ids, (
        f'the save wrote {ids}: it was based on the list loaded earlier, so it deleted a target '
        f'somebody else created')
    assert len(ids) == 2


def test_a_target_of_another_type_is_listed_and_survives_a_save_unchanged(page):
    _open(page, targets=[KUBERNETES])
    row = page.locator('[data-target-row]').first
    assert 'Cluster secret' in row.inner_text() and 'kubernetes-secret' in row.inner_text()
    assert row.locator('button:has-text("Edit")').count() == 0, (
        'this screen edits webhook targets only; offering Edit on another type would round-trip '
        'its token through a form that does not know its fields')

    _fill_new_target(page)
    body = _save_and_capture(page)

    assert KUBERNETES in body['targets'], 'the Kubernetes target was altered or dropped by a webhook save'


def test_fields_the_form_does_not_know_are_carried_through_an_edit(page):
    _open(page, targets=[_webhook()])
    page.locator('[aria-label="Edit target Load balancer"]').click()
    page.fill('[aria-label="Target name"]', 'Load balancer 2')
    body = _save_and_capture(page)

    config = body['targets'][0]['config']
    assert config['a_field_an_api_client_added'] == 'keep-me', (
        'an edit dropped a config field an API client had set: the form must not be the owner of '
        'fields it has never heard of')
    assert body['targets'][0]['name'] == 'Load balancer 2'


def test_only_the_chosen_trust_mode_is_sent(page):
    _open(page)
    _fill_new_target(page)
    page.check('[aria-label="Trust a CA I provide"]')
    page.fill('[aria-label="Target CA certificate"]', '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----')
    page.check('[aria-label="Pin the server certificate"]')
    page.fill('[aria-label="Target pinned SHA-256 fingerprint"]', 'ab:' * 31 + 'ab')
    body = _save_and_capture(page)

    config = body['targets'][0]['config']
    assert 'pin_sha256' in config and 'ca_cert' not in config, (
        'a CA typed before the pin was chosen rode along; the server refuses a CA together with a pin')


def test_the_enabled_switch_changes_only_that_flag(page):
    target = _webhook(template=WITH_KEY, consent_host='lb.internal')
    _open(page, targets=[target])
    with page.expect_request(lambda r: r.method == 'POST' and '/api/deploy/config' in r.url) as posted:
        page.locator('[aria-label="Enable target Load balancer"]').evaluate('el => el.click()')
    body = json.loads(posted.value.post_data)

    assert list(body) == ['targets']
    expected = dict(target, enabled=False)
    del expected['delivery_consent']
    assert body['targets'][0] == expected, (
        'the switch should change `enabled` and nothing else, and post no consent: the server keeps the one it holds')


def test_no_webhook_target_leaves_the_page_with_a_consent(page):
    """Even the targets this save did not touch: the consent is the server's to write, never the page's."""
    _open(page, targets=[_webhook(template=WITH_KEY, consent_host='lb.internal'),
                         _webhook(id='wh-2', name='Another', template=WITH_KEY, consent_host='lb.internal')])
    page.locator('[aria-label="Edit target Another"]').click()
    page.fill('[aria-label="Target name"]', 'Another, renamed')
    body = _save_and_capture(page)

    assert [t['id'] for t in body['targets']] == ['wh-1', 'wh-2']
    assert all('delivery_consent' not in t for t in body['targets']), (
        f'a consent went back to the server: {[t.get("delivery_consent") for t in body["targets"]]}')


def test_deleting_asks_first_and_removes_only_that_target(page):
    _open(page, targets=[_webhook(), KUBERNETES])
    page.locator('[aria-label="Delete target Load balancer"]').click()
    page.wait_for_selector('[data-action="confirm"]')
    with page.expect_request(lambda r: r.method == 'POST' and '/api/deploy/config' in r.url) as posted:
        page.click('[data-action="confirm"]')
    body = json.loads(posted.value.post_data)
    assert body['targets'] == [KUBERNETES]


# --------------------------------------------------------------------------
# The decision about the key
# --------------------------------------------------------------------------

def test_a_certificate_only_target_is_never_asked_for_a_confirmation(page):
    """CONTROL for the tests below: a confirmation that is always shown means nothing."""
    _open(page)
    _fill_new_target(page, template=CERT_ONLY)
    assert page.locator('#key-delivery-confirmation').count() == 0
    assert page.locator('#webhook-target-editor button:has-text("Save target")').is_enabled()


def test_a_key_variable_blocks_the_save_until_the_host_is_typed(page):
    _open(page)
    _fill_new_target(page, template=CERT_ONLY)
    page.click('[data-key-variable]:has-text("privkey_pkcs8")')

    save = page.locator('#webhook-target-editor button:has-text("Save target")')
    box = page.locator('#key-delivery-confirmation')
    assert box.count() == 1 and 'lb.internal' in box.inner_text(), 'naming the key must show the destination'
    assert save.is_disabled()

    confirm = page.locator('[aria-label="Type the destination host to confirm key delivery"]')
    confirm.fill('wrong.example.com')
    assert save.is_disabled(), 'a host that is not the destination must not unlock the save'
    confirm.fill('lb')
    assert save.is_disabled(), 'a prefix of the host must not unlock the save'
    confirm.fill('  LB.Internal ')
    assert save.is_enabled()

    body = _save_and_capture(page)
    target = body['targets'][0]
    assert target['config']['acknowledge_key_delivery_to'] == 'lb.internal'
    assert 'delivery_consent' not in target, (
        'the page posted its own consent: a client that can write the consent is confirming for itself')


def test_editing_the_template_to_name_the_key_asks_even_for_a_saved_target(page):
    _open(page, targets=[_webhook(template=CERT_ONLY)])
    page.locator('[aria-label="Edit target Load balancer"]').click()
    assert page.locator('#key-delivery-confirmation').count() == 0
    page.click('[data-key-variable]:has-text("privkey_traditional")')
    assert page.locator('#key-delivery-confirmation').count() == 1
    assert page.locator('#webhook-target-editor button:has-text("Save target")').is_disabled()


def test_a_confirmation_the_server_holds_for_this_host_is_not_asked_again(page):
    _open(page, targets=[_webhook(template=WITH_KEY, consent_host='lb.internal')])
    page.locator('[aria-label="Edit target Load balancer"]').click()
    page.fill('[aria-label="Target name"]', 'Renamed')

    assert page.locator('#key-delivery-confirmation').count() == 0
    assert 'confirmed by admin' in page.locator('#key-delivery-confirmed').inner_text()
    body = _save_and_capture(page)
    assert 'acknowledge_key_delivery_to' not in body['targets'][0]['config'], (
        'a rename re-confirmed the key delivery: the confirmation is about the destination')
    assert 'delivery_consent' not in body['targets'][0], (
        'the page posted the consent it had loaded: the server owns it, and a page that posts one back '
        'could post a different one')


def test_changing_the_host_asks_again(page):
    _open(page, targets=[_webhook(template=WITH_KEY, consent_host='lb.internal')])
    page.locator('[aria-label="Edit target Load balancer"]').click()
    page.fill('[aria-label="Target URL"]', 'https://other.internal/api/certificate')

    box = page.locator('#key-delivery-confirmation')
    assert box.count() == 1
    assert 'lb.internal' in box.inner_text() and 'other.internal' in box.inner_text(), (
        'the notice should say which host the earlier confirmation was for')
    assert page.locator('#webhook-target-editor button:has-text("Save target")').is_disabled()


def test_the_list_says_which_targets_send_the_key_and_which_are_not_confirmed(page):
    _open(page, targets=[
        _webhook(template=WITH_KEY, consent_host='lb.internal'),
        _webhook(id='wh-2', name='No consent', template=WITH_KEY),
        _webhook(id='wh-3', name='Certificate only'),
    ])
    rows = page.locator('[data-target-row]')
    assert 'sends the private key to lb.internal' in rows.nth(0).inner_text()
    assert 'not confirmed' in rows.nth(1).inner_text() and 'will not send' in rows.nth(1).inner_text()
    assert rows.nth(2).locator('[data-key-badge]').count() == 0


# --------------------------------------------------------------------------
# Operator input is text
# --------------------------------------------------------------------------

def test_a_name_with_markup_in_it_is_shown_and_not_run(page):
    hostile = '<img src=x onerror="window.__ran = 1"><b>bold</b>'
    page.evaluate('window.__ran = 0')
    _open(page, targets=[_webhook(name=hostile)])
    row = page.locator('[data-target-row]').first
    assert hostile in row.inner_text(), 'the name should be displayed literally'
    assert row.locator('b').count() == 0 and row.locator('img').count() == 0, (
        'markup in a target name became elements: it is bound as HTML')
    page.wait_for_timeout(300)
    assert page.evaluate('window.__ran === 1') is False
    page.locator('[aria-label^="Edit target"]').click()
    assert page.locator('#webhook-target-editor img').count() == 0


# --------------------------------------------------------------------------
# The preview comes from the real server
# --------------------------------------------------------------------------

def _preview(page):
    """Click Preview and wait for the panel, or fail with the reason the page gave instead."""
    responses = []
    page.on('response', lambda r: responses.append((r.status, r.url)) if 'targets/preview' in r.url else None)
    page.click('button:has-text("Preview what would be sent")')
    try:
        page.locator('#webhook-target-preview').wait_for(timeout=8000)
    except Exception:
        error = page.locator('#webhook-target-preview-error')
        raise AssertionError(
            f'no preview appeared; responses={responses}; '
            f'page said: {error.inner_text() if error.count() else None!r}')
    return page.locator('#webhook-target-preview')


def test_the_preview_shows_the_real_destination_and_the_example_key(page):
    _open(page)
    _fill_new_target(page, template=WITH_KEY, url='https://lb.internal:8443/api/certificate')
    text = _preview(page).inner_text()

    assert 'POST https://lb.internal:8443/api/certificate' in text, (
        'the preview named a destination without the port the request goes to')
    assert 'EXAMPLE-NOT-A-REAL-KEY' in text and 'carries the private key' in text
    assert 'nothing was sent' in text
    assert 'privkey.pem' in text, 'the files a delivery reads should be listed'


def test_a_preview_is_not_shown_once_the_form_has_changed(page):
    _open(page)
    _fill_new_target(page)
    _preview(page)
    page.fill('[aria-label="Target URL"]', 'https://elsewhere.internal/api/certificate')
    assert page.locator('#webhook-target-preview').count() == 0, (
        'a preview of the old form is still on screen: it describes a request that is no longer the one saved')


def test_a_preview_error_is_the_servers_reason(page):
    _open(page)
    _fill_new_target(page, template='{"name": ')
    page.click('button:has-text("Preview what would be sent")')
    error = page.locator('#webhook-target-preview-error')
    error.wait_for()
    assert 'valid JSON' in error.inner_text()


# --------------------------------------------------------------------------
# The pure parts
# --------------------------------------------------------------------------

@pytest.mark.parametrize('url,host', [
    ('https://LB.Internal:8443/x', 'lb.internal'),
    ('https://[2001:db8::1]:8443/x', '2001:db8::1'),
    ('https://10.0.0.5/x', '10.0.0.5'),
    ('not a url', ''),
])
def test_the_host_is_read_the_way_the_server_reads_it(page, url, host):
    """The typed confirmation is compared with this; it must equal the server's urlparse().hostname."""
    _open(page)
    assert page.evaluate('u => window.CertMateWebhookTargets.hostOf(u)', url) == host


# --------------------------------------------------------------------------
# End to end, with nothing mocked
# --------------------------------------------------------------------------

def test_key_delivery_is_confirmed_end_to_end_and_the_server_records_who(page, ui_session_cookie):
    """The one test with the real endpoint: the consent the list shows is the one the server wrote."""
    session = requests.Session()
    session.cookies.set('certmate_session', ui_session_cookie)
    headers = {'Origin': BASE_URL}
    name = f'e2e-{uuid.uuid4().hex[:8]}'
    saved = session.get(f'{BASE_URL}/api/deploy/config', headers=headers).json()
    session.post(f'{BASE_URL}/api/deploy/config', json={'enabled': True}, headers=headers)
    try:
        _open(page)
        page.unroute('**/api/deploy/config')       # from here the real endpoint answers
        page.evaluate(_RELOAD)
        page.locator('#deploy-targets button:has-text("Add Webhook Target")').click()
        page.fill('[aria-label="Target name"]', name)
        page.fill('[aria-label="Target domains"]', 'e2e.example.com')
        page.fill('[aria-label="Target URL"]', 'https://receiver.e2e.example.com/cert')
        page.fill('[aria-label="Target payload template"]', WITH_KEY)
        page.fill('[aria-label="Type the destination host to confirm key delivery"]',
                  'receiver.e2e.example.com')
        page.locator('#webhook-target-editor button:has-text("Save target")').click()
        page.wait_for_selector('#webhook-target-editor', state='detached')

        row = page.locator('[data-target-row]', has_text=name)
        assert 'Key delivery to receiver.e2e.example.com confirmed by admin' in row.inner_text()
        stored = [t for t in session.get(f'{BASE_URL}/api/deploy/config', headers=headers).json()['targets']
                  if t['name'] == name][0]
        assert stored['delivery_consent']['host'] == 'receiver.e2e.example.com'
        assert stored['delivery_consent']['by'] == 'admin'
        assert 'acknowledge_key_delivery_to' not in stored['config']
    finally:
        session.post(f'{BASE_URL}/api/deploy/config',
                     json={'targets': saved.get('targets', []), 'enabled': saved.get('enabled', False)},
                     headers=headers)
