"""A toast stays long enough to be read, waits while it is pointed at or
focused, can be reached and closed by keyboard, and a result does not live
only in a toast.

UX perception audit, 2026-11-18 (batch B9, P34): every toast went after 5 s
(10 s with a Report button) whatever its length, and went while the pointer
was on it: a 560-character renewal error was gone by 12.5 s. Its close
button was a bare glyph with no name. The live region was made with the first
toast, so the first announcement could be lost. With the create drawer open,
40 Tabs never reached a toast. "Issuing certificate for ..." stayed on screen
next to "Certificate issuance failed for ...". And the CA "Check
configuration" result was only a toast: once it went, the dialog said nothing.

The CA check and the renewal answers are given in the browser (page.route);
nothing is written.
"""
import json
import os
import time

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
DOMAIN = 'toast.example.test'
LONG = ('Certificate renewal failed for ' + DOMAIN + ': ' +
        'The DNS provider rejected the TXT record because the API token does not have the Zone.DNS edit '
        'permission for this zone. ' * 5).strip()


def _certificate(domain, **more):
    return dict({'domain': domain, 'exists': True, 'days_left': 20, 'days_until_expiry': 20,
                 'expired': False, 'seconds_left': 20 * 86400,
                 'expiry_date': '2027-01-01 10:00:00', 'expires_at': '2027-01-01T10:00:00Z',
                 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
                 'san_domains': [], 'has_private_key': True}, **more)


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.emulate_media(reduced_motion='reduce')
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


TOASTS_HAVE = "t => !!document.getElementById('cm-toasts') && document.getElementById('cm-toasts').innerText.includes(t)"


def _present(page, text):
    return page.evaluate(TOASTS_HAVE, text)


def test_the_toast_region_is_there_before_the_first_toast(page):
    page.goto(f'{BASE_URL}/settings', wait_until='networkidle')
    region = page.evaluate("() => { const r = document.getElementById('cm-toasts');"
                           " return r && {live: r.getAttribute('aria-live'), children: r.children.length}; }")
    assert region is not None, 'no live region until the first toast'
    assert region['live'] == 'polite', region


def test_a_toast_is_closed_by_a_button_that_says_so(page):
    page.goto(f'{BASE_URL}/settings', wait_until='networkidle')
    page.evaluate("() => CertMate.toast('Saved the thing', 'success')")
    close = page.locator('#cm-toasts').get_by_role('button', name='Dismiss notification')
    close.wait_for(state='visible', timeout=3000)
    close.click()
    page.wait_for_function("() => !document.getElementById('cm-toasts').innerText.includes('Saved the thing')",
                           timeout=3000)


def test_a_toast_waits_while_it_is_pointed_at_or_focused(page):
    page.goto(f'{BASE_URL}/settings', wait_until='networkidle')
    page.evaluate("() => CertMate.toast('Pointed at', 'info', 1500)")
    toast = page.locator('#cm-toasts > div', has_text='Pointed at')
    toast.hover()
    time.sleep(3)
    assert _present(page, 'Pointed at'), 'the toast went while the pointer was on it'
    page.mouse.move(5, 5)
    page.wait_for_function("() => !document.getElementById('cm-toasts').innerText.includes('Pointed at')",
                           timeout=4000)

    page.evaluate("() => CertMate.toast('Focused', 'info', 1500)")
    page.locator('#cm-toasts > div', has_text='Focused').get_by_role('button', name='Dismiss notification').focus()
    time.sleep(3)
    assert _present(page, 'Focused'), 'the toast went while focus was in it'


def test_a_long_toast_stays_long_enough_to_read_and_a_short_one_still_goes(page):
    page.goto(f'{BASE_URL}/settings', wait_until='networkidle')
    page.mouse.move(5, 5)
    page.evaluate("t => { CertMate.toast(t, 'error'); CertMate.toast('Short note', 'info'); }", LONG)
    assert len(LONG) > 500
    time.sleep(12.5)
    assert _present(page, 'The DNS provider rejected'), f'a {len(LONG)}-character error went within 12.5 s'
    assert not _present(page, 'Short note'), 'a short info toast should still go on its own'


def test_a_toast_can_be_reached_by_tab_from_the_open_create_drawer(page):
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.evaluate("() => openCertDrawer('server')")
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'domain'", timeout=5000)
    page.evaluate("() => CertMate.toast('Reach me', 'error', 0)")
    reached = False
    for _ in range(60):
        page.keyboard.press('Tab')
        where = page.evaluate("() => { const el = document.activeElement;"
                              " if (document.getElementById('cm-toasts').contains(el)) return 'toast';"
                              " if (document.getElementById('createCertFormContainer').contains(el)) return 'drawer';"
                              " return el ? el.tagName + ' ' + (el.id || el.innerText || '').slice(0, 40) : 'none'; }")
        assert where in ('toast', 'drawer'), f'focus left the drawer for {where}'
        if where == 'toast':
            reached = True
            break
    assert reached, 'Tab never reached the toast from the drawer'


def test_a_failed_ca_check_says_so_in_the_dialog(page):
    message = 'Connection failed - ACME endpoint is not accessible'

    def check(route):
        route.fulfill(status=400, content_type='application/json',
                      body=json.dumps({'success': False, 'message': message}))
    page.route('**/api/settings/test-ca-provider', check)
    page.goto(f'{BASE_URL}/settings#ca', wait_until='networkidle')
    page.evaluate("() => openCAAccountModal('private_ca')")
    page.fill('#private-ca-acme-url', 'https://127.0.0.1:9/acme/directory')
    page.fill('#private-ca-email', 'ops@example.test')
    page.locator('#caAccountModal button[data-click="testCAProvider"]').click()
    page.wait_for_function(TOASTS_HAVE, arg=message, timeout=5000)
    text = page.inner_text('#caAccountModal')
    assert message in text and 'failed' in text.lower(), text


def test_the_renewing_toast_gives_way_to_the_failure(page):
    def answer(route):
        request = route.request
        url = request.url.split('?')[0]
        if request.method == 'GET' and url.endswith('/api/certificates'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps([_certificate(DOMAIN)]))
        if request.method == 'GET' and url.endswith('/deployment-status'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps({'deployed': False}))
        if request.method == 'POST' and url.endswith(f'/api/certificates/{DOMAIN}/renew'):
            return route.fulfill(status=202, content_type='application/json', body=json.dumps(
                {'job_id': 'jr', 'domain': DOMAIN, 'status_url': '/api/certificates/jobs/jr'}))
        if request.method == 'GET' and url.endswith('/api/certificates/jobs/jr'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps(
                {'job_id': 'jr', 'domain': DOMAIN, 'operation': 'renew', 'status': 'failed',
                 'error': 'Renewal failed: the DNS provider said no', 'error_code': 'X', 'hint': ''}))
        if request.method == 'GET' and url.endswith('/api/certificates/jobs'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps({'count': 0, 'jobs': []}))
        return route.continue_()
    page.route('**/api/**', answer)
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.evaluate("d => renewCertificate(d)", DOMAIN)
    page.wait_for_function(TOASTS_HAVE, arg='Renewing ', timeout=5000)
    page.wait_for_function(TOASTS_HAVE, arg='renewal failed', timeout=10000)
    assert not _present(page, 'Renewing '), page.inner_text('#cm-toasts')
