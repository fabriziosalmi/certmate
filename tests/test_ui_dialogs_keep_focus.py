"""A dialog keeps the keyboard inside it while it is open, and gives focus back
to what opened it when it closes.

UX perception audit, 2026-11-18 (batch B9, P14): the certificate detail and
its Replace form let Tab walk out to the footer, the page body and the header
behind the blur (17 and 20 Tabs of 25 outside). The client certificate dialog
never took focus: the next Tabs reached that row's Details, Revoke and Renew
under the overlay, and closing it left focus on the page body. The keyboard
shortcuts overlay was not a dialog at all and Tab went to the page behind it.

A toast is the one place outside a dialog that Tab may reach, because a result
that lives in a toast must be reachable too (P34,
tests/test_ui_toasts_can_be_read.py).

The certificates are answered in the browser (page.route); nothing is written.
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
DOMAIN = 'focus.example.test'
EXTERNAL = 'external.example.test'


def _certificate(domain, **more):
    return dict({'domain': domain, 'exists': True, 'days_left': 60, 'days_until_expiry': 60,
                 'expired': False, 'seconds_left': 60 * 86400,
                 'expiry_date': '2027-01-01 10:00:00', 'expires_at': '2027-01-01T10:00:00Z',
                 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
                 'san_domains': [], 'has_private_key': True}, **more)


CERTIFICATES = [_certificate(DOMAIN), _certificate(EXTERNAL, external=True, auto_renew=False)]
CLIENT_CERTIFICATES = {'certificates': [
    {'identifier': f'c{i}', 'common_name': f'client{i}.example.test', 'email': f'user{i}@example.test',
     'cert_usage': 'vpn', 'created_at': '2026-10-01T10:00:00Z', 'expires_at': '2027-10-01T10:00:00Z',
     'revoked': False} for i in range(2)]}
DEPLOYED = {'deployed': True, 'reachable': True, 'certificate_match': True,
            'method': 'server', 'protocol': 'https-tls'}

# Where focus is: inside the dialog, in a toast, or elsewhere (with its name).
WHERE = """root => {
    const el = document.activeElement;
    const dialog = document.querySelector(root);
    if (dialog && dialog.contains(el)) return 'inside';
    const toasts = document.getElementById('cm-toasts');
    if (toasts && toasts.contains(el)) return 'toast';
    if (!el) return 'none';
    return el.tagName + ' ' + (el.getAttribute('aria-label') || el.id || (el.innerText || '').trim().slice(0, 40));
}"""


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.emulate_media(reduced_motion='reduce')

    def answer(route):
        request = route.request
        url = request.url.split('?')[0]
        if request.method == 'GET' and url.endswith('/api/certificates'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps(CERTIFICATES))
        if request.method == 'GET' and url.endswith('/deployment-status'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps(DEPLOYED))
        if request.method == 'GET' and url.endswith('/api/client-certs'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps(CLIENT_CERTIFICATES))
        return route.continue_()
    page.route('**/api/**', answer)
    page.route('https://*.example.test/**', lambda route: route.abort('namenotresolved'))
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _tab_around(page, root, times=30, shift=False):
    """Press Tab `times` times; return where focus was after each press that left the dialog."""
    outside = []
    for i in range(times):
        page.keyboard.press('Shift+Tab' if shift else 'Tab')
        where = page.evaluate(WHERE, root)
        if where not in ('inside', 'toast'):
            outside.append((i + 1, where))
    return outside


def _open_detail_by_keyboard(page, domain):
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    opener = page.locator(f'tr[data-row-domain="{domain}"] button[data-click="openCertRow"]').first
    opener.wait_for(state='visible', timeout=10000)
    opener.focus()
    page.keyboard.press('Enter')
    page.wait_for_function("() => { const c = document.getElementById('certDetailCard');"
                           " return c && !c.classList.contains('opacity-0'); }", timeout=5000)
    page.wait_for_function("() => !document.querySelector('#certDetailContent .animate-pulse')", timeout=10000)
    return opener


def test_tab_stays_in_the_certificate_detail_and_escape_gives_focus_back_to_its_row(page):
    opener = _open_detail_by_keyboard(page, DOMAIN)
    assert page.evaluate(WHERE, '#certDetailPanel') == 'inside'
    assert _tab_around(page, '#certDetailPanel') == []
    assert _tab_around(page, '#certDetailPanel', shift=True) == []
    page.keyboard.press('Escape')
    page.wait_for_function("() => document.getElementById('certDetailPanel').classList.contains('hidden')",
                           timeout=5000)
    assert opener.evaluate('el => el === document.activeElement'), page.evaluate(WHERE, 'body')


def test_tab_stays_in_the_replace_form_and_cancel_gives_focus_back_to_replace(page):
    _open_detail_by_keyboard(page, EXTERNAL)
    replace = page.locator('#certDetailPanel button', has_text='Replace').first
    replace.focus()
    page.keyboard.press('Enter')
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'replaceCertificateFile'",
                           timeout=5000)
    assert _tab_around(page, '#certDetailPanel') == []
    page.locator('#certReplaceSection button', has_text='Cancel').click()
    assert replace.evaluate('el => el === document.activeElement'), page.evaluate(WHERE, '#certDetailPanel')


def test_the_client_certificate_dialog_takes_focus_keeps_it_and_gives_it_back(page):
    page.goto(f'{BASE_URL}/#client', wait_until='networkidle')
    opener = page.get_by_role('button', name='View details for client0.example.test')
    opener.wait_for(state='visible', timeout=10000)
    opener.focus()
    page.keyboard.press('Enter')
    page.wait_for_function("() => !document.getElementById('certModal').classList.contains('hidden')", timeout=5000)
    assert page.evaluate(WHERE, '#certModal') == 'inside', 'focus stayed behind the dialog'
    assert _tab_around(page, '#certModal') == []
    page.keyboard.press('Escape')
    page.wait_for_function("() => document.getElementById('certModal').classList.contains('hidden')", timeout=5000)
    assert opener.evaluate('el => el === document.activeElement'), page.evaluate(WHERE, 'body')


def test_the_keyboard_shortcuts_overlay_is_a_dialog_that_keeps_and_returns_focus(page):
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    opener = page.locator('[data-status-chip]').first
    opener.focus()
    page.keyboard.press('?')
    page.wait_for_selector('#shortcutOverlay:not(.hidden)', timeout=5000)
    dialog = page.get_by_role('dialog', name='Keyboard Shortcuts')
    assert dialog.count() == 1
    assert dialog.get_attribute('aria-modal') == 'true'
    assert page.evaluate(WHERE, '#shortcutOverlay') == 'inside', 'focus stayed on the page behind'
    assert _tab_around(page, '#shortcutOverlay') == []
    page.keyboard.press('Escape')
    page.wait_for_selector('#shortcutOverlay.hidden', state='attached', timeout=5000)
    assert opener.evaluate('el => el === document.activeElement'), page.evaluate(WHERE, 'body')
