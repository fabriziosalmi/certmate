"""The small controls the audit measured are big enough to hit with a finger.

UX perception audit, 2026-11-18 (batch B9, P56): the certificate detail's
close button was 19x32 px, 8 px from Copy domain (26x36); the client dialog's
close 19x32; the Notes "Edit" 21x16; the login password eye 18x24; a row's
More actions 20x32; the Home breadcrumb 16x20; "Advanced Options" 20 px tall.
On a phone (below md) each of them is at least 44x44 px now, and at least
24x24 on a desktop; Copy domain and the close button are 8 px apart or more.

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
DOMAIN = 'touch.example.test'
CERTIFICATES = [{'domain': DOMAIN, 'exists': True, 'days_left': 60, 'days_until_expiry': 60,
                 'expired': False, 'seconds_left': 60 * 86400,
                 'expiry_date': '2027-01-01 10:00:00', 'expires_at': '2027-01-01T10:00:00Z',
                 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
                 'san_domains': [], 'has_private_key': True}]
CLIENT_CERTIFICATES = {'certificates': [
    {'identifier': 'c0', 'common_name': 'client0.example.test', 'email': 'user0@example.test',
     'cert_usage': 'vpn', 'created_at': '2026-10-01T10:00:00Z', 'expires_at': '2027-10-01T10:00:00Z',
     'revoked': False}]}
PHONE = (360, 740)
DESKTOP = (1440, 900)
SIZES = [(PHONE, 44), (DESKTOP, 24)]


@pytest.fixture
def open_page(browser_page, ui_session_cookie):
    contexts = []

    def make(size, signed_in=True):
        context = browser_page.context.browser.new_context(viewport={'width': size[0], 'height': size[1]})
        contexts.append(context)
        if signed_in:
            context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
        page = context.new_page()
        page.emulate_media(reduced_motion='reduce')

        def answer(route):
            request = route.request
            url = request.url.split('?')[0]
            if request.method == 'GET' and url.endswith('/api/certificates'):
                return route.fulfill(status=200, content_type='application/json', body=json.dumps(CERTIFICATES))
            if request.method == 'GET' and url.endswith('/deployment-status'):
                return route.fulfill(status=200, content_type='application/json', body=json.dumps({'deployed': False}))
            if request.method == 'GET' and url.endswith('/api/client-certs'):
                return route.fulfill(status=200, content_type='application/json',
                                     body=json.dumps(CLIENT_CERTIFICATES))
            return route.continue_()
        page.route('**/api/**', answer)
        page.route('https://*.example.test/**', lambda route: route.abort('namenotresolved'))
        return page
    yield make
    for context in contexts:
        context.close()


def _size(locator):
    box = locator.bounding_box()
    assert box is not None, f'{locator} is not on screen'
    return box


def _at_least(locator, minimum):
    box = _size(locator)
    assert box['width'] >= minimum - 0.5 and box['height'] >= minimum - 0.5, (
        f'{box["width"]:.1f}x{box["height"]:.1f}, wanted {minimum}x{minimum}')
    return box


def _open_detail(page):
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.locator(f'tr[data-row-domain="{DOMAIN}"] button[data-click="openCertRow"]').first.click()
    page.wait_for_function("() => { const c = document.getElementById('certDetailCard');"
                           " return c && !c.classList.contains('opacity-0'); }", timeout=5000)
    page.wait_for_selector('#certLabelsSection [data-labels-edit]', timeout=10000)
    # Measure after the card's scale-in: during it every box is 95% of its
    # size (44 px read 41.8 about one run in two).
    page.wait_for_function("() => document.getElementById('certDetailCard').getAnimations().length === 0",
                           timeout=5000)


@pytest.mark.parametrize('size,minimum', SIZES)
def test_the_certificate_detail_close_copy_and_edit_are_big_enough(open_page, size, minimum):
    page = open_page(size)
    _open_detail(page)
    close = _at_least(page.get_by_role('button', name='Close certificate details'), minimum)
    copy = _at_least(page.get_by_role('button', name='Copy domain'), minimum)
    assert close['x'] - (copy['x'] + copy['width']) >= 8, (copy, close)
    _at_least(page.locator('#certLabelsSection [data-labels-edit]'), minimum)


@pytest.mark.parametrize('size,minimum', SIZES)
def test_the_client_dialog_close_is_big_enough(open_page, size, minimum):
    page = open_page(size)
    page.goto(f'{BASE_URL}/#client', wait_until='networkidle')
    page.get_by_role('button', name='View details for client0.example.test').click()
    page.wait_for_function("() => !document.getElementById('certModal').classList.contains('hidden')", timeout=5000)
    _at_least(page.locator('#certModal').get_by_role('button', name='Close dialog'), minimum)


@pytest.mark.parametrize('size,minimum', SIZES)
def test_the_row_menu_and_advanced_options_are_big_enough(open_page, size, minimum):
    page = open_page(size)
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    more = page.locator(f'[data-more-domain="{DOMAIN}"]')
    if more.is_visible():  # below md a tap on the row opens the panel instead
        _at_least(more, minimum)
    page.evaluate("() => openCertDrawer('server')")
    page.wait_for_timeout(400)
    advanced = page.locator('#createCertFormContainer button', has_text='Advanced Options').first
    box = _size(advanced)
    assert box['height'] >= minimum - 0.5, box


@pytest.mark.parametrize('size,minimum', SIZES)
def test_the_home_breadcrumb_is_big_enough(open_page, size, minimum):
    page = open_page(size)
    page.goto(f'{BASE_URL}/settings', wait_until='networkidle')
    _at_least(page.get_by_role('link', name='Home', exact=True).first, minimum)


@pytest.mark.parametrize('size,minimum', SIZES)
def test_the_login_password_eye_is_big_enough(open_page, size, minimum):
    page = open_page(size, signed_in=False)
    page.goto(f'{BASE_URL}/login', wait_until='networkidle')
    eye = _at_least(page.get_by_role('button', name='Show password'), minimum)
    field = _size(page.locator('#password'))
    # Inside the field, and not over the text: the field's right padding clears it.
    assert field['x'] <= eye['x'] and eye['x'] + eye['width'] <= field['x'] + field['width'], (eye, field)
    padding_right = page.evaluate("() => parseFloat(getComputedStyle(document.getElementById('password')).paddingRight)")
    assert padding_right >= (field['x'] + field['width']) - eye['x'] - 0.5, (padding_right, eye, field)
