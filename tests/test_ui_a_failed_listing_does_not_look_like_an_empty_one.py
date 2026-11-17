"""A failed certificate listing does not look like an instance with no certificates.

Found by the UX audit of 2026-11-17: with the session logged out on the
server, a click on Refresh replaced the list with "Welcome to CertMate",
every counter went to 0, and the toast said "Authentication failed. Please
check your API token." Sessions are kept in memory, so every restart did this
to every open tab. Any other load error drew the same empty state.

Now a 401 goes to the login page and back, as CertMate.api does; a failure
after a list was loaded keeps that list; a failure on the first load says the
list could not be loaded, with a retry, instead of the first-run welcome.

The listing's answer is replaced in the browser (page.route); everything else
is the real dashboard.
"""
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
CERTIFICATES = [{'domain': f'kept-{i}.example.test', 'exists': True, 'days_left': 60,
                 'expiry_date': '2026-12-04 10:00:00', 'expires_at': '2026-12-04T10:00:00Z',
                 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
                 'san_domains': [], 'has_private_key': True} for i in range(3)]


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    context.close()


def _answer(page, status, body):
    import json

    def handle(route):
        if route.request.url.rstrip('/').endswith('/api/certificates'):
            return route.fulfill(status=status, content_type='application/json', body=json.dumps(body))
        return route.continue_()
    page.unroute('**/api/certificates*')
    page.route('**/api/certificates*', handle)


def _rows(page):
    return page.evaluate("""() => [...document.querySelectorAll('#certificatesList tr[data-row-domain]')]
        .map(tr => tr.getAttribute('data-row-domain'))""")


def _loaded(page):
    _answer(page, 200, CERTIFICATES)
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_function("() => document.querySelectorAll('#certificatesList tr[data-row-domain]').length === 3")


def test_a_session_that_ended_goes_to_the_login_page_and_back(page):
    _loaded(page)
    _answer(page, 401, {'error': 'Authentication required', 'code': 'AUTH_REQUIRED'})
    # The browser's session cookie is still valid on the server (the suite
    # shares it), so the real /login would send it straight back. Stand in for
    # the page a signed-out browser gets.
    page.route('**/login*', lambda route: route.fulfill(
        status=200, content_type='text/html', body='<html><body>login</body></html>'))
    page.evaluate('() => { window.loadCertificates(); }')
    page.wait_for_url('**/login?next=%2F', timeout=10000)
    assert page.url.endswith('/login?next=%2F')


def test_a_failed_refresh_keeps_the_list_it_had(page):
    _loaded(page)
    _answer(page, 500, {'error': 'boom'})
    page.evaluate('async () => { await window.loadCertificates(); }')
    assert sorted(_rows(page)) == sorted(c['domain'] for c in CERTIFICATES)
    assert not page.locator('text=Welcome to CertMate').count()
    assert page.locator('text=It shows the last successful load').count()


def test_a_failed_first_load_says_so_instead_of_welcoming(page):
    _answer(page, 500, {'error': 'boom'})
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_selector('[data-listing-failed]', timeout=10000)
    assert not page.locator('text=Welcome to CertMate').count()
    assert page.locator('text=The certificate list could not be loaded').count()

    # The retry is the real listing again.
    _answer(page, 200, CERTIFICATES)
    page.click('[data-listing-failed] button')
    page.wait_for_function("() => document.querySelectorAll('#certificatesList tr[data-row-domain]').length === 3")


def test_an_empty_instance_still_gets_the_welcome(page):
    """CONTROL: an instance that really has no certificates is welcomed as before."""
    _answer(page, 200, [])
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_selector('text=Welcome to CertMate', timeout=10000)
