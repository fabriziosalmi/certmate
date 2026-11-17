"""Three findings of the UX audit of 2026-11-17, in the browser.

* Force renew was one click from the row, the menu and the detail panel, with
  no confirmation; it skips the due check, counts against the CA's rate limits
  and on a paid CA can cost an issuance. It asks now; plain Renew does not.
* The PFX export password could not be removed: a blank field keeps it. A
  box sends the removal, and a line says whether a password is saved.
* The empty dashboard told the operator "Authentication is disabled by
  default"; setup turns login on before that page can be reached.

The answers the page reads are given in the browser (page.route), so the
shared instance is not changed.
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
DOMAIN = 'force.example.test'
CERTIFICATE = {'domain': DOMAIN, 'exists': True, 'days_left': 60, 'expiry_date': '2026-12-04 10:00:00',
               'expires_at': '2026-12-04T10:00:00Z', 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt',
               'auto_renew': True, 'san_domains': [], 'has_private_key': True}


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _dashboard(page, certificates):
    renewals = []

    def listing(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps(certificates))

    def renew(route):
        renewals.append(json.loads(route.request.post_data or '{}'))
        route.fulfill(status=202, content_type='application/json', body=json.dumps(
            {'job_id': 'r1', 'status': 'queued', 'operation': 'renew', 'domain': DOMAIN,
             'status_url': '/api/certificates/jobs/r1'}))
    page.route('**/api/certificates', listing)
    page.route(f'**/api/certificates/{DOMAIN}/renew', renew)
    page.route('**/api/certificates/jobs/r1', lambda route: route.fulfill(
        status=200, content_type='application/json',
        body=json.dumps({'job_id': 'r1', 'status': 'running', 'domain': DOMAIN})))
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    return renewals


def _ask(page, force):
    page.evaluate(f"() => {{ window.renewCertificate({DOMAIN!r}, {'true' if force else 'false'}); }}")


def test_force_renew_asks_and_cancel_sends_nothing(page):
    renewals = _dashboard(page, [CERTIFICATE])
    _ask(page, True)
    dialog = page.get_by_role('alertdialog', name='Force renew')
    dialog.wait_for(state='visible')
    assert DOMAIN in dialog.inner_text() and 'rate limits' in dialog.inner_text()
    dialog.get_by_role('button', name='Cancel').click()
    page.wait_for_timeout(500)
    assert renewals == []

    _ask(page, True)
    page.get_by_role('alertdialog', name='Force renew').get_by_role('button', name='Force renew').click()
    page.wait_for_function('() => true')
    page.wait_for_timeout(800)
    assert len(renewals) == 1 and renewals[0].get('force') is True


def test_plain_renew_does_not_ask(page):
    """CONTROL: the confirmation is about forcing, not about renewing."""
    renewals = _dashboard(page, [CERTIFICATE])
    _ask(page, False)
    page.wait_for_timeout(800)
    assert not page.get_by_role('alertdialog', name='Force renew').is_visible()
    assert len(renewals) == 1 and not renewals[0].get('force')


def test_the_empty_dashboard_no_longer_says_authentication_is_off(page):
    _dashboard(page, [])
    page.wait_for_selector('text=Welcome to CertMate')
    assert page.locator('text=Authentication is disabled by default').count() == 0


def _settings(page, pfx_saved):
    posts = []

    def handle(route):
        if route.request.method == 'GET':
            answer = route.fetch()
            settings = answer.json()
            settings['email'] = settings.get('email') or 'ops@example.test'
            settings['pfx_password'] = '********' if pfx_saved else ''
            return route.fulfill(response=answer, body=json.dumps(settings))
        posts.append(json.loads(route.request.post_data or '{}'))
        return route.fulfill(status=200, content_type='application/json', body=json.dumps({'message': 'saved'}))
    page.route('**/api/web/settings', handle)
    page.goto(f'{BASE_URL}/settings#general', wait_until='networkidle')
    page.wait_for_function("() => document.getElementById('pfx_password_state').textContent.trim() !== ''")
    return posts


def test_a_saved_pfx_password_is_said_and_can_be_removed(page):
    posts = _settings(page, pfx_saved=True)
    assert 'A password is saved' in page.inner_text('#pfx_password_state')
    page.check('#pfx_password_clear')
    page.click('#saveBtn')
    page.wait_for_function('() => true')
    page.wait_for_timeout(800)
    assert posts and 'pfx_password' in posts[-1] and posts[-1]['pfx_password'] is None


def test_a_blank_pfx_field_keeps_the_password(page):
    """CONTROL: saving without the box sends no password at all."""
    posts = _settings(page, pfx_saved=True)
    page.click('#saveBtn')
    page.wait_for_timeout(800)
    assert posts and 'pfx_password' not in posts[-1]


def test_no_saved_pfx_password_is_said_too(page):
    _settings(page, pfx_saved=False)
    assert 'No password saved' in page.inner_text('#pfx_password_state')
