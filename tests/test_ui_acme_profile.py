"""The ACME profile in the dashboard (#395): chosen, sent, shown.

What only a browser shows: that the request body carries the profile the operator chose and
nothing when they did not; that Edit & Reissue opens on the certificate's own profile, so
editing a SAN does not change its kind; that the panel says which profile it has, whether the
CA withdrew it, and when it renews (#393); and that a CA account's default reaches the server.
The certificate list and the writes are answered by the test, so no CA is involved.
"""
import json
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER, TEST_EMAIL
from tests.conftest import BASE_URL as _API_URL

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"

CERT = {
    'domain': 'profile.example.com', 'exists': True, 'days_left': 30, 'days_until_expiry': 30,
    'seconds_left': 30 * 86400, 'expired': False, 'needs_renewal': False, 'usable': True,
    'private_key_present': True, 'private_key_state': 'present', 'reissue_required': False,
    'expiry_date': '2026-11-02 03:00:00', 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt',
    'challenge_type': 'dns-01', 'san_domains': [], 'auto_renew': True, 'tags': [], 'notes': None,
    'renewal_info': None, 'renews_at': '2026-10-27T21:00:00Z',
    'acme_profile': 'shortlived', 'acme_profile_withdrawn_at': '2026-09-30T03:00:04',
}


@pytest.fixture(scope="module", autouse=True)
def _a_usable_ca(docker_container, ui_session_cookie):
    """The form refuses to submit while no CA is usable (#1045)."""
    import requests
    session = requests.Session()
    session.cookies.set("certmate_session", ui_session_cookie)
    session.headers["Origin"] = _API_URL
    url = f"{_API_URL}/api/web/settings"
    before = session.get(url).json().get("email") or ""
    assert session.post(url, json={"email": TEST_EMAIL}).ok
    yield
    assert session.post(url, json={"email": before}).ok


def _dashboard(page, certificates=None):
    if certificates is not None:
        page.route('**/api/certificates', lambda route: route.fulfill(
            status=200, content_type='application/json', body=json.dumps(certificates))
            if route.request.method == 'GET' else route.continue_())
    page.goto(BASE_URL, wait_until="networkidle")


def _posts(page, fragment):
    """Every POST to `fragment` is answered here and never reaches the shared instance. The
    trailing `**` matters: the CA account route is called with `?create=1`, and a pattern that
    stopped at the path let the first version of this file save a real account there."""
    seen = []
    page.on('request', lambda r: seen.append(json.loads(r.post_data or '{}'))
            if r.method == 'POST' and fragment in r.url else None)
    page.route(f'**{fragment}**', lambda route: route.fulfill(
        status=200, content_type='application/json',
        body=json.dumps({'success': True, 'domain': 'profile.example.com', 'message': 'ok'})))
    return seen


def _open_create(page):
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.click('#advancedOptionsToggle')
    page.wait_for_selector('#cert_acme_profile', state='visible')


def test_default_sends_no_profile_so_the_account_default_applies(browser_page):
    _dashboard(browser_page)
    posts = _posts(browser_page, '/api/certificates/create')
    _open_create(browser_page)
    browser_page.fill('#domain', 'profile.example.com')
    browser_page.click('#createCertForm button[type="submit"]')
    browser_page.wait_for_timeout(800)
    assert posts, 'the create request was never sent'
    assert 'acme_profile' not in posts[-1], posts[-1]


def test_a_chosen_profile_is_sent(browser_page):
    _dashboard(browser_page)
    posts = _posts(browser_page, '/api/certificates/create')
    _open_create(browser_page)
    browser_page.fill('#domain', 'profile.example.com')
    browser_page.select_option('#cert_acme_profile', 'tlsserver')
    browser_page.click('#createCertForm button[type="submit"]')
    browser_page.wait_for_timeout(800)
    assert posts and posts[-1].get('acme_profile') == 'tlsserver', posts


def test_edit_and_reissue_opens_on_the_certificate_s_own_profile(browser_page):
    _dashboard(browser_page, [CERT])
    posts = _posts(browser_page, '/api/certificates/profile.example.com/reissue')
    browser_page.evaluate("startEditReissue('profile.example.com')")
    browser_page.wait_for_selector('#createCertFormContainer', state='visible')
    assert browser_page.eval_on_selector('#cert_acme_profile', 'e => e.value') == 'shortlived'
    browser_page.click('#createCertForm button[type="submit"]')
    browser_page.wait_for_timeout(800)
    assert posts and posts[-1].get('acme_profile') == 'shortlived', posts


def test_the_panel_says_the_profile_its_withdrawal_and_when_it_renews(browser_page):
    _dashboard(browser_page, [CERT])
    browser_page.click('tr[data-row-domain="profile.example.com"]')
    browser_page.wait_for_selector('#certDetailContent dt:text("ACME profile")', state='visible')
    text = browser_page.inner_text('#certDetailContent')
    assert 'shortlived' in text
    assert 'Withdrawn by the CA' in text
    assert 'Renews' in text


def test_a_ca_account_default_reaches_the_server(browser_page):
    browser_page.goto(f'{BASE_URL}/settings#ca', wait_until="networkidle")
    posts = _posts(browser_page, '/api/web/settings/ca-providers/letsencrypt/accounts/short')
    browser_page.evaluate("openCAAccountModal('letsencrypt')")
    browser_page.fill('#ca-account-name', 'short')
    browser_page.fill('#letsencrypt-email', TEST_EMAIL)
    browser_page.select_option('#ca-account-acme-profile', 'shortlived')
    browser_page.evaluate("saveCAAccount()")
    browser_page.wait_for_timeout(800)
    assert posts and posts[-1].get('acme_profile') == 'shortlived', posts
    settings = browser_page.evaluate(
        "fetch('/api/web/settings').then(r => r.json()).then(s => s.ca_providers || {})")
    assert 'short' not in json.dumps(settings), 'the account write reached the shared instance'
