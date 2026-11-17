"""Findings of the UX audit of 2026-11-17 on the settings page.

* The Users tab showed local authentication as off and "Loading users..."
  for four seconds while /api/users answers in milliseconds: the list waited
  a fixed setTimeout(4000) after the page (backups 3000). They load when
  their tab is opened now.
* A DNS provider card read "1 accounts".
* A required account field left empty said "Enter your Cloudflare API token
  is required": the placeholder, not the field's name.

The settings and the account list the page reads are given in the browser
where a test needs a precise state (page.route); nothing is written.
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
LOADED = "() => !document.getElementById('userList').innerText.includes('Loading users')"


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def test_the_users_tab_opened_directly_loads_without_waiting(page):
    started = time.monotonic()
    page.goto(f'{BASE_URL}/settings#users', wait_until='domcontentloaded')
    page.wait_for_function(LOADED, timeout=10000)
    assert time.monotonic() - started < 2.5, 'the user list still waits a fixed delay'


def test_the_users_tab_opened_later_loads_when_it_is_opened(page):
    page.goto(f'{BASE_URL}/settings#general', wait_until='networkidle')
    assert not page.evaluate(LOADED), 'the users were loaded before anyone opened the tab'
    started = time.monotonic()
    page.click('#settings-tab-users')
    page.wait_for_function(LOADED, timeout=10000)
    assert time.monotonic() - started < 1.5


def _accounts(page, ids):
    def settings(route):
        answer = route.fetch()
        body = answer.json()
        body.setdefault('dns_providers', {})['cloudflare'] = {
            'accounts': {i: {'name': i, 'api_token': '********'} for i in ids}}
        route.fulfill(response=answer, body=json.dumps(body))

    def accounts(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps(
            [{'provider': 'cloudflare', 'account_id': i, 'name': i, 'configured': True} for i in ids]))
    page.route('**/api/web/settings', settings)
    page.route('**/api/dns/accounts', accounts)
    page.goto(f'{BASE_URL}/settings#dns', wait_until='networkidle')
    page.wait_for_function("() => !document.getElementById('cloudflare-accounts').classList.contains('invisible')")
    return page.inner_text('#cloudflare-accounts').strip()


def test_one_account_is_one_account(page):
    assert _accounts(page, ['production']) == '1 account'


def test_two_accounts_are_accounts(page):
    """CONTROL: the plural stays where it belongs."""
    assert _accounts(page, ['production', 'staging']) == '2 accounts'


def test_a_missing_required_field_is_named_by_its_label(page):
    page.goto(f'{BASE_URL}/settings#dns', wait_until='networkidle')
    page.click('#cloudflare-add-account')
    page.wait_for_selector('#addAccountModal:not(.hidden)')
    page.fill('#addAccountModal input[name="name"]', 'ui-no-token')
    page.click('#addAccountModal [data-click="saveAccount"]')
    shown = ("() => [...document.querySelectorAll('[role=alert], [role=status]')]"
             ".map(e => e.innerText).join(' | ')")
    page.wait_for_function(f"() => ({shown})().includes('is required')", timeout=5000)
    toast = page.evaluate(shown)
    assert 'API Token is required' in toast, toast
    assert 'Enter your Cloudflare API token is required' not in toast
