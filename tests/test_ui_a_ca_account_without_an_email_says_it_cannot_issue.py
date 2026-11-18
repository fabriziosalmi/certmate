"""A CA account that cannot issue says so, and says what it needs and where.

UX perception audit, 2026-11-18, P03: after Skip on the first-run wizard no
contact email is saved. Settings > CA listed "Let's Encrypt - Default account"
under a green check, as configured, while the create form refused to issue
with "Configure a certificate authority in Settings", without saying which CA
or what it lacks. Now the Settings row says "No contact email: cannot issue"
and offers "Add email", which opens that account; the create form says
"Let's Encrypt needs a contact email: add it in Settings > CA", in the drawer
with a link to /settings#ca and in the toast when Create is pressed.

Run against the shared instance with its contact email cleared, the state the
Skip button leaves, as tests/test_ui_create_needs_a_ca.py does.
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
NEEDS_EMAIL = "Let's Encrypt needs a contact email: add it in Settings > CA"


@pytest.fixture(scope="module")
def settings_api(docker_container, ui_session_cookie):
    import requests
    session = requests.Session()
    session.cookies.set("certmate_session", ui_session_cookie)
    session.headers["Origin"] = _API_URL
    url = f"{_API_URL}/api/web/settings"
    current = session.get(url).json()
    assert not current.get("ca_providers"), (
        "the shared instance has a CA account saved; this module needs none")
    before = current.get("email") or ""
    assert session.post(url, json={"email": ""}).ok
    yield lambda email: session.post(url, json={"email": email})
    assert session.post(url, json={"email": before}).ok


def _ca_tab(page):
    # From another document: a goto that only changes the hash would not
    # load the settings again.
    page.goto('about:blank')
    page.goto(f'{BASE_URL}/settings#ca', wait_until="networkidle")
    page.wait_for_function(
        "() => document.getElementById('configured-ca-list').innerText.includes(\"Let's Encrypt\")",
        timeout=10000)
    return page.locator('#configured-ca-list > div').filter(has_text="Let's Encrypt").first


def test_settings_says_the_account_cannot_issue_and_offers_to_add_the_email(browser_page, settings_api):
    row = _ca_tab(browser_page)
    assert 'No contact email: cannot issue' in row.inner_text(), row.inner_text()
    heading = browser_page.locator('[data-ca-accounts-status]')
    assert 'fa-check-circle' not in (heading.get_attribute('class') or ''), (
        'the heading still shows a green check over an account that cannot issue')
    row.get_by_role('button', name='Add email').click()
    browser_page.wait_for_selector('#caAccountModal', state='visible')
    browser_page.wait_for_selector('#letsencrypt-email', state='visible')


def test_with_an_email_the_account_does_not_say_it_cannot_issue(browser_page, settings_api):
    assert settings_api(TEST_EMAIL).ok
    try:
        row = _ca_tab(browser_page)
        text = row.inner_text()
        assert 'cannot issue' not in text, text
        assert row.get_by_role('button', name='Add email').count() == 0
        heading = browser_page.locator('[data-ca-accounts-status]')
        assert 'fa-check-circle' in (heading.get_attribute('class') or '')
    finally:
        assert settings_api('').ok


def test_the_create_form_says_which_ca_needs_what_and_where(browser_page, settings_api):
    page = browser_page
    page.goto(BASE_URL, wait_until="networkidle")
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    info = page.locator('#ca-provider-info')
    info.wait_for(state='visible', timeout=5000)
    assert NEEDS_EMAIL in info.inner_text(), info.inner_text()
    assert info.locator('a[href="/settings#ca"]').count() == 1

    posts = []
    page.on('request', lambda r: (
        posts.append(r.url) if r.method == 'POST' and '/api/certificates/create' in r.url else None))
    page.fill('#domain', 'api.example.com')
    page.click('#createCertForm button[type="submit"]')
    page.wait_for_function(
        "t => (document.getElementById('cm-toasts') || {innerText: ''}).innerText.includes(t)",
        arg=NEEDS_EMAIL, timeout=5000)
    page.wait_for_timeout(500)
    assert posts == []



# Accounts declared in CERTMATE_CONFIG_FILE (#1317) give their EAB secrets by
# reference, `<field>_env` or `<field>_file`, which the server reads when it
# issues (modules/core/ca_manager.py get_eab_credentials). The settings in the
# tests below are answered by the test (page.route): nothing is saved.
REFERENCE_ACCOUNTS = {
    'zerossl': {'accounts': {
        'zs': {'name': 'zs-prod', 'email': 'ops@example.com',
               'eab_kid_env': 'ZS_KID', 'eab_hmac_env': '********'},
    }},
    'google': {'accounts': {
        'gts': {'name': 'gts-prod', 'email': 'ops@example.com',
                'eab_key_id_file': '/run/secrets/gts-kid', 'eab_hmac_key_file': '********'},
    }},
}
EMPTY_DIGICERT = {'digicert': {'accounts': {'dc': {'name': 'dc-empty'}}}}
NEEDS_ALL = ("DigiCert needs an ACME directory URL, EAB credentials and a contact email: "
             "add them in Settings > CA")


@pytest.fixture
def stub_settings(browser_page):
    def stub(ca_providers):
        def settings(route):
            if route.request.method != 'GET':
                route.continue_()
                return
            body = route.fetch().json()
            body.update({'email': '', 'default_ca': 'digicert', 'default_ca_accounts': {},
                         'ca_providers': ca_providers})
            route.fulfill(status=200, content_type='application/json', body=json.dumps(body))
        browser_page.route('**/api/web/settings', settings)
        return browser_page
    yield stub
    browser_page.unroute_all(behavior='ignoreErrors')


def _ca_row(page, name):
    page.goto('about:blank')
    page.goto(f'{BASE_URL}/settings#ca', wait_until="networkidle")
    page.wait_for_function(
        "n => document.getElementById('configured-ca-list').innerText.includes(n)", arg=name, timeout=10000)
    return page.locator('#configured-ca-list > div').filter(has_text=name).first


def _create_form(page):
    page.goto('about:blank')
    page.goto(BASE_URL, wait_until="networkidle")
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')


@pytest.mark.parametrize('name', ['zs-prod', 'gts-prod'])
def test_an_account_whose_eab_credentials_are_given_by_reference_can_issue(stub_settings, name):
    page = stub_settings({**REFERENCE_ACCOUNTS, **EMPTY_DIGICERT})
    row = _ca_row(page, name)
    text = row.inner_text()
    assert 'cannot issue' not in text, text
    assert row.get_by_role('button', name='Complete account').count() == 0, text
    # The counter-case on the same page: the empty account still says so.
    empty = page.locator('#configured-ca-list > div').filter(has_text='dc-empty').first
    assert 'cannot issue' in empty.inner_text(), empty.inner_text()


def test_the_create_form_offers_the_accounts_given_by_reference(stub_settings):
    page = stub_settings({**REFERENCE_ACCOUNTS, **EMPTY_DIGICERT})
    _create_form(page)
    page.wait_for_function(
        "() => document.getElementById('ca_provider_select').options.length > 1", timeout=5000)
    offered = page.eval_on_selector('#ca_provider_select', 'e => Array.from(e.options).map(o => o.value)')
    assert 'zerossl' in offered and 'google' in offered, offered
    assert 'digicert' not in offered, offered


def test_an_account_that_lacks_several_things_names_them_in_one_list(stub_settings):
    page = stub_settings(EMPTY_DIGICERT)
    row = _ca_row(page, 'dc-empty')
    assert 'No ACME directory URL, EAB credentials or contact email: cannot issue' in row.inner_text(), (
        row.inner_text())
    assert row.get_by_role('button', name='Complete account').count() == 1
    _create_form(page)
    info = page.locator('#ca-provider-info')
    info.wait_for(state='visible', timeout=5000)
    assert NEEDS_ALL in info.inner_text(), info.inner_text()
