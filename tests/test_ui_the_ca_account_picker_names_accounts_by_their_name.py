"""The create form's CA account picker names each account by its name, with its
email (and, for a private CA, its directory host) beside it, and the detail
panel's Issuing CA row names the account a certificate was issued with.

UX perception audit, 2026-11-18, P64: Settings > CA names accounts
("Let's Encrypt - ops"), but the create form listed them by email only, so two
accounts on one address could not be told apart and the name an operator gave
an account appeared nowhere on the dashboard. The settings and the
certificate list are answered by the test (page.route), so no CA account is
saved on the shared instance.
"""
import json
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"

CA_SETTINGS = {
    'email': 'le@example.com',
    'default_ca': 'letsencrypt',
    'default_ca_accounts': {'letsencrypt': 'ops'},
    'ca_providers': {
        'letsencrypt': {'accounts': {
            'ops': {'name': 'ops', 'email': 'team@example.com'},
            'shop': {'name': 'shop', 'email': 'team@example.com'},
        }},
        'private_ca': {'accounts': {
            'internal': {'name': 'internal', 'email': 'pki@example.com',
                         'acme_url': 'https://acme.internal.example:9000/acme/directory'},
        }},
    },
}

CERT = {
    'domain': 'named.example.com', 'exists': True, 'days_left': 30, 'days_until_expiry': 30,
    'seconds_left': 30 * 86400, 'expired': False, 'needs_renewal': False, 'usable': True,
    'private_key_present': True, 'private_key_state': 'present', 'reissue_required': False,
    'expiry_date': '2026-12-18 03:00:00', 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt',
    'ca_account_id': 'shop', 'challenge_type': 'dns-01', 'san_domains': [], 'auto_renew': True,
    'tags': [], 'notes': None, 'renewal_info': None, 'renews_at': '2026-11-28T21:00:00Z',
}


def _dashboard(page):
    def settings(route):
        if route.request.method != 'GET':
            route.continue_()
            return
        body = route.fetch().json()
        body.update(CA_SETTINGS)
        route.fulfill(status=200, content_type='application/json', body=json.dumps(body))

    page.route('**/api/web/settings', settings)
    page.route('**/api/certificates', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps([CERT]))
        if route.request.method == 'GET' else route.continue_())
    page.goto(BASE_URL, wait_until="networkidle")


def _labels(page, selector):
    return page.eval_on_selector(selector, 'e => Array.from(e.options).map(o => o.textContent)')


@pytest.fixture
def page(browser_page):
    yield browser_page
    browser_page.unroute_all(behavior='ignoreErrors')


def test_the_account_picker_names_each_account_and_its_email(page):
    _dashboard(page)
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.wait_for_selector('#ca-account-container', state='visible')

    assert _labels(page, '#ca_provider_select')[0] == (
        "Global default: Let's Encrypt — ops (team@example.com)"), _labels(page, '#ca_provider_select')
    accounts = _labels(page, '#ca_account_id')
    assert accounts[0] == "Default for Let's Encrypt: ops (team@example.com)", accounts
    assert 'ops (team@example.com), default for this CA' in accounts, accounts
    assert 'shop (team@example.com)' in accounts, accounts


def test_a_private_ca_account_shows_its_directory_host(page):
    _dashboard(page)
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.select_option('#ca_provider_select', 'private_ca')
    accounts = _labels(page, '#ca_account_id')
    assert accounts[0] == 'Default for Private CA: internal (pki@example.com, acme.internal.example:9000)', accounts


def test_the_detail_names_the_account_that_issued_the_certificate(page):
    _dashboard(page)
    page.click('tr[data-row-domain="named.example.com"]')
    page.wait_for_selector('#certDetailContent dt:text("Issuing CA")', state='visible')
    row = page.locator('#certDetailContent div', has=page.locator('dt:text("Issuing CA")')).last
    assert row.locator('dd').inner_text() == "Let's Encrypt, account shop", row.inner_text()
