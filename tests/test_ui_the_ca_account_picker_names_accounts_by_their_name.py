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


def _dashboard(page, ca_settings=None, cert=None):
    ca_settings = ca_settings or CA_SETTINGS
    cert = cert or CERT

    def settings(route):
        if route.request.method != 'GET':
            route.continue_()
            return
        body = route.fetch().json()
        body.update(ca_settings)
        route.fulfill(status=200, content_type='application/json', body=json.dumps(body))

    page.unroute_all(behavior='ignoreErrors')
    page.route('**/api/web/settings', settings)
    page.route('**/api/certificates', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps([cert]))
        if route.request.method == 'GET' else route.continue_())
    page.goto('about:blank')
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


def _issuing_ca(page):
    page.click('tr[data-row-domain="named.example.com"]')
    page.wait_for_selector('#certDetailContent dt:text("Issuing CA")', state='visible')
    row = page.locator('#certDetailContent div', has=page.locator('dt:text("Issuing CA")')).last
    return row.locator('dd').inner_text()


def test_the_detail_names_the_account_that_issued_the_certificate(page):
    _dashboard(page)
    assert _issuing_ca(page) == "Let's Encrypt, account shop"


# Every certificate records the account it was issued with, 'default' when
# the CA has only that one: naming it ("account default") tells nothing.
@pytest.mark.parametrize('letsencrypt', [
    {'email': 'le@example.com'},
    {'accounts': {'default': {'name': 'default', 'email': 'le@example.com'}}},
], ids=['flat', 'saved-through-the-modal'])
def test_the_detail_does_not_name_the_only_default_account(page, letsencrypt):
    _dashboard(page, {'email': 'le@example.com', 'default_ca': 'letsencrypt', 'default_ca_accounts': {},
                      'ca_providers': {'letsencrypt': letsencrypt}},
               {**CERT, 'ca_account_id': 'default'})
    assert _issuing_ca(page) == "Let's Encrypt"


def _reissue_posts(page):
    """Every reissue POST is answered here and never reaches the shared instance."""
    seen = []
    fragment = '/api/certificates/named.example.com/reissue'
    page.on('request', lambda r: seen.append(json.loads(r.post_data or '{}'))
            if r.method == 'POST' and fragment in r.url else None)
    page.route(f'**{fragment}**', lambda route: route.fulfill(
        status=200, content_type='application/json',
        body=json.dumps({'message': 'ok', 'domain': 'named.example.com'})))
    return seen


# #1465: "Default for ..." sent no account, which the reissue read as "unchanged".
@pytest.mark.parametrize('choice, sent', [('', ''), ('ops', 'ops'), (None, 'shop')],
                         ids=['default-for-the-ca', 'another-account', 'unchanged'])
def test_edit_and_reissue_sends_the_ca_account_the_form_shows(page, choice, sent):
    _dashboard(page)
    posts = _reissue_posts(page)
    page.evaluate("startEditReissue('named.example.com')")
    page.wait_for_selector('#createCertFormContainer', state='visible')
    assert page.input_value('#ca_account_id') == 'shop'
    if choice is not None:
        page.select_option('#ca_account_id', choice)
    page.click('#createCertForm button[type="submit"]')
    page.wait_for_timeout(800)
    assert posts, 'the reissue request was never sent'
    assert posts[-1].get('ca_account_id') == sent, posts[-1]


def test_a_reissue_keeps_its_account_when_the_ca_accounts_did_not_load(page):
    """#1465: with no account list the picker shows only "Default for", and
    sending that would move the certificate to the CA's default account."""
    _dashboard(page)
    page.unroute('**/api/web/settings')
    page.route('**/api/web/settings', lambda route: route.fulfill(
        status=500, content_type='application/json', body=json.dumps({'error': 'unavailable'}))
        if route.request.method == 'GET' else route.continue_())
    page.goto('about:blank')
    page.goto(BASE_URL, wait_until="networkidle")
    posts = _reissue_posts(page)
    page.evaluate("startEditReissue('named.example.com')")
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.wait_for_selector('#ca-account-unloaded', state='visible')
    assert 'current account' in page.inner_text('#ca-account-unloaded')
    page.click('#createCertForm button[type="submit"]')
    page.wait_for_timeout(800)
    assert posts, 'the reissue request was never sent'
    assert 'ca_account_id' not in posts[-1] and 'ca_provider' not in posts[-1], posts[-1]


def test_global_default_moves_a_private_ca_certificate_to_the_default_ca(page):
    """The reporter's case on #1465: "Global default: Let's Encrypt" on a Private
    CA certificate sent no CA, so the reissue stayed on Private CA."""
    _dashboard(page, cert={**CERT, 'ca_provider': 'private_ca', 'ca_account_id': 'internal'})
    posts = _reissue_posts(page)
    page.evaluate("startEditReissue('named.example.com')")
    page.wait_for_selector('#createCertFormContainer', state='visible')
    assert page.input_value('#ca_provider_select') == 'private_ca'
    assert page.input_value('#ca_account_id') == 'internal'
    page.select_option('#ca_provider_select', '')
    assert page.input_value('#ca_account_id') == ''
    page.click('#createCertForm button[type="submit"]')
    page.wait_for_timeout(800)
    assert posts, 'the reissue request was never sent'
    assert posts[-1].get('ca_provider') == 'letsencrypt' and posts[-1].get('ca_account_id') == '', posts[-1]


def test_no_edit_can_start_before_the_ca_accounts_answer(page):
    """What the reissue's account choice rests on (#1465): it is read when the
    edit starts, and the certificate list, where an edit starts, is drawn only
    once /api/web/settings has answered. Were the list drawn first, an edit
    started then would keep its account after the CA list arrived."""
    held = []

    def settings(route):
        if route.request.method != 'GET':
            route.continue_()
            return
        held.append(route)

    page.unroute_all(behavior='ignoreErrors')
    page.route('**/api/web/settings', settings)
    page.route('**/api/certificates', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps([CERT]))
        if route.request.method == 'GET' else route.continue_())
    page.goto('about:blank')
    page.goto(BASE_URL, wait_until='domcontentloaded')
    page.wait_for_timeout(1000)
    # Another tab saying the certificates changed redraws the list after a
    # second: that waits for the CA settings too.
    other = page.context.new_page()
    other.goto(BASE_URL + '/health')
    other.evaluate("localStorage.setItem('certificates_updated', String(Date.now()))")
    other.close()
    page.wait_for_timeout(2500)
    assert held, 'the CA settings were not asked for'
    assert page.locator('tr[data-row-domain="named.example.com"]').count() == 0, \
        'the certificate list was drawn before the CA settings answered'
    for route in held:
        body = route.fetch().json()
        body.update(CA_SETTINGS)
        route.fulfill(status=200, content_type='application/json', body=json.dumps(body))
    page.wait_for_selector('tr[data-row-domain="named.example.com"]')


def _reissue_without_changes(page, ca_settings, cert):
    _dashboard(page, ca_settings, cert)
    posts = _reissue_posts(page)
    page.evaluate("startEditReissue('named.example.com')")
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.click('#createCertForm button[type="submit"]')
    page.wait_for_timeout(800)
    assert posts, 'the reissue request was never sent'
    return posts[-1]


def test_a_reissue_whose_ca_is_not_listed_is_not_sent_to_the_default_ca(page):
    """#1465 round 3: the CA select reads '' when no option matches the
    certificate's CA. That is not "Global default", and a Private CA name must
    not go to public Let's Encrypt because its account is unusable."""
    settings = {**CA_SETTINGS, 'ca_providers': {
        'letsencrypt': CA_SETTINGS['ca_providers']['letsencrypt'],
        'private_ca': {'accounts': {'internal': {'name': 'internal', 'email': 'pki@example.com'}}},
    }}
    body = _reissue_without_changes(page, settings,
                                    {**CERT, 'ca_provider': 'private_ca', 'ca_account_id': 'internal'})
    assert 'ca_provider' not in body, body


def test_global_default_never_names_a_ca_that_is_not_configured(page):
    settings = {**CA_SETTINGS, 'default_ca': 'digicert'}
    _dashboard(page, settings)
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    first = page.eval_on_selector('#ca_provider_select',
                                  'e => [e.options[0].textContent, e.options[0].disabled, e.options[0].value]')
    assert first == ['Global default: DigiCert (not configured in Settings)', True, ''], first
    body = _reissue_without_changes(page, settings, {**CERT, 'ca_provider': 'sectigo', 'ca_account_id': 'scm'})
    assert 'ca_provider' not in body, body
