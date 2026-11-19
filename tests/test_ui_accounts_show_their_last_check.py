"""Settings: every CA and DNS account shows its last credential check (UX audit P39).

A Cloudflare token Cloudflare refuses was saved with 'Account "prod-cf"
created successfully' and the tile read "Configured" in green; a private CA
that did not answer failed "Check configuration" and was then saved with a
green "CA account saved", under a heading with a green check, and its row
looked like every healthy one.

Now each account says "Never checked", "Last check passed <time>", "Last check
failed <time>: <reason>" or "Not checkable yet", has a "Check credentials"
button, and is drawn green only when its last check passed. A save whose check
fails asks in the page's own dialog, "The check failed: <reason>. Save
anyway?": Cancel saves nothing.

The DNS checks call Cloudflare, so here the check answers are given by the test
(page.route). The private CA is 127.0.0.1 port 1: the server's own check fails
on a refused connection, nothing is stubbed and nothing leaves the machine.
The server side is tests/test_accounts_carry_their_last_check.py.
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
CF = 'ui-b17-cf'
DO = 'ui-b17-do'
CA = 'ui-b17-corp'
TOKEN = 'Tk' + 'b17Q' * 10
REFUSED = 'Cloudflare answered HTTP 403: Invalid access token (code 9109)'
PROVED = ('the token can read zones; permission to change DNS records is tested when a '
          'certificate is requested')
CA_SAID = 'The CA checks the account only when it registers'
UNREACHABLE_CA = 'https://127.0.0.1:1/directory'
NO_CA = 'Could not connect to 127.0.0.1 (ConnectionError)'


def _check(outcome, reason=None):
    return {'outcome': outcome, 'at': '2026-11-19T01:12:00Z', 'reason': reason}


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    _clear(page)
    page.request.post(f'{BASE_URL}/api/web/settings', headers={'Origin': BASE_URL},
                      data={'email': 'ops@example.com'})
    yield page
    _clear(page)
    context.close()


def _clear(page):
    for provider, account in (('cloudflare', CF), ('digitalocean', DO)):
        page.request.delete(f'{BASE_URL}/api/dns/{provider}/accounts/{account}', headers={'Origin': BASE_URL})
    page.request.delete(f'{BASE_URL}/api/web/settings/ca-providers/private_ca/accounts/{CA}',
                        headers={'Origin': BASE_URL})


def _add(page, provider, account, config):
    answer = page.request.post(f'{BASE_URL}/api/dns/{provider}/accounts', headers={'Origin': BASE_URL},
                               data={'account_id': account, 'config': {'name': account, **config}})
    assert answer.ok, (answer.status, answer.text()[:200])


def _open(page, provider):
    page.goto(f'{BASE_URL}/settings#dns', wait_until='networkidle')
    page.wait_for_function("p => document.getElementById(p + '-status').textContent.trim() !== ''", arg=provider)
    page.click(f'label:has(input[name="dns_provider"][value="{provider}"])')
    card = page.locator(f'#{provider}-accounts-list > div').filter(has_text=f'ID: {CF if provider == "cloudflare" else DO}')
    card.wait_for(state='visible', timeout=5000)
    return card


def _stored(page, provider, account):
    return [a for a in page.request.get(f'{BASE_URL}/api/dns/accounts').json()
            if a['provider'] == provider and a['account_id'] == account]


def test_an_account_never_checked_says_so_and_is_not_drawn_green(page):
    _add(page, 'cloudflare', CF, {'api_token': TOKEN})
    card = _open(page, 'cloudflare')
    assert card.locator('[data-last-check]').inner_text() == 'Never checked'
    assert card.get_by_role('button', name='Check credentials').count() == 1
    status = page.locator('#cloudflare-status')
    assert status.inner_text().strip() == 'Configured'
    assert 'text-success-fg' not in (status.get_attribute('class') or '')


def test_a_provider_with_no_check_says_not_checkable_yet(page):
    _add(page, 'digitalocean', DO, {'api_token': 'd' * 40})
    card = _open(page, 'digitalocean')
    assert card.locator('[data-last-check]').inner_text() == 'Not checkable yet'


def test_check_credentials_shows_the_refusal_and_a_pass_says_what_it_proved(page):
    _add(page, 'cloudflare', CF, {'api_token': TOKEN})
    answers = [_check('failed', REFUSED), _check('passed', PROVED)]
    asked = []

    def check(route):
        asked.append(route.request.method)
        route.fulfill(status=200, content_type='application/json', body=json.dumps(
            {'provider': 'cloudflare', 'account_id': CF, 'last_check': answers[len(asked) - 1]}))
    page.route(f'**/api/dns/cloudflare/accounts/{CF}/check', check)
    card = _open(page, 'cloudflare')

    card.get_by_role('button', name='Check credentials').click()
    line = page.locator(f'#cloudflare-accounts-list > div:has-text("ID: {CF}") [data-last-check]')
    # The card is drawn again from the answer: wait on the selector, not on an element.
    page.wait_for_function(
        "() => (document.querySelector('#cloudflare-accounts-list [data-last-check]') || {dataset: {}})"
        ".dataset.lastCheck === 'failed'", timeout=5000)
    text = line.inner_text()
    assert text.startswith('Last check failed ') and text.endswith(': ' + REFUSED), text
    assert 'text-danger-fg' in line.get_attribute('class')
    toasts = page.locator('#cm-toasts').inner_text()
    assert 'Invalid access token' in toasts, toasts
    assert 'text-success-fg' not in (page.locator('#cloudflare-status').get_attribute('class') or '')

    page.locator(f'#cloudflare-accounts-list > div:has-text("ID: {CF}")').get_by_role(
        'button', name='Check credentials').click()
    page.wait_for_function(
        "() => (document.querySelector('#cloudflare-accounts-list [data-last-check]') || {dataset: {}})"
        ".dataset.lastCheck === 'passed'", timeout=5000)
    passed = page.locator(f'#cloudflare-accounts-list > div:has-text("ID: {CF}") [data-last-check]')
    text = passed.inner_text()
    # What the check proved is on the card, not only in the API (review F6).
    assert text.startswith('Last check passed ') and text.endswith(': ' + PROVED), text
    assert 'text-success-fg' in passed.get_attribute('class')
    # The tile has no room for that sentence, so a pass does not turn it green.
    assert 'text-success-fg' not in (page.locator('#cloudflare-status').get_attribute('class') or '')
    assert asked == ['POST', 'POST']


def _fill_cloudflare_modal(page):
    page.click('#cloudflare-add-account')
    page.wait_for_selector('#addAccountModal', state='visible')
    page.fill('#account-name', CF)
    page.fill('#modal-api_token', TOKEN)


def _dialog(page):
    dialog = page.get_by_role('alertdialog')
    dialog.wait_for(state='visible', timeout=10000)
    return dialog


def test_a_dns_save_whose_check_fails_asks_and_cancel_saves_nothing(page):
    sent = []

    def create(route):
        sent.append(route.request.url)
        if 'save_anyway=1' in route.request.url:
            route.fulfill(status=200, content_type='application/json', body=json.dumps(
                {'success': True, 'message': 'Account created', 'id': CF, 'last_check': _check('failed', REFUSED)}))
            return
        route.fulfill(status=422, content_type='application/json', body=json.dumps(
            {'error': 'The check failed: ' + REFUSED, 'code': 'ACCOUNT_CHECK_FAILED',
             'last_check': _check('failed', REFUSED)}))
    page.route('**/api/dns/cloudflare/accounts?check=1*', create)
    page.goto(f'{BASE_URL}/settings#dns', wait_until='networkidle')
    page.click('label:has(input[name="dns_provider"][value="cloudflare"])')
    _fill_cloudflare_modal(page)

    page.click('#addAccountModal [data-click="saveAccount"]')
    dialog = _dialog(page)
    assert dialog.inner_text().count('The check failed: ' + REFUSED + '. Save anyway?') == 1, dialog.inner_text()
    dialog.get_by_role('button', name='Cancel').click()
    dialog.wait_for(state='detached', timeout=5000)
    assert page.locator('#addAccountModal').is_visible(), 'Cancel closed the form'
    assert [url for url in sent if 'save_anyway' in url] == []
    assert _stored(page, 'cloudflare', CF) == []

    page.click('#addAccountModal [data-click="saveAccount"]')
    _dialog(page).get_by_role('button', name='Save anyway').click()
    page.wait_for_selector('#addAccountModal', state='hidden', timeout=5000)
    assert sent[-1].endswith('check=1&save_anyway=1'), sent
    assert 'saved; its check failed: ' + REFUSED in page.locator('#cm-toasts').inner_text()


def _ca_modal(page):
    page.goto('about:blank')
    page.goto(f'{BASE_URL}/settings#ca', wait_until='networkidle')
    page.click('[data-click="openCAAccountModal"]')
    page.wait_for_selector('#caAccountModal', state='visible')
    page.select_option('#add-ca-type', 'private_ca')
    page.fill('#ca-account-name', CA)
    page.fill('#private-ca-acme-url', UNREACHABLE_CA)
    page.fill('#private-ca-email', 'ops@example.com')


def test_an_unreachable_private_ca_asks_before_saving_and_its_row_shows_the_failure(page):
    _ca_modal(page)
    page.click('[data-click="saveCAAccount"]')
    dialog = _dialog(page)
    assert 'The check failed: ' + NO_CA + '. Save anyway?' in dialog.inner_text(), dialog.inner_text()
    dialog.get_by_role('button', name='Cancel').click()
    dialog.wait_for(state='detached', timeout=5000)
    assert page.locator('#caAccountModal').is_visible()
    saved = page.request.get(f'{BASE_URL}/api/web/settings').json().get('ca_providers') or {}
    assert 'private_ca' not in saved, saved

    page.click('[data-click="saveCAAccount"]')
    _dialog(page).get_by_role('button', name='Save anyway').click()
    page.wait_for_selector('#caAccountModal', state='hidden', timeout=15000)
    row = page.locator('#configured-ca-list > div').filter(has_text=CA).first
    page.wait_for_function(
        "n => Array.from(document.querySelectorAll('#configured-ca-list > div')).some(r => "
        "r.innerText.includes(n) && r.querySelector('[data-last-check=\"failed\"]'))", arg=CA, timeout=10000)
    text = row.locator('[data-last-check]').inner_text()
    assert text.startswith('Last check failed ') and text.endswith(': ' + NO_CA), text
    heading = page.locator('[data-ca-accounts-status]').get_attribute('class') or ''
    assert 'fa-check-circle' not in heading and 'text-green-500' not in heading, heading
    assert 'fa-exclamation-triangle' in heading, heading


def test_a_record_that_cannot_be_read_is_not_called_never_checked(page):
    """When the page cannot ask the server, an account's last check is not
    known: "Never checked" may be untrue, and green would be."""
    page.route('**/api/web/settings/ca-account-checks',
               lambda route: route.fulfill(status=503, content_type='application/json', body='{}'))
    page.goto(f'{BASE_URL}/settings#ca', wait_until='networkidle')
    page.wait_for_function(
        "() => document.querySelector('#configured-ca-list [data-last-check]') !== null", timeout=10000)
    lines = page.locator('#configured-ca-list [data-last-check]')
    for i in range(lines.count()):
        assert lines.nth(i).inner_text() == 'Last check not known: CertMate could not be asked'
    heading = page.locator('[data-ca-accounts-status]').get_attribute('class') or ''
    assert 'fa-check-circle' not in heading, heading


def test_a_ca_whose_directory_answers_reads_reachable_never_green(page):
    """A CA check proves the directory answers, not the account (review F2)."""
    page.route('**/api/web/settings/ca-providers/letsencrypt/accounts/default/check',
               lambda route: route.fulfill(status=200, content_type='application/json', body=json.dumps(
                   {'provider': 'letsencrypt', 'account_id': 'default',
                    'last_check': _check('reachable', CA_SAID)})))
    page.goto(f'{BASE_URL}/settings#ca', wait_until='networkidle')
    row = page.locator('#configured-ca-list > div').filter(has_text="Let's Encrypt").first
    row.wait_for(state='visible', timeout=10000)
    row.get_by_role('button', name='Check credentials').click()
    page.wait_for_function(
        "() => (document.querySelector('#configured-ca-list [data-last-check]') || {dataset: {}})"
        ".dataset.lastCheck === 'reachable'", timeout=5000)
    line = page.locator('#configured-ca-list > div').filter(has_text="Let's Encrypt").first.locator(
        '[data-last-check]')
    text = line.inner_text()
    assert text.startswith('Directory answered ') and text.endswith('. ' + CA_SAID + '.'), text
    assert 'passed' not in text
    assert 'text-success-fg' not in line.get_attribute('class')
    heading = page.locator('[data-ca-accounts-status]').get_attribute('class') or ''
    assert 'fa-check-circle' not in heading and 'text-green-500' not in heading, heading
    assert 'Invalid' not in page.locator('#cm-toasts').inner_text()
    assert 'Directory answered' in page.locator('#cm-toasts').inner_text()
