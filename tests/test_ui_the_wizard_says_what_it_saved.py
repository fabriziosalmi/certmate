"""The wizard's last step says what it saved and that nothing was checked,
instead of "You're All Set!" with green checks.

UX perception audit, 2026-11-18 (P19): with the token "not-a-real-token" and
an email the CA later refused, step 3 said "You're All Set! CertMate is
configured and ready to manage your certificates." with a green check on each
value. The wizard tests nothing: it saves the settings and draws step 3.
Decided: no success claim, a statement of what happened, neutral icons.

Each value on step 3 is read back from the settings after the save, so it is
what this instance now holds: an operator who pinned LETSENCRYPT_EMAIL sees
that address, not the one typed. A save that is refused stays on step 2.

The settings the page reads (setup not completed) and its save are answered in
the browser (page.route), so the shared instance is not changed.
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
TYPED = 'ops@example.test'


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _wizard(page, save_status=200, pinned=None, not_in_effect=()):
    """The wizard on step 2. A save is kept and read back, as a server does;
    *pinned* stands for the environment overriding what was saved, and
    *not_in_effect* for the save's answer naming it (API contract 2.72)."""
    stored = {}

    def settings(route):
        if route.request.method == 'GET':
            answer = route.fetch()
            body = answer.json()
            body.update(setup_completed=False, wizard_dismissed=False, email='', challenge_type='dns-01')
            body.update(stored)
            body.update(pinned or {})
            return route.fulfill(response=answer, body=json.dumps(body))
        if save_status != 200:
            return route.fulfill(status=save_status, content_type='application/json',
                                 body=json.dumps({'error': 'Update failed'}))
        stored.update(json.loads(route.request.post_data or '{}'))
        return route.fulfill(status=200, content_type='application/json',
                             body=json.dumps({'message': 'Settings updated',
                                              'not_in_effect': list(not_in_effect)}))
    page.route('**/api/web/settings*', settings)
    page.add_init_script("localStorage.removeItem('certmate_wizard_skipped')")
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_selector('#wizEmail', state='visible', timeout=10000)
    page.fill('#wizEmail', TYPED)
    page.click('#wizNext1')
    page.wait_for_selector('#challengeChoice', state='visible')
    return stored


def _finish_http01(page):
    page.click('[data-challenge="http-01"]')
    page.click('#wizNext2')
    page.wait_for_selector('#wizFinish', timeout=10000)
    return page.locator('#wizardBody')


# Classes that colour a thing as a status: green or a success token, in the
# step and in the step indicator above it.
STATUS_COLOURED = ', '.join(f'{part} [class*="{tone}"]' for part in ('#wizardBody', '#wizardSteps')
                            for tone in ('green', 'success', 'danger', 'warning'))


def test_step_three_makes_no_success_claim_and_says_nothing_was_checked(page):
    _wizard(page)
    body = _finish_http01(page)
    text = body.inner_text()
    assert 'All Set' not in text and 'ready to manage' not in text, text
    assert 'Settings saved' in text, text
    assert 'has not checked them with your certificate authority' in text, text
    assert page.locator(STATUS_COLOURED).count() == 0, page.inner_html('#setupWizard')


def test_step_three_lists_what_was_saved(page):
    stored = _wizard(page)
    text = _finish_http01(page).inner_text()
    assert stored['email'] == TYPED
    assert f'Email: {TYPED}' in text, text
    assert 'Validation: HTTP-01, on port 80' in text, text
    assert 'Auto-renewal: Enabled' in text, text


def test_with_a_dns_provider_step_three_names_it_as_unchecked(page):
    _wizard(page)
    page.click('[data-provider="cloudflare"]')
    page.fill('#wiz_api_token', 'not-a-real-token')
    page.click('#wizNext2')
    page.wait_for_selector('#wizFinish', timeout=10000)
    text = page.inner_text('#wizardBody')
    assert 'DNS Provider: Cloudflare' in text, text
    assert 'has not checked them with your certificate authority or with Cloudflare' in text, text
    assert page.locator(STATUS_COLOURED).count() == 0, page.inner_html('#setupWizard')


def test_an_email_the_environment_pins_is_the_one_step_three_shows(page):
    _wizard(page, pinned={'email': 'pinned@example.test'},
            not_in_effect=[{'setting': 'email', 'by': 'LETSENCRYPT_EMAIL'}])
    text = _finish_http01(page).inner_text()
    assert 'Email: pinned@example.test' in text, text
    assert 'Settings saved, not all in effect' in text, text
    note = page.inner_text('[data-not-in-effect]')
    assert 'LETSENCRYPT_EMAIL' in note and TYPED in note, note


@pytest.mark.parametrize('entry, says', [
    ({'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'CLOUDFLARE_TOKEN'},
     'Cloudflare API Token: CLOUDFLARE_TOKEN on this instance replaces what you entered.'),
    ({'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'api_token_env'},
     'Cloudflare API Token: the account default takes it from api_token_env, not from what you entered.'),
    ({'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'api_token_file', 'readable': False},
     'Cloudflare API Token: not used. The account default reads it from api_token_file, which cannot be read; '
     'issuance fails until it can.'),
    ({'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'CERTMATE_CONFIG_FILE'},
     'Cloudflare API Token: not saved. The configuration file named by CERTMATE_CONFIG_FILE declares the account '
     'default, and the account as it declares it is what issuance uses.'),
    ({'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'another setting'},
     'Cloudflare API Token: what you entered is not the value in use.'),
    # A value this page does not know claims nothing and shows no raw name.
    ({'setting': 'dns_providers.cloudflare.accounts.default.api_token', 'by': 'some_future_source'},
     'Cloudflare API Token: what you entered is not the value in use.'),
    ({'setting': 'email', 'by': 'ca_providers.letsencrypt.accounts.default.email'},
     "Email: the Let's Encrypt account default in Settings, CA has an email of its own, and certificates use it, "
     'not the address you entered.'),
    ({'setting': 'email', 'by': 'default_ca'},
     'Email: the default certificate authority is not configured in Settings, CA, so no certificate uses the '
     'address you entered yet.'),
])
def test_credentials_something_else_decides_are_said_so(page, entry, says):
    _wizard(page, not_in_effect=[entry])
    page.click('[data-provider="cloudflare"]')
    page.fill('#wiz_api_token', 'not-a-real-token')
    page.click('#wizNext2')
    page.wait_for_selector('#wizFinish', timeout=10000)
    assert 'Settings saved, not all in effect' in page.inner_text('#wizardBody')
    note = page.inner_text('[data-not-in-effect]')
    assert says in note, note
    assert 'not-a-real-token' not in note and 'some_future_source' not in note


def test_keys_an_iam_role_hides_are_not_sent(page):
    """Typed, then hidden by switching to an IAM role: not saved unused."""
    stored = _wizard(page)
    page.click('[data-provider="route53"]')
    page.fill('#wiz_access_key_id', 'AKIAEXAMPLEKEY')
    page.fill('#wiz_secret_access_key', 'typed-secret-key')
    page.select_option('#wiz_auth_mode', 'iam_role')
    page.click('#wizNext2')
    page.wait_for_selector('#wizFinish', timeout=10000)
    account = stored['dns_providers']['route53']['accounts']['default']
    assert account['auth_mode'] == 'iam_role'
    assert 'access_key_id' not in account and 'secret_access_key' not in account, account


def test_a_refused_save_stays_on_step_two(page):
    """CONTROL: step 3 is drawn only after the save succeeded."""
    _wizard(page, save_status=500)
    page.click('[data-challenge="http-01"]')
    page.click('#wizNext2')
    page.wait_for_selector('text=Failed to save settings', timeout=10000)
    assert page.locator('#wizFinish').count() == 0
    assert page.is_visible('#wizNext2') and page.is_enabled('#wizNext2')
