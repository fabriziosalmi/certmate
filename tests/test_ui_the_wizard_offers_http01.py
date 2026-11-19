"""The first-run wizard can be finished with HTTP-01, without a DNS provider.

Found by the UX audit of 2026-11-17: step 2 could not be passed without
picking a DNS provider, so an operator who validates over HTTP-01 had no way
through the wizard; decided the same day to offer it. And "Create Your First
Certificate" opened a form whose CA list had been read before the wizard saved
the email, so it said "Configure a CA in Settings"; the list is read again
first.

The UX perception audit of 2026-11-18 added three more: picking a DNS provider
brings its credentials and "Save & Finish" into the card's view, an empty
credential says it is required, and the empty dashboard behind the wizard is
read again once it has saved.

The settings the page reads (setup not completed) and its save are answered
in the browser (page.route), so the shared instance is not changed.
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


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _wizard(page):
    saved = []

    def settings(route):
        if route.request.method == 'GET':
            answer = route.fetch()
            body = answer.json()
            body.update(setup_completed=False, wizard_dismissed=False)
            # Read back as a server would: step 3 lists what the settings hold
            # after the save (P19), not what the page sent.
            for posted in saved:
                body.update(posted)
            return route.fulfill(response=answer, body=json.dumps(body))
        saved.append(json.loads(route.request.post_data or '{}'))
        return route.fulfill(status=200, content_type='application/json', body=json.dumps({'message': 'saved'}))
    page.route('**/api/web/settings*', settings)
    page.add_init_script("localStorage.removeItem('certmate_wizard_skipped')")
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_selector('#wizEmail', state='visible', timeout=10000)
    page.fill('#wizEmail', 'ops@example.test')
    page.click('#wizNext1')
    page.wait_for_selector('#challengeChoice', state='visible')
    return saved


def test_http01_finishes_the_wizard_without_a_dns_provider(page):
    saved = _wizard(page)
    page.click('[data-challenge="http-01"]')
    assert page.is_visible('#http01Note') and not page.is_visible('#providerGrid')
    assert page.is_enabled('#wizNext2')
    page.click('#wizNext2')
    page.wait_for_selector('text=HTTP-01, on port 80')
    assert len(saved) == 1
    assert saved[0]['challenge_type'] == 'http-01'
    assert 'dns_provider' not in saved[0] and 'dns_providers' not in saved[0]
    assert saved[0]['email'] == 'ops@example.test' and saved[0]['setup_completed'] is True


def test_dns01_still_needs_a_provider(page):
    """CONTROL: the DNS path is as it was, and says so in what it saves."""
    saved = _wizard(page)
    assert page.is_visible('#providerGrid')
    assert not page.is_enabled('#wizNext2')
    page.click('[data-provider="cloudflare"]')
    page.fill('#wiz_api_token', 'x' * 40)
    page.click('#wizNext2')
    page.wait_for_selector('text=DNS Provider:')
    assert saved[0]['challenge_type'] == 'dns-01' and saved[0]['dns_provider'] == 'cloudflare'


def test_the_first_certificate_form_reads_the_ca_list_again(page):
    _wizard(page)
    page.click('[data-challenge="http-01"]')
    page.click('#wizNext2')
    page.wait_for_selector('#wizFinish')
    page.evaluate("""() => {
        window.__caReloads = 0;
        const original = window.loadCAProviders;
        window.loadCAProviders = function () { window.__caReloads++; return original.apply(this, arguments); };
    }""")
    page.click('#wizFinish')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    assert page.evaluate('() => window.__caReloads') == 1


# UX perception audit, 2026-11-18 (P18): picking a provider changed only the
# tile's border. The 28 tiles fill the card, so the credential form and "Save &
# Finish" were drawn below its visible bottom (the token at y 1267, the card
# ending at 855 on a 900 px screen), and nothing scrolled to them or focused
# them. Saving with the token empty only turned its border red, with no text.
SEEN = """sel => {
    const el = document.querySelector(sel);
    if (!el) return false;
    const r = el.getBoundingClientRect();
    let box = {top: 0, bottom: window.innerHeight};
    const card = el.closest('#setupWizard > div');
    if (card) {
        const c = card.getBoundingClientRect();
        box = {top: Math.max(0, c.top), bottom: Math.min(window.innerHeight, c.bottom)};
    }
    // Not under the card's sticky footer either.
    const footer = document.getElementById('wizardFooter');
    if (footer && !footer.contains(el)) {
        const f = footer.getBoundingClientRect();
        if (f.top < box.bottom && f.bottom >= box.bottom - 1) box.bottom = f.top;
    }
    return r.height > 0 && r.top >= box.top - 1 && r.bottom <= box.bottom + 1;
}"""


def test_picking_a_provider_brings_its_credentials_and_save_into_view(page):
    _wizard(page)
    page.click('[data-provider="cloudflare"]')
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'wiz_api_token'",
                           timeout=3000)
    page.wait_for_function(f"() => ({SEEN})('#wiz_api_token')", timeout=3000)
    assert page.evaluate(f"() => ({SEEN})('#wizNext2')")


def test_an_empty_token_says_it_is_required(page):
    _wizard(page)
    page.click('[data-provider="cloudflare"]')
    page.click('#wizNext2')
    assert page.get_attribute('#wiz_api_token', 'aria-invalid') == 'true'
    described = page.evaluate("""() => (document.getElementById('wiz_api_token')
        .getAttribute('aria-describedby') || '').split(/\\s+/)
        .map(id => (document.getElementById(id) || {}).innerText || '').join(' ')""")
    assert 'API Token is required' in described, described
    assert page.evaluate("() => document.activeElement.id") == 'wiz_api_token'


# UX perception audit, 2026-11-18 (P17): behind the wizard, the empty dashboard
# still said "configure your DNS provider" after it was finished, with HTTP-01
# or with a DNS provider. The settings and the DNS accounts are answered from
# what the wizard saved, as a server would after the save.
def _finish_on_an_empty_dashboard(page, choose):
    stored = {}

    def settings(route):
        if route.request.method == 'GET':
            answer = route.fetch()
            body = answer.json()
            body.update(setup_completed=False, wizard_dismissed=False, email='', challenge_type='dns-01',
                        default_ca='letsencrypt', ca_providers={})
            body.update(stored)
            return route.fulfill(response=answer, body=json.dumps(body))
        stored.update(json.loads(route.request.post_data or '{}'))
        return route.fulfill(status=200, content_type='application/json', body=json.dumps({'message': 'saved'}))

    def listing(route):
        if route.request.method != 'GET':
            return route.continue_()
        return route.fulfill(status=200, content_type='application/json', body='[]')

    def accounts(route):
        saved = (stored.get('dns_providers') or {}).get('cloudflare')
        return route.fulfill(status=200, content_type='application/json', body=json.dumps(
            [{'provider': 'cloudflare', 'account_id': 'default', 'name': 'Default', 'configured': True}]
            if saved else []))
    page.route('**/api/web/settings*', settings)
    page.route('**/api/certificates', listing)
    page.route('**/api/dns/accounts', accounts)
    page.add_init_script("localStorage.removeItem('certmate_wizard_skipped')")
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_selector('#wizEmail', state='visible', timeout=10000)
    before = page.inner_text('tr[data-empty-state]')
    page.fill('#wizEmail', 'ops@example.test')
    page.click('#wizNext1')
    choose()
    page.click('#wizNext2')
    page.wait_for_selector('#wizFinish')
    page.click('#wizFinish')
    # The drawer opens once what the wizard saved has been read again.
    page.wait_for_function("() => !document.getElementById('createCertFormContainer').hasAttribute('inert')",
                           timeout=5000)
    return before, page.inner_text('tr[data-empty-state]')


def test_after_http01_the_empty_dashboard_asks_for_no_dns_provider(page):
    def http01():
        page.click('[data-challenge="http-01"]')
    before, after = _finish_on_an_empty_dashboard(page, http01)
    assert 'DNS provider' in before and 'email' in before, before
    assert 'DNS provider' not in after and 'email' not in after, after
    assert 'Create your first certificate' in after, after


def test_after_a_dns_provider_the_empty_dashboard_does_not_ask_for_it_again(page):
    def cloudflare():
        page.click('[data-provider="cloudflare"]')
        page.fill('#wiz_api_token', 'x' * 40)
    before, after = _finish_on_an_empty_dashboard(page, cloudflare)
    assert 'DNS provider' in before, before
    assert 'DNS provider' not in after and 'email' not in after, after
    assert 'Create your first certificate' in after, after
