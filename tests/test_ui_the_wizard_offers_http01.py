"""The first-run wizard can be finished with HTTP-01, without a DNS provider.

Found by the UX audit of 2026-11-17: step 2 could not be passed without
picking a DNS provider, so an operator who validates over HTTP-01 had no way
through the wizard; decided the same day to offer it. And "Create Your First
Certificate" opened a form whose CA list had been read before the wizard saved
the email, so it said "Configure a CA in Settings"; the list is read again
first.

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
