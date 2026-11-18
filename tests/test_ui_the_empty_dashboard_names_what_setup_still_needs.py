"""The empty dashboard names what setup still needs, from the instance's own
settings, and links to the Settings tab where it is done.

UX perception audit, 2026-11-18 (P17): the empty dashboard always said "Go to
Settings and configure your DNS provider", after the wizard had saved a DNS
provider, after it had been finished with HTTP-01 (no DNS provider needed), and
after Skip, where what was missing was the email. Its link opened Settings on
the General tab. The steps are now built from the settings: the email when the
certificate authority has none (linked to #ca), the DNS provider's credentials
only when DNS-01 is the default and they are missing (linked to #dns), and
then the first certificate.

The listing, the settings and the DNS accounts the page reads are answered in
the browser (page.route), so the instance is not changed.
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
CLOUDFLARE = [{'provider': 'cloudflare', 'account_id': 'default', 'name': 'Default', 'configured': True}]


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _empty_dashboard(page, accounts, **settings):
    def answer_settings(route):
        if route.request.method != 'GET':
            return route.continue_()
        answer = route.fetch()
        body = answer.json()
        body.update(setup_completed=True, wizard_dismissed=True, default_ca='letsencrypt', ca_providers={})
        body.update(settings)
        return route.fulfill(response=answer, body=json.dumps(body))

    def listing(route):
        if route.request.method != 'GET':
            return route.continue_()
        return route.fulfill(status=200, content_type='application/json', body='[]')
    page.route('**/api/web/settings*', answer_settings)
    page.route('**/api/certificates', listing)
    page.route('**/api/dns/accounts', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps(accounts)))
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_selector('tr[data-empty-state]', state='visible', timeout=10000)
    return _steps(page)


def _steps(page):
    return page.evaluate("""() => {
        const state = document.querySelector('tr[data-empty-state]');
        return {text: state.innerText,
                links: Array.from(state.querySelectorAll('a[href]')).map(a => a.getAttribute('href'))};
    }""")


def test_after_the_wizard_with_http01_no_dns_provider_is_asked_for(page):
    steps = _empty_dashboard(page, [], email='ops@example.test', challenge_type='http-01',
                             dns_provider='cloudflare')
    assert 'DNS provider' not in steps['text'], steps
    assert 'Create your first certificate' in steps['text'], steps


def test_after_the_wizard_with_a_dns_provider_it_is_not_asked_for_again(page):
    steps = _empty_dashboard(page, CLOUDFLARE, email='ops@example.test', challenge_type='dns-01',
                             dns_provider='cloudflare')
    assert 'DNS provider' not in steps['text'], steps
    assert 'Create your first certificate' in steps['text'], steps


def test_after_skip_it_asks_for_the_email_on_the_ca_tab(page):
    steps = _empty_dashboard(page, [], email='', challenge_type='dns-01', dns_provider='cloudflare')
    assert 'email' in steps['text'].lower(), steps
    assert any(href.endswith('#ca') for href in steps['links']), steps


def test_dns01_without_credentials_links_to_the_dns_tab(page):
    """CONTROL: the DNS step is still there when it is the gap."""
    steps = _empty_dashboard(page, [], email='ops@example.test', challenge_type='dns-01',
                             dns_provider='cloudflare')
    assert 'DNS provider' in steps['text'], steps
    assert any(href.endswith('#dns') for href in steps['links']), steps
    assert not any(href.endswith('#ca') for href in steps['links']), steps
