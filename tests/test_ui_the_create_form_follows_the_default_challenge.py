"""The create form follows the instance's default challenge when it is left on
"Use default from settings".

UX perception audit, 2026-11-18 (P20): the form looked only at the literal
value of the Challenge Type select. Left on its default ('') on an instance
whose default is HTTP-01, it still showed the whole DNS Provider list, and a
wildcard name went to the server, came back as a failed job ("HTTP-01 challenge
does not support wildcard domains"), with a hint about port 80. The form now
reads the default when the select is on it: no DNS provider list, and a
wildcard is refused next to the field before anything is sent.

The settings the page reads are answered in the browser (page.route), so the
instance is not changed; a create request is recorded and refused, never sent.
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
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _drawer(page, challenge_type):
    """The dashboard with *challenge_type* as the instance default, a usable
    CA (an email for Let's Encrypt), and the create drawer open."""
    posts = []

    def settings(route):
        if route.request.method != 'GET':
            return route.continue_()
        answer = route.fetch()
        body = answer.json()
        body.update(setup_completed=True, wizard_dismissed=True, email='ops@example.test',
                    default_ca='letsencrypt', challenge_type=challenge_type)
        return route.fulfill(response=answer, body=json.dumps(body))

    def create(route):
        posts.append(route.request.post_data)
        return route.fulfill(status=400, content_type='application/json',
                             body=json.dumps({'error': 'refused by the test', 'code': 'TEST'}))
    page.route('**/api/web/settings*', settings)
    page.route('**/api/certificates/create', create)
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.evaluate("() => window.openCertDrawer('server')")
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'domain'",
                           timeout=5000)
    return posts


def test_an_http01_default_shows_no_dns_provider_list(page):
    _drawer(page, 'http-01')
    assert page.input_value('#challenge_type_select') == ''
    assert not page.is_visible('#dns-provider-container')


def test_a_dns01_default_still_shows_the_dns_provider_list(page):
    """CONTROL: the DNS-01 default keeps the provider list."""
    _drawer(page, 'dns-01')
    assert page.input_value('#challenge_type_select') == ''
    assert page.is_visible('#dns-provider-container')


def test_a_wildcard_under_an_http01_default_is_refused_next_to_the_field(page):
    posts = _drawer(page, 'http-01')
    page.fill('#domain', '*.a.example')
    page.press('#domain', 'Enter')
    page.wait_for_selector('#domain_error', state='visible', timeout=3000)
    error = page.inner_text('#domain_error')
    assert 'DNS-01' in error, error
    # The message is the field's: described by it, marked invalid, and focus is there.
    described = page.evaluate("""() => (document.getElementById('domain').getAttribute('aria-describedby') || '')
        .split(/\\s+/).map(id => (document.getElementById(id) || {}).innerText || '').join(' ')""")
    assert 'DNS-01' in described, described
    assert page.get_attribute('#domain', 'aria-invalid') == 'true'
    assert page.evaluate("() => document.activeElement.id") == 'domain'
    page.wait_for_timeout(500)
    assert posts == []


def test_a_wildcard_is_sent_when_dns01_is_the_default(page):
    """CONTROL: the same name under a DNS-01 default reaches the server."""
    posts = _drawer(page, 'dns-01')
    page.fill('#domain', '*.a.example')
    page.press('#domain', 'Enter')
    page.wait_for_timeout(1000)
    assert len(posts) == 1 and '*.a.example' in posts[0]
    assert not page.is_visible('#domain_error')
