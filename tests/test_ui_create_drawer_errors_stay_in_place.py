"""A failed Create keeps focus in the drawer, on the field the error is about,
and the error is written next to that field; "Check all deployments" keeps
focus on itself while it runs.

UX perception audit, 2026-11-18 (P33): the submit disabled every field of the
form, the focused one included, so focus fell to the page body within 50 ms
and stayed there after the fields came back; the server's "Invalid domain"
answer was only a toast at the top right, outside the drawer, and #domain got
no aria-invalid and no description of the error. "Check all deployments"
disabled its own focused button the same way. Now the focused control is
marked busy instead of disabled (the submit is still single-flight), a
refusal about the name is written under #domain, which is marked invalid,
described by it and focused, and the Check all button stays focused.

The settings the page reads, the create answer, the listing and the deployment
checks are answered in the browser (page.route), so the instance is not changed.
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
# What POST /api/certificates/create answers for 'not a domain!!' (resources_lifecycle.py, ValueError).
INVALID_DOMAIN = {'code': 'CERTIFICATE_CREATION_FAILED',
                  'error': "Invalid domain: Invalid domain format (e.g., must be like 'example.com').",
                  'hint': None}

# Sample document.activeElement every 50 ms for two seconds, from now.
START_FOCUS_TIMELINE = """() => {
    const seen = window.__focusTimeline = [];
    window.__focusTimelineDone = false;
    const started = performance.now();
    const tick = () => {
        const el = document.activeElement;
        seen.push(el ? el.tagName + (el.id ? '#' + el.id : '') : 'null');
        if (performance.now() - started < 2000) setTimeout(tick, 50); else window.__focusTimelineDone = true;
    };
    tick();
}"""


def _focus_timeline(page):
    page.wait_for_function('() => window.__focusTimelineDone === true', timeout=5000)
    return page.evaluate('() => window.__focusTimeline')


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _settings_with_a_usable_ca(route):
    if route.request.method != 'GET':
        return route.continue_()
    answer = route.fetch()
    body = answer.json()
    body.update(setup_completed=True, wizard_dismissed=True, email='ops@example.test',
                default_ca='letsencrypt', challenge_type='dns-01')
    return route.fulfill(response=answer, body=json.dumps(body))


def _submit_refused(page, answer, status=400):
    page.route('**/api/web/settings*', _settings_with_a_usable_ca)

    def create(route):
        # A real server takes a moment: long enough for focus to fall, if it is going to.
        time.sleep(0.3)
        return route.fulfill(status=status, content_type='application/json', body=json.dumps(answer))
    page.route('**/api/certificates/create', create)
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.evaluate("() => window.openCertDrawer('server')")
    page.wait_for_function("() => document.activeElement && document.activeElement.id === 'domain'",
                           timeout=5000)
    page.fill('#domain', 'not a domain!!')
    page.evaluate(START_FOCUS_TIMELINE)
    page.press('#domain', 'Enter')
    return _focus_timeline(page)


def _described_by(page, selector):
    return page.evaluate("""sel => (document.querySelector(sel).getAttribute('aria-describedby') || '')
        .split(/\\s+/).map(id => (document.getElementById(id) || {}).innerText || '').join(' | ')""", selector)


def test_a_refused_name_keeps_focus_on_the_field_and_says_why_beside_it(page):
    timeline = _submit_refused(page, INVALID_DOMAIN)
    assert 'BODY' not in timeline, timeline
    assert timeline[-1] == 'INPUT#domain', timeline
    assert page.get_attribute('#domain', 'aria-invalid') == 'true'
    described = _described_by(page, '#domain')
    assert 'Invalid domain' in described, described
    assert page.is_visible('#domain_error')
    # Inside the drawer, not only in a toast at the corner of the page.
    assert page.evaluate("() => !!document.getElementById('domain_error').closest('#createCertFormContainer')")


def test_typing_in_the_field_clears_the_error(page):
    _submit_refused(page, INVALID_DOMAIN)
    page.fill('#domain', 'example.com')
    assert page.get_attribute('#domain', 'aria-invalid') in (None, 'false')
    assert not page.is_visible('#domain_error')


def test_a_refusal_about_something_else_keeps_focus_where_it_was(page):
    """CONTROL: an error that is not about the name does not mark the name invalid,
    and focus still does not fall to the page."""
    timeline = _submit_refused(page, {'code': 'CERTIFICATE_CREATION_FAILED',
                                      'error': "DNS provider 'cloudflare' account 'default' not configured"})
    assert 'BODY' not in timeline, timeline
    assert page.get_attribute('#domain', 'aria-invalid') in (None, 'false')
    assert not page.is_visible('#domain_error')


def _certificate(index):
    domain = f'site{index}.example.test'
    return {'domain': domain, 'exists': True, 'days_left': 40, 'days_until_expiry': 40,
            'expired': False, 'seconds_left': 40 * 86400,
            'expiry_date': '2027-01-01 10:00:00', 'expires_at': '2027-01-01T10:00:00Z',
            'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
            'san_domains': [], 'has_private_key': True}


def test_check_all_deployments_keeps_focus_on_its_button(page):
    certificates = [_certificate(i) for i in range(3)]
    sweep = {'started': False}

    def answer(route):
        url = route.request.url.split('?')[0]
        if route.request.method == 'GET' and url.endswith('/api/certificates'):
            return route.fulfill(status=200, content_type='application/json', body=json.dumps(certificates))
        if route.request.method == 'GET' and url.endswith('/deployment-status'):
            if not sweep['started']:
                # The checks the page starts by itself are left unanswered, so
                # nothing is cached and the sweep asks for every certificate.
                return None
            time.sleep(0.4)
            return route.fulfill(status=200, content_type='application/json', body=json.dumps(
                {'deployed': True, 'reachable': True, 'certificate_match': True,
                 'method': 'server', 'protocol': 'https-tls'}))
        return route.continue_()
    page.route('**/api/**', answer)
    page.goto(f'{BASE_URL}/', wait_until='load')
    page.wait_for_selector('[data-deployment-domain]', state='attached', timeout=10000)
    sweep['started'] = True
    page.locator('[data-click="checkAllDeploymentStatuses"]').focus()
    page.evaluate(START_FOCUS_TIMELINE)
    page.keyboard.press('Enter')
    timeline = _focus_timeline(page)
    assert 'BODY' not in timeline, timeline
    assert page.evaluate("() => document.activeElement.getAttribute('data-click')") == 'checkAllDeploymentStatuses'
