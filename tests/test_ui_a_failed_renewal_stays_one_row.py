"""A failed renewal stays one certificate on the dashboard, and the detail
panel says the last renewal failed instead of promising the next run.

UX perception audit, 2026-11-18. P38: a renewal job that failed was drawn as
a second row for the same domain, at the top of the table, marked "Failed"
with no expiry, provider or CA, while the real row further down still read
"Expiring". A failed create showed "—" for the CA it had asked for. P37: after
the failure, and after every reload, the detail panel kept saying "Due: the
next renewal run renews it" under a past date, and nothing about the failure.

Now the failure is on the certificate's own row (a "Renewal failed" chip and
the cause under the name) and in its detail panel ("Last renewal failed",
the cause, the hint ending "The previous certificate is still in place.",
and "Renewal overdue since <date>" for a past renewal date), read from the
`last_renewal_attempt` the server keeps (tests/test_a_failed_renewal_is_kept_on_the_certificate.py).
A failed create's row names the CA the request chose. The answers are given
in the browser (page.route), as in tests/test_ui_a_failed_job_shows_what_to_check.py.
"""
import datetime
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
DOMAIN = 'shop.oncall.example.test'
# certbot's own words when the CA is not there, as the job records them: the
# cause line carries tokens without spaces (NewConnectionError("HTTPSConnection(...)
ERROR = ("Certificate creation failed: An unexpected error occurred:\n"
         "requests.exceptions.ConnectionError: HTTPSConnectionPool(host='127.0.0.1', port=9): "
         "Max retries exceeded with url: /acme/directory (Caused by NewConnectionError("
         "\"HTTPSConnection(host='127.0.0.1', port=9): Failed to establish a new connection: "
         "[Errno 61] Connection refused\"))\n"
         "Ask for help or search for solutions at https://community.letsencrypt.org. See the logfile "
         "/var/lib/certmate/certificates/shop.oncall.example.test/logs/letsencrypt.log or re-run "
         "Certbot with -v for more details.")
HINT = ("CertMate could not reach the CA's ACME directory at https://127.0.0.1:9/acme/directory: "
        "check the directory URL, that its name resolves from this host, and that outbound HTTPS "
        "to it is allowed. The previous certificate is still in place.")


def _stamp(delta):
    return (datetime.datetime.now(datetime.UTC) + delta).strftime('%Y-%m-%dT%H:%M:%SZ')


def _cert(attempt=None):
    """A private-CA certificate with 5 days left, whose renewal date is 25 days past."""
    expires = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=5, hours=1)
    return {
        'domain': DOMAIN, 'host': DOMAIN, 'ip_address': None, 'exists': True, 'days_left': 5,
        'days_until_expiry': 5, 'seconds_left': 5 * 86400 + 3600, 'expired': False,
        'needs_renewal': True, 'usable': True, 'private_key_present': True,
        'private_key_state': 'present', 'reissue_required': False, 'external': False,
        'expiry_date': expires.strftime('%Y-%m-%d %H:%M:%S'), 'expires_at': _stamp(datetime.timedelta(days=5, hours=1)),
        'expiry_status': 'critical', 'dns_provider': None, 'ca_provider': 'private_ca',
        'challenge_type': 'http-01', 'san_domains': [], 'auto_renew': True, 'tags': [], 'notes': None,
        'renewal_info': None, 'renews_at': _stamp(-datetime.timedelta(days=25)), 'acme_profile': None,
        'acme_profile_withdrawn_at': None, 'imported_at': None, 'renewed_at': None,
        'last_renewal_attempt': attempt,
    }


FAILED = {'attempted_at': _stamp(-datetime.timedelta(minutes=2)), 'outcome': 'failed',
          'error': ERROR, 'hint': HINT}


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _json(route, body, status=200):
    route.fulfill(status=status, content_type='application/json', body=json.dumps(body))


def _serve(page, state, job_after):
    """The list answers with `state['cert']`; Renew queues job r1, which ends
    as `job_after` and leaves `state['after']` as the certificate."""
    page.route('**/api/certificates', lambda route: _json(route, [state['cert']])
               if route.request.method == 'GET' else route.continue_())
    page.route('**/api/certificates/jobs', lambda route: _json(route, {'count': 0, 'jobs': []}))

    def renew(route):
        state['cert'] = state['after']
        _json(route, {'job_id': 'r1', 'status': 'queued', 'operation': 'renew', 'domain': DOMAIN,
                      'status_url': '/api/certificates/jobs/r1'}, status=202)
    page.route(f'**/api/certificates/{DOMAIN}/renew', renew)
    page.route('**/api/certificates/jobs/r1', lambda route: _json(
        route, {'job_id': 'r1', 'domain': DOMAIN, 'operation': 'renew', **job_after}))


def _rows(page):
    return page.locator('#certificatesList tr', has_text=DOMAIN)


def _renew(page):
    page.goto(BASE_URL, wait_until='networkidle')
    page.wait_for_selector(f'tr[data-row-domain="{DOMAIN}"]', state='visible')
    page.click(f'button[data-action="renew"][data-domain="{DOMAIN}"]')


def test_a_failed_renewal_leaves_one_row_with_its_days_and_a_marker(page):
    state = {'cert': _cert(), 'after': _cert(FAILED)}
    _serve(page, state, {'status': 'failed', 'error': ERROR, 'error_code': 'RENEWAL_FAILED', 'hint': HINT})

    _renew(page)

    page.wait_for_selector('text=Certificate renewal failed for', timeout=15000)
    page.wait_for_load_state('networkidle')
    page.wait_for_timeout(1000)
    assert _rows(page).count() == 1, [_rows(page).nth(i).inner_text() for i in range(_rows(page).count())]
    page.wait_for_selector(f'tr[data-row-domain="{DOMAIN}"] [data-renewal-failed]', timeout=5000)
    row = page.inner_text(f'tr[data-row-domain="{DOMAIN}"]')
    assert '5 days left' in row, row
    assert 'Renewal failed' in row, row


def test_after_a_reload_the_detail_says_the_last_renewal_failed(page):
    state = {'cert': _cert(FAILED), 'after': _cert(FAILED)}
    _serve(page, state, {'status': 'failed'})
    page.goto(BASE_URL, wait_until='networkidle')
    page.wait_for_selector(f'tr[data-row-domain="{DOMAIN}"]', state='visible')

    page.evaluate(f"openCertDetail('{DOMAIN}')")
    page.wait_for_selector('#certDetailContent dl', timeout=5000)
    detail = page.inner_text('#certDetailContent')

    assert 'Last renewal failed' in detail, detail
    assert "could not reach the CA's ACME directory" in detail, detail
    assert 'still in place' in detail, detail
    assert 'the next renewal run renews it' not in detail, detail
    assert 'Renewal overdue since' in detail, detail


def test_a_renewal_after_a_failure_clears_the_marker(page):
    state = {'cert': _cert(FAILED), 'after': _cert()}
    _serve(page, state, {'status': 'succeeded'})
    page.goto(BASE_URL, wait_until='networkidle')
    page.wait_for_selector(f'tr[data-row-domain="{DOMAIN}"] [data-renewal-failed]', timeout=5000)

    page.click(f'button[data-action="renew"][data-domain="{DOMAIN}"]')

    page.wait_for_selector(f'tr[data-row-domain="{DOMAIN}"] [data-renewal-failed]', state='detached',
                           timeout=15000)
    assert _rows(page).count() == 1


def test_on_a_phone_the_failure_line_does_not_widen_the_domain_column(browser_page, ui_session_cookie):
    """At 390 px the cause under the name wraps inside the Domain cell. With
    break-words, certbot's tokens without spaces set the cell's min-content
    width: in review the cell grew from 280 to 430 px and the line ran past the
    screen."""
    context = browser_page.context.browser.new_context(viewport={'width': 390, 'height': 844})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    try:
        _serve(page, {'cert': _cert(FAILED), 'after': _cert(FAILED)}, {'status': 'failed'})
        page.goto(BASE_URL, wait_until='networkidle')
        marker = f'tr[data-row-domain="{DOMAIN}"] [data-renewal-failed]'
        page.wait_for_selector(marker, state='visible', timeout=5000)
        widths = page.evaluate("""(marker) => {
            const line = document.querySelector(marker);
            const cell = line.closest('td');
            const text = line.querySelector('span').getBoundingClientRect();
            const withLine = cell.getBoundingClientRect();
            line.remove();
            const without = cell.getBoundingClientRect();
            return {withLine: withLine.width, without: without.width,
                    textRight: text.right, cellRight: withLine.right};
        }""", marker)
    finally:
        page.unroute_all(behavior='ignoreErrors')
        context.close()

    assert widths['withLine'] <= widths['without'] + 1, widths
    assert widths['textRight'] <= widths['cellRight'] + 1, widths


def test_on_a_phone_the_detail_tells_the_failure_across_the_banner(browser_page, ui_session_cookie):
    """At 390 px the failure is told under the banner's status row, across its
    width. Inside the status column, beside the Auto-renew switch, it had some
    90 px and the cause ran to twenty lines."""
    context = browser_page.context.browser.new_context(viewport={'width': 390, 'height': 844})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    try:
        _serve(page, {'cert': _cert(FAILED), 'after': _cert(FAILED)}, {'status': 'failed'})
        page.goto(BASE_URL, wait_until='networkidle')
        page.wait_for_selector(f'tr[data-row-domain="{DOMAIN}"]', state='visible')
        page.evaluate(f"openCertDetail('{DOMAIN}')")
        page.wait_for_selector('#certDetailContent [data-last-renewal-failed]', state='visible', timeout=5000)
        widths = page.evaluate("""() => {
            const block = document.querySelector('#certDetailContent [data-last-renewal-failed]');
            const banner = document.querySelector('#certDetailContent > div > div');
            return {block: block.offsetWidth, banner: banner.clientWidth};
        }""")
    finally:
        page.unroute_all(behavior='ignoreErrors')
        context.close()

    # Layout widths, not boxes: the dialog scales in as it opens. The
    # banner's padding is 16 px a side; the block fills the rest.
    assert widths['block'] >= widths['banner'] - 32 - 1, widths


@pytest.fixture
def usable_ca(docker_container, ui_session_cookie):
    """The form refuses to submit while no CA is usable (#1045)."""
    import requests
    session = requests.Session()
    session.cookies.set("certmate_session", ui_session_cookie)
    session.headers["Origin"] = _API_URL
    url = f"{_API_URL}/api/web/settings"
    before = session.get(url).json().get("email") or ""
    assert session.post(url, json={"email": TEST_EMAIL}).ok
    yield
    assert session.post(url, json={"email": before}).ok


def test_a_failed_create_names_the_ca_it_asked_for(page, usable_ca):
    page.route('**/api/certificates/jobs', lambda route: _json(route, {'count': 0, 'jobs': []}))
    page.route('**/api/certificates/create', lambda route: _json(
        route, {'job_id': 'c1', 'status': 'queued', 'operation': 'create', 'domain': 'new.example.test',
                'status_url': '/api/certificates/jobs/c1'}, status=202))
    page.route('**/api/certificates/jobs/c1', lambda route: _json(
        route, {'job_id': 'c1', 'domain': 'new.example.test', 'operation': 'create', 'status': 'failed',
                'error': ERROR, 'error_code': 'CERTIFICATE_CREATION_FAILED', 'hint': None}))
    page.goto(BASE_URL, wait_until='networkidle')
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.fill('#domain', 'new.example.test')
    # Private CA, as the person in the audit chose it; added if this instance
    # has none configured, since only the request body matters here.
    page.evaluate("""() => {
        const select = document.getElementById('ca_provider_select');
        if (![...select.options].some(o => o.value === 'private_ca')) select.add(new Option('Private CA', 'private_ca'));
        select.value = 'private_ca';
    }""")
    page.click('#createCertForm button[type="submit"]')

    page.wait_for_selector('tr[data-pending-job="c1"]', timeout=15000)
    page.wait_for_function("() => document.querySelector('[data-pending-job=\"c1\"]').innerText.includes('Failed')",
                           timeout=15000)
    row = page.inner_text('tr[data-pending-job="c1"]')
    assert 'Private CA' in row, row
