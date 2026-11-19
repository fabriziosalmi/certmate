"""A certificate that failed at production Let's Encrypt suggests testing with
staging first, and says how; no other certificate does.

UX perception audit, 2026-11-18 (P22): a newcomer's first certificate goes to
production Let's Encrypt, whose limits count failed attempts, and nothing on
the way says a test mode exists. Decided: no wizard change and no new default,
only a hint on a failed certificate whose CA is production Let's Encrypt, on
the failed row and in the detail panel's last renewal.

Production Let's Encrypt is `ca_provider` "letsencrypt" without `staging`: a
certificate from before 2.12.0 records Let's Encrypt staging as "letsencrypt"
with that flag, and one with no recorded CA is not known to be either. A
failed create names the CA it went to in its job, the instance default when
the request named none (tests/test_a_job_and_a_certificate_say_which_ca_they_went_to.py).
The answers are given in the browser (page.route), as in
tests/test_ui_a_failed_renewal_stays_one_row.py.
"""
import datetime
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
DOMAIN = 'shop.first-run.example.test'
NEW = 'new.first-run.example.test'
ERROR = ("Certificate renewal failed: Some challenges have failed.\n"
         "Detail: DNS problem: NXDOMAIN looking up TXT for _acme-challenge.shop.first-run.example.test")


def _stamp(delta):
    return (datetime.datetime.now(datetime.UTC) + delta).strftime('%Y-%m-%dT%H:%M:%SZ')


FAILED = {'attempted_at': _stamp(-datetime.timedelta(minutes=2)), 'outcome': 'failed',
          'error': ERROR, 'hint': 'The previous certificate is still in place.'}


def _cert(ca_provider, staging=False, attempt=FAILED):
    expires = datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=20)
    return {
        'domain': DOMAIN, 'host': DOMAIN, 'ip_address': None, 'exists': True, 'days_left': 20,
        'days_until_expiry': 20, 'seconds_left': 20 * 86400, 'expired': False,
        'needs_renewal': True, 'usable': True, 'private_key_present': True,
        'private_key_state': 'present', 'reissue_required': False, 'external': False,
        'expiry_date': expires.strftime('%Y-%m-%d %H:%M:%S'), 'expires_at': _stamp(datetime.timedelta(days=20)),
        'expiry_status': 'warning', 'dns_provider': 'cloudflare', 'ca_provider': ca_provider,
        'staging': staging, 'challenge_type': 'dns-01', 'san_domains': [], 'auto_renew': True, 'tags': [],
        'notes': None, 'renewal_info': None, 'renews_at': _stamp(-datetime.timedelta(days=10)),
        'acme_profile': None, 'acme_profile_withdrawn_at': None, 'imported_at': None, 'renewed_at': None,
        'last_renewal_attempt': attempt,
    }


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


def _serve(page, certs, job=None):
    page.route('**/api/certificates', lambda route: _json(route, certs)
               if route.request.method == 'GET' else route.continue_())
    jobs = [{'job_id': 'c1', 'domain': NEW, 'operation': 'create', 'status': 'running'}] if job is not None else []
    page.route('**/api/certificates/jobs', lambda route: _json(route, {'count': len(jobs), 'jobs': jobs}))
    if job is not None:
        page.route('**/api/certificates/jobs/c1', lambda route: _json(route, {
            'job_id': 'c1', 'domain': NEW, 'operation': 'create', 'status': 'failed',
            'error': 'Certificate creation failed: urn:ietf:params:acme:error:dns', 'error_code':
            'CERTIFICATE_CREATION_FAILED', 'hint': None, **job}))


def _open(page, certs, job=None):
    _serve(page, certs, job)
    page.goto(BASE_URL, wait_until='networkidle')
    if certs:
        page.wait_for_selector(f'tr[data-row-domain="{DOMAIN}"]', state='visible')


def _detail(page):
    page.evaluate(f"openCertDetail('{DOMAIN}')")
    page.wait_for_selector('#certDetailContent dl', timeout=5000)
    return page.locator('#certDetailContent')


ROW = f'tr[data-row-domain="{DOMAIN}"]'


def test_a_failed_production_letsencrypt_renewal_suggests_staging_on_the_row_and_in_the_panel(page):
    _open(page, [_cert('letsencrypt')])
    assert 'Test with staging first' in page.inner_text(f'{ROW} [data-staging-hint]')

    detail = _detail(page)
    hint = detail.locator('[data-staging-hint]')
    text = hint.inner_text()
    assert 'Test with staging first' in text, text
    # The control it names, and what a staging certificate is.
    assert "Let's Encrypt (Staging)" in text and 'Certificate Authority' in text, text
    assert 'not trusted by browsers' in text, text
    assert 'Add CA Account' in text, text
    assert hint.locator('a[href="/settings#ca"]').count() == 1


@pytest.mark.parametrize('ca_provider, staging', [
    ('letsencrypt_staging', True),
    # Before 2.12.0: Let's Encrypt staging was recorded as letsencrypt with the flag.
    ('letsencrypt', True),
    ('zerossl', False),
    ('private_ca', False),
    # No recorded CA: not known to be production Let's Encrypt.
    (None, False),
])
def test_a_failed_renewal_elsewhere_than_production_letsencrypt_says_nothing_of_staging(page, ca_provider, staging):
    _open(page, [_cert(ca_provider, staging)])
    page.wait_for_selector(f'{ROW} [data-renewal-failed]', timeout=5000)
    assert page.locator(f'{ROW} [data-staging-hint]').count() == 0
    detail = _detail(page)
    assert 'Last renewal failed' in detail.inner_text()
    assert detail.locator('[data-staging-hint]').count() == 0


def test_a_production_letsencrypt_certificate_that_did_not_fail_says_nothing_of_staging(page):
    """CONTROL: the hint is about a failure, not about the CA."""
    _open(page, [_cert('letsencrypt', attempt=None)])
    assert page.locator(f'{ROW} [data-staging-hint]').count() == 0
    assert _detail(page).locator('[data-staging-hint]').count() == 0


def test_a_failed_create_that_went_to_production_letsencrypt_suggests_staging(page):
    # The request named no CA: the job says the default it went to.
    _open(page, [], job={'ca_provider': 'letsencrypt'})
    row = '[data-pending-job="c1"]'
    page.wait_for_selector(f'{row} [data-staging-hint]', timeout=15000)
    text = page.inner_text(f'{row} [data-staging-hint]')
    assert 'Test with staging first' in text and 'not trusted by browsers' in text, text


@pytest.mark.parametrize('job', [{'ca_provider': 'letsencrypt_staging'}, {'ca_provider': 'zerossl'},
                                 # A job from before 2.72 does not say.
                                 {}])
def test_a_failed_create_elsewhere_says_nothing_of_staging(page, job):
    _open(page, [], job=job)
    row = '[data-pending-job="c1"]'
    page.wait_for_function(f"() => (document.querySelector('{row}') || {{}}).innerText?.includes('Failed')",
                           timeout=15000)
    assert page.locator(f'{row} [data-staging-hint]').count() == 0
