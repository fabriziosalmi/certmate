"""The dashboard shows what to check when a background issuance fails.

The server side is tests/test_a_failed_job_says_what_to_check.py. Here the
job answers are given in the browser (page.route): a job the page adopts at
load, which then fails with a hint. The toast carries the hint after the
error's first sentence (tests/test_ui_a_failed_job_toast_leads_with_the_cause.py),
and the failed row carries it under the error.
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
HINT = ("CertMate could not reach the CA's ACME directory at https://127.0.0.1:9/directory: "
        "check the directory URL, that its name resolves from this host, and that outbound HTTPS to it is allowed.")
ERROR = "Certificate creation failed: requests.exceptions.ConnectionError: HTTPSConnectionPool(...)"


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _jobs(page, failed):
    def listing(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps(
            {'count': 1, 'jobs': [{'job_id': 'j1', 'domain': 'hint.example.test', 'operation': 'create',
                                   'status': 'running'}]}))

    def one(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps(failed))
    page.route('**/api/certificates/jobs', listing)
    page.route('**/api/certificates/jobs/j1', one)


def test_the_toast_and_the_row_say_what_to_check(page):
    _jobs(page, {'job_id': 'j1', 'domain': 'hint.example.test', 'operation': 'create', 'status': 'failed',
                 'error': ERROR, 'error_code': 'CERTIFICATE_CREATION_FAILED', 'hint': HINT})
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_selector('[data-pending-job="j1"] [data-failure-hint]', timeout=15000)
    assert page.inner_text('[data-pending-job="j1"] [data-failure-hint]') == HINT
    assert page.locator(f'text={HINT[:60]}').count() >= 2, 'the toast does not carry the hint'


def test_a_failure_with_no_hint_shows_the_error_as_before(page):
    """CONTROL: a job from before 2.67, or a renewal, has no hint."""
    _jobs(page, {'job_id': 'j1', 'domain': 'hint.example.test', 'operation': 'create', 'status': 'failed',
                 'error': ERROR, 'error_code': None})
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_selector('[data-pending-job="j1"]', timeout=15000)
    page.wait_for_function("() => document.querySelector('[data-pending-job=\"j1\"]').innerText.includes('Failed')")
    assert page.locator('[data-pending-job="j1"] [data-failure-hint]').count() == 0
