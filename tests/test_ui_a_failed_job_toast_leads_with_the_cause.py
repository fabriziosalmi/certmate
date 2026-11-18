"""The toast of a failed background job leads with the error's own cause, and
the hint follows it.

UX perception audit, 2026-11-18: the toast read `hint || error`. A renewal or
a reissue whose error no rule knows has the hint "The previous certificate is
still in place.", so its toast said that and nothing about why it failed. The
toast now says the error's cause line, then the hint. The server side
is tests/test_a_failed_renewal_says_the_old_certificate_stays.py; here the job
answers are given in the browser (page.route), as in
tests/test_ui_a_failed_job_shows_what_to_check.py.
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
KEPT = 'The previous certificate is still in place.'
DNS_ACCOUNT_HINT = ("The DNS provider account this certificate uses is no longer configured. "
                    "Re-add it in Settings → DNS, then retry the renewal. " + KEPT)


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _toast_after_failure(page, operation, error, hint):
    domain = 'toast.example.test'

    def listing(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps(
            {'count': 1, 'jobs': [{'job_id': 'j1', 'domain': domain, 'operation': operation,
                                   'status': 'running'}]}))

    def one(route):
        route.fulfill(status=200, content_type='application/json', body=json.dumps(
            {'job_id': 'j1', 'domain': domain, 'operation': operation, 'status': 'failed',
             'error': error, 'error_code': 'X', 'hint': hint}))
    page.route('**/api/certificates/jobs', listing)
    page.route('**/api/certificates/jobs/j1', one)
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_function(
        "d => document.getElementById('cm-toasts') && document.getElementById('cm-toasts').innerText.includes(d)",
        arg=domain, timeout=15000)
    return page.inner_text('#cm-toasts')


@pytest.mark.parametrize('operation,lead', [('renew', 'Certificate renewal failed for'),
                                            ('reissue', 'Certificate reissue failed for')])
def test_an_error_no_rule_knows_shows_its_text_in_the_toast(page, operation, lead):
    toast = _toast_after_failure(page, operation, 'Renewal failed: something no rule knows\nmore output', KEPT)
    assert lead in toast, toast
    assert 'something no rule knows' in toast, toast
    assert KEPT in toast, toast
    assert 'more output' not in toast, toast


def test_a_known_cause_shows_the_cause_and_then_the_hint(page):
    error = "DNS provider 'cloudflare' account 'default' not configured"
    toast = _toast_after_failure(page, 'renew', error, DNS_ACCOUNT_HINT)
    assert error in toast, toast
    assert 'Re-add it in Settings' in toast, toast
    assert toast.index(error) < toast.index('Re-add it in Settings'), toast


def test_certbots_unexpected_error_shows_the_line_that_names_the_cause(page):
    """certbot's first line only announces the cause and ends on a colon; the
    toast shows the line after it."""
    error = ('An unexpected error occurred:\nCannot issue for "x.local": Domain name does not end '
             'with a valid public suffix (TLD)')
    toast = _toast_after_failure(page, 'create', error, None)
    assert 'Domain name does not end with a valid public suffix' in toast, toast


def test_a_refusal_keeps_its_remedy_sentence(page):
    """The cause is not cut at its first sentence: the wildcard refusal's second
    sentence is what to do."""
    error = ('Certificate creation failed: HTTP-01 challenge does not support wildcard domains. '
             'Use DNS-01 instead.')
    toast = _toast_after_failure(page, 'create', error, None)
    assert 'Certificate issuance failed for' in toast, toast
    assert 'does not support wildcard domains. Use DNS-01 instead.' in toast, toast


@pytest.mark.parametrize('first', [
    'certbot exited with code 1 without reporting an error. The last it printed:',
    'certbot was killed by SIGKILL before it reported an error. The last it printed:',
])
def test_certmates_own_exit_line_is_the_cause_not_the_line_after_it(page, first):
    """CertMate's own line for a silent certbot (modules/core/certificates.py)
    ends on a colon too, but it states the cause before it: the toast keeps
    that sentence and not certbot's progress line that follows."""
    error = 'Certificate creation failed: ' + first + '\nRequesting a certificate for x.example.com'
    toast = _toast_after_failure(page, 'create', error, None)
    assert first.split('. ')[0] + '.' in toast, toast
    assert 'Requesting a certificate' not in toast, toast
    assert 'The last it printed' not in toast, toast
