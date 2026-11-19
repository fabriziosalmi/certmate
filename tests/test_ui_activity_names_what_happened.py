"""Activity says what happened: a hook test is a test, a client certificate is
named by its name, and a download says whether it carried the key.

UX perception audit, 2026-11-18 (#1511).

P41: one press of Test on a hook that exits 1 was listed as "Deploy hook ran
FAILED, Certificate: test.example.com" with the red failure icon: a dry run
read as a real failed deploy of a certificate that does not exist, and
`dry_run` was only in the raw JSON.

P24: Activity now records client certificates created, revoked and renewed,
and every download. The rows have to say it: a client certificate by its
common name, a download with what was taken and whether it carried the
private key, and the Revoked and Downloaded filters have to find them.

/api/activity is answered in the browser (page.route) with entries of the
shape the server writes (tests/test_activity_records_client_certificates_and_downloads.py
and tests/test_a_hook_test_is_recorded_as_what_it_was.py hold the server to it).
"""
import json
import os
from datetime import UTC, datetime

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

from playwright.sync_api import expect

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
NOW = datetime.now(UTC).isoformat()


def _entry(**fields):
    entry = {'timestamp': NOW, 'status': 'success', 'user': 'admin', 'ip_address': '127.0.0.1',
             'details': {}, 'error': None, 'actor': {'kind': 'user', 'label': 'admin'},
             'trigger': {'cause': 'manual'}}
    entry.update(fields)
    return entry


ENTRIES = [
    _entry(operation='deploy_hook', resource_type='certificate', resource_id='test.example.com',
           status='failure', error='exit code 1',
           details={'hook_name': 'reload nginx', 'hook_id': 'h1', 'exit_code': 1,
                    'duration_ms': 12, 'dry_run': True, 'stdout': '', 'stderr': ''}),
    _entry(operation='deploy_hook', resource_type='certificate', resource_id='shop.example.com',
           status='failure', error='exit code 2',
           details={'hook_name': 'push to lb', 'hook_id': 'h2', 'exit_code': 2,
                    'duration_ms': 12, 'dry_run': False, 'stdout': '', 'stderr': ''}),
    _entry(operation='revoke', resource_type='client_certificate', resource_id='laptop-anna-1a2b3c4d',
           user='bob', details={'reason': 'keyCompromise', 'common_name': 'laptop-anna'}),
    _entry(operation='download', resource_type='certificate', resource_id='payments.example.com',
           user='carol', details={'file_type': 'zip', 'private_key': True}),
    _entry(operation='download', resource_type='client_certificate', resource_id='laptop-anna-1a2b3c4d',
           user='dave', details={'file_type': 'crt', 'private_key': False}),
]


@pytest.fixture
def activity(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.emulate_media(reduced_motion='reduce')

    def answer(route):
        return route.fulfill(status=200, content_type='application/json',
                             body=json.dumps({'entries': ENTRIES, 'limit': 100, 'complete': True}))

    page.route('**/api/activity?*', answer)
    page.goto(f'{BASE_URL}/activity', wait_until='networkidle')
    page.wait_for_selector('#activityList [data-entry-index]')
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _row(page, text):
    return page.locator('#activityList [data-entry-index]', has_text=text)


def test_a_hook_test_reads_as_a_dry_run_of_the_hook_not_a_failed_deploy(activity):
    row = _row(activity, 'reload nginx')
    assert row.count() == 1, 'the hook test row does not name the hook'
    text = row.inner_text()
    assert 'Hook test' in text, text
    assert 'dry run' in text.lower(), text
    assert 'Certificate: test.example.com' not in text, text
    # Its outcome is still there, in words, not as the red failure icon.
    assert 'failed' in text.lower(), text
    assert row.locator('.fa-exclamation-circle').count() == 0, 'a dry run wears the red failure icon'
    assert row.locator('.bg-danger-surface').count() == 0, 'a dry run wears the red FAILED badge'


def test_a_real_failed_deploy_still_reads_as_one(activity):
    """CONTROL: the dry-run styling must not reach a real deploy."""
    row = _row(activity, 'shop.example.com')
    text = row.inner_text()
    assert 'Deploy hook ran' in text and 'FAILED' in text, text
    assert row.locator('.fa-exclamation-circle').count() == 1


def test_a_hook_test_does_not_offer_a_certificate_that_is_not_there(activity):
    _row(activity, 'reload nginx').click()
    actions = activity.locator('#activityDetailActions')
    actions.wait_for(state='visible')
    assert actions.get_by_text('View certificate').count() == 0, (
        'the detail of a hook test links to test.example.com, which is not a certificate')
    assert 'dry run' in activity.locator('#activityDetailTitle').inner_text().lower()
    activity.keyboard.press('Escape')


def test_the_revoked_filter_shows_the_client_certificate_by_its_name_and_who(activity):
    activity.select_option('#filterOp', 'revoke')
    expect(activity.locator('#activityList [data-entry-index]')).to_have_count(1)
    text = activity.locator('#activityList [data-entry-index]').inner_text()
    assert 'Client certificate: laptop-anna' in text, text
    assert 'bob' in text, text


def test_the_downloaded_filter_says_who_took_what_and_whether_it_carried_the_key(activity):
    activity.select_option('#filterOp', 'download')
    expect(activity.locator('#activityList [data-entry-index]')).to_have_count(2)
    server = _row(activity, 'payments.example.com').inner_text()
    assert 'carol' in server and 'with the private key' in server, server
    client = _row(activity, 'Client certificate: laptop-anna').inner_text()
    assert 'dave' in client and 'no private key' in client, client
