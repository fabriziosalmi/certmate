"""On a phone a client certificate can be revoked or renewed without hunting
for a sideways scroll.

UX perception audit, 2026-11-18 (P10): at 390 px the client list kept four
columns (name, expiry, status, actions), wider than the screen, so the Status
and the Revoke and Renew buttons were past the right edge of a scroll box that
shows no scrollbar until it is dragged. The detail dialog a tap opened offered
downloads only. Below md the status now reads under the name and the Status
and Actions columns are left out; the dialog has labelled Renew and Revoke
buttons.

The list and the two endpoints are answered in the browser (page.route), so
nothing is issued or revoked on the instance.
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
CN = 'alice.vpn.example.test'


@pytest.fixture
def phone(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(
        viewport={'width': 390, 'height': 844}, is_mobile=True, has_touch=True)
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.emulate_media(reduced_motion='reduce')
    page.posted = []

    def answer(route):
        url = route.request.url.split('?')[0]
        method = route.request.method
        if method == 'GET' and url.endswith('/api/client-certs'):
            body = {'certificates': [{
                'identifier': 'cc-alice', 'common_name': CN, 'email': 'alice@example.test',
                'cert_usage': 'vpn', 'created_at': '2026-10-01T10:00:00Z',
                'expires_at': '2027-10-01T10:00:00Z', 'revoked': False}]}
        elif method == 'GET' and url.endswith('/api/client-certs/stats'):
            body = {'total': 1, 'active': 1, 'revoked': 0, 'by_usage': {'vpn': 1}}
        elif method == 'POST' and url.endswith(('/renew', '/revoke')) and '/api/client-certs/' in url:
            page.posted.append(url.split('/api/client-certs/')[1])
            body = {'success': True}
        else:
            return route.continue_()
        return route.fulfill(status=200, content_type='application/json', body=json.dumps(body))

    page.route('**/api/**', answer)
    page.goto(f'{BASE_URL}/#client', wait_until='networkidle')
    page.wait_for_selector('#certTableBody tr[data-cc-id="cc-alice"]')
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _within_the_screen(page, locator):
    box = locator.bounding_box()
    width = page.evaluate('() => document.documentElement.clientWidth')
    return box is not None and box['x'] >= 0 and box['x'] + box['width'] <= width, (box, width)


def test_the_client_list_fits_the_phone_and_says_the_status_under_the_name(phone):
    page = phone
    scroll = page.evaluate("""() => { const box = document.getElementById('clientCertificatesTable');
        return [box.scrollWidth, box.clientWidth]; }""")
    assert scroll[0] <= scroll[1], f'the client list scrolls sideways on a phone [content, box]: {scroll}'
    row = page.locator('#certTableBody tr[data-cc-id="cc-alice"]')
    status = row.locator('text=Active').locator('visible=true')
    assert status.count() == 1, 'the status is not on screen in the row'
    fits, seen = _within_the_screen(page, status.first)
    assert fits, f'the status is past the edge: {seen}'
    name = row.get_by_role('button', name=f'View details for {CN}').bounding_box()
    assert status.first.bounding_box()['y'] > name['y'], 'the status is not under the name'


def test_the_detail_dialog_renews_on_a_phone(phone):
    page = phone
    page.get_by_role('button', name=f'View details for {CN}').tap()
    dialog = page.locator('#certModal')
    renew = dialog.get_by_role('button', name='Renew', exact=True)
    renew.wait_for(state='visible')
    fits, seen = _within_the_screen(page, renew)
    assert fits, f'Renew is past the edge: {seen}'
    renew.tap()
    page.wait_for_function("() => document.getElementById('certModal').classList.contains('hidden')")
    assert page.posted == ['cc-alice/renew']


def test_the_detail_dialog_revokes_on_a_phone_after_asking(phone):
    page = phone
    page.get_by_role('button', name=f'View details for {CN}').tap()
    dialog = page.locator('#certModal')
    revoke = dialog.get_by_role('button', name='Revoke', exact=True)
    revoke.wait_for(state='visible')
    fits, seen = _within_the_screen(page, revoke)
    assert fits, f'Revoke is past the edge: {seen}'
    revoke.tap()
    asked = page.locator('[role="alertdialog"]')
    asked.wait_for(state='visible')
    assert page.posted == [], 'revoked before the question was answered'
    asked.get_by_role('button', name='Cancel').tap()
    asked.wait_for(state='hidden')
    # Cancelling the question leaves the dialog where it was; so does Escape,
    # which the question owns.
    assert dialog.is_visible()
    revoke.tap()
    asked.wait_for(state='visible')
    # The question takes the focus (its Cancel) a moment after it opens.
    page.wait_for_function(
        "() => document.activeElement && document.activeElement.closest('[role=alertdialog]')")
    page.keyboard.press('Escape')
    asked.wait_for(state='hidden')
    page.wait_for_timeout(300)
    assert dialog.is_visible(), 'Escape on the question also closed the dialog'
    assert page.posted == []
    revoke.tap()
    asked.wait_for(state='visible')
    asked.get_by_role('button', name='Confirm').tap()
    page.wait_for_function("() => document.getElementById('certModal').classList.contains('hidden')")
    assert page.posted == ['cc-alice/revoke']
