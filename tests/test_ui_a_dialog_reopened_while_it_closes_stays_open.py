"""A dialog reopened while it closes stays open.

The certificate dialog fades out for 200 ms before it is hidden, and closing it
gives the focus back to the row it was opened from. So Escape and then Enter is
all it takes to open it again while the fade is still running, and the timer of
the first close then hid the dialog that had just been opened, emptied it, and
left the focus on nothing.

Whether two keys land inside 200 ms depends on the machine, so the page's
timers are held here: the keys are real, and the time between them is not left
to chance. The control is the same two keys with the fade allowed to finish in
between, which opened the dialog before the fix too.
"""
import datetime
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


def _certificate(domain):
    return {'domain': domain, 'exists': True, 'days_left': 60, 'expiry_date': '2026-12-04 10:00:00',
            'expires_at': '2026-12-04T10:00:00Z', 'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt',
            'auto_renew': True, 'san_domains': [], 'has_private_key': True}


CERTIFICATES = [_certificate('alpha.example.test'), _certificate('beta.example.test')]

DIALOG = """() => ({
    open: !document.getElementById('certDetailPanel').classList.contains('hidden'),
    title: document.getElementById('detailDomain').textContent,
    filled: document.getElementById('certDetailContent').innerHTML.length > 0,
    focus: document.activeElement.hasAttribute('data-detail-close') ? 'the close button'
        : (document.activeElement.getAttribute('data-row-domain') || document.activeElement.tagName),
})"""
OPEN = "() => !document.getElementById('certDetailPanel').classList.contains('hidden')"


@pytest.fixture
def dashboard(browser_page):
    page = browser_page
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); } catch (e) {}")
    page.route('**/api/certificates', lambda route: (
        route.fulfill(status=200, content_type='application/json', body=json.dumps(CERTIFICATES))
        if route.request.method == 'GET' else route.continue_()))
    start = datetime.datetime(2026, 10, 6, 12, 0, 0)
    page.clock.install(time=start)
    page.goto(f'{BASE_URL}/', wait_until="networkidle")
    row = page.locator('tr[data-row-domain="alpha.example.test"]')
    row.locator('td').first.click()
    page.wait_for_function(OPEN)
    page.clock.run_for(1000)                    # the dialog has finished opening
    page.wait_for_function("() => document.getElementById('certDetailContent').innerHTML.length > 0")
    # From here the page's timers run only when the test says so.
    page.clock.pause_at(start + datetime.timedelta(hours=1))
    return page


def test_enter_right_after_escape_opens_the_dialog_and_it_stays(dashboard):
    page = dashboard
    page.keyboard.press('Escape')
    # Closing gave the focus back to the row, and the dialog is still fading.
    assert page.evaluate(DIALOG) == {
        'open': True, 'title': 'alpha.example.test', 'filled': True, 'focus': 'alpha.example.test'}
    page.keyboard.press('Enter')
    page.clock.run_for(1000)                    # the fade of the first close, and more
    assert page.evaluate(DIALOG) == {
        'open': True, 'title': 'alpha.example.test', 'filled': True, 'focus': 'the close button'}

    # And it still closes: the reopening did not leave it unable to.
    page.keyboard.press('Escape')
    page.clock.run_for(1000)
    assert page.evaluate(DIALOG)['open'] is False


def test_closing_twice_and_reopening_leaves_no_close_behind(dashboard):
    """Two closes inside the fade (Escape, then the backdrop) are two timers,
    and the one that is not remembered must not outlive the reopening."""
    page = dashboard
    page.keyboard.press('Escape')
    page.mouse.click(6, 6)                      # the backdrop is still there for 200 ms
    page.locator('tr[data-row-domain="alpha.example.test"]').press('Enter')
    page.clock.run_for(1000)
    state = page.evaluate(DIALOG)
    assert (state['open'], state['filled'], state['focus']) == (True, True, 'the close button'), state


def test_control_the_same_keys_with_the_fade_finished_in_between(dashboard):
    page = dashboard
    page.keyboard.press('Escape')
    page.clock.run_for(1000)
    assert page.evaluate(DIALOG)['open'] is False
    assert page.evaluate(DIALOG)['focus'] == 'alpha.example.test'
    page.keyboard.press('Enter')
    page.clock.run_for(1000)
    assert page.evaluate(DIALOG) == {
        'open': True, 'title': 'alpha.example.test', 'filled': True, 'focus': 'the close button'}
