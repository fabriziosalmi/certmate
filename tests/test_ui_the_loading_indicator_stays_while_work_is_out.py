"""The loading indicator stays while work is out.

When a request ends, the indicator fills its bar and is hidden half a second
later. A renewal that is refused at once leaves the focus on its button, so
Enter starts another before that half second is over, and the timer of the
first then hid the indicator of the second: the page looked idle with a
renewal out.

The page's timers are held, so the keys are real and the time between them is
not left to the machine. The control is the same two renewals with the half
second allowed to pass in between, which showed the indicator before the fix
too.
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

CERTIFICATE = {'domain': 'alpha.example.test', 'exists': True, 'days_left': 60,
               'expiry_date': '2026-12-04 10:00:00', 'expires_at': '2026-12-04T10:00:00Z',
               'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
               'san_domains': [], 'has_private_key': True}

SHOWN = "() => !document.getElementById('loadingModal').classList.contains('hidden')"
BAR_AT = "() => document.getElementById('progressBar').style.width === '%s'"


@pytest.fixture
def renewing(browser_page):
    """The dashboard with one certificate, its dialog open, and a renewal that
    is refused at once the first time and left without an answer after that."""
    page = browser_page
    asked, out = [], []

    def renew(route):
        asked.append(route)
        if len(asked) == 1:
            route.fulfill(status=400, content_type='application/json',
                          body=json.dumps({'error': 'refused for the test'}))
        else:
            out.append(route)

    page.route('**/api/certificates', lambda route: (
        route.fulfill(status=200, content_type='application/json', body=json.dumps([CERTIFICATE]))
        if route.request.method == 'GET' else route.continue_()))
    page.route('**/api/certificates/*/renew', renew)
    start = datetime.datetime(2026, 10, 6, 12, 0, 0)
    page.clock.install(time=start)
    page.goto(f'{BASE_URL}/', wait_until="networkidle")
    page.locator('tr[data-row-domain="alpha.example.test"] td').first.click()
    button = page.locator('#certDetailPanel button[title="Renew certificate"]')
    button.wait_for()
    page.clock.run_for(1000)
    # From here the page's timers run only when the test says so.
    page.clock.pause_at(start + datetime.timedelta(hours=1))
    button.click()
    page.wait_for_function(BAR_AT % '100%')         # the refusal has been read
    yield page, asked, out
    page.unroute('**/api/certificates/*/renew')
    page.unroute('**/api/certificates')


def test_a_second_renewal_started_at_once_keeps_its_indicator(renewing):
    page, asked, out = renewing
    assert page.evaluate(SHOWN) is True         # the first has ended, and its bar is still filling
    page.keyboard.press('Enter')                # the focus is on the button that was clicked
    page.wait_for_function(BAR_AT % '40%')          # the indicator was shown again
    page.clock.run_for(1000)                    # the half second of the first, and more
    assert (len(asked), len(out)) == (2, 1)     # CONTROL: the second renewal is out
    assert page.evaluate(SHOWN) is True


def test_control_the_same_two_renewals_with_the_half_second_in_between(renewing):
    page, asked, out = renewing
    page.clock.run_for(1000)
    assert page.evaluate(SHOWN) is False        # the first ended, and the indicator went
    page.keyboard.press('Enter')
    page.wait_for_function(BAR_AT % '40%')          # the indicator was shown again
    page.clock.run_for(1000)
    assert (len(asked), len(out)) == (2, 1)
    assert page.evaluate(SHOWN) is True
