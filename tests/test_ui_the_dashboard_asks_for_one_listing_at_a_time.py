"""The dashboard asks for one certificate listing at a time (#1463, the dashboard's part).

On an estate of about 2,000 certificates `GET /api/certificates` takes 2 to 15
seconds alone, and four overlapping listings took about 168 seconds each. The
dashboard asks for a listing after every action, every live event and every
click on refresh, without waiting for the one in flight, so a single browser
held up to five at once and with them every gunicorn thread: `/health` stopped
answering and Docker marked the container unhealthy.

Now a call made while a listing is in flight shares one listing queued behind
it, started when the current one ends. Queued rather than reused: the call
usually follows a change, which the listing already in flight may have read
too early. The server's side of the issue (overlapping listings that do not
share the work) is separate.

The page's own fetch is wrapped to hold each listing's answer for 400 ms and
record when each one started and ended; the listing itself is the real one.
"""
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

# Every listing the page asks for, held 400 ms; `fail` answers the next one 500.
INSTRUMENT = """() => {
    window.__listings = [];
    window.__failNext = false;
    const real = window.fetch;
    window.fetch = function (url, options) {
        if (url !== '/api/certificates') return real.apply(this, arguments);
        const record = { started: performance.now(), ended: null };
        window.__listings.push(record);
        const fail = window.__failNext;
        window.__failNext = false;
        const answer = fail ? Promise.resolve(new Response('{}', { status: 500 }))
                            : real.call(this, url, options);
        return answer.then((response) => new Promise((resolve) => setTimeout(() => {
            record.ended = performance.now();
            resolve(response);
        }, 400)));
    };
}"""


@pytest.fixture
def dashboard(browser_page):
    page = browser_page
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.wait_for_function("() => typeof window.loadCertificates === 'function'")
    page.evaluate(INSTRUMENT)
    return page


def test_overlapping_calls_make_two_listings_not_six(dashboard):
    count = dashboard.evaluate("""async () => {
        const calls = [];
        for (let i = 0; i < 6; i++) calls.push(window.loadCertificates());
        await Promise.all(calls);
        return window.__listings.length;
    }""")
    assert count == 2, f'{count} listings for 6 overlapping calls'


def test_a_call_made_during_a_listing_gets_a_listing_started_after_it(dashboard):
    """The queued listing must not overlap the one in flight, and must start
    after the call that asked for it, or a refresh after a change could show
    the state from before the change."""
    seen = dashboard.evaluate("""async () => {
        const first = window.loadCertificates();
        await new Promise((r) => setTimeout(r, 100));
        const calledAt = performance.now();
        const second = window.loadCertificates();
        await Promise.all([first, second]);
        return { calledAt, listings: window.__listings };
    }""")
    first, second = seen['listings']
    assert second['started'] >= first['ended'], seen
    assert second['started'] >= seen['calledAt'], seen


def test_a_failed_listing_does_not_hold_the_next_one(dashboard):
    """The first listing answers 500: the one queued behind it still runs, and
    a later call starts its own."""
    count = dashboard.evaluate("""async () => {
        window.__failNext = true;
        await Promise.all([window.loadCertificates(), window.loadCertificates()]);
        await window.loadCertificates();
        return window.__listings.length;
    }""")
    assert count == 3, f'{count} listings, expected the failed one, the queued one and a later one'


def test_calls_one_after_another_each_get_their_own_listing(dashboard):
    """CONTROL: nothing is cached. A call made after the previous listing has
    ended asks the server again."""
    count = dashboard.evaluate("""async () => {
        for (let i = 0; i < 3; i++) await window.loadCertificates();
        return window.__listings.length;
    }""")
    assert count == 3
