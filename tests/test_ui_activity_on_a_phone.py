"""On a phone, an Activity row shows the whole name of what it is about, and
who and when in text that can be read.

UX perception audit, 2026-11-18 (#1511, P30): at 360 px the resource line had
106 px for names that need 202 to 570, so every row read "Certificate: sit…",
four in a row, all at the same time, all by admin: they could not be told
apart. The absolute time and the actor were 10 px text in a column that never
gave up its width, and the header controls stacked raggedly beside the
breadcrumb.

Below sm the absolute date is left out (the relative time stays, and the
detail dialog has the exact moment), the actor moves under the resource line,
the name wraps to two lines, and the header stacks: breadcrumb, a full-width
search, then the selects.

/api/activity is answered in the browser (page.route).
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

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
NOW = datetime.now(UTC).isoformat()
# Measured at 360 px: the name has 248 px a line, and "Certificate: " plus a
# 48-character name fills two lines.
NAMES = [
    'site0.example.test',
    'payments-gateway.eu-west.internal.example.com',
    'checkout.payments.eu-west-1.internal.example.com',
    'mail.example.org',
]
# Longer than two lines hold at 360 px: it ends in an ellipsis, whole in the title.
LONG = 'a-much-longer-name-for-the-checkout-service.payments.eu-west-1.internal.example.com'


@pytest.fixture
def phone(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(
        viewport={'width': 360, 'height': 740}, is_mobile=True, has_touch=True)
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.emulate_media(reduced_motion='reduce')
    entries = [{'timestamp': NOW, 'operation': 'renew', 'resource_type': 'certificate',
                'resource_id': name, 'status': 'success', 'user': 'admin',
                'details': {}, 'error': None} for name in [*NAMES, LONG]]

    def answer(route):
        return route.fulfill(status=200, content_type='application/json',
                             body=json.dumps({'entries': entries, 'limit': 100, 'complete': True}))

    page.route('**/api/activity?*', answer)
    page.goto(f'{BASE_URL}/activity', wait_until='networkidle')
    page.wait_for_selector('#activityList [data-entry-index]')
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def test_each_row_shows_the_whole_name_in_at_most_two_lines(phone):
    seen = phone.evaluate("""() => Array.from(
        document.querySelectorAll('#activityList [data-entry-index] .min-w-0 > p:first-of-type')
    ).map(p => {
        const lineHeight = parseFloat(getComputedStyle(p).lineHeight);
        return {text: p.textContent, scrollWidth: p.scrollWidth, clientWidth: p.clientWidth,
                scrollHeight: p.scrollHeight, clientHeight: p.clientHeight,
                lines: Math.round(p.getBoundingClientRect().height / lineHeight)};
    })""")
    assert len(seen) == len(NAMES) + 1, seen
    for row, name in zip(seen[:-1], NAMES, strict=True):
        assert name in row['text'], row
        assert row['scrollWidth'] <= row['clientWidth'], f'the name is cut sideways: {row}'
        assert row['scrollHeight'] <= row['clientHeight'] + 1, f'the name is cut below: {row}'
        assert row['lines'] <= 2, f'the name takes more than two lines: {row}'


def test_a_name_longer_than_two_lines_stops_at_two_and_is_whole_in_the_title(phone):
    row = phone.evaluate("""() => {
        const p = Array.from(document.querySelectorAll(
            '#activityList [data-entry-index] .min-w-0 > p:first-of-type')).pop();
        const lineHeight = parseFloat(getComputedStyle(p).lineHeight);
        return {title: p.title, scrollWidth: p.scrollWidth, clientWidth: p.clientWidth,
                lines: Math.round(p.getBoundingClientRect().height / lineHeight)};
    }""")
    assert row['lines'] == 2, row
    assert row['scrollWidth'] <= row['clientWidth'], row
    assert LONG in row['title'], row


def test_who_did_it_is_on_screen_in_each_row(phone):
    width = phone.evaluate('() => document.documentElement.clientWidth')
    rows = phone.locator('#activityList [data-entry-index]')
    for i in range(rows.count()):
        who = rows.nth(i).get_by_text('admin', exact=True).locator('visible=true')
        assert who.count() == 1, f'row {i} does not show who acted'
        box = who.first.bounding_box()
        assert box['x'] >= 0 and box['x'] + box['width'] <= width, box


def test_no_text_of_the_log_is_smaller_than_12_px(phone):
    small = phone.evaluate("""() => {
        const out = [];
        const page = document.getElementById('activityList').closest('.max-w-7xl');
        for (const el of page.querySelectorAll('*')) {
            const own = Array.from(el.childNodes).some(n => n.nodeType === 3 && n.textContent.trim());
            if (!own || !el.getClientRects().length) continue;
            const style = getComputedStyle(el);
            if (style.visibility === 'hidden') continue;
            const size = parseFloat(style.fontSize);
            if (size < 12) out.push([el.tagName, el.className, el.textContent.trim().slice(0, 40), size]);
        }
        return out;
    }""")
    assert not small, f'text under 12 px: {small}'


def test_the_header_stacks_with_a_full_width_search(phone):
    seen = phone.evaluate("""() => {
        const search = document.getElementById('filterSearch').getBoundingClientRect();
        const crumb = document.querySelector('nav[aria-label="Breadcrumb"]').getBoundingClientRect();
        const op = document.getElementById('filterOp').getBoundingClientRect();
        const box = document.getElementById('filterSearch').closest('.border-b');
        const style = getComputedStyle(box);
        const inner = box.clientWidth - parseFloat(style.paddingLeft) - parseFloat(style.paddingRight);
        return {search: search.width, inner, searchTop: search.top, crumbBottom: crumb.bottom,
                opTop: op.top, searchBottom: search.bottom};
    }""")
    assert seen['search'] >= seen['inner'] - 1, f'the search is not full width: {seen}'
    assert seen['searchTop'] >= seen['crumbBottom'] - 1, f'the search is beside the breadcrumb: {seen}'
    assert seen['opTop'] >= seen['searchBottom'] - 1, f'the selects are beside the search: {seen}'
