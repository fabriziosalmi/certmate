"""One expiry vocabulary across the dashboard, the inventory, the notifications
page and the header.

UX perception audit, 2026-11-18 (#1511, batch B3):

* P25: a renewal that is overdue and one that is only due shared the amber
  "Expiring" chip, the detail called it "Expiring Soon" and the notifications
  page "Critical, renewal overdue" and "Expiring, renewal due". Now they are
  "Overdue" (red) and "Due" (amber) in the row, the detail, the counters, the
  notifications page ("1 overdue · 1 due") and the inventory.
* P23: two certificates with the same days left, one Valid and one not, with
  nothing that said why. The status chip now says when the renewal is due and
  how that relates to the lifetime, and the detail says when the certificate was
  issued and how long it lives.
* P73: the counters in the header did nothing when clicked, the status filter
  was gone after a reload, and site10 sorted before site2.
* P65: the Client and ACME counters painted a zero red or green; the Server
  counters mute it.
* P53: the bell's badge came four seconds after the page.
* P09: the inventory cards counted calendar days while the pills and the filter
  used the renewal rule, so "≤ 7 days 2" filtered to nothing. The cards now
  count by the same rule and each one applies its own filter.

The certificates are built with the server's own rule (modules/core/renewal_policy)
and given to the page through page.route, as in
tests/test_ui_a_failed_renewal_stays_one_row.py; the inventory answer is built by
modules/core/inventory_view.build_inventory_view, the function the API calls.
"""
import datetime
import json
import os
import re
import time

import pytest

from modules.core import inventory_view, renewal_policy
from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
DAY = datetime.timedelta(days=1)
THRESHOLD_DAYS = 30


def _now():
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None, microsecond=0)


def _cert(domain, lifetime, left, threshold=None):
    """A certificate as /api/certificates answers it, its status and renewal
    instant from renewal_policy with the default 30-day threshold (or the one
    given)."""
    threshold = THRESHOLD_DAYS if threshold is None else threshold
    now = _now()
    not_after = now + left
    not_before = not_after - lifetime
    renew_at, _reason = renewal_policy.renews_at(not_before, not_after, threshold)
    seconds_left = int((not_after - now).total_seconds())
    return {
        'domain': domain, 'host': domain, 'ip_address': None, 'exists': True,
        'days_left': seconds_left // 86400, 'days_until_expiry': seconds_left // 86400,
        'seconds_left': seconds_left, 'expired': False, 'needs_renewal': now >= renew_at,
        'usable': True, 'private_key_present': True, 'private_key_state': 'present',
        'reissue_required': False, 'external': False,
        'expiry_date': not_after.strftime('%Y-%m-%d %H:%M:%S'),
        'expires_at': renewal_policy.stamp(not_after),
        'expiry_status': renewal_policy.expiry_status(not_before, not_after, threshold, now, renew_at),
        'not_before': renewal_policy.stamp(not_before), 'renews_at': renewal_policy.stamp(renew_at),
        'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'challenge_type': 'dns-01',
        'san_domains': [], 'auto_renew': True, 'tags': [], 'notes': None, 'renewal_info': None,
        'acme_profile': None, 'acme_profile_withdrawn_at': None, 'imported_at': None,
        'renewed_at': None, 'last_renewal_attempt': None,
    }


# Four days left on a 90-day certificate is overdue; on a 6-day one it is not
# due yet (the renewal comes at half its lifetime). 19 days on 90 is due.
CERTS = [
    _cert('payments.example.test', 90 * DAY, 4 * DAY + datetime.timedelta(hours=1)),
    _cert('ops-api.example.test', 90 * DAY, 19 * DAY + datetime.timedelta(hours=1)),
    _cert('site3.example.test', 6 * DAY, 4 * DAY + datetime.timedelta(hours=1)),
    _cert('site2.example.test', 90 * DAY, 60 * DAY),
    _cert('site10.example.test', 90 * DAY, 60 * DAY),
]


def test_the_seed_is_what_the_tests_say_it_is():
    """CONTROL: the statuses the assertions below rely on come from the rule."""
    status = {c['domain']: c['expiry_status'] for c in CERTS}
    assert status == {'payments.example.test': 'critical', 'ops-api.example.test': 'warning',
                      'site3.example.test': 'ok', 'site2.example.test': 'ok',
                      'site10.example.test': 'ok'}, status
    assert CERTS[0]['days_until_expiry'] == CERTS[2]['days_until_expiry'] == 4


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.route('**/api/certificates', lambda route: _json(route, CERTS)
               if route.request.method == 'GET' else route.continue_())
    page.route('**/api/certificates/jobs', lambda route: _json(route, {'count': 0, 'jobs': []}))
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _json(route, body, status=200):
    route.fulfill(status=status, content_type='application/json', body=json.dumps(body))


def _dashboard(page, query=''):
    page.goto(BASE_URL + '/' + query, wait_until='networkidle')
    page.wait_for_selector('tr[data-row-domain="payments.example.test"]', state='visible')


def _chip(page, domain):
    return page.locator(f'tr[data-row-domain="{domain}"] td').nth(1).locator('span').first


def _open_detail(page, domain):
    page.locator(f'tr[data-row-domain="{domain}"] td').first.click()
    page.wait_for_function(
        f"() => document.getElementById('detailDomain').textContent.trim() === '{domain}'")
    heading = page.locator('#certDetailContent .text-lg.font-semibold').first
    heading.wait_for(state='visible')
    return heading


def _close_detail(page):
    page.keyboard.press('Escape')
    page.wait_for_timeout(400)


# --- P25: two states, two names, the same everywhere ------------------------

def test_an_overdue_renewal_is_red_overdue_and_a_due_one_amber_due_everywhere(page):
    _dashboard(page)

    overdue, due = _chip(page, 'payments.example.test'), _chip(page, 'ops-api.example.test')
    assert overdue.inner_text().strip() == 'Overdue', overdue.inner_text()
    assert due.inner_text().strip() == 'Due', due.inner_text()
    assert 'text-danger-fg' in overdue.get_attribute('class'), overdue.get_attribute('class')
    assert 'text-warning-fg' in due.get_attribute('class'), due.get_attribute('class')

    # The detail's heading starts with the chip's word.
    for domain, word in (('payments.example.test', 'Overdue'), ('ops-api.example.test', 'Due')):
        heading = _open_detail(page, domain).inner_text().strip()
        assert heading.startswith(word + ' · '), (domain, heading)
        _close_detail(page)

    # The header says the same, and each word has its own filter chip.
    tile = page.locator('#statsCards > *').nth(2)
    assert tile.inner_text().split() == ['1', 'OVERDUE'], tile.inner_text()
    assert tile.get_attribute('title') == '1 overdue · 1 due', tile.get_attribute('title')
    assert page.locator('[data-status-count="overdue"]').inner_text() == '1'
    assert page.locator('[data-status-count="due"]').inner_text() == '1'

    # The notifications page: the same two words for its groups and its summary.
    page.goto(BASE_URL + '/notifications', wait_until='networkidle')
    page.wait_for_function("() => document.getElementById('notifContent').getAttribute('aria-busy') === 'false'")
    groups = [t.strip() for t in page.locator('#notifContent h2').all_text_contents()]
    assert groups == ['Renewal overdue (1)', 'Renewal due (1)'], groups
    assert page.locator('#notifSummary').inner_text().strip() == '1 overdue · 1 due'


# --- P23: the same days left, and the reason the status differs -------------

def test_the_same_days_left_says_why_one_is_overdue_and_the_other_valid(page):
    _dashboard(page)

    long_lived, short_lived = _chip(page, 'payments.example.test'), _chip(page, 'site3.example.test')
    assert short_lived.inner_text().strip() == 'Valid'
    titles = {}
    for domain, chip in (('payments.example.test', long_lived), ('site3.example.test', short_lived)):
        cert = next(c for c in CERTS if c['domain'] == domain)
        renews = page.evaluate('(at) => CertMate.formatDate(new Date(at))', cert['renews_at'])
        title = chip.get_attribute('title') or ''
        assert renews in title, (domain, renews, title)
        titles[domain] = title
    assert titles['payments.example.test'] != titles['site3.example.test'], titles
    assert '90-day lifetime' in titles['payments.example.test'], titles
    assert 'half of its 6-day lifetime' in titles['site3.example.test'], titles

    _open_detail(page, 'site3.example.test')
    banner = page.locator('#certDetailContent > div > div').first.inner_text()
    issued = page.evaluate('(at) => CertMate.formatDate(new Date(at))', CERTS[2]['not_before'])
    assert 'Issued ' + issued in banner and '6-day lifetime' in banner, banner


# --- P73: the header counters filter, the filter is in the URL, names sort by number

def _pressed(page):
    return page.evaluate("() => Array.from(document.querySelectorAll('[data-status-chip]'))"
                         ".filter(c => c.getAttribute('aria-pressed') === 'true')"
                         ".map(c => c.getAttribute('data-status-chip'))")


def _shown(page):
    return page.locator('#certificatesList tr[data-row-domain]').count()


def test_a_header_counter_applies_its_filter(page):
    _dashboard(page)

    for index, status, rows in ((1, 'valid', 3), (2, 'overdue', 1), (0, 'all', 5)):
        tile = page.locator('#statsCards > *').nth(index)
        assert tile.evaluate('(el) => el.tagName') == 'BUTTON', tile.evaluate('(el) => el.outerHTML')
        tile.click()
        assert _pressed(page) == [status], (status, _pressed(page))
        assert _shown(page) == rows == int(tile.inner_text().split()[0]), (status, _shown(page))


def test_the_status_filter_survives_a_reload(page):
    _dashboard(page)
    page.click('[data-status-chip="due"]')
    assert re.search(r'[?&]status=due\b', page.url), page.url
    assert _shown(page) == 1

    page.reload(wait_until='networkidle')
    page.wait_for_selector('tr[data-row-domain="ops-api.example.test"]', state='visible')
    assert _pressed(page) == ['due'], _pressed(page)
    assert _shown(page) == 1

    page.click('[data-status-chip="all"]')
    assert 'status=' not in page.url, page.url


def test_names_sort_by_their_numbers(page):
    _dashboard(page)
    order = page.eval_on_selector_all('#certificatesList tr[data-row-domain]',
                                      '(rows) => rows.map(r => r.getAttribute("data-row-domain"))')
    assert order.index('site2.example.test') < order.index('site10.example.test'), order


# --- P65: a zero is muted on every view --------------------------------------

def _counter_colour(page, selector):
    return page.eval_on_selector(selector, '(el) => el.className')


def test_a_zero_is_muted_on_the_client_and_acme_views(page):
    stats = {'total': 2, 'active': 2, 'revoked': 0, 'by_usage': {}}
    page.route('**/api/client-certs/stats', lambda route: _json(route, stats))
    page.goto(BASE_URL + '/#client', wait_until='networkidle')
    page.wait_for_function("() => document.getElementById('totalCount').textContent.trim() === '2'")
    assert 'text-muted' in _counter_colour(page, '#revokedCount')
    assert 'text-danger-fg' not in _counter_colour(page, '#revokedCount')
    assert 'text-success-fg' in _counter_colour(page, '#activeCount')

    stats.update(active=1, revoked=1)
    page.reload(wait_until='networkidle')
    page.wait_for_function("() => document.getElementById('revokedCount').textContent.trim() === '1'")
    assert 'text-danger-fg' in _counter_colour(page, '#revokedCount')
    assert 'text-muted' not in _counter_colour(page, '#revokedCount')

    acme = {'certificates': []}
    page.route('**/api/acme/certificates', lambda route: _json(route, acme))
    page.goto(BASE_URL + '/#acme', wait_until='networkidle')
    strip = page.locator('#acmeStatsCards span.text-lg')
    page.wait_for_function("() => document.querySelector('#acmeStatsCards span.text-lg').textContent.trim() === '0'")
    for i in (1, 2):
        assert strip.nth(i).inner_text() == '0'
        cls = strip.nth(i).get_attribute('class')
        assert 'text-muted' in cls and 'text-success-fg' not in cls and 'text-danger-fg' not in cls, cls


# --- P53: the bell is counted with the list -----------------------------------

def test_the_bell_is_counted_with_the_list(page):
    page.goto(BASE_URL + '/', wait_until='domcontentloaded')
    page.wait_for_selector('tr[data-row-domain="payments.example.test"]', state='visible')
    page.wait_for_selector('#notifBadge', state='visible', timeout=1500)
    badge = page.locator('#notifBadge')
    assert badge.inner_text() == '2'
    assert 'badge-pulse' not in badge.get_attribute('class')

    # Elsewhere it asks at once, not four seconds later.
    page.goto(BASE_URL + '/help', wait_until='load')
    started = time.monotonic()
    page.wait_for_selector('#notifBadge', state='visible', timeout=1500)
    assert page.locator('#notifBadge').inner_text() == '2', time.monotonic() - started


# --- P09: the inventory cards count what their filter shows -------------------

def _record(name, lifetime, left, **more):
    not_after = _now() + left
    return dict({'fingerprint': name, 'subject_cn': name, 'san_dns': [name], 'issuer_cn': 'Test CA',
                 'not_before': (not_after - lifetime).isoformat() + 'Z',
                 'not_after': not_after.isoformat() + 'Z', 'managed': False, 'source': 'probed',
                 'endpoints': [], 'key': {'type': 'EC', 'curve': 'P-256'}}, **more)


INVENTORY = [
    # Short lifetimes with two to four days left: not due by the rule.
    _record('short3.example.test', 3 * DAY, 2 * DAY - datetime.timedelta(hours=8)),
    _record('short5.example.test', 5 * DAY, 3 * DAY),
    _record('short6.example.test', 6 * DAY, 4 * DAY),
    # 90-day certificates: overdue, due and not due.
    _record('overdue.example.test', 90 * DAY, 3 * DAY),
    _record('due.example.test', 90 * DAY, 20 * DAY, managed=True, source='issued'),
    _record('fine.example.test', 90 * DAY, 60 * DAY, managed=True, source='issued'),
    _record('gone.example.test', 90 * DAY, -2 * DAY),
]


def test_each_inventory_card_shows_the_rows_it_counts(page):
    body = inventory_view.build_inventory_view(INVENTORY)
    status = {c['subject_cn']: c['expiry_status'] for c in body['certificates']}
    assert status['short3.example.test'] == 'ok' and status['overdue.example.test'] == 'critical', status
    page.route(re.compile(r'.*/api/inventory(\?.*)?$'), lambda route: _json(route, body))

    page.goto(BASE_URL + '/inventory', wait_until='networkidle')
    page.wait_for_selector('#inventoryBody tr td >> text=short3.example.test')
    cards = page.locator('#summaryCards > button')
    assert cards.count() >= 7, page.locator('#summaryCards').inner_html()

    labels = [cards.nth(i).locator('div').first.inner_text().strip() for i in range(cards.count())]
    assert 'Renewal overdue' in labels and 'Renewal due' in labels, labels
    for label in ('Renewal overdue', 'Renewal due'):
        assert cards.nth(labels.index(label)).get_attribute('title'), label

    seen = {}
    for i in range(cards.count()):
        card = cards.nth(i)
        number = int(card.locator('div').nth(1).inner_text())
        card.click()
        shown = int(page.locator('#invCount').inner_text().split()[0])
        assert shown == number, (labels[i], number, page.locator('#invCount').inner_text())
        seen[labels[i]] = number
        if labels[i] in ('Renewal overdue', 'Renewal due'):
            pills = page.locator('#inventoryBody td.hidden span.rounded-full').evaluate_all(
                '(spans) => spans.map(s => s.className)')
            assert not [p for p in pills if 'green' in p], (labels[i], pills)
    assert seen['Renewal overdue'] == 1 and seen['Renewal due'] == 1, seen


# --- review of this batch: "since" only for a date already past; the bell readable

def _contrast(page, selector):
    """WCAG contrast of an element's text against its own background."""
    return page.evaluate("""(sel) => {
        const el = document.querySelector(sel);
        const s = getComputedStyle(el);
        const rgb = (c) => c.match(/[0-9.]+/g).slice(0, 3).map(Number);
        const lum = (c) => { const [r, g, b] = rgb(c).map((v) => { v /= 255;
            return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); });
            return 0.2126 * r + 0.7152 * g + 0.0722 * b; };
        const a = lum(s.color), b = lum(s.backgroundColor);
        return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
    }""", selector)


def test_an_overdue_certificate_whose_renewal_is_still_ahead_says_no_since(page):
    """With a renewal threshold under 7 days the server calls a certificate
    Overdue before its renews_at; its title said "renewal due since <a future
    date>". It says when it expires and when the renewal is set for."""
    early = _cert('early.example.test', 90 * DAY, 5 * DAY + datetime.timedelta(hours=1), threshold=3)
    assert early['expiry_status'] == 'critical' and early['needs_renewal'] is False, early
    page.unroute('**/api/certificates')
    page.route('**/api/certificates', lambda route: _json(route, [*CERTS, early])
               if route.request.method == 'GET' else route.continue_())
    _dashboard(page)
    title = _chip(page, 'early.example.test').get_attribute('title') or ''
    renews = page.evaluate('(at) => CertMate.formatDate(new Date(at))', early['renews_at'])
    assert title.startswith('Overdue:'), title
    assert 'since' not in title, title
    assert 'renewal set for ' + renews in title, title
    # CONTROL: a past renewal date still says since. renews_at is when the
    # renewal fell due, so both states say "due since"; the state word leads.
    overdue = _chip(page, 'payments.example.test').get_attribute('title') or ''
    due = _chip(page, 'ops-api.example.test').get_attribute('title') or ''
    assert overdue.startswith('Overdue: renewal due since'), overdue
    assert due.startswith('Due: renewal due since'), due


def test_the_bell_badge_is_readable_as_soon_as_it_shows(page):
    """P53 shows the badge at once, so the readable guard measures it: white
    on red-500 was 3.76:1, under AA."""
    _dashboard(page)
    page.wait_for_selector('#notifBadge:not(.hidden)', timeout=3000)
    ratio = _contrast(page, '#notifBadge')
    assert ratio >= 4.5, ratio


def test_no_line_says_overdue_since_the_date_the_renewal_fell_due(page):
    """renews_at is when the renewal fell due; the certificate became Overdue
    later (min(7 days, a sixth of its life) left). "Renewal overdue since
    <renews_at>" named the wrong instant for weeks, while the chip was amber."""
    _dashboard(page)
    titles = page.eval_on_selector_all(
        'tr[data-row-domain] td:nth-child(2) span', 'els => els.map(e => e.title || "")')
    assert not [t for t in titles if 'overdue since' in t.lower()], titles
    _open_detail(page, 'payments.example.test')
    detail = page.inner_text('#certDetailContent')
    assert 'overdue since' not in detail.lower(), detail
    assert 'Renewal due since' in detail, detail


def test_a_certificate_without_its_key_shows_no_renewal_rule(page):
    """A keyless certificate cannot be renewed, only reissued: its banner said
    "Renews <date> (...)" right above "No private key anywhere"."""
    # Due, so the renewal date is past and a promise could be drawn.
    keyless = dict(_cert('nokey.example.test', 90 * DAY, 19 * DAY + datetime.timedelta(hours=1)),
                   private_key_present=False, private_key_state='missing', reissue_required=True)
    page.unroute('**/api/certificates')
    page.route('**/api/certificates', lambda route: _json(route, [*CERTS, keyless])
               if route.request.method == 'GET' else route.continue_())
    _dashboard(page)
    _open_detail(page, 'nokey.example.test')
    detail = page.inner_text('#certDetailContent')
    assert 'No private key anywhere' in detail, detail
    assert page.locator('#certDetailContent [data-renewal-rule]').count() == 0, detail
    assert 'the next renewal run renews it' not in detail, detail
    assert 'Needs a reissue: it has no private key' in detail, detail
    # CONTROL: a certificate with its key keeps the rule line.
    _close_detail(page)
    _open_detail(page, 'site3.example.test')
    assert page.locator('#certDetailContent [data-renewal-rule]').count() == 1


def test_an_expired_certificate_is_promised_no_renewal(page):
    """The line under a past renewal date said "Overdue: the next renewal run
    renews it" under an Expired chip, a promise the sweep does not always keep."""
    gone = dict(_cert('gone.example.test', 90 * DAY, -2 * DAY), expired=True)
    assert gone['needs_renewal'] is True, gone
    page.unroute('**/api/certificates')
    page.route('**/api/certificates', lambda route: _json(route, [*CERTS, gone])
               if route.request.method == 'GET' else route.continue_())
    _dashboard(page)
    _open_detail(page, 'gone.example.test')
    detail = page.inner_text('#certDetailContent')
    assert 'Renewal due since' in detail, detail
    # No renewal is promised: the sweep may skip it (auto-renew off globally,
    # or a certificate with no settings entry it cannot renew on its own).
    assert 'the next renewal run renews it' not in detail, detail
    # Nor to a Due certificate with auto-renew on, for the same reasons.
    _close_detail(page)
    _open_detail(page, 'ops-api.example.test')
    due = page.inner_text('#certDetailContent')
    assert 'Renewal due since' in due and 'the next renewal run renews it' not in due, due


def test_a_certificate_with_auto_renew_off_is_not_promised_a_renewal(page):
    """The sweep skips a certificate whose auto-renew is off (skipped_disabled),
    yet its line said the next renewal run renews it."""
    off = dict(_cert('manual.example.test', 90 * DAY, 19 * DAY + datetime.timedelta(hours=1)), auto_renew=False)
    assert off['needs_renewal'] is True, off
    page.unroute('**/api/certificates')
    page.route('**/api/certificates', lambda route: _json(route, [*CERTS, off])
               if route.request.method == 'GET' else route.continue_())
    _dashboard(page)
    _open_detail(page, 'manual.example.test')
    detail = page.inner_text('#certDetailContent')
    assert 'auto-renew is off for this certificate, so renew it by hand' in detail, detail
    assert 'the next renewal run renews it' not in detail, detail

