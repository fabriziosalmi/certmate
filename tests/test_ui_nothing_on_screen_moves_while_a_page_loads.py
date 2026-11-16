"""Nothing on screen moves while a page loads.

Every page paints first and fills in after: the certificate list, the counters,
a report, a settings tab, all arrive from /api after the first frame. Each time
something already on screen was not sized for what arrived, it moved: the
navigation bar grew a second line and dropped the whole dashboard 40 px for a
moment, the table headers slid sideways, the footer jumped out of the middle of
the screen, the Deployment chips shrank and grew back row by row.

Whether a response lands before or after the first paint depends on the machine
and the network, so it is not left to chance here: every /api request is held
until the page has painted, and released only then. What a person sees on a slow
link is what every run sees.

Two witnesses, because one is not enough. The browser's own layout-shift entries
(what Core Web Vitals call CLS) did not report the DNS settings cards moving
20 px, which a screen recording shows plainly. So a sampler also records, frame
by frame, where every element a person reads or clicks is laid out (navigation,
headings, table headers, buttons, labels, inputs, the Deployment chips, the
footer), and an element that was on screen at one place and is later at another
moved. Layout positions, not painted ones: the deliberate entrance animations
(`page-enter`, `row-enter`) move by transform and are not layout.

An element that appears late is fine; one that moves after it appeared is not.
"""
import json
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER, BASE_URL

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError(
            "playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1"
        )
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

# Layout shift below this is sub-pixel rounding. One real move of a line of text
# across a 900 px screen is already several times larger.
CLS_NOISE = 0.001

SAMPLER = r"""
(() => {
  const log = window.__stillness = {shifts: [], moves: [], firstPaint: null};
  const name = n => {
    let s = n.tagName.toLowerCase();
    if (n.id) s += '#' + n.id;
    const text = (n.innerText || n.getAttribute('aria-label') || '').trim().split('\n')[0].slice(0, 40);
    return text ? s + ' "' + text + '"' : s;
  };
  new PerformanceObserver(list => {
    for (const e of list.getEntries()) if (!e.hadRecentInput) log.shifts.push({
      value: e.value,
      sources: (e.sources || []).map(s => s.node && s.node.tagName ? name(s.node) : String(s.node && s.node.nodeName)),
    });
  }).observe({type: 'layout-shift', buffered: true});
  new PerformanceObserver(list => {
    for (const e of list.getEntries()) if (e.name === 'first-paint') log.firstPaint = e.startTime;
  }).observe({type: 'paint', buffered: true});
  const WATCHED = 'nav, nav a, nav button, footer, main h1, main h2, main h3, main th, main label, '
    + 'main button, main input, main select, main table, [data-deployment-domain]';
  const last = new Map();
  log.serverListSeen = false;
  function sample() {
    const t = performance.now();
    const serverList = document.getElementById('certificatesTable');
    if (log.firstPaint !== null && serverList && serverList.checkVisibility() && serverList.offsetHeight > 0) {
      log.serverListSeen = true;
    }
    for (const el of document.querySelectorAll(WATCHED)) {
      // A closed drawer is inert and translated out of view; it is not on screen.
      if (el.closest('[inert]') || !el.checkVisibility({visibilityProperty: true})
          || el.offsetWidth === 0 || el.offsetHeight === 0) { last.delete(el); continue; }
      const painted = el.getBoundingClientRect();
      const onScreen = painted.right > 0 && painted.left < innerWidth && painted.bottom > 0 && painted.top < innerHeight;
      let x = 0, y = 0;
      for (let n = el; n; n = n.offsetParent) { x += n.offsetLeft; y += n.offsetTop; }
      const prev = last.get(el);
      if (prev && (prev.onScreen || onScreen) && log.firstPaint !== null && t > log.firstPaint
          && (Math.abs(x - prev.x) > 1 || Math.abs(y - prev.y) > 1) && log.moves.length < 200) {
        log.moves.push({element: name(el), from: [prev.x, prev.y], to: [x, y]});
      }
      last.set(el, {x, y, onScreen});
    }
    if (!window.__stillnessStop) requestAnimationFrame(sample);
  }
  // From the moment the document is parsed, before the deferred scripts (Alpine
  // among them) run: what they change has to be seen changing.
  const start = () => requestAnimationFrame(sample);
  if (document.readyState !== 'loading') start();
  else document.addEventListener('readystatechange', start, {once: true});
})();
"""


def _certificate(index, days):
    domain = f'site{index}.example.test'
    return {'domain': domain, 'exists': True, 'days_left': days, 'days_until_expiry': days,
            'expired': False, 'seconds_left': days * 86400,
            'expiry_date': '2027-01-01 10:00:00', 'expires_at': '2027-01-01T10:00:00Z',
            'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'auto_renew': True,
            'san_domains': [], 'has_private_key': True}


# Twelve, with some expiring: two-digit counters, the size most dashboards have.
TWELVE = [_certificate(i, d) for i, d in enumerate([80, 45, 20, 5, 60, 30, 85, 12, 70, 3, 50, 40])]
# A hundred and fifty: three-digit counters, wider than the placeholder strip.
# This is the size at which the navigation bar wrapped onto a second line and
# stayed there. And fifteen hundred, the size at which the counters no longer
# fit beside the toggle at all: the bar still keeps one line, and the labels
# shorten instead.
HUNDREDS = [_certificate(i, 40 + i % 50) for i in range(150)]
THOUSANDS = [_certificate(i, 40 + i % 50) for i in range(1500)]

DEPLOYED = json.dumps({'deployed': True, 'reachable': True, 'certificate_match': True,
                       'method': 'server', 'protocol': 'https-tls'})

CLIENT_CERTIFICATES = json.dumps({'certificates': [
    {'id': f'c{i}', 'common_name': f'client{i}.example.test', 'email': f'user{i}@example.test',
     'cert_usage': usage, 'created_at': '2026-10-01T10:00:00Z', 'expires_at': '2027-10-01T10:00:00Z',
     'revoked': False}
    for i, usage in enumerate(['vpn', 'api-mtls', 'user', 'vpn', 'api-mtls', 'user', 'vpn'])]})


def _fake(certificates):
    """Answers for the dashboard: its list and its deployment checks are
    fixtures, so the rows and the chips exist without issuing anything."""
    body = json.dumps(certificates)

    def answer(route):
        url = route.request.url.split('?')[0]
        if route.request.method == 'GET' and url.endswith('/api/certificates'):
            return route.fulfill(status=200, content_type='application/json', body=body)
        if route.request.method == 'GET' and url.endswith('/deployment-status'):
            return route.fulfill(status=200, content_type='application/json', body=DEPLOYED)
        if route.request.method == 'GET' and url.endswith('/api/client-certs'):
            return route.fulfill(status=200, content_type='application/json', body=CLIENT_CERTIFICATES)
        return route.continue_()
    return answer


@pytest.fixture
def load(browser_page, ui_session_cookie):
    """Load a page with every /api request held until it has painted, and,
    with hold_alpine, Alpine too: on a slow link the 45 KB of Alpine also
    arrives after the first paint, and what Alpine shows, hides or moves is
    then on screen first in its state without Alpine.

    Returns what the two witnesses saw after the first paint: the browser's
    layout shifts and the sampler's moves.
    """
    browser = browser_page.context.browser
    contexts = []

    def run(path, width, answer=None, settled=None, before_answers=None, hold_alpine=False):
        context = browser.new_context(viewport={'width': width, 'height': 900})
        contexts.append(context)
        context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
        context.add_init_script(SAMPLER)
        page = context.new_page()
        # Slower frames, so a move that lasts a frame or two is sampled.
        page.context.new_cdp_session(page).send('Emulation.setCPUThrottlingRate', {'rate': 4})
        held, released = [], []

        def hold(route):
            if released:
                return (answer or (lambda r: r.continue_()))(route)
            held.append(route)
        page.route('**/api/**', hold)
        if hold_alpine:
            page.route('**/static/js/alpine.min.js', lambda route: route.continue_() if released else held.append(route))
        # 'commit', not 'load': a held script keeps 'load' from firing.
        page.goto(f'{BASE_URL}{path}', wait_until='commit')
        assert page.url.split('#')[0].endswith(path.split('#')[0]), (
            f'{path} landed on {page.url}: the page measured is not the page asked for')
        page.wait_for_function('() => window.__stillness && window.__stillness.firstPaint !== null')
        # Two more frames on screen with nothing from /api, then the answers.
        page.evaluate('() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))')
        early = page.evaluate(before_answers) if before_answers else None
        released.append(True)
        for route in held:
            if route.request.url.endswith('/alpine.min.js'):
                route.continue_()
            else:
                (answer or (lambda r: r.continue_()))(route)
        page.wait_for_load_state('load')
        page.wait_for_load_state('networkidle')
        if settled:
            page.wait_for_function(settled, timeout=20000)
        page.wait_for_timeout(1500)
        page.evaluate('() => { window.__stillnessStop = true; }')
        seen = page.evaluate('() => window.__stillness')
        seen['held'] = len(held)
        seen['before_answers'] = early
        seen['page'] = page
        return seen

    yield run
    for context in contexts:
        context.close()


def _assert_still(seen, where):
    cls = sum(s['value'] for s in seen['shifts'])
    assert not seen['moves'], (
        f'{where}: {len(seen["moves"])} things on screen moved after the first paint, '
        f'first ones: {seen["moves"][:6]}')
    assert cls < CLS_NOISE, f'{where}: layout shift {cls:.4f}: {seen["shifts"]}'


# Every server-side check has answered: the chips went through "checking" to a
# result, which is the change that used to resize them.
CHECKS_DONE = """() => {
    const chips = [...document.querySelectorAll('#certificatesList [data-deployment-role="backend"]')];
    return chips.length > 0 && chips.every(c => (c.getAttribute('title') || '').startsWith('Server: Deployed'));
}"""


@pytest.mark.parametrize('width', [390, 1280, 1440, 1920])
def test_the_certificate_list_opens_without_anything_moving(load, width):
    seen = load('/', width, _fake(TWELVE), settled=CHECKS_DONE)
    assert seen['held'] > 0, 'no /api request was held: the test did not test the late answer'
    page = seen['page']
    assert page.locator('#certificatesList tr[data-row-domain]').count() == 12
    _assert_still(seen, f'dashboard at {width} px')


@pytest.mark.parametrize('certificates', [HUNDREDS, THOUSANDS], ids=['150', '1500'])
@pytest.mark.parametrize('width', [1280, 1440, 1920])
def test_large_counters_keep_the_navigation_on_one_line(load, width, certificates):
    seen = load('/', width, _fake(certificates))
    page = seen['page']
    total = str(len(certificates))
    assert page.locator('#statsCards').inner_text().split()[0] == total
    nav = page.locator('body > nav').first.bounding_box()
    logo = page.locator('body > nav img').first.bounding_box()
    # One line: the bar is as tall as its logo row (64 px) plus its border.
    assert nav['height'] < logo['height'] + 4, f'navigation is {nav["height"]} px tall at {width} px'
    _assert_still(seen, f'dashboard with {total} certificates at {width} px')


@pytest.mark.parametrize('width', [1280, 1440])
def test_the_client_list_opens_without_anything_moving(load, width):
    seen = load('/#client', width, _fake(TWELVE))
    page = seen['page']
    assert page.locator('#certTableBody tr').count() == 7
    _assert_still(seen, f'client view at {width} px')


# The text of the counter strips on screen. A placeholder segment is
# aria-hidden and its text transparent: it says nothing, to the eye or to a
# screen reader, so it is left out.
COUNTERS = """() => [...document.querySelectorAll('#statsCards, #clientStatsCards, #acmeStatsCards')]
    .filter(s => s.checkVisibility())
    .map(s => [...s.children].filter(c => c.getAttribute('aria-hidden') !== 'true').map(c => c.innerText).join(' '))"""


@pytest.mark.parametrize('view', ['client', 'acme'])
def test_a_link_to_the_client_or_acme_view_never_shows_the_server_list(load, view):
    """The server list is the default view and is not cloaked. On /#client it
    used to be on screen until Alpine switched views (about 130 ms on a link
    with 400 ms of latency, in a screen recording)."""
    seen = load(f'/#{view}', 1440, _fake(TWELVE), before_answers=COUNTERS, hold_alpine=True)
    assert seen['serverListSeen'] is False
    # And the strip on screen before any answer is that view's own, not empty.
    assert len(seen['before_answers']) == 1, seen['before_answers']


@pytest.mark.parametrize('path', ['/', '/#client', '/#acme'])
def test_no_counter_says_zero_before_its_numbers_arrive(load, path):
    """Before the answers, a counter is a placeholder. The client and ACME
    strips printed 0 ("0 TOTAL 0 ACTIVE") until their numbers came, which on a
    slow link is a false claim on screen for most of a second."""
    seen = load(path, 1440, _fake(TWELVE), before_answers=COUNTERS)
    strips = seen['before_answers']
    assert len(strips) == 1, f'{path}: {len(strips)} counter strips on screen before the answers'
    numbers = [line for line in strips[0].split() if line[:1].isdigit()]
    assert numbers == [], f'{path}: counters before the answers read {strips[0]!r}'


@pytest.mark.parametrize('path, width', [
    ('/', 390), ('/', 1440), ('/#client', 390), ('/#acme', 390),
    ('/settings', 1440), ('/settings#dns', 1440), ('/settings#storage', 1440), ('/settings#deploy', 1440),
])
def test_nothing_moves_when_alpine_arrives_after_the_first_paint(load, path, width):
    """Until Alpine runs, x-show is not applied and x-cloak is: an element that
    is visible without Alpine and hidden with it, or the other way round, takes
    or gives back its space at that moment. The Save bar of the settings page
    and the dashboard's counter strip on a phone did."""
    seen = load(path, width, _fake(TWELVE), hold_alpine=True)
    _assert_still(seen, f'{path} at {width} px, Alpine late')


def test_every_dns_provider_card_has_the_same_glyph_box(browser_page, ui_session_cookie):
    """provider-icons.js swaps the card's font glyph for a 24 px logo or
    monogram once the page has loaded, and a font glyph's line also depends on
    when its font arrives: the card changed height and the rows under it moved
    7 px. Whatever sits first in a card is the same box, before and after."""
    context = _context(browser_page, ui_session_cookie, 1440)
    try:
        page = context.new_page()
        page.goto(f'{BASE_URL}/settings#dns', wait_until='networkidle')
        boxes = page.evaluate('''() => [...document.querySelectorAll(
            '#dns-provider-section label > div > .text-center > :first-child')]
            .map(e => [e.tagName.toLowerCase(), e.offsetWidth, e.offsetHeight])''')
        assert len(boxes) > 20
        assert {(w, h) for _, w, h in boxes} == {(24, 24)}, boxes
        # The three kinds are all there: a brand logo, a monogram, a font glyph.
        assert {tag for tag, _, _ in boxes} >= {'img', 'span', 'i'}, boxes
    finally:
        context.close()


@pytest.mark.parametrize('path', [
    '/inventory', '/inventory/crypto-report', '/activity', '/notifications', '/help',
    '/settings', '/settings#dns', '/settings#ca', '/settings#acme', '/settings#oidc', '/settings#backup',
])
def test_the_other_pages_open_without_anything_moving(load, path):
    seen = load(path, 1440)
    _assert_still(seen, path)


def test_the_icon_font_is_requested_before_the_first_layout():
    """Not something the held answers can show: the font is not /api. On a cold
    cache the navigation's icon rail grew 37 px when the icon font arrived after
    the first layout (measured before this preload, on every page). The preload
    must name the very file the stylesheet asks for, with `crossorigin`, or the
    browser downloads it twice and the first copy is wasted."""
    root = os.path.join(os.path.dirname(__file__), '..')
    base = open(os.path.join(root, 'templates/base.html')).read()
    css = open(os.path.join(root, 'static/css/fontawesome.min.css')).read()
    assert 'url(../webfonts/fa-solid-900.woff2)' in css
    assert ('<link rel="preload" href="/static/webfonts/fa-solid-900.woff2" as="font" '
            'type="font/woff2" crossorigin>') in base
    assert os.path.exists(os.path.join(root, 'static/webfonts/fa-solid-900.woff2'))
    # Before the stylesheet that asks for it, so the request is already under way.
    assert (base.index('<link rel="preload" href="/static/webfonts/fa-solid-900.woff2"')
            < base.index('<link href="/static/css/fontawesome.min.css"'))


# What follows moves on a click rather than on a load, and is held to the same
# rule: what a person is looking at, or about to click, stays where it is.

SETTINGS_TABS = ['general', 'dns', 'ca', 'storage', 'deploy', 'probe', 'acme', 'users', 'apikeys', 'oidc',
                 'notifications', 'backup']


def _context(browser_page, cookie, width, phone=False):
    context = browser_page.context.browser.new_context(
        viewport={'width': width, 'height': 900}, is_mobile=phone, has_touch=phone)
    context.add_cookies([{'name': 'certmate_session', 'value': cookie, 'url': BASE_URL}])
    return context


def test_every_settings_tab_starts_at_the_same_height(browser_page, ui_session_cookie):
    """General, CA and Storage started 32 px lower than DNS (a space-y margin
    that went to whichever panel was not first), and the tabs outside the form
    24 px lower: the content jumped on every switch."""
    context = _context(browser_page, ui_session_cookie, 1440)
    try:
        page = context.new_page()
        page.goto(f'{BASE_URL}/settings#general', wait_until='networkidle')
        tops = {}
        for tab in SETTINGS_TABS:
            page.evaluate(f"location.hash = '#{tab}'")
            page.wait_for_function(f"() => document.getElementById('settings-panel-{tab}').checkVisibility()")
            tops[tab] = page.evaluate(
                f"() => Math.round(document.getElementById('settings-panel-{tab}').getBoundingClientRect().top + scrollY)")
        assert len(set(tops.values())) == 1, tops
    finally:
        context.close()


@pytest.mark.parametrize('width', [390, 768, 1280])
def test_the_drawer_type_switch_stays_under_the_pointer(browser_page, ui_session_cookie, width):
    """The Server line under the drawer title wrapped once more than the Client
    line, so the Server/Client switch moved 20 px each time it was clicked."""
    context = _context(browser_page, ui_session_cookie, width, phone=width < 500)
    try:
        page = context.new_page()
        page.goto(f'{BASE_URL}/', wait_until='networkidle')
        page.evaluate("() => openCertDrawer('server')")
        switch = page.locator('#createCertFormContainer [aria-label="Certificate type"]')
        switch.wait_for(state='visible')
        tops = []
        for kind in ('#drawerTypeClient', '#drawerTypeServer', '#drawerTypeClient'):
            page.click(kind)
            tops.append(round(switch.bounding_box()['y']))
        assert len(set(tops)) == 1, f'the switch moved at {width} px: {tops}'
    finally:
        context.close()


PHONE_PATHS = ['/', '/#client', '/#acme', '/inventory', '/inventory/crypto-report', '/activity', '/notifications',
               '/help'] + [f'/settings#{tab}' for tab in SETTINGS_TABS]


@pytest.mark.parametrize('width', [360, 390])
def test_no_page_is_wider_than_a_phone(browser_page, ui_session_cookie, width):
    """A page wider than the screen pans sideways under the thumb. It was the
    inventory (an sr-only header escaping its scroll box: 590 px on a 390 px
    phone) and five settings tabs (rows whose field would not shrink, a file
    input, an unbroken callback URL). And the view toggle's "New" was cut to
    "+ Ne" at 360 px."""
    context = _context(browser_page, ui_session_cookie, width, phone=True)
    try:
        page = context.new_page()
        wide = {}
        for path in PHONE_PATHS:
            page.goto(f'{BASE_URL}/static/manifest.json')
            page.goto(f'{BASE_URL}{path}', wait_until='networkidle')
            scroll, client = page.evaluate(
                '() => [document.documentElement.scrollWidth, document.documentElement.clientWidth]')
            if scroll > client:
                wide[path] = scroll
        assert wide == {}, f'wider than a {width} px phone: {wide}'
        page.goto(f'{BASE_URL}/', wait_until='networkidle')
        # "New" ends inside the bar row that holds the toggle, not past it.
        ends = page.evaluate('''() => {
            const group = document.querySelector('[aria-label="Certificate view and creation"]');
            const row = group.parentElement.getBoundingClientRect();
            const style = getComputedStyle(group.parentElement);
            const inner = row.right - parseFloat(style.paddingRight);
            return {new: document.querySelector('button[title="New certificate"]').getBoundingClientRect().right,
                    row: inner, screen: document.documentElement.clientWidth}; }''')
        assert ends['new'] <= ends['row'] + 0.5 and ends['row'] <= ends['screen'], ends
    finally:
        context.close()
