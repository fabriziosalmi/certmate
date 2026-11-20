"""The heading outline a screen reader lists never skips a level, and no name carries an icon glyph (#1511, P63).

Every app page had its h1 (sr-only, in base.html) and then card titles in h3:
the dashboard, Help, every Settings tab, the create drawer and the dialogs
went from h1 to h3, and Storage then from its h3 to h5; the setup page had
no h1 at all. Card titles are h2 now and their sections h3. And the Font
Awesome icons had no aria-hidden, so the private-use character of their
glyph was read out, and started names like " Create New Certificate".

What is read is what Chromium gives a screen reader: its accessibility tree
(CDP Accessibility.getFullAXTree), in tree order, without the nodes it
ignores. A template lint (tests/test_templates_icons_are_hidden_and_headings_do_not_skip.py)
checks each file; the order across a page, its partials, its base and what
its scripts build is only known here.
"""
import datetime
import json
import os
import re

import pytest

from modules.core import renewal_policy
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

_TEMPLATES = os.path.join(os.path.dirname(__file__), '..', 'templates')
PRIVATE_USE = re.compile('[-]')
TABS = ['general', 'dns', 'ca', 'storage', 'deploy', 'probe', 'acme', 'users', 'apikeys', 'oidc',
        'notifications', 'backup']


def _certificate(domain, days_left):
    """A 90-day certificate as /api/certificates answers it, its status and
    renewal instant from renewal_policy with the default 30-day threshold."""
    now = datetime.datetime.now(datetime.UTC).replace(tzinfo=None, microsecond=0)
    not_after = now + datetime.timedelta(days=days_left, hours=1)
    not_before = not_after - datetime.timedelta(days=90)
    renew_at, _reason = renewal_policy.renews_at(not_before, not_after, 30)
    return {'domain': domain, 'exists': True, 'days_left': days_left, 'days_until_expiry': days_left,
            'expired': False, 'needs_renewal': now >= renew_at, 'usable': True, 'has_private_key': True,
            'private_key_present': True, 'private_key_state': 'present',
            'expiry_date': not_after.strftime('%Y-%m-%d %H:%M:%S'), 'expires_at': renewal_policy.stamp(not_after),
            'expiry_status': renewal_policy.expiry_status(not_before, not_after, 30, now, renew_at),
            'not_before': renewal_policy.stamp(not_before), 'renews_at': renewal_policy.stamp(renew_at),
            'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'challenge_type': 'dns-01',
            'auto_renew': True, 'san_domains': [], 'tags': [], 'notes': None}


# One valid certificate and one overdue, so the list, the detail dialog and
# the notification groups have something to show.
CERTIFICATES = [_certificate('alpha.example.test', 60), _certificate('beta.example.test', 4)]


def _render(template, **context):
    """A page the signed-in admin of this instance is never served (the 403 an
    operator gets for /settings, the setup page before the first admin),
    rendered from its template."""
    from flask import Flask, render_template

    app = Flask(__name__, template_folder=_TEMPLATES)
    app.secret_key = 'test'
    with app.test_request_context('/'):
        return render_template(template, **context)


def _outline(page, dialog=False):
    """The headings (level, name) a screen reader lists, and every name with a
    private-use character. With `dialog`, only what is inside the open modal
    dialog (the page behind it is out of reach)."""
    session = page.context.new_cdp_session(page)
    try:
        nodes = session.send('Accessibility.getFullAXTree')['nodes']
    finally:
        session.detach()
    by_id = {node['nodeId']: node for node in nodes}
    root = nodes[0]
    if dialog:
        open_dialogs = [node for node in nodes if not node.get('ignored')
                        and node.get('role', {}).get('value') in ('dialog', 'alertdialog')]
        assert len(open_dialogs) == 1, f'expected one open dialog, found {len(open_dialogs)}'
        root = open_dialogs[0]
    headings, glyphs, unnamed = [], [], []
    stack = [root]
    while stack:
        node = stack.pop()
        stack.extend(by_id[child] for child in reversed(node.get('childIds', [])) if child in by_id)
        if node.get('ignored'):
            continue
        role = node.get('role', {}).get('value')
        name = str(node.get('name', {}).get('value', ''))
        # An InlineTextBox repeats the text of its StaticText parent.
        if role != 'InlineTextBox' and PRIVATE_USE.search(name):
            glyphs.append(f'{role} {name.strip()[:40]!r}')
        if role in ('button', 'link') and not name.strip():
            unnamed.append(role)
        if role == 'heading':
            level = next((p['value']['value'] for p in node.get('properties', []) if p['name'] == 'level'), None)
            headings.append((level, name.strip()[:40]))
    return headings, glyphs, unnamed


def _skips(headings, start):
    found, before = [], start
    for level, name in headings:
        if level > before + 1:
            found.append(f'h{before} to h{level} {name!r}')
        before = level
    return found


def _views(page):
    """Every app page, Settings tab and open dialog, with its outline."""
    seen = {}

    def go(path):
        page.goto('about:blank')
        page.goto(f'{BASE_URL}{path}', wait_until='networkidle')
        page.wait_for_timeout(300)

    def take(view, dialog=False):
        seen[view] = (_outline(page, dialog), 1 if dialog else 0)

    for path in ('/', '/#client', '/#acme', '/activity', '/inventory', '/notifications', '/help',
                 '/inventory/crypto-report', '/__forbidden', '/__setup'):
        go(path)
        if path == '/notifications':
            # Its groups are headings its script builds from the certificates.
            page.wait_for_function("() => document.getElementById('notifContent').getAttribute('aria-busy') === 'false'"
                                   " && document.querySelector('#notifContent ul')")
        take(path)
    go('/')
    page.locator('tr[data-row-domain="alpha.example.test"] td').first.click()
    page.wait_for_function("() => document.getElementById('detailDomain').textContent.trim() === 'alpha.example.test'")
    page.wait_for_timeout(400)
    take('/ certificate detail', dialog=True)
    for form in ('server', 'client'):
        go('/')
        page.evaluate(f"() => openCertDrawer('{form}')")
        page.wait_for_timeout(500)
        take(f'/ create drawer ({form})')
    go('/')
    page.keyboard.press('?')
    page.wait_for_selector('#shortcutOverlayTitle')
    take('/ keyboard shortcuts', dialog=True)
    go('/inventory')
    page.click('summary:has-text("Discovery configuration")')
    take('/inventory discovery configuration')
    go('/settings#general')
    for tab in TABS:
        page.evaluate(f"location.hash = '#{tab}'")
        page.wait_for_function(f"() => document.getElementById('settings-panel-{tab}').checkVisibility()")
        page.wait_for_timeout(200)
        take(f'/settings#{tab}')
    go('/settings#ca')
    page.click('button[data-click="openCAAccountModal"]')
    page.wait_for_timeout(400)
    take('/settings#ca CA account dialog', dialog=True)
    return seen


@pytest.fixture(scope='module')
def views(browser_page, ui_session_cookie):
    browser = browser_page.context.browser
    context = browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.emulate_media(reduced_motion='reduce')
    forbidden = _render('403.html', required_role='admin', current_role='viewer')
    setup = _render('setup.html', bootstrap_requires_token=False)
    page.route(f'{BASE_URL}/__forbidden', lambda route: route.fulfill(
        status=403, content_type='text/html; charset=utf-8', body=forbidden))
    page.route(f'{BASE_URL}/__setup', lambda route: route.fulfill(
        status=200, content_type='text/html; charset=utf-8', body=setup))
    page.route('**/api/certificates', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps(CERTIFICATES))
        if route.request.method == 'GET' else route.continue_())
    try:
        seen = _views(page)
        # Signed out: the login page.
        anonymous = browser.new_context(viewport={'width': 1440, 'height': 900})
        login = anonymous.new_page()
        login.goto(f'{BASE_URL}/login', wait_until='networkidle')
        seen['/login'] = (_outline(login), 0)
        anonymous.close()
        yield seen
    finally:
        context.close()


def test_no_page_tab_or_dialog_skips_a_heading_level(views):
    skips = {view: _skips(headings, start) for view, ((headings, _, _), start) in views.items()}
    skips = {view: found for view, found in skips.items() if found}
    bare = [view for view, ((headings, _, _), _) in views.items() if not headings]
    assert not bare, f'no heading at all on: {bare}'
    assert not skips, f'heading levels skipped: {skips}'


def test_every_page_has_an_h1_first(views):
    first = {view: headings[0] for view, ((headings, _, _), start) in views.items()
             if start == 0 and headings and headings[0][0] != 1}
    assert not first, f'pages whose first heading is not an h1: {first}'


def test_no_accessible_name_carries_an_icon_glyph(views):
    glyphs = {view: found for view, ((_, found, _), _) in views.items() if found}
    assert not glyphs, f'names with a private-use (icon font) character: {glyphs}'


def test_no_button_or_link_is_left_without_a_name(views):
    unnamed = {view: found for view, ((_, _, found), _) in views.items() if found}
    assert not unnamed, f'buttons and links with no accessible name: {unnamed}'
