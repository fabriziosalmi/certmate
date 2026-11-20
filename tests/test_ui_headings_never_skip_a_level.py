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

The views: every app page, every Settings tab, the 403, setup and login
pages, the create drawer, and every dialog that opens without saving
anything: certificate detail, keyboard shortcuts, curl command, confirm,
prompt, the report-issue fallback, CA account, storage migration, DNS add
and edit account, deploy execution detail, and the first two steps of the
setup wizard. A dialog's content that needs the server to hold something
(an account, a run, a wizard not yet dismissed) is given it in the page
only: a changed answer to what the page reads, or, for the run, the entry
handed to the page's own showExecutionDetail.
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


# The text a person sees in a heading, and in the label of a form field that
# has one (and no aria-label or aria-labelledby): its text nodes that are
# rendered, visible and not under aria-hidden, and the alt of an image there,
# the field's own subtree left out. Text in an sr-only element is not seen,
# unless the heading or label is itself sr-only (or inside one): an sr-only
# sentence inside a label would lengthen the name as much as a tooltip. Case is not
# compared: a name keeps the text-transform the page draws it with. Each
# element checked is marked for the accessibility tree.
SEEN_TEXT = """() => {
    const text = (root, skip) => {
        const hiddenRoot = !!root.closest('.sr-only');
        let out = '';
        const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
            const element = n.nodeType === 1 ? n : n.parentElement;
            if ((skip && skip.contains(n)) || element.closest('[aria-hidden=true]')
                || !element.checkVisibility({visibilityProperty: true})
                || (!hiddenRoot && element.closest('.sr-only'))) continue;
            if (n.nodeType === 3) out += n.textContent;
            else if (n.tagName === 'IMG' && n.alt) out += ' ' + n.alt + ' ';
        }
        return out.replace(/\\s+/g, ' ').trim();
    };
    const found = [];
    document.querySelectorAll('[data-ax-check]').forEach(e => e.removeAttribute('data-ax-check'));
    document.querySelectorAll('h1, h2, h3, h4, h5, h6').forEach(h => {
        h.dataset.axCheck = String(found.length);
        found.push(['heading', text(h)]);
    });
    document.querySelectorAll('input, select, textarea').forEach(f => {
        if (f.type === 'hidden' || f.hasAttribute('aria-label') || f.hasAttribute('aria-labelledby')
            || !f.labels || !f.labels.length) return;
        const label = [...f.labels].map(l => text(l, f)).filter(Boolean).join(' ');
        if (!label) return;
        f.dataset.axCheck = String(found.length);
        found.push([f.tagName.toLowerCase() + ' ' + (f.id || f.name || f.type), label]);
    });
    return found;
}"""


def _marked(session):
    """backendNodeId -> the data-ax-check index of each element SEEN_TEXT marked."""
    marked, stack = {}, [session.send('DOM.getDocument', {'depth': -1})['root']]
    while stack:
        node = stack.pop()
        attributes = node.get('attributes', [])
        for index in range(0, len(attributes), 2):
            if attributes[index] == 'data-ax-check':
                marked[node['backendNodeId']] = int(attributes[index + 1])
        stack.extend(node.get('children', []))
    return marked


def _outline(page, dialog=False):
    """The headings (level, name) a screen reader lists, every name with a
    private-use character, every button or link with no name, and every
    heading or labelled field whose name is not the text seen in it. With
    `dialog`, only what is inside the open modal dialog (the page behind it
    is out of reach)."""
    seen_text = page.evaluate(SEEN_TEXT)
    session = page.context.new_cdp_session(page)
    try:
        marked = _marked(session)
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
    headings, glyphs, unnamed, renamed, compared = [], [], [], [], 0
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
        if node.get('backendDOMNodeId') in marked:
            what, text = seen_text[marked[node['backendDOMNodeId']]]
            compared += 1
            if ' '.join(name.split()).casefold() != text.casefold():
                renamed.append(f'{what}: seen {text[:60]!r}, named {name.strip()[:200]!r}')
    return headings, glyphs, unnamed, renamed, compared


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
    # The private CA form, whose two info icons carry its only help text.
    page.select_option('#add-ca-type', 'private_ca')
    page.wait_for_selector('#private-ca-config', state='visible')
    take('/settings#ca CA account dialog, private CA', dialog=True)
    _dialogs(go, take, page)
    return seen


def _dialogs(go, take, page):
    """The other dialogs, opened the way their page opens them; none saves."""
    go('/')
    page.evaluate("() => document.getElementById('curlModal').classList.remove('hidden')")
    page.wait_for_timeout(300)
    take('/ curl command dialog', dialog=True)
    for kind, call in (('confirm', "CertMate.confirm('Sure?', 'Confirm title')"),
                       ('prompt', "CertMate.prompt('Name?', 'Prompt title', '')")):
        go('/')
        page.evaluate(f'() => {{ {call}; }}')
        page.wait_for_timeout(400)
        take(f'/ {kind} dialog', dialog=True)
    # The report-issue fallback, shown when the clipboard and a new tab are
    # both refused. It is an overlay with no dialog role, so the page's
    # outline is read with it on top.
    go('/help')
    page.evaluate("""() => {
        Object.defineProperty(navigator, 'clipboard',
            {value: {writeText: () => Promise.reject(new Error('refused'))}, configurable: true});
        window.open = () => null;
        CertMate.reportIssue({message: 'heading test'}); }""")
    page.wait_for_selector('text=Report this issue')
    take('/help report-issue fallback')
    go('/settings#storage')
    page.evaluate('() => showStorageMigrationModal()')
    page.wait_for_selector('#storageMigrationModal')
    page.wait_for_timeout(300)
    take('/settings#storage migration dialog', dialog=True)
    go('/settings#dns')
    page.click('label:has(input[name="dns_provider"][value="cloudflare"])')
    page.click('#cloudflare-add-account')
    page.wait_for_selector('#addAccountModal:not(.hidden)')
    page.wait_for_timeout(300)
    take('/settings#dns add account dialog', dialog=True)
    # The edit dialog needs an account: the settings the page reads are given
    # one, in the page only.
    settings = re.compile(r'.*/api/web/settings(\?.*)?$')

    def with_an_account(route):
        if route.request.method != 'GET':
            route.continue_()
            return
        answer = route.fetch()
        body = answer.json()
        providers = body.setdefault('dns_providers', {})
        cloudflare = providers.setdefault('cloudflare', {})
        cloudflare.setdefault('accounts', {})['headingtest'] = {'name': 'Heading test', 'api_token': ''}
        route.fulfill(response=answer, json=body)

    page.route(settings, with_an_account)
    try:
        go('/settings#dns')
        page.evaluate("() => showEditAccountModal('cloudflare', 'headingtest')")
        page.wait_for_selector('#editAccountModal:not(.hidden)')
        page.wait_for_timeout(300)
        take('/settings#dns edit account dialog', dialog=True)
    finally:
        page.unroute(settings)
    go('/settings#deploy')
    page.evaluate("""() => Alpine.$data(document.getElementById('settings-panel-deploy')).showExecutionDetail(
        {run_id: 'r1', hook_id: 'h1', hook_name: 'reload', domain: 'alpha.example.test', event: 'renewed',
         success: true, exit_code: 0, duration_ms: 12, timestamp: '2026-11-20T10:00:00Z',
         stdout: 'ok', stderr: ''})""")
    page.wait_for_selector('#executionDetailModal:not(.hidden)')
    page.wait_for_timeout(300)
    take('/settings#deploy execution detail dialog', dialog=True)


def _wizard(context):
    """The first-run wizard's first two steps. The suite dismissed it on the
    server, so the page is told it was not: the settings it reads say so.
    Step 1 to step 2 is in the page; nothing is posted."""
    page = context.new_page()
    seen = {}

    def not_dismissed(route):
        if route.request.method != 'GET':
            route.continue_()
            return
        answer = route.fetch()
        body = answer.json()
        body.update(setup_completed=False, wizard_dismissed=False)
        route.fulfill(response=answer, json=body)

    page.route('**/api/web/settings?t=*', not_dismissed)
    page.route('**/api/certificates', lambda route: route.fulfill(
        status=200, content_type='application/json', body='[]')
        if route.request.method == 'GET' else route.continue_())
    try:
        page.goto(f'{BASE_URL}/', wait_until='networkidle')
        page.wait_for_selector('#setupWizard #wizEmail')
        seen['/ setup wizard step 1'] = (_outline(page, True), 1)
        page.fill('#wizEmail', 'admin@example.test')
        page.click('#wizNext1')
        page.wait_for_function("() => !document.getElementById('wizEmail')")
        page.wait_for_timeout(500)
        seen['/ setup wizard step 2'] = (_outline(page, True), 1)
    finally:
        page.close()
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
        seen.update(_wizard(context))
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
    skips = {view: _skips(headings, start) for view, ((headings, *_), start) in views.items()}
    skips = {view: found for view, found in skips.items() if found}
    bare = [view for view, ((headings, *_), _) in views.items() if not headings]
    assert not bare, f'no heading at all on: {bare}'
    assert not skips, f'heading levels skipped: {skips}'


def test_every_page_has_an_h1_first(views):
    first = {view: headings[0] for view, ((headings, *_), start) in views.items()
             if start == 0 and headings and headings[0][0] != 1}
    assert not first, f'pages whose first heading is not an h1: {first}'


def test_no_accessible_name_carries_an_icon_glyph(views):
    glyphs = {view: found for view, ((_, found, *_), _) in views.items() if found}
    assert not glyphs, f'names with a private-use (icon font) character: {glyphs}'


def test_no_button_or_link_is_left_without_a_name(views):
    unnamed = {view: found for view, ((_, _, found, *_), _) in views.items() if found}
    assert not unnamed, f'buttons and links with no accessible name: {unnamed}'


def test_a_heading_or_a_labelled_field_is_named_by_the_text_it_shows(views):
    """A tooltip given a name (role="img" with an aria-label) inside a heading
    or a label put a help sentence into the name: "Role mappings First match
    wins...", "AI agent key Mark this key as...". Help text is a description."""
    renamed = {view: found for view, ((_, _, _, found, _), _) in views.items() if found}
    compared = {view: count for view, ((*_, count), _) in views.items()}
    # 275 on a fresh instance (#1511): a much lower count means the check lost its subject.
    assert sum(compared.values()) >= 250, f'only {sum(compared.values())} names compared: {compared}'
    assert not renamed, f'names that are not the text shown: {renamed}'
    print(f'{sum(compared.values())} names compared in {len(compared)} views')
