"""One primary button, one status badge, one icon colour (UX audit #1511, B18: P42, P68, P69).

Measured on 2026-11-19 before this change, light theme, 1440 wide:

* P42: filled buttons were 28, 30, 36, 38, 40 and 42 px tall with 12, 14 and 16 px
  text and 4, 6 and 8 px corners; "Test Connection", "Add Probe" and "Copy
  Diagnostic Snapshot" were Tailwind blue-600 rgb(37, 99, 235) beside the brand
  rgb(26, 93, 193); "Save SSO Settings" indigo-600; "Save Rate Limits" amber
  rgb(161, 98, 7), the colour of the risky "Migrate Certificates". A DNS
  account's Edit and Delete were 26 px white buttons with a border and icons; a
  CA account's were 24 px tinted chips with no border and no icon.
* P68: the server "Valid" was a 20 px pill with an icon and a ring; the client
  "Active" a 23 px square chip with no icon, the shape of the "vpn" usage tag
  beside it; the inventory pill a 20 px pill in another green with no icon.
* P69: the create drawer's field icons were blue, indigo, purple, green, teal
  and orange, the green one beside "Certificate Authority" the green of a valid
  certificate; the Help section links were green, blue, purple, indigo, amber
  and orange.

Now a filled button is 36 px with 14 px text, or 28 px with 12 px text in the
two dense toolbars named in SMALL, with 6 px corners, in the brand blue or the
danger red; amber is only on the two buttons that start a certificate
migration. The status badges are one pill with an icon; the category tags stay
square. Decorative icons are muted, the Help link of the section in the
address primary.

The certificate lists are answered in the browser (page.route); the two
accounts the Edit/Delete test needs are created and removed by it.
"""
import datetime
import json
import os
import re

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
BRAND = 'rgb(26, 93, 193)'
DANGER = 'rgb(220, 38, 38)'
AMBER = 'rgb(161, 98, 7)'
# Amber is for a risky action that is not a deletion: copying every certificate
# into another backend, over what is there. Nothing else may be amber.
RISKY = {'Migrate Certificates', 'Start Migration'}
# The 28 px size, only where a button shares a strip of compact controls:
# - the inventory header holds the breadcrumb, the scan message, Scan now and
#   the icon-only Refresh in one row;
# - the crypto report's export strip holds CSV, JSON and Print side by side.
SMALL = {('/inventory', 'Scan now'), ('/inventory/crypto-report', 'Print / Save as PDF')}
DAY = datetime.timedelta(days=1)

EVERY_VIEW = ['/', '/#client', '/#acme', '/inventory', '/inventory/crypto-report', '/activity', '/notifications',
              '/help'] + [f'/settings#{tab}' for tab in (
                  'general', 'dns', 'ca', 'storage', 'deploy', 'probe', 'acme', 'users', 'apikeys', 'oidc',
                  'notifications', 'backup')]

FILLED = r"""
(root) => {
  const scope = root ? document.querySelector(root) : document;
  const rgb = c => (c.match(/[0-9.]+/g) || []).map(Number);
  const lum = c => { const p = rgb(c).slice(0, 3).map(v => { v /= 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); });
    return 0.2126 * p[0] + 0.7152 * p[1] + 0.0722 * p[2]; };
  const out = [];
  for (const el of scope.querySelectorAll('button, a, [role=button]')) {
    if (el.closest('[inert],[aria-hidden=true]')) continue;
    if (!el.checkVisibility({opacityProperty: true, visibilityProperty: true})) continue;
    const s = getComputedStyle(el), r = el.getBoundingClientRect(), bg = rgb(s.backgroundColor);
    if (r.height === 0) continue;
    const painted = s.backgroundImage !== 'none' || (bg.length === 3 || bg[3] >= 0.5);
    if (!painted || lum(s.color) < 0.8) continue;
    out.push({text: (el.innerText || '').trim().replace(/\s+/g, ' '), h: Math.round(r.height * 10) / 10,
              fs: s.fontSize, radius: s.borderTopLeftRadius, bg: s.backgroundColor, image: s.backgroundImage});
  }
  return out;
}
"""

# --- fixtures and what the pages are given -----------------------------------


def _now():
    return datetime.datetime.now(datetime.UTC).replace(tzinfo=None, microsecond=0)


def _cert(domain, lifetime, left):
    now = _now()
    not_after = now + left
    not_before = not_after - lifetime
    renew_at, _reason = renewal_policy.renews_at(not_before, not_after, 30)
    seconds_left = int((not_after - now).total_seconds())
    return {
        'domain': domain, 'host': domain, 'ip_address': None, 'exists': True,
        'days_left': seconds_left // 86400, 'days_until_expiry': seconds_left // 86400,
        'seconds_left': seconds_left, 'expired': seconds_left < 0, 'needs_renewal': now >= renew_at,
        'usable': True, 'private_key_present': True, 'private_key_state': 'present',
        'reissue_required': False, 'external': False,
        'expiry_date': not_after.strftime('%Y-%m-%d %H:%M:%S'), 'expires_at': renewal_policy.stamp(not_after),
        'expiry_status': renewal_policy.expiry_status(not_before, not_after, 30, now, renew_at),
        'not_before': renewal_policy.stamp(not_before), 'renews_at': renewal_policy.stamp(renew_at),
        'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'challenge_type': 'dns-01',
        'san_domains': [], 'auto_renew': True, 'tags': [], 'notes': None, 'renewal_info': None,
        'acme_profile': None, 'acme_profile_withdrawn_at': None, 'imported_at': None,
        'renewed_at': None, 'last_renewal_attempt': None,
    }


CERTS = [_cert('valid.example.test', 90 * DAY, 60 * DAY),
         _cert('due.example.test', 90 * DAY, 19 * DAY + DAY / 24),
         _cert('overdue.example.test', 90 * DAY, 4 * DAY + DAY / 24),
         _cert('gone.example.test', 90 * DAY, -2 * DAY)]
CLIENTS = [
    {'identifier': 'cc-alice', 'common_name': 'alice.vpn.example.test', 'email': 'a@example.test',
     'cert_usage': 'vpn', 'created_at': '2026-10-01T10:00:00Z', 'expires_at': '2027-10-01T10:00:00Z',
     'revoked': False, 'serial_number': '1234'},
    {'identifier': 'cc-bob', 'common_name': 'bob.api.example.test', 'email': 'b@example.test',
     'cert_usage': 'api-mtls', 'created_at': '2026-10-01T10:00:00Z', 'expires_at': '2027-10-01T10:00:00Z',
     'revoked': True, 'serial_number': '5678'},
]


def _record(name, lifetime, left, revocation=None):
    record = {'fingerprint': name, 'subject_cn': name, 'san_dns': [name], 'issuer_cn': 'Test CA',
              'managed': False, 'source': 'probed', 'endpoints': [], 'key': {'type': 'EC', 'curve': 'P-256'}}
    if left is not None:
        not_after = _now() + left
        record.update(not_before=(not_after - lifetime).isoformat() + 'Z', not_after=not_after.isoformat() + 'Z')
    if revocation:
        record['revocation'] = dict({'checked_at': '2026-11-19T10:00:00Z', 'method': 'ocsp'}, status=revocation)
    return record


# Each of the five answers modules/core/revocation.py gives, and one record
# with no expiry date at all.
INVENTORY = [_record('fine.example.test', 90 * DAY, 60 * DAY, 'good'),
             _record('due.example.test', 90 * DAY, 20 * DAY, 'unknown'),
             _record('overdue.example.test', 90 * DAY, 3 * DAY, 'unavailable'),
             _record('gone.example.test', 90 * DAY, -2 * DAY, 'revoked'),
             _record('nodate.example.test', 90 * DAY, None, 'not_applicable'),
             _record('plain.example.test', 90 * DAY, 60 * DAY)]


def _json(route, body):
    route.fulfill(status=200, content_type='application/json', body=json.dumps(body))


def _client_answer(route):
    url = route.request.url.split('?')[0]
    if route.request.method == 'GET' and url.endswith('/api/client-certs'):
        return _json(route, {'certificates': CLIENTS})
    if route.request.method == 'GET' and url.endswith('/api/client-certs/stats'):
        return _json(route, {'total': 2, 'active': 1, 'revoked': 1, 'by_usage': {'vpn': 1, 'api-mtls': 1}})
    return route.continue_()


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.route('**/api/certificates', lambda route: _json(route, CERTS)
               if route.request.method == 'GET' else route.continue_())
    page.route('**/api/certificates/jobs', lambda route: _json(route, {'count': 0, 'jobs': []}))
    page.route('**/api/client-certs**', _client_answer)
    body = inventory_view.build_inventory_view(INVENTORY)
    page.route(re.compile(r'.*/api/inventory(\?.*)?$'), lambda route: _json(route, body))
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _open(page, path):
    page.goto(BASE_URL + path, wait_until='networkidle')
    if '#' in path and not path.startswith('/settings'):
        page.reload(wait_until='networkidle')
    page.wait_for_timeout(500)


def _settled(page, selector):
    page.wait_for_function(
        "(s) => { const e = document.querySelector(s); return e && e.getAnimations({subtree: true}).length === 0; }",
        arg=selector)


def _wrong(path, buttons):
    """Every way a filled button differs from the one primary button."""
    wrong = []
    for b in buttons:
        small = (path, b['text']) in SMALL
        height, size = (28, '12px') if small else (36, '14px')
        colours = {BRAND, DANGER} | ({AMBER} if b['text'] in RISKY else set())
        if b['h'] != height or b['fs'] != size or b['radius'] != '6px' or b['bg'] not in colours \
                or b['image'] != 'none':
            wrong.append(b)
    return wrong


# --- P42: one primary button --------------------------------------------------

@pytest.mark.parametrize('path', EVERY_VIEW)
def test_every_filled_button_on_a_page_is_the_one_primary_button(page, path):
    _open(page, path)
    buttons = page.evaluate(FILLED, None)
    wrong = _wrong(path, buttons)
    assert wrong == [], f'{path}: filled buttons off the system: {wrong}'


def _dialog_buttons(page, path, opener, root):
    _open(page, path)
    opener(page)
    _settled(page, root)
    page.wait_for_timeout(250)
    return page.evaluate(FILLED, root)


DIALOGS = {
    'create drawer, server': ('/', lambda p: p.evaluate("() => openCertDrawer('server')"),
                              '#createCertFormContainer'),
    'create drawer, client': ('/', lambda p: p.evaluate("() => openCertDrawer('client')"),
                              '#createCertFormContainer'),
    'confirm, destructive': ('/', lambda p: p.evaluate("() => { CertMate.confirm('Delete it?', 'Delete'); }"),
                             '[role=alertdialog]'),
    'confirm, not destructive': ('/', lambda p: p.evaluate(
        "() => { CertMate.confirm('Go on?', 'Go', {danger: false}); }"), '[role=alertdialog]'),
    'storage migration': ('/settings#storage', lambda p: p.click('button:has-text("Migrate Certificates")'),
                          '#storageMigrationModal'),
    'CA account': ('/settings#ca', lambda p: p.click('button:has-text("Add CA Account")'), '#caAccountModal'),
}


@pytest.mark.parametrize('name', list(DIALOGS))
def test_every_filled_button_in_a_dialog_is_the_one_primary_button(page, name):
    path, opener, root = DIALOGS[name]
    buttons = _dialog_buttons(page, path, opener, root)
    assert buttons, f'{name}: no filled button found in {root}'
    wrong = _wrong(path, buttons)
    assert wrong == [], f'{name}: filled buttons off the system: {wrong}'


def test_amber_is_only_on_the_risky_migration(page):
    """CONTROL for the rule above: Migrate Certificates is still amber, and the
    plain Save Rate Limits is the brand blue."""
    _open(page, '/settings#storage')
    migrate = [b for b in page.evaluate(FILLED, None) if b['text'] == 'Migrate Certificates']
    assert [b['bg'] for b in migrate] == [AMBER], migrate
    _open(page, '/settings#apikeys')
    save = [b for b in page.evaluate(FILLED, None) if b['text'] == 'Save Rate Limits']
    assert [b['bg'] for b in save] == [BRAND], save


# What the server does with each certificate (StorageBackendMigrate,
# migrate_certificates, each backend's store_certificate), for the target the
# Settings form shows: (form backend, Azure storage mode) -> words that must be
# there, and words of the other targets that must not.
EFFECT = {
    ('local_filesystem', None): ['into the local directory shown in Settings',
                                 'a file the source does not have stays as it was'],
    ('s3_compatible', None): ['into the S3-compatible bucket shown in Settings',
                              'replacing a certificate with the same name there whole'],
    ('azure_keyvault', 'secrets'): ['into Azure Key Vault (secrets only) shown in Settings',
                                    'a file the source does not have stays as it was'],
    ('azure_keyvault', 'certificate'): ['into Azure Key Vault (certificate object only) shown in Settings',
                                        'a new version of the certificate object with the same name',
                                        'A certificate without a private key cannot be imported: '
                                        'it is counted as failed and nothing is written for it'],
    ('azure_keyvault', 'both'): ['into Azure Key Vault (secrets and certificate object) shown in Settings',
                                 'a file the source does not have stays as it was',
                                 'its secrets are written first, so it is counted as failed after being partly copied'],
}
EVERYWHERE = ['A certificate that cannot be copied is counted as failed', 'the migration goes on with the others',
              'The source keeps its copies', 'Nothing in Settings changes']


def _migration_dialog(page, source=None):
    page.click('button:has-text("Migrate Certificates")')
    dialog = page.locator('#storageMigrationModal[role=dialog]')
    dialog.wait_for(state='visible')
    if source is not None:
        page.select_option('#storageMigSource', source)
    return dialog


@pytest.mark.parametrize('target', list(EFFECT), ids=lambda t: '-'.join(x for x in t if x))
def test_migrate_certificates_says_what_it_writes_into_the_backend_settings_shows(page, target):
    sent = []
    page.route('**/api/storage/migrate', lambda route: (sent.append(route.request.url), _json(route, {}))[1])
    page.on('dialog', lambda d: (sent.append('window dialog: ' + d.message), d.dismiss()))
    _open(page, '/settings#storage')
    backend, mode = target
    page.select_option('#storage-backend', backend)
    if mode:
        page.select_option('#azure-storage-mode', mode)
    dialog = _migration_dialog(page)
    text = ' '.join(dialog.inner_text().split())
    for words in EFFECT[target] + EVERYWHERE:
        assert words in text, (target, words, text)
    for other, phrases in EFFECT.items():
        if other != target:
            assert phrases[0] not in text, (target, phrases[0])
    dialog.locator('button:has-text("Cancel")').click()
    dialog.wait_for(state='detached')
    assert sent == [], sent


SAME = ('If this source is the same location as the backend in use, there is nothing to copy: '
        'each certificate would be written onto itself and counted as migrated.')


def test_a_source_of_the_backend_in_use_says_it_may_be_a_copy_onto_itself(page):
    """The server does not refuse a migration onto the same location: it writes
    each certificate onto itself and counts it migrated. The page cannot always
    tell the same location from another one of the same type (another bucket,
    a directory written another way), so it says so and leaves Start on."""
    def settings(route):
        if route.request.method != 'GET':
            return route.continue_()
        body = route.fetch().json()
        storage = dict(body.get('certificate_storage') or {}, backend='local_filesystem')
        storage['s3_compatible'] = {'bucket': 'other-b18', 'auth_mode': 'iam_role'}
        body['certificate_storage'] = storage
        return _json(route, body)
    page.route('**/api/web/settings', settings)
    _open(page, '/settings#storage')
    page.wait_for_function("() => document.getElementById('storage-backend').value === 'local_filesystem'")
    dialog = _migration_dialog(page, 'local_filesystem')
    same = dialog.locator('#storageMigSame')
    start = dialog.locator('#storageMigStartBtn')
    assert same.is_visible() and ' '.join(same.inner_text().split()) == SAME, same.inner_text()
    assert start.is_enabled()
    # Another type than the one in use: not said.
    page.select_option('#storageMigSource', 's3_compatible')
    assert not same.is_visible() and start.is_enabled()
    page.select_option('#storageMigSource', '')
    assert not same.is_visible()
    dialog.locator('button:has-text("Cancel")').click()


ROW_FIT = """(button) => {
  const card = button.closest('.p-4, .px-4');
  const b = button.getBoundingClientRect(), c = card.getBoundingClientRect(), s = getComputedStyle(card);
  return {h: Math.round(b.height), inside: b.left >= c.left + parseFloat(s.paddingLeft) - 0.5
          && b.right <= c.right - parseFloat(s.paddingRight) + 0.5};
}"""


@pytest.mark.parametrize('width', [360, 390])
def test_the_add_account_buttons_stay_one_line_and_inside_their_card_on_a_phone(
        browser_page, ui_session_cookie, width):
    """At 390 px "Add Account" and "Add CA Account" wrapped onto two lines, 54
    px tall; kept on one line, at 360 px they ran 16 px onto the card's padding.
    The row wraps instead: the button moves under the heading."""
    context = browser_page.context.browser.new_context(viewport={'width': width, 'height': 844})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    phone = context.new_page()
    try:
        seen = {}
        phone.goto(BASE_URL + '/settings#dns', wait_until='networkidle')
        for provider in ('cloudflare', 'rfc2136'):
            phone.click(f'label:has(input[name="dns_provider"][value="{provider}"])')
            button = phone.locator(f'#{provider}-add-account')
            button.wait_for(state='visible')
            seen[provider] = button.evaluate(ROW_FIT)
        phone.goto(BASE_URL + '/settings#ca', wait_until='networkidle')
        phone.reload(wait_until='networkidle')
        button = phone.locator('button:has-text("Add CA Account")')
        button.wait_for(state='visible')
        seen['ca'] = button.evaluate(ROW_FIT)
        assert all(v == {'h': 36, 'inside': True} for v in seen.values()), (width, seen)
    finally:
        context.close()


def _account_buttons(page, path, row):
    page.goto(BASE_URL + path, wait_until='networkidle')
    if path.endswith('#dns'):
        page.click('label:has(input[name="dns_provider"][value="cloudflare"])')
    row.wait_for(state='visible', timeout=5000)
    return row.evaluate("""(row) => Object.fromEntries([...row.querySelectorAll('button')]
        .filter(b => ['Edit', 'Delete'].includes(b.innerText.trim()))
        .map(b => { const s = getComputedStyle(b), r = b.getBoundingClientRect();
          return [b.innerText.trim(), {h: Math.round(r.height), fs: s.fontSize, fw: s.fontWeight,
            radius: s.borderTopLeftRadius, bg: s.backgroundColor, color: s.color, border: s.borderTopWidth,
            borderColour: s.borderTopColor, icon: (b.querySelector('i') || {}).className || ''}]; }))""")


def test_a_dns_and_a_ca_account_have_the_same_edit_and_delete(page):
    # A private CA account, as tests/test_ui_accounts_show_their_last_check.py
    # adds one: removing it leaves no CA configured, which the modules after
    # this one rely on. (Adding a Let's Encrypt account also saves a "default"
    # one, which cannot be deleted while it is the default.)
    headers = {'Origin': BASE_URL}
    dns = page.request.post(f'{BASE_URL}/api/dns/cloudflare/accounts', headers=headers, data={
        'account_id': 'ui-b18-cf', 'config': {'name': 'ui-b18-cf', 'api_token': 'Tk' + 'b18Q' * 10}})
    ca = page.request.post(f'{BASE_URL}/api/web/settings/ca-providers/private_ca/accounts/ui-b18-pca',
                           headers=headers, data={'acme_url': 'https://127.0.0.1:1/directory',
                                                  'email': 'ops@example.com'})
    try:
        assert dns.ok and ca.ok, (dns.status, ca.status)
        on_dns = _account_buttons(page, '/settings#dns', page.locator('#cloudflare-accounts-list > div').filter(
            has_text='ID: ui-b18-cf'))
        on_ca = _account_buttons(page, '/settings#ca', page.locator('#configured-ca-list > div').filter(
            has_text='ui-b18-pca'))
        assert set(on_dns) == set(on_ca) == {'Edit', 'Delete'}, (on_dns, on_ca)
        for name in ('Edit', 'Delete'):
            assert on_dns[name] == on_ca[name], (name, on_dns[name], on_ca[name])
            assert on_dns[name]['h'] == 28 and on_dns[name]['fs'] == '12px', on_dns[name]
        assert 'fa-pen' in on_dns['Edit']['icon'] and 'fa-trash-alt' in on_dns['Delete']['icon'], on_dns
    finally:
        page.request.delete(f'{BASE_URL}/api/dns/cloudflare/accounts/ui-b18-cf', headers=headers)
        page.request.delete(f'{BASE_URL}/api/web/settings/ca-providers/private_ca/accounts/ui-b18-pca',
                            headers=headers)


# --- P68: one status badge ----------------------------------------------------

BADGE = """(els) => els.map(el => { const s = getComputedStyle(el), r = el.getBoundingClientRect();
    return {text: el.innerText.trim(), h: Math.round(r.height * 10) / 10, radius: s.borderTopLeftRadius,
            fs: s.fontSize, bg: s.backgroundColor, color: s.color, ring: s.boxShadow,
            icon: !!el.querySelector('i.fas[aria-hidden=true]')}; })"""


def _badges(page):
    _open(page, '/')
    page.wait_for_selector('tr[data-row-domain="valid.example.test"]')
    server = page.locator('#certificatesList tr[data-row-domain] td:nth-child(2) > span:first-child').evaluate_all(BADGE)
    _open(page, '/#client')
    page.locator('[data-cc-status-chip=""]').click()
    page.wait_for_selector('#certTableBody tr[data-cc-id="cc-bob"]')
    client = page.locator('#certTableBody tr[data-cc-id] td:nth-child(6) > span').evaluate_all(BADGE)
    usage = page.locator('#certTableBody tr[data-cc-id] td:nth-child(3) > span').evaluate_all(BADGE)
    _open(page, '/inventory')
    page.wait_for_selector('#inventoryBody tr td >> text=fine.example.test')
    inventory = page.locator('#inventoryBody tr > td:nth-child(3) > span:first-child').evaluate_all(BADGE)
    revocation = page.locator('#inventoryBody tr > td:nth-child(3) > div > span').evaluate_all(BADGE)
    # A row with no revocation answer draws no empty line under its expiry.
    empty = page.locator('#inventoryBody tr > td:nth-child(3) > div:empty').count()
    assert empty == 0, empty
    return server, client, usage, inventory, revocation


def test_every_status_badge_is_one_pill_with_an_icon_and_a_tag_stays_square(page):
    server, client, usage, inventory, revocation = _badges(page)
    # The labels, and so the states, are what they were; a record with no
    # expiry date says so in a word (it was a minus icon and a dash).
    assert sorted(b['text'] for b in server) == ['Due', 'Expired', 'Overdue', 'Valid'], server
    assert sorted(b['text'] for b in client) == ['Active', 'Revoked'], client
    assert [b['text'] for b in inventory][3:5] == ['Expired', 'Unknown'] and len(inventory) == 6, inventory
    # The revocation answer under the expiry is the same pill, in the same cell.
    assert sorted(b['text'] for b in revocation) == ['Not revoked', 'Revocation unknown', 'Revocation unverified',
                                                      'Revoked', 'Self-signed'], revocation
    odd = [b for b in server + client + inventory + revocation
           if (b['radius'], b['h'], b['fs'], b['icon']) != ('9999px', 20, '12px', True)]
    assert odd == [], odd
    # A category tag is a square chip, never the status pill's shape.
    assert usage and all(b['radius'] == '4px' for b in usage), usage


def test_a_good_badge_is_the_same_green_on_the_three_lists(page):
    server, client, _usage, inventory, revocation = _badges(page)
    server = {b['text']: b for b in server}
    client = {b['text']: b for b in client}
    revocation = {b['text']: b for b in revocation}
    # The inventory rows come in the order of INVENTORY: 60, 20, 3 days, gone, no date, 60.
    ok, due, overdue, gone, nodate, _plain = inventory
    good = [server['Valid'], client['Active'], ok, revocation['Not revoked']]
    looks = {(b['bg'], b['color'], b['ring']) for b in good}
    assert len(looks) == 1, good
    # And each state keeps its colour: the inventory pills read like the server ones.
    assert due['color'] == server['Due']['color'], (due, server['Due'])
    assert overdue['color'] == gone['color'] == server['Overdue']['color'] == server['Expired']['color'], \
        (overdue, gone, server)
    assert client['Revoked']['color'] == server['Expired']['color'], (client['Revoked'], server['Expired'])
    assert revocation['Revoked']['color'] == server['Expired']['color'], revocation['Revoked']
    # Not known is neither good nor bad: the neutral grey of the other unknowns.
    neutral = {(b['bg'], b['color']) for b in (nodate, revocation['Revocation unknown'],
                                                revocation['Revocation unverified'], revocation['Self-signed'])}
    assert len(neutral) == 1 and nodate['color'] not in (ok['color'], due['color'], gone['color']), neutral


# --- P69: decorative icons are muted ------------------------------------------

ICONS = """([root, skip]) => {
  const probe = (cls) => { const s = document.createElement('span'); s.className = cls; document.body.appendChild(s);
    const c = getComputedStyle(s).color; s.remove(); return c; };
  const muted = probe('text-muted'), primary = probe('text-primary');
  const rgb = c => (c.match(/[0-9.]+/g) || []).map(Number);
  return [...document.querySelectorAll(root + ' i.fas, ' + root + ' i.fab')]
    .filter(i => i.getBoundingClientRect().height > 0 && !(skip && i.closest(skip)))
    .map(i => { const c = getComputedStyle(i).color, p = rgb(c);
      return {near: (i.parentElement.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 30), cls: i.className,
              colour: c, muted: c === muted, primary: c === primary,
              hue: Math.max(p[0], p[1], p[2]) - Math.min(p[0], p[1], p[2]) > 40,
              current: !!i.closest('[aria-current]')}; });
}"""
# Icons that carry a state keep its colour: a callout (info, warning, error),
# a status line, an error, the line under the CA picker (on an instance with
# no usable CA it warns which one needs what).
STATUS_PARTS = ('.bg-info-surface, .bg-warning-surface, .bg-danger-surface, .bg-success-surface, '
                '[role=status], [role=alert], #caa_warning, #ca-provider-info')


@pytest.mark.parametrize('form', ['server', 'client'])
def test_the_create_drawer_s_field_icons_are_muted(page, form):
    _open(page, '/')
    page.evaluate(f"() => openCertDrawer('{form}')")
    _settled(page, '#createCertFormContainer')
    icons = page.evaluate(ICONS, [f'#form-{form}', STATUS_PARTS])
    assert len(icons) >= 5, icons
    hued = [i for i in icons if i['hue'] and not i['primary']]
    assert hued == [], f'{form}: decorative icons in a colour: {hued}'


def test_help_s_section_icons_are_muted_and_the_current_one_primary(page):
    _open(page, '/help#troubleshooting')
    nav = page.evaluate(ICONS, ['nav[aria-label="Help sections"]', None])
    current = [i for i in nav if i['current']]
    assert [i['near'] for i in current] == ['Troubleshooting'], nav
    assert current[0]['primary'], current
    others = [i for i in nav if not i['current'] and not i['muted']]
    assert others == [], others
    headings = page.evaluate(ICONS, ['[data-help-section] h3', None])
    hued = [i for i in headings if i['hue'] and not i['primary']]
    assert headings and hued == [], hued
    # Following another section link moves it.
    page.click('nav[aria-label="Help sections"] a[href="#api-usage"]')
    page.wait_for_function("""() => document.querySelector(
        'nav[aria-label="Help sections"] [aria-current]')?.getAttribute('href') === '#api-usage'""")
