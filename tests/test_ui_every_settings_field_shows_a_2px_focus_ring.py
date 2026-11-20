"""Every settings field reached by Tab shows a 2 px focus ring (UX perception audit, #1511, P62).

The settings fields carried `focus:outline-none focus:ring-primary` with no ring
width, and without the forms plugin that draws no ring: on focus by keyboard
the only change was their 1 px border turning blue, about 2:1 against the
unfocused border in the dark theme. A few fields (the probe's domain, the
create drawer's) had `focus:ring-2` and showed a 2 px ring. Now one rule in
static/css/input.css gives every text field, select and textarea the same
2 px ring in the accent colour on :focus-visible, and it replaces the ring of
a field that had its own, so none draws two.

The fields are reached the way a keyboard user reaches them: the walk starts
at the top of a tab (and of each DNS provider's and storage backend's form)
and presses Tab, and what is measured is the computed style of the focused
element. A field on screen that Tab did not reach fails, and so does a field
of a tab that the walk never saw, unless the server confirms why it is not
on screen (a provider with accounts lists them in place of its token field).
"""
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

TABS = ['general', 'dns', 'ca', 'storage', 'deploy', 'probe', 'acme', 'users', 'apikeys', 'oidc',
        'notifications', 'backup']

# The form controls the rule is for: text-like inputs, selects, textareas.
# Checkboxes, radios, switches and buttons keep their own focus styles.
FIELDS = ('input:not([type=checkbox]):not([type=radio]):not([type=range]):not([type=file]):not([type=color])'
          ':not([type=hidden]):not([type=button]):not([type=submit]):not([type=reset]):not([type=image]), '
          'select, textarea')

# Puts a focus starting point (not itself in the tab order) at the top of the
# scope and focuses it, so the next Tab reaches the scope's first control.
START = """(scope) => {
    const root = document.querySelector(scope);
    const start = document.createElement('span');
    start.tabIndex = -1;
    start.id = '__focus_walk_start';
    root.prepend(start);
    start.focus();
    return document.activeElement === start;
}"""
STOP = "() => { const s = document.getElementById('__focus_walk_start'); if (s) s.remove(); }"

# What the focused element shows. A ring is a box-shadow with no offset and no
# blur; the band of it that is seen is its spread less the spread of the
# shadows drawn above it (a ring offset is one). Each band and the outline are
# composited over the colour behind the field, and a band counts as a focus
# indicator when it differs from that colour by 3:1 (WCAG 1.4.11).
MEASURE = """([scope, fields]) => {
    const el = document.activeElement;
    const root = document.querySelector(scope);
    if (!el || el === document.body || !root.contains(el)) return {outside: true};
    if (!el.matches(fields)) return {outside: false, field: false};
    const rgba = c => { const m = (c.match(/[0-9.]+/g) || []).map(Number);
        return m.length >= 3 ? [m[0], m[1], m[2], m.length > 3 ? m[3] : 1] : [0, 0, 0, 0]; };
    const over = (top, bottom) => [0, 1, 2].map(i => top[i] * top[3] + bottom[i] * (1 - top[3]));
    const lum = c => { const p = c.map(v => { v /= 255;
            return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); });
        return 0.2126 * p[0] + 0.7152 * p[1] + 0.0722 * p[2]; };
    const ratio = (a, b) => { const x = lum(a), y = lum(b); return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05); };
    const layers = [];
    for (let e = el.parentElement; e; e = e.parentElement) {
        const c = rgba(getComputedStyle(e).backgroundColor);
        if (c[3] > 0) layers.push(c);
        if (c[3] >= 1) break;
    }
    let bg = [255, 255, 255];
    for (const c of layers.reverse()) bg = over(c, bg);
    const st = getComputedStyle(el);
    const shadows = [];
    let depth = 0;
    for (const part of st.boxShadow === 'none' ? [] : st.boxShadow.split(/,(?![^(]*\\))/)) {
        const colour = (part.match(/rgba?\\([^)]*\\)/) || ['rgba(0,0,0,0)'])[0];
        const lengths = part.replace(colour, '').trim().split(/\\s+/).filter(t => t.endsWith('px')).map(parseFloat);
        const [x, y, blur, spread] = [lengths[0] || 0, lengths[1] || 0, lengths[2] || 0, lengths[3] || 0];
        const ring = !/inset/.test(part) && x === 0 && y === 0 && blur === 0 && spread > 0;
        if (!ring) continue;
        const band = Math.max(0, spread - depth);
        depth = Math.max(depth, spread);
        const c = rgba(colour);
        shadows.push({band, contrast: c[3] > 0 ? Math.round(ratio(over(c, bg), bg) * 100) / 100 : 1, colour});
    }
    const oc = rgba(st.outlineColor);
    const outline = st.outlineStyle !== 'none' && parseFloat(st.outlineWidth) > 0 && oc[3] > 0
        ? {width: parseFloat(st.outlineWidth), contrast: Math.round(ratio(over(oc, bg), bg) * 100) / 100} : null;
    const visible = shadows.filter(s => s.band > 0 && s.contrast >= 3);
    // A ring cut off by a box that hides its overflow is not seen either:
    // across, by any clipping box; up and down, by one that does not scroll
    // (a scrolling list may leave a focused field at its very edge).
    const r = el.getBoundingClientRect();
    const clippedBy = [];
    for (let e = el.parentElement; e && e !== document.body; e = e.parentElement) {
        const cs = getComputedStyle(e);
        const b = e.getBoundingClientRect();
        const left = b.left + parseFloat(cs.borderLeftWidth), right = left + e.clientWidth;
        const top = b.top + parseFloat(cs.borderTopWidth), bottom = top + e.clientHeight;
        const across = cs.overflowX !== 'visible' && (r.left - 2 < left - 0.5 || r.right + 2 > right + 0.5);
        const down = ['hidden', 'clip'].includes(cs.overflowY) && (r.top - 2 < top - 0.5 || r.bottom + 2 > bottom + 0.5);
        if (across || down) clippedBy.push(e.id || e.className.toString().slice(0, 40));
    }
    return {outside: false, field: true, key: el.id || el.name || el.outerHTML.slice(0, 60), clippedBy,
            focusVisible: el.matches(':focus-visible'), rings: visible.map(s => [s.band, s.contrast]),
            outline: outline && outline.contrast >= 3 ? [outline.width, outline.contrast] : null,
            boxShadow: st.boxShadow, background: bg.map(Math.round)};
}"""

ON_SCREEN = """([scope, fields]) => [...document.querySelector(scope).querySelectorAll(fields)]
    .filter(f => f.checkVisibility({visibilityProperty: true}) && !f.disabled && f.tabIndex >= 0
                 && !f.closest('[inert]'))
    .map(f => f.id || f.name || f.outerHTML.slice(0, 60))"""

IN_DOM = """([tabs, fields]) => Object.fromEntries(tabs.map(t => [t,
    [...document.getElementById('settings-panel-' + t).querySelectorAll(fields)]
        .map(f => f.id || f.name || f.outerHTML.slice(0, 60))]))"""


def _walk(page, scope, seen, unreached):
    """Tab through `scope` from its top; measure every field focused on the way."""
    expected = set(page.evaluate(ON_SCREEN, [scope, FIELDS]))
    assert page.evaluate(START, scope), f'could not start the keyboard walk in {scope}'
    reached = set()
    try:
        for _ in range(400):
            page.keyboard.press('Tab')
            focus = page.evaluate(MEASURE, [scope, FIELDS])
            if focus['outside']:
                break
            if focus['field']:
                reached.add(focus['key'])
                seen.setdefault(focus['key'], focus)
        else:
            raise AssertionError(f'400 presses of Tab did not leave {scope}')
    finally:
        page.evaluate(STOP)
    for key in expected - reached:
        unreached.append(f'{scope}: {key}')


def _why_not_seen(page, fields):
    """A field of a tab the walk never saw is accepted for one reason only, read
    from the server: it is a provider's single-credential field (in
    #<provider>-legacy-config) and that provider has accounts, so the page lists
    the accounts in its place (what an earlier test leaves behind)."""
    accepted, unexplained = {}, []
    for field in fields:
        holder = page.evaluate(
            "(id) => { const f = document.getElementById(id); const c = f && f.closest('[id$=\"-legacy-config\"]');"
            " return c ? c.id.slice(0, -'-legacy-config'.length) : null; }", field)
        if not holder:
            unexplained.append(field)
            continue
        answer = page.request.get(f'{BASE_URL}/api/dns/{holder}/accounts')
        accounts = answer.json() if answer.ok else None
        if isinstance(accounts, list) and accounts:
            accepted[field] = f'{holder} has {len(accounts)} account(s)'
        else:
            unexplained.append(f'{field} ({holder} accounts: HTTP {answer.status}, {accounts!r})')
    return accepted, unexplained


# Fields a tab shows only once something on it is set or opened. Each is
# revealed the way a person does it, on a fresh page that is closed without
# saving, and walked: (tab, what is done, the scope walked).
REVEALS = [
    ('general', [('select', '#default_key_type', 'ecdsa')], '#default_elliptic_curve_container'),
    ('notifications', [('switch_on', '#settings-panel-notifications input[x-model="config.enabled"]'),
                       ('click', '#settings-panel-notifications button:has-text("Email (SMTP)")'),
                       ('click', '#settings-panel-notifications button:has-text("Webhooks")')],
     '#settings-panel-notifications'),
    ('acme', [('uncheck', '#settings-panel-acme input[x-model="server.eab_required"]')], '#settings-panel-acme'),
    ('deploy', [('switch_on', '#settings-panel-deploy input[x-model="config.enabled"]'),
                ('click', '#settings-panel-deploy button:has-text("Global Hooks")'),
                ('click', '#settings-panel-deploy button:has-text("Add Global Hook")'),
                ('click', '#settings-panel-deploy button:has-text("Domain-Specific Hooks")')],
     '#settings-panel-deploy'),
]


def _reveal(page, steps):
    for step in steps:
        kind, selector = step[0], step[1]
        if kind == 'select':
            page.select_option(selector, step[2])
        elif kind == 'uncheck':
            page.uncheck(selector)
        elif kind == 'switch_on':
            # A switch is an sr-only checkbox drawn by its label.
            if not page.is_checked(selector):
                page.click(f'{selector} >> xpath=ancestor::label[1]')
            assert page.is_checked(selector), selector
        else:
            page.click(selector)
    page.wait_for_timeout(150)


def _settings(context, tab):
    page = context.new_page()
    page.goto(f'{BASE_URL}/settings#{tab}', wait_until='networkidle')
    page.wait_for_function(f"() => document.getElementById('settings-panel-{tab}').checkVisibility()")
    page.wait_for_timeout(150)
    return page


@pytest.mark.parametrize('scheme', ['light', 'dark'])
def test_every_settings_field_reached_by_tab_shows_one_2px_ring_that_stands_out(
        browser_page, ui_session_cookie, scheme):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900}, color_scheme=scheme)
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    try:
        page = context.new_page()
        page.goto(f'{BASE_URL}/settings#general', wait_until='networkidle')
        assert page.evaluate("document.documentElement.classList.contains('dark')") == (scheme == 'dark')
        in_dom = page.evaluate(IN_DOM, [TABS, FIELDS])
        seen, unreached = {}, []
        for tab, steps, scope in REVEALS:
            revealed = _settings(context, tab)
            _reveal(revealed, steps)
            _walk(revealed, scope, seen, unreached)
            revealed.close()
        for tab in TABS:
            page.evaluate(f"location.hash = '#{tab}'")
            page.wait_for_function(f"() => document.getElementById('settings-panel-{tab}').checkVisibility()")
            page.wait_for_timeout(150)
            _walk(page, f'#settings-panel-{tab}', seen, unreached)
            if tab == 'dns':
                for provider in page.evaluate(
                        "() => [...document.querySelectorAll('input[name=\"dns_provider\"]')].map(i => i.value)"):
                    page.click(f'label:has(input[name="dns_provider"][value="{provider}"])')
                    shown = page.evaluate("() => [...document.querySelectorAll('.dns-config')]"
                                          ".filter(c => c.checkVisibility()).map(c => c.id)")
                    assert len(shown) == 1, f'{provider}: provider forms on screen: {shown}'
                    _walk(page, f'#{shown[0]}', seen, unreached)
            elif tab == 'storage':
                for backend in page.evaluate(
                        "() => [...document.querySelectorAll('#storage-backend option')].map(o => o.value)"):
                    page.select_option('#storage-backend', backend)
                    shown = page.evaluate("() => [...document.querySelectorAll('.storage-config')]"
                                          ".filter(c => c.checkVisibility()).map(c => c.id)")
                    assert len(shown) == 1, f'{backend}: backend forms on screen: {shown}'
                    _walk(page, f'#{shown[0]}', seen, unreached)
        never = sorted({f for fields in in_dom.values() for f in fields} - set(seen))
        hidden_by_accounts, unexplained = _why_not_seen(page, never)
        weak = {key: (f['rings'], f['outline'], f['boxShadow'], f['background']) for key, f in seen.items()
                if not ([r for r in f['rings'] if r[0] >= 2] or (f['outline'] and f['outline'][0] >= 2))}
        doubled = {key: (f['rings'], f['outline']) for key, f in seen.items()
                   if len(f['rings']) + (1 if f['outline'] else 0) > 1}
        not_visible = sorted(key for key, f in seen.items() if not f['focusVisible'])
        clipped = {key: f['clippedBy'] for key, f in seen.items() if f['clippedBy']}
        assert len(seen) >= 80, f'only {len(seen)} fields reached: the walk lost its subject'
        assert not unreached, f'{scheme}: fields on screen that Tab did not reach: {unreached}'
        assert not unexplained, f'{scheme}: settings fields the walk never saw, with no reason: {unexplained}'
        assert not not_visible, f'{scheme}: reached by Tab but not :focus-visible: {not_visible}'
        assert not weak, (f'{scheme}: {len(weak)} of {len(seen)} fields show no 2 px ring or outline at 3:1 '
                          f'(rings, outline, box-shadow, background): {weak}')
        assert not doubled, f'{scheme}: fields with two focus indicators: {doubled}'
        assert not clipped, f'{scheme}: fields whose ring a box cuts off: {clipped}'
        print(f'{scheme}: {len(seen)} fields measured on focus by Tab, '
              f'{len(hidden_by_accounts)} hidden by accounts: {hidden_by_accounts}')
    finally:
        context.close()


# The focus style of the other controls the walk meets on General and Deploy,
# measured by Tab on main (69b9d67) before the field rule: the browser's own
# outline on a checkbox (its colour is the platform's, so only its style and
# width are compared), the 2 px accent outline of a bare button, the .btn ring,
# and the peer ring a switch draws on its track. (scheme, tab, control):
# (outline, box-shadow, the track's box-shadow when the control is sr-only).
OTHER_CONTROLS_ON_MAIN = {
    ('light', 'general', 'Auto'): ('solid 2px rgb(36, 99, 235)', 'rgb(255, 255, 255) 0px 0px 0px 0px, '
                                   'rgb(26, 93, 193) 0px 0px 0px 1px, rgba(0, 0, 0, 0.05) 0px 1px 2px 0px', None),
    ('light', 'general', 'Light'): ('solid 2px rgb(36, 99, 235)', 'none', None),
    ('light', 'general', 'Dark'): ('solid 2px rgb(36, 99, 235)', 'none', None),
    ('light', 'general', 'auto_renew'): ('auto 1px', 'none', None),
    ('light', 'general', 'update_check_enabled'): ('auto 1px', 'none', None),
    ('light', 'general', 'pfx_password_clear'): ('auto 1px', 'none', None),
    ('light', 'general', 'tokenToggleBtn'): ('solid 2px rgb(36, 99, 235)', 'none', None),
    ('light', 'deploy', 'Enable deploy hooks'): ('auto 1px', 'none', 'rgb(255, 255, 255) 0px 0px 0px 0px, '
                                                 'rgb(147, 197, 253) 0px 0px 0px 4px, rgba(0, 0, 0, 0) 0px 0px 0px 0px'),
    ('light', 'deploy', 'deploy-hooks-save'): ('solid 2px rgba(0, 0, 0, 0)', 'rgb(255, 255, 255) 0px 0px 0px 2px, '
                                               'rgb(26, 93, 193) 0px 0px 0px 4px, rgba(0, 0, 0, 0) 0px 0px 0px 0px',
                                               None),
    ('dark', 'general', 'Auto'): ('solid 2px rgb(97, 166, 250)', 'rgb(255, 255, 255) 0px 0px 0px 0px, '
                                  'rgb(26, 93, 193) 0px 0px 0px 1px, rgba(0, 0, 0, 0.05) 0px 1px 2px 0px', None),
    ('dark', 'general', 'Light'): ('solid 2px rgb(97, 166, 250)', 'none', None),
    ('dark', 'general', 'Dark'): ('solid 2px rgb(97, 166, 250)', 'none', None),
    ('dark', 'general', 'auto_renew'): ('auto 1px', 'none', None),
    ('dark', 'general', 'update_check_enabled'): ('auto 1px', 'none', None),
    ('dark', 'general', 'pfx_password_clear'): ('auto 1px', 'none', None),
    ('dark', 'general', 'tokenToggleBtn'): ('solid 2px rgb(97, 166, 250)', 'none', None),
    ('dark', 'deploy', 'Enable deploy hooks'): ('auto 1px', 'none', 'rgb(255, 255, 255) 0px 0px 0px 0px, '
                                                'rgb(30, 64, 175) 0px 0px 0px 4px, rgba(0, 0, 0, 0) 0px 0px 0px 0px'),
    ('dark', 'deploy', 'deploy-hooks-save'): ('solid 2px rgba(0, 0, 0, 0)', 'rgb(31, 41, 55) 0px 0px 0px 2px, '
                                              'rgb(26, 93, 193) 0px 0px 0px 4px, rgba(0, 0, 0, 0) 0px 0px 0px 0px',
                                              None),
}
OTHER = """() => { const el = document.activeElement, st = getComputedStyle(el);
    if (!(el.tagName === 'BUTTON' || ['checkbox', 'radio'].includes(el.type))) return null;
    const track = el.classList.contains('sr-only') ? el.nextElementSibling : null;
    const outline = st.outlineStyle === 'auto' ? 'auto ' + st.outlineWidth
        : st.outlineStyle + ' ' + st.outlineWidth + ' ' + st.outlineColor;
    return [el.id || el.getAttribute('aria-label') || el.innerText.trim().slice(0, 25),
            outline, st.boxShadow, track ? getComputedStyle(track).boxShadow : null]; }"""


@pytest.mark.parametrize('scheme', ['light', 'dark'])
def test_checkboxes_switches_and_buttons_keep_the_focus_style_they_had(browser_page, ui_session_cookie, scheme):
    """The rule is for fields: a checkbox, a switch and a button focused by
    Tab look as they did, and none of them gets the field ring."""
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900}, color_scheme=scheme)
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    try:
        seen = {}
        for tab in ('general', 'deploy'):
            page = _settings(context, tab)
            assert page.evaluate(START, f'#settings-panel-{tab}')
            for _ in range(60):
                page.keyboard.press('Tab')
                if not page.evaluate(f"document.getElementById('settings-panel-{tab}')"
                                     ".contains(document.activeElement)"):
                    break
                control = page.evaluate(OTHER)
                if control:
                    seen[(scheme, tab, control[0])] = tuple(control[1:])
            page.close()
        expected = {key: style for key, style in OTHER_CONTROLS_ON_MAIN.items() if key[0] == scheme}
        assert seen == expected, {key: (seen.get(key), style) for key, style in expected.items()
                                  if seen.get(key) != style} or seen
    finally:
        context.close()
