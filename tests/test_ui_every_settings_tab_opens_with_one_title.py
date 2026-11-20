"""Every settings tab opens in the same shell (UX perception audit, #1511, P66).

Nine tabs opened with a bordered card, an 18px/600 title with an icon and a
description line. General opened with a 16px/600 "Appearance" and no card,
and DNS and Storage with a 14px/500 label in a grey panel and no title at all:
the first words of the page sat 9 to 25 px apart from tab to tab. Inside
General, DNS and Storage the sections were 16px/600, 14px/500 and 18px/500.
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

TITLE = """(id) => {
    const panel = document.getElementById('settings-panel-' + id);
    const shown = e => e.getClientRects().length > 0;
    const heading = [...panel.querySelectorAll('h1, h2, h3, h4, h5, h6')].find(shown);
    if (!heading) return null;
    const st = getComputedStyle(heading);
    // The card the title is in: the nearest box with a border, up to the panel.
    let card = null;
    for (let e = heading.parentElement; e; e = e.parentElement) {
        const cs = getComputedStyle(e);
        if (parseFloat(cs.borderTopWidth) > 0 && cs.boxShadow !== 'none') { card = e; break; }
        if (e === panel) break;
    }
    // A provider account's name in its list is an h5 too, and not a section.
    const subsections = [...panel.querySelectorAll('h4, h5, h6')]
        .filter(h => shown(h) && !h.closest('[id$="-accounts-list"]'))
        .map(h => [h.innerText.trim().slice(0, 30), getComputedStyle(h).fontSize, getComputedStyle(h).fontWeight])
        .filter(([, size, weight]) => size !== '14px' || weight !== '600');
    return {text: heading.innerText.trim(), size: st.fontSize, weight: st.fontWeight,
            top: heading.getBoundingClientRect().top + scrollY, card: !!card, icon: !!heading.querySelector('i'),
            subsections};
}"""


@pytest.fixture
def settings_page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.goto(f'{BASE_URL}/settings#general', wait_until='networkidle')
    yield page
    context.close()


def _titles(page):
    seen = {}
    for tab in TABS:
        page.evaluate(f"location.hash = '#{tab}'")
        page.wait_for_function(f"() => document.getElementById('settings-panel-{tab}').checkVisibility()")
        seen[tab] = page.evaluate(TITLE, tab)
    return seen


def test_every_settings_tab_opens_with_an_18px_semibold_title_at_the_same_height(settings_page):
    seen = _titles(settings_page)
    untitled = [tab for tab, title in seen.items() if not title]
    assert not untitled, f'no heading in: {untitled}'
    wrong = {tab: (t['text'], t['size'], t['weight']) for tab, t in seen.items()
             if (t['size'], t['weight']) != ('18px', '600')}
    assert not wrong, f'first heading not 18px/600: {wrong}'
    tops = {tab: round(t['top']) for tab, t in seen.items()}
    assert max(tops.values()) - min(tops.values()) <= 2, f'the titles are not at one height: {tops}'


def test_every_settings_tab_title_has_an_icon_and_sits_in_a_bordered_card(settings_page):
    seen = _titles(settings_page)
    bare = {tab: t and (t['card'], t['icon']) for tab, t in seen.items() if not (t and t['card'] and t['icon'])}
    assert not bare, f'title without a bordered card or an icon (card, icon): {bare}'


OUTSIDE = """(id) => {
    const panel = document.getElementById('settings-panel-' + id);
    const box = panel.getBoundingClientRect();
    return [...panel.querySelectorAll('input, select, textarea, button, a')].filter(c => {
        const r = c.getBoundingClientRect();
        // A radio drawn as a card is sr-only: a 1 px box, not a control on screen.
        return c.getClientRects().length && r.width > 1 && r.height > 1
            && (r.left < box.left - 0.5 || r.right > box.right + 0.5);
    }).map(c => [c.id || c.name || c.innerText.trim().slice(0, 20), Math.round(c.getBoundingClientRect().left),
                 Math.round(c.getBoundingClientRect().right), Math.round(box.left), Math.round(box.right)]);
}"""


PLACEHOLDERS = """(id) => {
    const ctx = document.createElement('canvas').getContext('2d');
    return [...document.getElementById('settings-panel-' + id).querySelectorAll('input[placeholder]')]
        .filter(f => f.getClientRects().length && f.placeholder).map(f => {
            const st = getComputedStyle(f);
            ctx.font = `${st.fontStyle} ${st.fontWeight} ${st.fontSize} ${st.fontFamily}`;
            const text = ctx.measureText(f.placeholder).width;
            const room = f.clientWidth - parseFloat(st.paddingLeft) - parseFloat(st.paddingRight);
            return [f.id, Math.ceil(text), Math.floor(room)];
        }).filter(([, text, room]) => text > room);
}"""


@pytest.mark.parametrize('width', [360, 390])
def test_on_a_phone_every_control_of_general_dns_and_storage_stays_inside_its_card(
        browser_page, ui_session_cookie, width):
    """In its new card the Windows .pfx password field (a fixed 288 px)
    crossed the General card at 390 px, and the Settings card too at 360."""
    context = browser_page.context.browser.new_context(viewport={'width': width, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    try:
        page = context.new_page()
        page.goto(f'{BASE_URL}/settings#general', wait_until='networkidle')
        outside = {}
        for tab in ('general', 'dns', 'storage'):
            page.evaluate(f"location.hash = '#{tab}'")
            page.wait_for_function(f"() => document.getElementById('settings-panel-{tab}').checkVisibility()")
            found = page.evaluate(OUTSIDE, tab)
            if found:
                outside[tab] = found
        assert not outside, f'at {width} px, controls past their card (name, left, right, card left, right): {outside}'
        # A placeholder cut by its field reads as another sentence: "Leave
        # blank to keep the current password" showed as "Leave blank to keep
        # the curre" at 360 px. Measured in the field's own font.
        page.evaluate("location.hash = '#general'")
        page.wait_for_function("() => document.getElementById('settings-panel-general').checkVisibility()")
        cut = page.evaluate(PLACEHOLDERS, 'general')
        assert not cut, f'at {width} px, placeholders wider than their field (id, text px, room px): {cut}'
    finally:
        context.close()


# A field as wide as the panel, per tab, and its text room on main before the
# shell (#1511 review): the card's border and padding are left out below sm,
# so on a phone the fields are no narrower than they were. Linode's key and the
# local directory are shown whatever the instance holds once their provider or
# backend is chosen (Cloudflare's token hides when it has accounts).
ROOM_ON_MAIN = {
    360: {'general': ('api_bearer_token', 193), 'dns': ('linode_api_key', 209),
          'storage': ('storage-cert-dir', 193)},
    390: {'general': ('api_bearer_token', 223), 'dns': ('linode_api_key', 239),
          'storage': ('storage-cert-dir', 223)},
}

# Placeholders already wider than their field on main, measured for every DNS
# provider and storage backend before the shell. They are a follow-up of their
# own; what this test refuses is one more.
CUT_ON_MAIN = {
    360: {
        'azure_client_id', 'azure_subscription_id', 'azure_tenant_id', 'cloudflare_api_token',
        'custom-script_auth_hook', 'custom-script_cleanup_hook', 'desec_api_token', 'digitalocean_api_token',
        'dnsmadeeasy_api_key', 'dnsmadeeasy_secret_key', 'duckdns_api_token', 'edgedns_access_token',
        'edgedns_client_token', 'edgedns_host', 'gandi_api_token', 'google_service_account_key',
        'he_ddns_password', 'he_ddns_username', 'hetzner-cloud_api_token', 'hetzner_api_token',
        'powerdns_api_url', 'route53_assume_role_arn', 'route53_secret_access_key',
        'scaleway_application_token', 'solidserver_dns_name',
        'aws-assume-role-arn', 'azure-client-id', 'azure-tenant-id', 'azure-vault-url', 's3-assume-role-arn',
        's3-endpoint-url', 'vault-url',
    },
    390: {
        'azure_client_id', 'azure_subscription_id', 'azure_tenant_id', 'custom-script_auth_hook',
        'custom-script_cleanup_hook', 'desec_api_token', 'dnsmadeeasy_secret_key', 'duckdns_api_token',
        'edgedns_access_token', 'edgedns_client_token', 'google_service_account_key', 'he_ddns_password',
        'he_ddns_username', 'hetzner-cloud_api_token', 'powerdns_api_url', 'route53_assume_role_arn',
        'solidserver_dns_name',
        'aws-assume-role-arn', 'azure-client-id', 'azure-tenant-id', 's3-assume-role-arn', 's3-endpoint-url',
    },
}

CUT_PLACEHOLDERS = """(id) => {
    const ctx = document.createElement('canvas').getContext('2d');
    const panel = document.getElementById('settings-panel-' + id);
    return [...panel.querySelectorAll('input[placeholder], textarea[placeholder]')]
        .filter(f => f.checkVisibility() && f.placeholder).filter(f => {
            const st = getComputedStyle(f);
            ctx.font = `${st.fontStyle} ${st.fontWeight} ${st.fontSize} ${st.fontFamily}`;
            return ctx.measureText(f.placeholder).width > f.clientWidth - parseFloat(st.paddingLeft)
                - parseFloat(st.paddingRight) + 0.5;
        }).map(f => f.id || f.name);
}"""

ROOM = """(id) => { const e = document.getElementById(id); const st = getComputedStyle(e);
    return Math.round(e.clientWidth - parseFloat(st.paddingLeft) - parseFloat(st.paddingRight)); }"""


@pytest.mark.parametrize('width', [360, 390])
def test_on_a_phone_the_tab_card_takes_no_room_from_the_fields(browser_page, ui_session_cookie, width):
    """With its border and padding at every width, the card took 50 px from
    the General and DNS fields on a phone and 18 from the Storage ones: 22
    more placeholders were cut at 360 px and 19 more at 390."""
    context = browser_page.context.browser.new_context(viewport={'width': width, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    try:
        page = context.new_page()
        narrower, cut = {}, set()
        for tab, (field, room) in ROOM_ON_MAIN[width].items():
            page.goto('about:blank')
            page.goto(f'{BASE_URL}/settings#{tab}', wait_until='networkidle')
            page.wait_for_function(f"() => document.getElementById('settings-panel-{tab}').checkVisibility()")
            if tab == 'dns':
                page.click('label:has(input[name="dns_provider"][value="linode"])')
            elif tab == 'storage':
                page.select_option('#storage-backend', 'local_filesystem')
            now = page.evaluate(ROOM, field)
            if now < room:
                narrower[field] = (now, room)
            if tab == 'dns':
                for provider in page.evaluate(
                        "() => [...document.querySelectorAll('input[name=\"dns_provider\"]')].map(i => i.value)"):
                    page.click(f'label:has(input[name="dns_provider"][value="{provider}"])')
                    cut.update(page.evaluate(CUT_PLACEHOLDERS, tab))
            elif tab == 'storage':
                for backend in page.evaluate(
                        "() => [...document.querySelectorAll('#storage-backend option')].map(o => o.value)"):
                    page.select_option('#storage-backend', backend)
                    cut.update(page.evaluate(CUT_PLACEHOLDERS, tab))
            else:
                cut.update(page.evaluate(CUT_PLACEHOLDERS, tab))
        new = sorted(cut - CUT_ON_MAIN[width])
        assert not narrower and not new, (
            f'at {width} px, fields narrower than on main (now, main): {narrower}; '
            f'placeholders cut that were whole on main ({len(new)}): {new}')
    finally:
        context.close()


def test_the_sections_of_general_dns_and_storage_are_14px_semibold(settings_page):
    seen = _titles(settings_page)
    odd = {tab: seen[tab]['subsections'] for tab in ('general', 'dns', 'storage')
           if seen[tab] and seen[tab]['subsections']}
    assert not odd, f'sections not 14px/600: {odd}'
