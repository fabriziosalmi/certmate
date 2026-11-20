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
    // The title is the tab's h2 and its sections are h3 (#1511, P63). A
    // provider account's name in its list is an h4, and not a section.
    const subsections = [...panel.querySelectorAll('h3, h4, h5, h6')]
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


# The text room (content width) of every text field of General, of every DNS
# provider and of every storage backend at 360 and 390 px, measured on main
# (179b474) before the shell with the probe below (#1511 review). The card's
# border and padding are left out below sm, so on a phone no field may be
# narrower than it was. Widths, not placeholders: a field's width comes from
# the layout (none of these shares a row with text at these widths, checked on
# main), while whether a placeholder fits depends on the fonts of the platform.
# One exception: on main the .pfx password field was a fixed 288 px and ran
# 19 px past its panel at 360 px (room 262); its baseline is its room at the
# panel's width.
FIELD_ROOM_ON_MAIN = {
    360: {
        'acme-dns_api_url': 209, 'acme-dns_password': 209, 'acme-dns_subdomain': 209, 'acme-dns_username': 209,
        'api_bearer_token': 193, 'arvancloud_api_key': 209, 'aws-access-key-id': 193, 'aws-assume-role-arn': 193,
        'aws-region': 193, 'aws-secret-access-key': 193, 'azure-client-id': 193, 'azure-client-secret': 193,
        'azure-tenant-id': 193, 'azure-vault-url': 193, 'azure_client_id': 209, 'azure_client_secret': 209,
        'azure_resource_group': 209, 'azure_subscription_id': 209, 'azure_tenant_id': 209, 'cache_ttl': 102,
        'cloudflare_api_token': 209, 'custom-script_auth_hook': 209, 'custom-script_cleanup_hook': 209,
        'desec_api_token': 209, 'digitalocean_api_token': 209, 'dns_propagation_current': 102,
        'dnsmadeeasy_api_key': 209, 'dnsmadeeasy_secret_key': 209, 'duckdns_api_token': 209, 'dynudns_token': 209,
        'edgedns_access_token': 209, 'edgedns_client_secret': 209, 'edgedns_client_token': 209, 'edgedns_host': 209,
        'gandi_api_token': 209, 'godaddy_api_key': 209, 'godaddy_secret': 209, 'google_project_id': 209,
        'google_service_account_key': 209, 'he_ddns_password': 209, 'he_ddns_username': 209,
        'hetzner-cloud_api_token': 209, 'hetzner_api_token': 209, 'infisical-client-id': 193,
        'infisical-client-secret': 193, 'infisical-environment': 193, 'infisical-project-id': 193,
        'infisical-site-url': 193, 'infomaniak_api_token': 209, 'linode_api_key': 209, 'namecheap_api_key': 209,
        'namecheap_username': 209, 'nsone_api_key': 209, 'ovh_application_key': 209, 'ovh_application_secret': 209,
        'ovh_consumer_key': 209, 'pfx_password': 243, 'porkbun_api_key': 209, 'porkbun_secret_key': 209,
        'powerdns_api_key': 209, 'powerdns_api_url': 209, 'renewal_threshold_days': 102, 'rfc2136_nameserver': 209,
        'rfc2136_tsig_key': 209, 'rfc2136_tsig_secret': 209, 'route53_access_key_id': 209,
        'route53_assume_role_arn': 209, 'route53_region': 209, 'route53_secret_access_key': 209,
        's3-access-key-id': 193, 's3-assume-role-arn': 193, 's3-bucket': 193, 's3-endpoint-url': 193,
        's3-prefix': 193, 's3-region': 193, 's3-secret-access-key': 193, 'scaleway_application_token': 209,
        'solidserver_dns_name': 209, 'solidserver_dnsview_name': 209, 'solidserver_host': 209,
        'solidserver_password': 209, 'solidserver_propagation_seconds': 209, 'solidserver_username': 209,
        'storage-cert-dir': 193, 'vault-mount-point': 193, 'vault-token': 193, 'vault-url': 193,
        'vultr_api_key': 209,
    },
    390: {
        'acme-dns_api_url': 239, 'acme-dns_password': 239, 'acme-dns_subdomain': 239, 'acme-dns_username': 239,
        'api_bearer_token': 223, 'arvancloud_api_key': 239, 'aws-access-key-id': 223, 'aws-assume-role-arn': 223,
        'aws-region': 223, 'aws-secret-access-key': 223, 'azure-client-id': 223, 'azure-client-secret': 223,
        'azure-tenant-id': 223, 'azure-vault-url': 223, 'azure_client_id': 239, 'azure_client_secret': 239,
        'azure_resource_group': 239, 'azure_subscription_id': 239, 'azure_tenant_id': 239, 'cache_ttl': 102,
        'cloudflare_api_token': 239, 'custom-script_auth_hook': 239, 'custom-script_cleanup_hook': 239,
        'desec_api_token': 239, 'digitalocean_api_token': 239, 'dns_propagation_current': 102,
        'dnsmadeeasy_api_key': 239, 'dnsmadeeasy_secret_key': 239, 'duckdns_api_token': 239, 'dynudns_token': 239,
        'edgedns_access_token': 239, 'edgedns_client_secret': 239, 'edgedns_client_token': 239, 'edgedns_host': 239,
        'gandi_api_token': 239, 'godaddy_api_key': 239, 'godaddy_secret': 239, 'google_project_id': 239,
        'google_service_account_key': 239, 'he_ddns_password': 239, 'he_ddns_username': 239,
        'hetzner-cloud_api_token': 239, 'hetzner_api_token': 239, 'infisical-client-id': 223,
        'infisical-client-secret': 223, 'infisical-environment': 223, 'infisical-project-id': 223,
        'infisical-site-url': 223, 'infomaniak_api_token': 239, 'linode_api_key': 239, 'namecheap_api_key': 239,
        'namecheap_username': 239, 'nsone_api_key': 239, 'ovh_application_key': 239, 'ovh_application_secret': 239,
        'ovh_consumer_key': 239, 'pfx_password': 262, 'porkbun_api_key': 239, 'porkbun_secret_key': 239,
        'powerdns_api_key': 239, 'powerdns_api_url': 239, 'renewal_threshold_days': 102, 'rfc2136_nameserver': 239,
        'rfc2136_tsig_key': 239, 'rfc2136_tsig_secret': 239, 'route53_access_key_id': 239,
        'route53_assume_role_arn': 239, 'route53_region': 239, 'route53_secret_access_key': 239,
        's3-access-key-id': 223, 's3-assume-role-arn': 223, 's3-bucket': 223, 's3-endpoint-url': 223,
        's3-prefix': 223, 's3-region': 223, 's3-secret-access-key': 223, 'scaleway_application_token': 239,
        'solidserver_dns_name': 239, 'solidserver_dnsview_name': 239, 'solidserver_host': 239,
        'solidserver_password': 239, 'solidserver_propagation_seconds': 239, 'solidserver_username': 239,
        'storage-cert-dir': 223, 'vault-mount-point': 223, 'vault-token': 223, 'vault-url': 223,
        'vultr_api_key': 239,
    },
}
TEXT_FIELDS = """(id) => {
    const out = {};
    const sel = 'input[type=text], input[type=password], input[type=url], input[type=email], input[type=number], '
        + 'input[type=search], input:not([type]), textarea';
    const ctx = document.createElement('canvas').getContext('2d');
    for (const f of document.getElementById('settings-panel-' + id).querySelectorAll(sel)) {
        if (!f.checkVisibility() || !f.id) continue;
        const st = getComputedStyle(f);
        const room = f.clientWidth - parseFloat(st.paddingLeft) - parseFloat(st.paddingRight);
        ctx.font = `${st.fontStyle} ${st.fontWeight} ${st.fontSize} ${st.fontFamily}`;
        const cut = !!f.placeholder && ctx.measureText(f.placeholder).width > room + 0.5;
        out[f.id] = [Math.round(room * 100) / 100, cut];
    }
    return out;
}"""


def _visit(page, tab):
    """Every state of the tab that shows other fields: each DNS provider, each
    storage backend. The smallest room a field has in any of them counts."""
    page.goto('about:blank')
    page.goto(f'{BASE_URL}/settings#{tab}', wait_until='networkidle')
    page.wait_for_function(f"() => document.getElementById('settings-panel-{tab}').checkVisibility()")
    seen = {}

    def take():
        for field, (room, cut) in page.evaluate(TEXT_FIELDS, tab).items():
            if field not in seen or room < seen[field][0]:
                seen[field] = (room, cut)

    if tab == 'dns':
        for provider in page.evaluate(
                "() => [...document.querySelectorAll('input[name=\"dns_provider\"]')].map(i => i.value)"):
            page.click(f'label:has(input[name="dns_provider"][value="{provider}"])')
            take()
    elif tab == 'storage':
        for backend in page.evaluate(
                "() => [...document.querySelectorAll('#storage-backend option')].map(o => o.value)"):
            page.select_option('#storage-backend', backend)
            take()
    else:
        take()
    return seen


def _why_not_seen(page, fields):
    """A field of main the test did not see is accepted for one reason only,
    read from the server: it is a provider's single-credential field (in
    #<provider>-legacy-config), and that provider has accounts, so the page
    lists the accounts in its place. That is what an earlier test leaves
    behind (a Cloudflare account): the provider's box then holds account cards
    and no text field, and its token is edited in the account dialog, which is
    not in the tab. Returns (accepted with their reason, unexplained)."""
    accepted, unexplained = {}, []
    for field in fields:
        holder = page.evaluate(
            "(id) => { const f = document.getElementById(id); const c = f && f.closest('[id$=\"-legacy-config\"]');"
            " return c ? c.id.slice(0, -'-legacy-config'.length) : null; }", field)
        if not holder:
            unexplained.append(f'{field} (not a provider credential field)')
            continue
        answer = page.request.get(f'{BASE_URL}/api/dns/{holder}/accounts')
        accounts = answer.json() if answer.ok else None
        if isinstance(accounts, list) and accounts:
            accepted[field] = f'{holder} has {len(accounts)} account(s)'
        else:
            unexplained.append(f'{field} ({holder} accounts: HTTP {answer.status}, {accounts!r})')
    return accepted, unexplained


@pytest.mark.parametrize('width', [360, 390])
def test_on_a_phone_the_tab_card_takes_no_room_from_the_fields(browser_page, ui_session_cookie, width):
    """With its border and padding at every width, the card took 50 px from
    the General and DNS fields on a phone and 18 from the Storage ones."""
    context = browser_page.context.browser.new_context(viewport={'width': width, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    try:
        page = context.new_page()
        seen = {}
        for tab in ('general', 'dns', 'storage'):
            seen.update(_visit(page, tab))
        baseline = FIELD_ROOM_ON_MAIN[width]
        absent, missing = _why_not_seen(page, sorted(set(baseline) - set(seen)))
        narrower = {field: (seen[field][0], room) for field, room in baseline.items()
                    if field in seen and seen[field][0] < room - 0.5}
        # Information only: whether a placeholder fits depends on the fonts.
        cut = sorted(field for field, (_, is_cut) in seen.items() if is_cut)
        assert not missing and not narrower, (
            f'at {width} px, fields narrower than on main (now, main): {narrower}; '
            f'fields of main not seen, with no reason the server confirms: {missing}; '
            f'not seen because the server says their provider has accounts: {absent}; '
            f'placeholders cut here ({len(cut)}, for information): {cut}')
        # Measured in the other state, so a skip there is not silent.
        print(f'at {width} px: {len(baseline) - len(absent)} fields compared with main, '
              f'{len(absent)} hidden by accounts: {absent}')
    finally:
        context.close()


def test_the_sections_of_general_dns_and_storage_are_14px_semibold(settings_page):
    seen = _titles(settings_page)
    odd = {tab: seen[tab]['subsections'] for tab in ('general', 'dns', 'storage')
           if seen[tab] and seen[tab]['subsections']}
    assert not odd, f'sections not 14px/600: {odd}'
