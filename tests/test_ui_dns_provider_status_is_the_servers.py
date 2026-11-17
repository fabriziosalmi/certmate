"""A DNS provider reads "Configured" only when an account of it can issue (#1469).

The first-run settings carry sixteen providers with every credential empty, and
the migration wraps each in an account named "default". The settings page
counted accounts, so a fresh instance showed Cloudflare, Route53 and fourteen
others as "Configured, 1 accounts" with nothing filled in, and the create form
offered that empty account next to real ones.

The server already decides whether an account has its provider's credentials
(`/api/dns/accounts`, `configured`), and since #1469 issuance asks the same
question. The page shows that answer.
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

REAL = ['ui-status-a', 'ui-status-b']


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    for account in REAL:
        page.request.delete(f'{BASE_URL}/api/dns/cloudflare/accounts/{account}', headers={'Origin': BASE_URL})
    context.close()


def _server(page):
    answer = page.request.get(f'{BASE_URL}/api/dns/accounts')
    assert answer.ok, answer.status
    verdict = {}
    for account in answer.json():
        verdict.setdefault(account['provider'], []).append(account['configured'] is True)
    return verdict


def _cards(page):
    page.goto(f'{BASE_URL}/settings#dns', wait_until='networkidle')
    page.wait_for_function("() => document.getElementById('cloudflare-status').textContent.trim() !== ''")
    page.wait_for_timeout(300)
    return page.evaluate("""() => Object.fromEntries([...document.querySelectorAll('[id$="-status"]')]
        .filter(e => e.closest('#dns-provider-section'))
        .map(e => {
            const provider = e.id.replace(/-status$/, '');
            const line = document.getElementById(provider + '-accounts');
            const count = document.getElementById(provider + '-account-count');
            return [provider, {status: e.textContent.trim(),
                               shown: !!line && !line.classList.contains('invisible'),
                               count: count ? count.textContent.trim() : null}];
        }))""")


def _add(page, account_id):
    answer = page.request.post(f'{BASE_URL}/api/dns/cloudflare/accounts', headers={'Origin': BASE_URL}, data={
        'account_id': account_id, 'name': account_id,
        'config': {'name': account_id, 'api_token': 'x' * 40}})
    assert answer.ok, (answer.status, answer.text()[:200])


def test_every_card_says_what_the_server_says(page):
    verdict = _server(page)
    cards = _cards(page)
    wrong = {}
    for provider, card in cards.items():
        flags = verdict.get(provider, [])
        configured = any(flags)
        expected = {'status': 'Configured' if configured else 'Not configured', 'shown': configured}
        if configured:
            expected['count'] = str(sum(flags))
        if {k: card[k] for k in expected} != expected:
            wrong[provider] = (card, flags)
    assert wrong == {}, wrong
    # And the empty accounts a fresh instance carries do not count.
    empty_only = [p for p, flags in verdict.items() if flags and not any(flags)]
    assert all(cards[p]['status'] == 'Not configured' for p in empty_only if p in cards), empty_only


def test_a_real_account_is_configured_and_the_empty_one_is_marked(page):
    _add(page, REAL[0])
    card = _cards(page)['cloudflare']
    expected_count = str(sum(_server(page)['cloudflare']))
    assert card == {'status': 'Configured', 'shown': True, 'count': expected_count}, card
    empty = [a for a in page.request.get(f'{BASE_URL}/api/dns/accounts').json()
             if a['provider'] == 'cloudflare' and not a['configured']]
    badges = page.locator('#cloudflare-accounts-list').get_by_text('No credentials').count()
    assert badges == len(empty), (badges, empty)


def test_the_create_form_offers_only_accounts_that_can_issue(page):
    for account in REAL:
        _add(page, account)
    page.goto(f'{BASE_URL}/', wait_until='networkidle')
    page.evaluate("() => openCertDrawer('server')")
    page.select_option('#dns_provider_select', 'cloudflare')
    page.wait_for_function("() => document.getElementById('account-selection-container').style.display === 'block'")
    offered = page.evaluate("() => [...document.querySelectorAll('#account_select option')].map(o => o.value)")
    can_issue = sorted(a['account_id'] for a in page.request.get(f'{BASE_URL}/api/dns/accounts').json()
                       if a['provider'] == 'cloudflare' and a['configured'])
    assert sorted(v for v in offered if v) == can_issue, offered
    assert set(REAL) <= set(offered)
