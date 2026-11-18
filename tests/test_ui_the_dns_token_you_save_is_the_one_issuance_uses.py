"""Settings > DNS: the token you save is the one issuance uses, and the
providers stay in reach under HTTP-01 (UX perception audit P05, P21).

P05: on a fresh instance every provider showed an account "Default ...
Account, No credentials, Migrated from single-account configuration", and
under it a single "API Token" field. Saving that field reported success and
wrote the token beside the accounts, where issuance never reads it: the card
still said "No credentials" and the first certificate failed. Adding one
account then showed two cards and a tile counting one.

P21: the setup wizard tells an HTTP-01 user to add a DNS provider later in
Settings, and Settings hid every provider and every Add Account while HTTP-01
was the default.

The server side is tests/test_the_dns_token_you_save_is_the_one_issuance_uses.py.
"""
import os

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
PLACEHOLDER = 'Migrated from single-account configuration'
TOKEN = 'Tk' + 'x7Q2' * 10
ADDED = 'ui-prod-cf'


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1440, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    _clear(page)
    # Until setup is finished the page asks for the CA email before it saves.
    page.request.post(f'{BASE_URL}/api/web/settings', headers={'Origin': BASE_URL},
                      data={'email': 'ops@example.com'})
    yield page
    _clear(page)
    page.request.post(f'{BASE_URL}/api/web/settings', headers={'Origin': BASE_URL},
                      data={'challenge_type': 'dns-01'})
    context.close()


def _clear(page, account=ADDED):
    # Only what a test made: deleting "default" here would also delete the
    # placeholder an unfixed instance carries, and hide the bug.
    page.request.delete(f'{BASE_URL}/api/dns/cloudflare/accounts/{account}', headers={'Origin': BASE_URL})


def _cloudflare_accounts(page):
    answer = page.request.get(f'{BASE_URL}/api/dns/accounts')
    assert answer.ok, answer.status
    return [a for a in answer.json() if a['provider'] == 'cloudflare']


def _open_cloudflare(page):
    page.goto(f'{BASE_URL}/settings#dns', wait_until='networkidle')
    page.wait_for_function("() => document.getElementById('cloudflare-status').textContent.trim() !== ''")
    page.click('label:has(input[name="dns_provider"][value="cloudflare"])')
    page.wait_for_timeout(300)


def test_no_provider_has_an_empty_placeholder_account(page):
    answer = page.request.get(f'{BASE_URL}/api/dns/accounts')
    assert answer.ok, answer.status
    placeholders = [a for a in answer.json() if a.get('description') == PLACEHOLDER]
    assert placeholders == [], placeholders


def test_one_account_added_is_one_card_and_the_tile_counts_it(page):
    answer = page.request.post(f'{BASE_URL}/api/dns/cloudflare/accounts', headers={'Origin': BASE_URL}, data={
        'account_id': ADDED, 'name': ADDED, 'config': {'name': ADDED, 'api_token': TOKEN}})
    assert answer.ok, (answer.status, answer.text()[:200])
    _open_cloudflare(page)
    cards = page.locator('#cloudflare-accounts-list > div')
    assert cards.count() == 1, page.locator('#cloudflare-accounts-list').inner_text()
    assert PLACEHOLDER not in page.locator('#cloudflare-accounts-list').inner_text()
    assert page.locator('#cloudflare-account-count').inner_text().strip() == str(cards.count())


def test_the_token_saved_in_the_single_field_is_the_account_issuance_reads(page):
    try:
        _open_cloudflare(page)
        field = page.locator('#cloudflare_api_token')
        assert field.is_visible()
        field.fill(TOKEN)
        with page.expect_response(lambda r: r.url.endswith('/api/web/settings')
                                  and r.request.method == 'POST') as saved:
            page.click('#saveBtn')
        assert saved.value.ok, saved.value.status
        page.wait_for_function("() => document.getElementById('cloudflare-status').textContent.trim() === 'Configured'",
                               timeout=10000)

        stored = page.request.get(f'{BASE_URL}/api/web/settings').json()['dns_providers']['cloudflare']
        assert 'api_token' not in stored, stored
        assert stored['accounts']['default']['api_token'] == '********', stored
        assert [(a['account_id'], a['configured']) for a in _cloudflare_accounts(page)] == [('default', True)]

        page.reload(wait_until='networkidle')
        _open_cloudflare(page)
        cards = page.locator('#cloudflare-accounts-list > div')
        assert cards.count() == 1
        assert 'No credentials' not in cards.first.inner_text()
        assert page.locator('#cloudflare-status').inner_text().strip() == 'Configured'
        # One place per credential: the card's Edit, not a second field under it.
        assert not page.locator('#cloudflare_api_token').is_visible()
    finally:
        _clear(page, 'default')


def test_the_providers_stay_in_reach_under_http01(page):
    saved = page.request.post(f'{BASE_URL}/api/web/settings', headers={'Origin': BASE_URL},
                              data={'challenge_type': 'http-01'})
    assert saved.ok, (saved.status, saved.text()[:200])
    _open_cloudflare(page)
    assert page.locator('input[name="challenge_type"][value="http-01"]').is_checked()
    assert page.locator('#dns-provider-section').is_visible()
    assert page.locator('#cloudflare-add-account').is_visible()
    note = page.locator('#dns-provider-note')
    assert note.is_visible()
    assert 'Used only by certificates that choose DNS-01' in note.inner_text()
    # And HTTP-01 is still the choice: looking at a provider does not change it.
    assert page.locator('input[name="challenge_type"][value="http-01"]').is_checked()
