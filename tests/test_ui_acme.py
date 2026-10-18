"""The ACME screens in a browser (#476, H1 to H4).

Settings > ACME creates an EAB key and shows its HMAC key once, with the
commands for each client filled in; the dashboard's ACME view lists what the
server issued and lets an admin revoke. The /api/acme answers are given by the
test, so the shared instance needs no ACME server of its own, and what the
page sends is captured instead of reaching it.
"""
import json
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
DIRECTORY = 'https://certmate.lab.internal/acme/directory'
SERVER = {'enabled': True, 'allow_http': False, 'eab_required': True, 'validity_days': 45,
          'allowed_identifiers': [], 'directory_url': DIRECTORY, 'eab_keys': []}
CREATED = {'kid': 'team-a', 'hmac_key': 'FVsPsHydKskTnOMTpAR0jODNiKL9blcYIkrYp7FJtG0',
           'allowed_identifiers': ['*.lab.internal'], 'note': '', 'created_at': '2026-10-18T10:00:00Z',
           'disabled': False, 'accounts': 0}
CERTIFICATES = [
    {'id': 'cert-api', 'names': ['api.lab.internal'], 'serial': 'aa', 'status': 'valid',
     'not_after': '2026-12-02T10:00:00Z', 'created_at': '2026-10-18T10:00:00Z', 'revoked_at': None,
     'revocation_reason': None, 'account_id': 'aC1dEQ-6xyz', 'eab_kid': 'team-a'},
    {'id': 'cert-web', 'names': ['web.lab.internal'], 'serial': 'bb', 'status': 'revoked',
     'not_after': '2026-12-02T10:00:00Z', 'created_at': '2026-10-17T10:00:00Z',
     'revoked_at': '2026-10-18T11:00:00Z', 'revocation_reason': 'superseded',
     'account_id': 'aC1dEQ-6xyz', 'eab_kid': 'team-a'},
]


def _answer(page, pattern, body, method='GET'):
    page.route(pattern, lambda route: route.fulfill(status=200, content_type='application/json',
                                                     body=json.dumps(body))
               if route.request.method == method else route.continue_())


def _captured_posts(page, fragment, answer):
    seen = []
    page.on('request', lambda r: seen.append((r.url, json.loads(r.post_data or '{}')))
            if r.method == 'POST' and fragment in r.url else None)
    page.route(f'**{fragment}**', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps(answer))
        if route.request.method == 'POST' else route.continue_())
    return seen


def test_a_new_eab_key_is_shown_once_with_each_clients_command(browser_page):
    page = browser_page
    _answer(page, '**/api/acme/server', SERVER)
    _answer(page, '**/api/acme/accounts', {'accounts': []})
    posts = _captured_posts(page, '/api/acme/eab-keys', CREATED)
    page.goto(f'{BASE_URL}/settings#acme', wait_until='networkidle')
    page.fill('#acmeKeyNames', '*.lab.internal')
    page.fill('#acmeKeyKid', 'team-a')
    page.click('#acmeCreateKey')
    page.wait_for_selector('#acmeCreated', state='visible')
    assert posts and posts[-1][1] == {'allowed_identifiers': ['*.lab.internal'], 'note': '', 'kid': 'team-a'}
    assert page.inner_text('#acmeCreatedHmac') == CREATED['hmac_key']
    certbot = page.inner_text('#acmeSnippet')
    assert DIRECTORY in certbot and '--eab-kid team-a' in certbot and CREATED['hmac_key'] in certbot
    page.click('#acmeCreated button[role="tab"]:has-text("lego")')
    assert page.inner_text('#acmeSnippet').startswith('lego run --server ' + DIRECTORY)
    page.click('#acmeCreated button[role="tab"]:has-text("cert-manager")')
    assert 'keyID: team-a' in page.inner_text('#acmeSnippet')
    page.click('#acmeCreated >> text=I have copied it')
    page.wait_for_selector('#acmeCreated', state='hidden')
    assert CREATED['hmac_key'] not in page.content()


def test_the_acme_view_lists_what_was_issued_and_an_admin_revokes(browser_page):
    page = browser_page
    _answer(page, '**/api/acme/certificates', {'certificates': CERTIFICATES})
    posts = _captured_posts(page, '/api/acme/certificates/', dict(CERTIFICATES[0], status='revoked'))
    page.goto(f'{BASE_URL}/#acme', wait_until='networkidle')
    page.wait_for_selector('#acmeCertTable tbody tr')
    rows = page.locator('#acmeCertTable tbody tr')
    assert rows.count() == 2
    assert 'api.lab.internal' in rows.nth(0).inner_text() and 'valid' in rows.nth(0).inner_text()
    assert 'revoked' in rows.nth(1).inner_text()
    assert rows.nth(1).locator('button[title="Revoke"]').count() == 0  # nothing to revoke twice
    assert page.locator('button[title="New certificate"]').is_hidden()
    rows.nth(0).locator('button[title="Revoke"]').click()
    page.click('button:has-text("Confirm")')
    page.wait_for_timeout(800)
    assert posts and posts[-1][0].endswith('/api/acme/certificates/cert-api/revoke')


def test_the_acme_view_says_where_to_start_when_nothing_was_issued(browser_page):
    page = browser_page
    _answer(page, '**/api/acme/certificates', {'certificates': []})
    # The page is shared with the test above, which left it on /#acme: going to
    # the same address is no navigation, so it is reloaded to load again.
    page.goto(f'{BASE_URL}/#acme', wait_until='networkidle')
    page.reload(wait_until='networkidle')
    page.wait_for_selector('#acmeEmpty', state='visible')
    assert page.locator('#acmeEmpty a[href="/settings#acme"]').count() == 1
