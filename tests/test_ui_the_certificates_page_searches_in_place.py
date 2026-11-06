"""Typing in the Certificates page search narrows the table, in a real browser (#1385).

tests/test_the_certificates_page_searches_in_place.py proves the filtering in
dashboard.js under Node. This drives the page itself: the field is on it, typing
reaches the action through its data-input binding, the table shrinks and grows
back, and Clear filters empties it.
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


def _cert(domain, **fields):
    return {
        'domain': domain, 'host': domain, 'ip_address': None, 'exists': True, 'days_left': 60,
        'days_until_expiry': 60, 'seconds_left': 60 * 86400, 'expired': False,
        'needs_renewal': False, 'usable': True, 'private_key_present': True,
        'private_key_state': 'present', 'reissue_required': False,
        'expiry_date': '2026-12-25 03:00:00', 'dns_provider': 'cloudflare',
        'ca_provider': 'letsencrypt', 'challenge_type': 'dns-01', 'san_domains': [],
        'auto_renew': True, 'tags': [], 'notes': None, 'renewal_info': None,
        'renews_at': '2026-11-25T00:00:00Z', 'acme_profile': None,
        'acme_profile_withdrawn_at': None, **fields,
    }


CERTIFICATES = [_cert(f'site{i:02d}.example.com') for i in range(30)] + [
    _cert('shop.example.com', san_domains=['www.shop.example.net'], tags=['loadbalancer']),
    _cert('mail.example.com', notes='Ticket 4321'),
]


def _rows(page):
    return page.locator('#certificatesList tr[data-row-domain]')


@pytest.fixture
def dashboard(browser_page):
    page = browser_page
    page.route('**/api/certificates', lambda route: route.fulfill(
        status=200, content_type='application/json', body=json.dumps(CERTIFICATES))
        if route.request.method == 'GET' else route.continue_())
    page.goto(BASE_URL, wait_until="networkidle")
    page.wait_for_selector('#certificatesList tr[data-row-domain]')
    return page


def test_the_field_is_on_the_page_and_labelled(dashboard):
    field = dashboard.locator('#certificateSearch')
    assert field.is_visible()
    assert dashboard.locator('label[for="certificateSearch"]').count() == 1


def test_typing_narrows_the_table_and_clearing_brings_it_back(dashboard):
    page = dashboard
    assert _rows(page).count() == 25                      # the first page of 32

    page.fill('#certificateSearch', 'site0')
    page.wait_for_timeout(200)
    assert _rows(page).count() == 10                      # site00 to site09

    page.fill('#certificateSearch', 'shop.example.net')   # a SAN
    page.wait_for_timeout(200)
    assert [r.get_attribute('data-row-domain') for r in _rows(page).all()] == ['shop.example.com']

    page.fill('#certificateSearch', '4321')                # a note
    page.wait_for_timeout(200)
    assert [r.get_attribute('data-row-domain') for r in _rows(page).all()] == ['mail.example.com']

    page.fill('#certificateSearch', '')
    page.wait_for_timeout(200)
    assert _rows(page).count() == 25


def test_a_search_with_no_match_says_so(dashboard):
    dashboard.fill('#certificateSearch', 'nothing-is-called-this')
    dashboard.wait_for_timeout(200)

    assert _rows(dashboard).count() == 0
    assert dashboard.locator('#certificatesList [data-empty-state]').count() == 1
