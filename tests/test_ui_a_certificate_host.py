"""The dashboard's panel says where a certificate is served when that is not its name (#854).

A certificate named apart from the host it is served at carries `host` in every
answer since API contract 2.59. The panel shows it in a Host row; a
certificate served at its own name shows none, and an IP certificate keeps its
IP address row. The list is answered by the test, so no CA is involved.
"""
import pytest

from tests.test_ui_an_ip_certificate import IP_CERT, _dashboard

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

HOSTED = dict(IP_CERT, domain='internal.example.net', ip_address=None, host='example.com',
              challenge_type='dns-01', dns_provider='cloudflare', acme_profile=None)
NAMED = dict(HOSTED, domain='shop.example.com', host='shop.example.com')


def _panel_rows(page, name):
    page.click(f'tr[data-row-domain="{name}"]')
    page.wait_for_selector('#certDetailContent dl', state='visible')
    return page.evaluate("""() => Object.fromEntries(
        [...document.querySelectorAll('#certDetailContent dl dt')]
            .map(dt => [dt.textContent.trim(), dt.nextElementSibling.textContent.trim()]))""")


def test_the_panel_says_where_a_certificate_named_apart_is_served(browser_page):
    _dashboard(browser_page, [HOSTED, NAMED])
    rows = _panel_rows(browser_page, 'internal.example.net')
    assert rows.get('Host') == 'example.com'


def test_a_certificate_served_at_its_name_shows_no_host_row(browser_page):
    _dashboard(browser_page, [HOSTED, NAMED])
    rows = _panel_rows(browser_page, 'shop.example.com')
    assert 'Host' not in rows


def test_an_ip_certificate_keeps_its_address_row_and_no_host_row(browser_page):
    _dashboard(browser_page, [dict(IP_CERT, host='1.1.1.1')])
    rows = _panel_rows(browser_page, 'ip-1-1-1-1')
    assert (rows.get('IP address'), rows.get('Host')) == ('1.1.1.1', None)
