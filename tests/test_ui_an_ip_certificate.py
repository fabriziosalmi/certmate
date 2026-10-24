"""An IP-address certificate in the dashboard (#1130): entered, sent, shown.

What only a browser shows: that typing an address into the domain field locks the challenge to
HTTP-01 and the profile to shortlived and says why, hides what an address cannot take, and gives
the fields back when the address is gone; that the request names nothing the hidden sections
still held; that the list and the panel show the address with the certificate's name; and that
Edit & Reissue of an IP certificate keeps its shape. The list and the writes are answered by the
test, so no CA is involved.
"""
import json
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER, TEST_EMAIL
from tests.conftest import BASE_URL as _API_URL

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"

IP_CERT = {
    'domain': 'ip-1-1-1-1', 'ip_address': '1.1.1.1', 'exists': True, 'days_left': 5,
    'days_until_expiry': 5, 'seconds_left': 5 * 86400, 'expired': False, 'needs_renewal': False,
    'usable': True, 'private_key_present': True, 'private_key_state': 'present',
    'reissue_required': False, 'expiry_date': '2026-10-30 03:00:00', 'dns_provider': None,
    'ca_provider': 'letsencrypt', 'challenge_type': 'http-01', 'san_domains': [],
    'auto_renew': True, 'tags': [], 'notes': None, 'renewal_info': None,
    'renews_at': '2026-10-28T00:00:00Z', 'acme_profile': 'shortlived',
    'acme_profile_withdrawn_at': None,
}


@pytest.fixture(scope="module", autouse=True)
def _a_usable_ca(docker_container, ui_session_cookie):
    """The form refuses to submit while no CA is usable (#1045)."""
    import requests
    session = requests.Session()
    session.cookies.set("certmate_session", ui_session_cookie)
    session.headers["Origin"] = _API_URL
    url = f"{_API_URL}/api/web/settings"
    before = session.get(url).json().get("email") or ""
    assert session.post(url, json={"email": TEST_EMAIL}).ok
    yield
    assert session.post(url, json={"email": before}).ok


def _dashboard(page, certificates=None):
    if certificates is not None:
        page.route('**/api/certificates', lambda route: route.fulfill(
            status=200, content_type='application/json', body=json.dumps(certificates))
            if route.request.method == 'GET' else route.continue_())
    page.goto(BASE_URL, wait_until="networkidle")


def _posts(page, fragment):
    """Every POST to `fragment` is answered here and never reaches the shared instance."""
    seen = []
    page.on('request', lambda r: seen.append(json.loads(r.post_data or '{}'))
            if r.method == 'POST' and fragment in r.url else None)
    page.route(f'**{fragment}**', lambda route: route.fulfill(
        status=200, content_type='application/json',
        body=json.dumps({'success': True, 'domain': 'ip-1-1-1-1', 'message': 'ok'})))
    return seen


def _open_create(page):
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.click('#advancedOptionsToggle')
    page.wait_for_selector('#cert_acme_profile', state='visible')


def _state(page):
    return page.evaluate("""() => ({
        challenge: document.getElementById('challenge_type_select').value,
        challengeDisabled: document.getElementById('challenge_type_select').disabled,
        profile: document.getElementById('cert_acme_profile').value,
        profileDisabled: document.getElementById('cert_acme_profile').disabled,
        note: !document.getElementById('ip_address_note').classList.contains('hidden'),
    })""")


def test_an_address_locks_what_it_decides_and_says_why(browser_page):
    _dashboard(browser_page)
    _open_create(browser_page)
    browser_page.fill('#domain', '1.1.1.1')
    assert _state(browser_page) == {'challenge': 'http-01', 'challengeDisabled': True,
                                    'profile': 'shortlived', 'profileDisabled': True, 'note': True}
    assert 'port 80 of this address' in browser_page.inner_text('#ip_address_note')
    for hidden in ('#san_editor', '#csr_toggle', '#wildcard-cert', '#dns_alias_domain',
                   '#dns-provider-container'):
        assert not browser_page.is_visible(hidden), hidden


def test_the_fields_come_back_as_they_were_without_the_address(browser_page):
    _dashboard(browser_page)
    _open_create(browser_page)
    browser_page.select_option('#challenge_type_select', 'dns-01')
    browser_page.select_option('#cert_acme_profile', 'tlsserver')
    browser_page.fill('#domain', '1.1.1.1')
    assert _state(browser_page)['challenge'] == 'http-01'
    browser_page.fill('#domain', 'www.example.com')
    assert _state(browser_page) == {'challenge': 'dns-01', 'challengeDisabled': False,
                                    'profile': 'tlsserver', 'profileDisabled': False, 'note': False}
    assert browser_page.is_visible('#san_editor')


def test_the_request_for_an_address_names_nothing_else(browser_page):
    """A SAN and an alias typed before the address stay in their hidden fields
    and are not sent: the server would refuse an address with either."""
    _dashboard(browser_page)
    posts = _posts(browser_page, '/api/certificates/create')
    _open_create(browser_page)
    browser_page.fill('#domain', 'www.example.com')
    browser_page.fill('#san_entry', 'api.example.com,')
    browser_page.fill('#dns_alias_domain', 'validation.example.org')
    browser_page.fill('#domain', '1.1.1.1')
    browser_page.click('#createCertForm button[type="submit"]')
    browser_page.wait_for_timeout(800)
    assert posts, 'the create request was never sent'
    body = posts[-1]
    assert body['domain'] == '1.1.1.1'
    assert body['challenge_type'] == 'http-01'
    assert body['acme_profile'] == 'shortlived'
    for absent in ('san_domains', 'domain_alias', 'csr', 'dns_provider'):
        assert absent not in body, body


def test_the_list_and_the_panel_show_the_address_and_the_name(browser_page):
    _dashboard(browser_page, [IP_CERT])
    row = browser_page.inner_text('tr[data-row-domain="ip-1-1-1-1"]')
    assert '1.1.1.1' in row and 'ip-1-1-1-1' in row and 'IP' in row
    browser_page.click('tr[data-row-domain="ip-1-1-1-1"]')
    browser_page.wait_for_selector('#certDetailContent dt:text("IP address")', state='visible')
    assert '1.1.1.1' in browser_page.inner_text('#certDetailContent')


def test_edit_and_reissue_of_an_ip_certificate_keeps_its_shape(browser_page):
    _dashboard(browser_page, [IP_CERT])
    posts = _posts(browser_page, '/api/certificates/ip-1-1-1-1/reissue')
    browser_page.evaluate("startEditReissue('ip-1-1-1-1')")
    browser_page.wait_for_selector('#createCertFormContainer', state='visible')
    assert _state(browser_page) == {'challenge': 'http-01', 'challengeDisabled': True,
                                    'profile': 'shortlived', 'profileDisabled': True, 'note': True}
    browser_page.click('#createCertForm button[type="submit"]')
    browser_page.wait_for_timeout(800)
    assert posts, 'the reissue request was never sent'
    body = posts[-1]
    assert body.get('san_domains') == [] and body.get('domain_alias') == ''
    assert body.get('acme_profile') == 'shortlived' and body.get('challenge_type') == 'http-01'
