"""The Client Certificates page gives what a checking server needs, says up
front when the .pfx cannot be made, and shows the serial the way openssl does.

UX perception audit, 2026-11-18:

* P45: nothing on the page linked to the CA certificate a relying server has
  to trust or to the CRL it reads, though GET /api/client-certs/ca and
  /api/crl/download/pem both answer. After a revoke the toast said only
  "Certificate revoked", not that a server goes on accepting the certificate
  until it fetches the CRL again. /api/crl/download/der is not linked.
* P49: the .pfx button looked available, and only a click said a PFX password
  had to be set "in Settings".
* P71: the serial was the decimal string the API stores. `openssl x509
  -serial` and a CRL print upper-case hex, two digits a byte.

The client list and the revoke are answered in the browser (page.route), so
nothing is issued or revoked on the instance. The PFX password is set and
removed again through the settings API for the one test that needs it.
"""
import json
import os

import pytest
import requests

from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"

# The audited certificate: `openssl x509 -serial` printed the hex for the
# decimal the detail dialog showed.
SERIAL_DECIMAL = '106505857200714862350652171193708822696771002175'
SERIAL_OPENSSL = '12A7E347AC1CC40BF6BDD7BE8B352F3C5D091F3F'
CERT = {'identifier': 'cc-alice', 'common_name': 'alice.vpn.example.test', 'email': 'alice@example.test',
        'cert_usage': 'vpn', 'created_at': '2026-10-01T10:00:00Z', 'expires_at': '2027-10-01T10:00:00Z',
        'revoked': False, 'serial_number': SERIAL_DECIMAL}


def _openssl_hex(decimal):
    """What openssl prints for a serial: upper-case hex, an even number of digits."""
    digits = format(int(decimal), 'X')
    return digits if len(digits) % 2 == 0 else '0' + digits


def _client_page(page, certs=None, revoked=None):
    certs = certs or [CERT]

    def answer(route):
        url = route.request.url.split('?')[0]
        method = route.request.method
        if method == 'GET' and url.endswith('/api/client-certs'):
            body = {'certificates': certs}
        elif method == 'GET' and url.endswith('/api/client-certs/stats'):
            body = {'total': len(certs), 'active': len(certs), 'revoked': 0, 'by_usage': {'vpn': len(certs)}}
        elif method == 'POST' and url.endswith('/revoke') and '/api/client-certs/' in url:
            if revoked is not None:
                revoked.append(url)
            body = {'message': 'Certificate revoked: cc-alice'}
        else:
            return route.continue_()
        return route.fulfill(status=200, content_type='application/json', body=json.dumps(body))

    page.route('**/api/client-certs**', answer)
    page.goto(f'{BASE_URL}/#client', wait_until='networkidle')
    page.reload(wait_until='networkidle')
    page.wait_for_selector('#certTableBody tr[data-cc-id]')


def _open_detail(page, identifier='cc-alice'):
    page.locator(f'#certTableBody tr[data-cc-id="{identifier}"] button').first.click()
    page.wait_for_selector('#certModal:not(.hidden)')


def test_the_client_page_links_the_ca_certificate_and_the_crl_a_server_needs(browser_page):
    page = browser_page
    _client_page(page)
    ca = page.locator('a[href="/api/client-certs/ca"]')
    crl = page.locator('a[href="/api/crl/download/pem"]')
    assert ca.count() == 1 and ca.is_visible()
    assert crl.count() == 1 and crl.is_visible()
    # DER answers 404 until the first revocation: it is not offered.
    assert page.locator('a[href="/api/crl/download/der"]').count() == 0
    for path in ('/api/client-certs/ca', '/api/crl/download/pem'):
        answer = page.request.get(f'{BASE_URL}{path}')
        assert answer.status == 200, (path, answer.status)


def test_a_revoke_says_a_server_accepts_it_until_it_fetches_the_crl_again(browser_page):
    page = browser_page
    revoked = []
    _client_page(page, revoked=revoked)
    _open_detail(page)
    page.click('#certModalRevoke')
    page.get_by_role('alertdialog').get_by_role('button', name='Confirm').click()
    toast = page.locator('#cm-toasts > div', has_text='revoked').first
    toast.wait_for()
    assert revoked and revoked[-1].endswith('/api/client-certs/cc-alice/revoke')
    assert 'until it fetches the CRL again' in toast.inner_text(), toast.inner_text()
    assert toast.locator('a[href="/api/crl/download/pem"]').count() == 1


def test_the_serial_is_shown_as_openssl_prints_it_and_can_be_copied(browser_page):
    page = browser_page
    page.context.grant_permissions(['clipboard-read', 'clipboard-write'], origin=BASE_URL)
    small = dict(CERT, identifier='cc-bob', common_name='bob.vpn.example.test', serial_number='5')
    _client_page(page, certs=[CERT, small])
    assert _openssl_hex(SERIAL_DECIMAL) == SERIAL_OPENSSL

    for cert in (CERT, small):
        _open_detail(page, cert['identifier'])
        serial = page.locator('#ccSerial')
        assert serial.inner_text().strip() == _openssl_hex(cert['serial_number'])
        page.get_by_role('button', name='Copy serial number').click()
        page.wait_for_timeout(200)
        assert page.evaluate('navigator.clipboard.readText()') == _openssl_hex(cert['serial_number'])
        page.keyboard.press('Escape')
        page.wait_for_selector('#certModal', state='hidden')


def _set_pfx_password(cookie, value):
    s = requests.Session()
    s.cookies.set('certmate_session', cookie)
    answer = s.post(f'{BASE_URL}/api/web/settings', json={'pfx_password': value},
                    headers={'Origin': BASE_URL}, timeout=10)
    assert answer.status_code == 200, answer.text[:200]


def test_the_pfx_button_says_up_front_that_it_needs_a_pfx_password(browser_page, ui_session_cookie):
    page = browser_page
    _set_pfx_password(ui_session_cookie, None)
    _client_page(page)
    _open_detail(page)
    pfx = page.locator('#certModal button:has-text(".pfx")')
    assert pfx.get_attribute('aria-disabled') == 'true'
    link = page.locator('#certModal a[href="/settings#general"]')
    assert link.count() == 1 and link.is_visible()
    downloads = []
    page.on('download', lambda d: downloads.append(d))
    pfx.click(force=True)
    page.wait_for_timeout(300)
    assert downloads == []

    _set_pfx_password(ui_session_cookie, 'a-pfx-password-for-the-test')
    try:
        _client_page(page)
        _open_detail(page)
        pfx = page.locator('#certModal button:has-text(".pfx")')
        assert pfx.get_attribute('aria-disabled') in (None, 'false')
        assert page.locator('#certModal a[href="/settings#general"]').count() == 0
    finally:
        _set_pfx_password(ui_session_cookie, None)


def test_a_toast_link_that_leaves_the_origin_is_not_drawn(browser_page):
    """options.link is for same-origin paths: '/\\host' and '//host' are read
    by the browser as another host, and a check on the first two characters let
    the backslash form through."""
    page = browser_page
    page.goto(f"{BASE_URL}/#client", wait_until='networkidle')
    drawn = page.evaluate("""() => {
        const hrefs = ['/\\\\evil.example', '//evil.example', 'https://evil.example/x', '/api/crl/download/pem'];
        return hrefs.map((href, i) => {
            CertMate.toast('link test ' + i, 'info', null, {link: {href: href, text: 'go'}});
            const box = Array.from(document.querySelectorAll('#cm-toasts > div'))
                .find(t => t.innerText.includes('link test ' + i));
            return box ? box.querySelectorAll('a').length : -1;
        });
    }""")
    assert drawn == [0, 0, 0, 1], drawn

