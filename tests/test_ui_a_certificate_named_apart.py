"""A certificate named apart from its domain, in the dashboard (#854, step 4: #1149).

`POST /api/certificates/create` takes `name` since API contract 2.61; the form
gives it a field, Name, in Advanced Options. What only a browser shows: that the
name typed there is sent with the domain, and nothing is sent when it is empty or
the domain itself; that an address and an import, which take no name, neither show
nor send it; that the row of an asynchronous create carries the name while the
domain's own certificate is listed; and that Edit & Reissue of such a certificate
shows its host as the domain and its name as the name, both fixed, with the
wildcard reckoned from the host. The writes are answered by the test, so no CA is
involved.
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

HOST = 'example.com'
NAME = 'internal.example.com'


def _cert(domain, host, **fields):
    return {
        'domain': domain, 'host': host, 'ip_address': None, 'exists': True, 'days_left': 60,
        'days_until_expiry': 60, 'seconds_left': 60 * 86400, 'expired': False,
        'needs_renewal': False, 'usable': True, 'private_key_present': True,
        'private_key_state': 'present', 'reissue_required': False,
        'expiry_date': '2026-12-25 03:00:00', 'dns_provider': 'cloudflare',
        'ca_provider': 'letsencrypt', 'challenge_type': 'dns-01', 'san_domains': [],
        'auto_renew': True, 'tags': [], 'notes': None, 'renewal_info': None,
        'renews_at': '2026-11-25T00:00:00Z', 'acme_profile': None,
        'acme_profile_withdrawn_at': None, **fields,
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


def _posts(page, fragment, status=200, answer=None):
    """Every POST to `fragment` is answered here and never reaches the shared instance."""
    seen = []
    page.on('request', lambda r: seen.append(json.loads(r.post_data or '{}'))
            if r.method == 'POST' and fragment in r.url else None)
    page.route(f'**{fragment}**', lambda route: route.fulfill(
        status=status, content_type='application/json',
        body=json.dumps(answer or {'success': True, 'domain': NAME, 'message': 'ok'})))
    return seen


def _open_create(page):
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    page.click('#advancedOptionsToggle')
    page.wait_for_selector('#cert_name', state='visible')


def _submit(page, posts):
    page.click('#createCertForm button[type="submit"]')
    page.wait_for_timeout(800)
    assert posts, 'the request was never sent'
    return posts[-1]


def test_the_name_is_sent_with_the_domain(browser_page):
    _dashboard(browser_page)
    posts = _posts(browser_page, '/api/certificates/create')
    _open_create(browser_page)
    browser_page.fill('#domain', HOST)
    browser_page.fill('#cert_name', ' Internal.Example.com ')

    body = _submit(browser_page, posts)

    assert (body['domain'], body['name']) == (HOST, NAME)
    # Not carried into the next certificate.
    assert browser_page.input_value('#cert_name') == ''


@pytest.mark.parametrize('typed', ['', '   ', 'EXAMPLE.com'])
def test_no_name_is_sent_when_it_is_empty_or_the_domain(browser_page, typed):
    _dashboard(browser_page)
    posts = _posts(browser_page, '/api/certificates/create')
    _open_create(browser_page)
    browser_page.fill('#domain', HOST)
    browser_page.fill('#cert_name', typed)

    body = _submit(browser_page, posts)

    assert body['domain'] == HOST and 'name' not in body, body


def test_a_name_the_server_would_refuse_is_sent_for_it_to_refuse(browser_page):
    """Not cut down to something valid, nor dropped: the certificate would then
    be named by its domain, which is not what was asked."""
    _dashboard(browser_page)
    posts = _posts(browser_page, '/api/certificates/create')
    _open_create(browser_page)
    browser_page.fill('#domain', HOST)
    browser_page.fill('#cert_name', '../etc')

    body = _submit(browser_page, posts)

    assert body['name'] == '../etc', body


def test_an_address_neither_shows_nor_sends_a_name(browser_page):
    """A name typed before the address stays in its hidden field and is not
    sent: the server refuses a name for an IP certificate."""
    _dashboard(browser_page)
    posts = _posts(browser_page, '/api/certificates/create')
    _open_create(browser_page)
    browser_page.fill('#domain', HOST)
    browser_page.fill('#cert_name', NAME)
    browser_page.fill('#domain', '1.1.1.1')
    assert not browser_page.is_visible('#cert_name')

    body = _submit(browser_page, posts)

    assert body['domain'] == '1.1.1.1' and 'name' not in body, body


def test_an_import_takes_no_name(browser_page):
    _dashboard(browser_page)
    _open_create(browser_page)
    browser_page.check('#importExistingCertificate')
    assert browser_page.is_disabled('#cert_name')
    browser_page.uncheck('#importExistingCertificate')
    assert browser_page.is_enabled('#cert_name')


def test_a_named_create_is_shown_by_its_name_beside_the_domains_own(browser_page):
    _dashboard(browser_page, [_cert(HOST, HOST)])
    job = {'job_id': 'named-job', 'status': 'queued', 'operation': 'create', 'domain': NAME,
           'status_url': '/api/certificates/jobs/named-job'}
    posts = _posts(browser_page, '/api/certificates/create', status=202, answer=job)
    browser_page.route('**/api/certificates/jobs/named-job', lambda route: route.fulfill(
        status=200, content_type='application/json',
        body=json.dumps({**job, 'status': 'running'})))
    _open_create(browser_page)
    browser_page.fill('#domain', HOST)
    browser_page.fill('#cert_name', NAME)

    _submit(browser_page, posts)

    assert f'{HOST} as {NAME}' in browser_page.inner_text('body')
    row = browser_page.wait_for_selector('tr[data-pending-job="named-job"]', state='visible')
    assert NAME in row.inner_text()
    assert browser_page.is_visible(f'tr[data-row-domain="{HOST}"]')


def test_edit_and_reissue_shows_the_host_and_the_name_and_reckons_the_wildcard_from_the_host(browser_page):
    named = _cert(NAME, HOST, san_domains=[f'*.{HOST}'])
    _dashboard(browser_page, [_cert(HOST, HOST), named])
    posts = _posts(browser_page, f'/api/certificates/{NAME}/reissue')
    browser_page.evaluate(f"startEditReissue('{NAME}')")
    browser_page.wait_for_selector('#cert_name', state='visible')

    shown = browser_page.evaluate("""() => ({
        domain: document.getElementById('domain').value,
        domainFixed: document.getElementById('domain').readOnly,
        name: document.getElementById('cert_name').value,
        nameFixed: document.getElementById('cert_name').readOnly,
        wildcard: document.getElementById('wildcard-cert').checked,
    })""")
    assert shown == {'domain': HOST, 'domainFixed': True, 'name': NAME, 'nameFixed': True,
                     'wildcard': True}

    body = _submit(browser_page, posts)
    assert body.get('san_domains') == [f'*.{HOST}']
    assert 'name' not in body and 'domain' not in body, body

    browser_page.evaluate("cancelEditReissue()")
    assert browser_page.evaluate(
        "() => [document.getElementById('cert_name').value, document.getElementById('cert_name').readOnly]"
    ) == ['', False]
