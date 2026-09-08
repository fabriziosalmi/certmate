"""Submitting a CSR from the create form (#599).

The issue asks for the CSR to be submittable "either through the UI or via the
CertMate API", so the API alone does not close it. What is pinned here is not
that a textarea exists — it is the two things that are invisible from the JS
source and would each produce a confusing server-side refusal:

* the CSR reaches the request body;
* when a CSR is given, the SAN list and the key options are **not** sent. The
  server refuses a request that specifies both, and learning that after an ACME
  round trip is a bad way to find out that a CSR carries its own names.

And the control that matters more than either: with no CSR, the form still
sends exactly what it always sent.
"""
import json
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

CSR = (
    "-----BEGIN CERTIFICATE REQUEST-----\n"
    "MIHxMIGYAgEAMBkxFzAVBgNVBAMMDmFwaS5leGFtcGxlLmNvbTBZMBMGByqGSM49\n"
    "-----END CERTIFICATE REQUEST-----"
)


def _open_create_drawer(page):
    """The create form lives in a drawer, not on the page.

    Opening it is part of this helper because a locator that resolves inside a
    closed drawer still accepts `fill()` — the element is in the DOM — and the
    test would then assert against a form the operator never sees.
    """
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); }"
        " catch (e) {}")
    page.goto(BASE_URL, wait_until="networkidle")
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')


def _open_advanced(page):
    """The key-shape selector lives behind "Advanced Options", collapsed.

    A test that reached it without opening the section would be asserting
    against a control the operator cannot see — and `select_option` refuses a
    hidden element, which is how this was found rather than assumed.
    """
    page.click('#advancedOptionsToggle')
    page.wait_for_selector('#cert_key_type', state='visible')


def _capture_creates(page):
    seen = []
    page.on('request', lambda r: (
        seen.append(r.post_data)
        if r.method == 'POST' and '/api/certificates/create' in r.url else None))
    return seen


def _submit(page):
    page.route('**/api/certificates/create',
               lambda route: route.fulfill(
                   status=200, content_type='application/json',
                   body=json.dumps({'success': True, 'domain': 'api.example.com'})))
    page.click('#createCertForm button[type="submit"]')
    page.wait_for_timeout(800)


def test_the_create_form_offers_a_csr(browser_page):
    _open_create_drawer(browser_page)
    assert browser_page.locator('#csr_toggle').count() == 1, (
        'the create form has no way to submit a CSR, so #599 can only be used '
        'through the API'
    )


def test_the_csr_field_is_collapsed_until_asked_for(browser_page):
    """CONTROL: almost every certificate here is key-managed. An always-open
    textarea would suggest a CSR is expected."""
    _open_create_drawer(browser_page)
    assert not browser_page.locator('#cert_csr').is_visible()

    browser_page.click('#csr_toggle')
    browser_page.wait_for_timeout(200)
    assert browser_page.locator('#cert_csr').is_visible()
    assert browser_page.locator('#csr_toggle').get_attribute(
        'aria-expanded') == 'true'


def test_opening_the_panel_alone_changes_nothing(browser_page):
    """Opening it to read the explanation and closing it again must not put the
    form into CSR mode — only an actual CSR does."""
    _open_create_drawer(browser_page)
    browser_page.click('#csr_toggle')
    browser_page.wait_for_timeout(200)

    assert not browser_page.locator('#san_entry').is_disabled(), (
        'an empty CSR panel disabled the SAN editor'
    )


def test_a_csr_disables_what_it_already_decides(browser_page):
    """The names and the key shape come from the CSR. Leaving those fields
    enabled would let an operator fill them in and get a 400 back."""
    _open_create_drawer(browser_page)
    browser_page.click('#csr_toggle')
    browser_page.fill('#cert_csr', CSR)
    browser_page.wait_for_timeout(300)

    for field in ('#san_entry', '#cert_key_type'):
        assert browser_page.locator(field).is_disabled(), (
            f'{field} is still editable while a CSR is present'
        )


def test_the_csr_reaches_the_request_body(browser_page):
    _open_create_drawer(browser_page)
    posts = _capture_creates(browser_page)
    browser_page.fill('#domain', 'api.example.com')
    browser_page.click('#csr_toggle')
    browser_page.fill('#cert_csr', CSR)
    browser_page.wait_for_timeout(200)

    _submit(browser_page)

    assert posts, 'the create request was never sent'
    body = json.loads(posts[-1] or '{}')
    assert body.get('csr', '').startswith('-----BEGIN CERTIFICATE REQUEST'), (
        f'the CSR did not reach the request body: {body}'
    )


def test_a_csr_request_sends_neither_sans_nor_key_options(browser_page):
    """The one that would be a confusing 400. The server refuses a request
    that specifies both, so the form must not send both."""
    _open_create_drawer(browser_page)
    posts = _capture_creates(browser_page)
    browser_page.fill('#domain', 'api.example.com')
    # Fill the SAN editor and the key selector FIRST, then add the CSR — the
    # order an operator would actually stumble into.
    browser_page.fill('#san_entry', 'www.example.com')
    browser_page.press('#san_entry', 'Enter')
    _open_advanced(browser_page)
    browser_page.select_option('#cert_key_type', 'rsa')
    browser_page.click('#csr_toggle')
    browser_page.fill('#cert_csr', CSR)
    browser_page.wait_for_timeout(300)

    _submit(browser_page)

    assert posts, 'the create request was never sent'
    body = json.loads(posts[-1] or '{}')
    assert 'san_domains' not in body, (
        f'a SAN list was sent alongside the CSR: {body.get("san_domains")!r}'
    )
    for key in ('key_type', 'key_size', 'elliptic_curve'):
        assert key not in body, f'{key} was sent alongside the CSR'


def test_without_a_csr_the_form_sends_what_it_always_sent(browser_page):
    """The control that matters most. Every existing create goes through this
    path, and a CSR field that quietly changed the ordinary payload would be a
    regression for everyone."""
    _open_create_drawer(browser_page)
    posts = _capture_creates(browser_page)
    browser_page.fill('#domain', 'api.example.com')
    browser_page.fill('#san_entry', 'www.example.com')
    browser_page.press('#san_entry', 'Enter')
    _open_advanced(browser_page)
    browser_page.select_option('#cert_key_type', 'ecdsa')
    browser_page.wait_for_timeout(200)

    _submit(browser_page)

    assert posts, 'the create request was never sent'
    body = json.loads(posts[-1] or '{}')
    assert body['san_domains'] == ['www.example.com']
    assert body['key_type'] == 'ecdsa'
    assert 'csr' not in body
