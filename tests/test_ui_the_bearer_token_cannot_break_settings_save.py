"""A value in the API Bearer Token field cannot make Settings Save fail.

Found by the UX perception audit of 2026-11-18 (P04). Generate filled the field
with a new token and said "Remember to save your settings!", and anything typed
there went into the bulk save as api_bearer_token. That endpoint refuses the
key (the token is changed only through API_BEARER_TOKEN and a restart), so Save
answered 400 "Forbidden fields in payload". The field kept its value, so every
later Save, from any tab, failed the same way until the page was reloaded, and
the old token, the one the admin meant to replace, stayed the working one.

The field is now read-only, has no Generate button, and is never sent. These
tests put a value in it anyway (a password manager can still fill it) and save.
"""
import os
import secrets

import pytest
import requests

from tests.conftest import _REQUIRE_BROWSER, e2e_auth_headers

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


def _open(page, tab):
    page.goto(f'{BASE_URL}/settings#{tab}', wait_until='networkidle')
    page.wait_for_function("() => typeof window.CertMate.unsavedSettings === 'function'")
    page.wait_for_selector(f'#settings-panel-{tab}', state='visible')


def _save(page):
    with page.expect_response(lambda r: r.request.method == 'POST'
                              and r.url.endswith('/api/web/settings')) as info:
        page.click('#saveBtn')
    return info.value


def test_a_value_in_the_token_field_is_not_sent_and_every_save_after_it_succeeds(browser_page):
    page = browser_page
    # Until setup is finished the page asks for the CA email before it saves.
    page.request.post(f'{BASE_URL}/api/web/settings', headers={'Origin': BASE_URL},
                      data={'email': 'ops@example.com'})
    _open(page, 'general')
    page.evaluate("t => { document.getElementById('api_bearer_token').value = t; }",
                  secrets.token_hex(32))

    first = _save(page)
    assert first.status == 200, f'Save from General: {first.status} {first.text()[:200]}'
    assert 'api_bearer_token' not in first.request.post_data_json

    page.evaluate("() => { location.hash = 'storage'; }")
    page.wait_for_selector('#settings-panel-storage', state='visible')
    second = _save(page)
    assert second.status == 200, f'Save from Storage: {second.status} {second.text()[:200]}'

    # The stored token was neither replaced nor wiped by the two saves.
    if e2e_auth_headers():
        still = requests.get(f'{BASE_URL}/api/certificates', headers=e2e_auth_headers(), timeout=10)
        assert still.status_code == 200, f'the stored API Bearer Token stopped working: {still.status_code}'


def test_the_token_field_is_read_only_and_offers_no_generate(browser_page):
    page = browser_page
    _open(page, 'general')
    panel = page.locator('#settings-panel-general')
    assert panel.locator('[data-click="generateToken"]').count() == 0
    assert panel.get_by_role('button', name='Generate').count() == 0
    assert page.locator('#api_bearer_token').evaluate('el => el.readOnly') is True
