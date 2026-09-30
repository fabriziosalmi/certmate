"""The create form does not submit while no CA is usable (#1045).

The server refuses a create without an ACME email anyway ("Domain and email
are required"), but only after the request; the form now says so up front and
points at Settings. Pinned in a browser because the check depends on the CA
list the page loads asynchronously, which a JS unit test stubs away.
"""
import os

import pytest

from tests.conftest import _REQUIRE_BROWSER, BASE_URL as _API_URL

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


@pytest.fixture(scope="module", autouse=True)
def _no_usable_ca(docker_container, ui_session_cookie):
    import requests
    session = requests.Session()
    session.cookies.set("certmate_session", ui_session_cookie)
    # A cookie-authenticated write must say where it comes from (CSRF).
    session.headers["Origin"] = _API_URL
    url = f"{_API_URL}/api/web/settings"
    current = session.get(url).json()
    assert not current.get("ca_providers"), (
        "the shared instance has a CA configured; this module needs none")
    before = current.get("email") or ""
    response = session.post(url, json={"email": ""})
    assert response.ok, response.text
    yield
    restored = session.post(url, json={"email": before})
    assert restored.ok, restored.text


def test_without_a_usable_ca_the_form_says_so_and_sends_nothing(browser_page):
    page = browser_page
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); }"
        " catch (e) {}")
    page.goto(BASE_URL, wait_until="networkidle")
    page.click('button[title="New certificate"]')
    page.wait_for_selector('#createCertFormContainer', state='visible')
    posts = []
    page.on('request', lambda r: (
        posts.append(r.url)
        if r.method == 'POST' and '/api/certificates/create' in r.url else None))

    page.fill('#domain', 'api.example.com')
    page.click('#createCertForm button[type="submit"]')

    page.get_by_text('Configure a certificate authority in Settings').first.wait_for(
        state='visible', timeout=5000)
    page.wait_for_timeout(1000)
    assert posts == []
