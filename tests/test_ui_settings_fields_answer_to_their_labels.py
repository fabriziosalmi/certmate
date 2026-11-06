"""A Settings field is found by the words written above it, and an icon button by what it does.

tests/test_every_form_control_has_an_accessible_name.py reads the templates as
text. This asks a browser, which is what a screen reader asks: the label of the
OIDC client ID and of a new API key's name lead to the field the component
binds, a click on the label puts the cursor in it, and the eye button next to
the API bearer token is a button named "Show token" that becomes "Hide token",
pressed, when it shows the token.
"""
import os

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"


def _open(page, tab):
    page.goto(f"{BASE_URL}/settings#{tab}", wait_until="networkidle")
    page.reload(wait_until="networkidle")
    panel = page.locator(f"#settings-panel-{tab}")
    panel.wait_for(state="visible")
    return panel


@pytest.mark.parametrize("tab, label, model", [
    ("oidc", "Client ID", "cfg.client_id"),
    ("oidc", "Post-logout redirect URI (optional)", "cfg.post_logout_redirect_uri"),
    ("apikeys", "Key Name", "newKey.name"),
])
def test_a_label_leads_to_its_field(browser_page, tab, label, model):
    panel = _open(browser_page, tab)
    field = panel.get_by_label(label, exact=True)
    assert field.count() == 1
    assert field.get_attribute("x-model") == model
    panel.locator("label", has_text=label).first.click()
    assert field.evaluate("el => el === document.activeElement")


def test_the_token_eye_is_a_named_toggle(browser_page):
    panel = _open(browser_page, "general")
    token = panel.locator("#api_bearer_token")
    show = panel.get_by_role("button", name="Show token", exact=True)
    assert show.get_attribute("aria-pressed") == "false"
    assert token.get_attribute("type") == "password"

    show.click()
    hide = panel.get_by_role("button", name="Hide token", exact=True)
    assert hide.get_attribute("aria-pressed") == "true"
    assert token.get_attribute("type") == "text"

    hide.click()
    assert panel.get_by_role("button", name="Show token", exact=True).get_attribute("aria-pressed") == "false"
    assert token.get_attribute("type") == "password"
