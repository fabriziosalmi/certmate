"""A second recipient can be typed into the SMTP "To Addresses" field.

The field is bound to a list through an accessor: the setter splits what is
typed at the commas, trims and drops the empty parts, and the getter joins the
list back with ", ". Alpine writes the getter's answer into the field after
every input event, so the comma and the space just typed, which split into
nothing, were taken out again. `a@example.com, b@example.com` typed key by key
became `a@example.comb@example.com`, and was saved as one recipient. Pasting the
same text worked, because it arrives in one piece, which is why nobody saw it
for eight months.

The binding is `x-model.unintrusive`: while the field has the focus, the page
does not write into it. The list is still updated at every key, so nothing
that reads it while the field is focused sees an old value.

The keys are real. Each scenario starts from the same stored state, and the
page is loaded once for the module (the dashboard's requests share one rate
limit).
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

A, B, C = 'a@example.com', 'b@example.com', 'c@example.com'
FIELD = 'input[aria-label="To addresses, comma-separated"]'
PANEL = "document.getElementById('settings-panel-notifications')"


@pytest.fixture(scope="module")
def notifications(browser_page):
    """The Settings page on its Notifications tab, with the Email block open."""
    page = browser_page
    sent = []
    page.route('**/api/notifications/config', lambda route: (
        (sent.append(route.request.post_data),
         route.fulfill(status=200, content_type='application/json', body='{"message": "ok"}'))
        if route.request.method == 'POST' else route.continue_()))
    page.goto(f'{BASE_URL}/settings#notifications', wait_until="networkidle")
    page.locator('[role=tab]:has-text("Notifications")').first.click()
    page.wait_for_selector('#settings-panel-notifications', state='visible')
    page.wait_for_function(
        f"() => {{ const d = Alpine.$data({PANEL}); return d && d.config && d.config.channels; }}")
    page.wait_for_timeout(300)                  # loadConfig() has answered
    # Set-up only: the two switches that reveal the field. It is typed into with real keys.
    page.evaluate(f"() => {{ const d = Alpine.$data({PANEL}); d.config.enabled = true; d.showSmtp = true; }}")
    page.locator(FIELD).wait_for(state='visible')
    yield page, sent
    page.unroute('**/api/notifications/config')


@pytest.fixture
def stored(notifications):
    """Sets the stored list. The field is left first: the page writes into a field only when it has no focus."""
    page, sent = notifications
    del sent[:]

    def set_list(addresses):
        page.locator(FIELD).evaluate('(el) => el.blur()')
        page.evaluate(
            f"(a) => {{ Alpine.$data({PANEL}).config.channels.smtp.to_addresses = a; }}", addresses)
    return set_list


@pytest.fixture
def field(notifications, stored):
    """The field, emptied."""
    page, _ = notifications
    stored([])
    element = page.locator(FIELD)
    assert element.input_value() == ''
    return element


def _list(field):
    return field.evaluate("(el) => Alpine.$data(el).config.channels.smtp.to_addresses")


@pytest.mark.parametrize('typed,expected', [
    (f'{A}, {B}', [A, B]),
    (f'{A},{B}', [A, B]),
    (f'{A}, {B}, {C}', [A, B, C]),
    (A, [A]),
], ids=['comma and space', 'comma only', 'three', 'one'])
def test_what_is_typed_key_by_key_is_the_list(field, typed, expected):
    field.click()
    field.press_sequentially(typed, delay=10)
    assert _list(field) == expected
    assert field.input_value() == typed, 'the field shows what was typed, not a rewritten copy'


def test_deleting_the_second_address_and_the_separator_leaves_the_first_alone(field, stored):
    stored([A, B])
    field.click()
    field.press('End')
    for _ in range(len(B) + 2):                 # the address, the comma and the space
        field.press('Backspace')
    assert field.input_value() == A
    field.press_sequentially(f', {C}', delay=10)
    assert _list(field) == [A, C]


def test_a_stored_list_is_shown_joined_and_edited_in_place(field, stored):
    stored([A, B])
    assert field.input_value() == f'{A}, {B}', 'a stored list is written into a field that has no focus'
    field.click()
    field.press('End')
    field.press_sequentially('x', delay=10)
    assert _list(field) == [A, B + 'x']


def test_a_pasted_list_still_works(field):
    """CONTROL: this arrived in one piece before the change, and still does."""
    field.click()
    field.page.keyboard.insert_text(f'{A}, {B}')
    assert _list(field) == [A, B]


def test_a_trailing_separator_is_not_a_recipient(field):
    field.click()
    field.press_sequentially(f'{A},', delay=10)
    field.evaluate('(el) => el.blur()')
    assert _list(field) == [A]


def test_clearing_the_field_clears_the_list(field, stored):
    stored([A, B])
    field.click()
    field.press('ControlOrMeta+a')
    field.press('Delete')
    assert _list(field) == []


def test_save_sends_the_addresses_that_were_typed(notifications, field):
    page, sent = notifications
    field.click()
    field.press_sequentially(f'{A}, {B}', delay=10)
    page.locator('#settings-panel-notifications button:has-text("Save")').first.click()
    for _ in range(50):
        if sent:
            break
        page.wait_for_timeout(100)
    assert len(sent) == 1, sent
    assert json.loads(sent[0])['channels']['smtp']['to_addresses'] == [A, B]
