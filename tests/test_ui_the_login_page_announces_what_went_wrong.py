"""The login page tells a screen reader what went wrong, and the username field
takes what is typed.

UX perception audit, 2026-11-18 (batch B9):

* P15. "Invalid credentials" appeared in a red box above the form, and nothing
  announced it: the box had no role and no live region, focus stayed in the
  password field, and the field said nothing about being wrong. The box is an
  alert now, and the password field is marked invalid and described by it
  while it is shown.
* P31. The username field had no autocapitalize, autocorrect or spellcheck, so
  a phone typed "Admin" for "admin", and usernames are case-sensitive (that
  stays: no authentication change). The login, setup and Settings > Users
  username fields now take what is typed. The setup page is checked in its
  template by tests/test_username_fields_take_what_is_typed.py, because a
  set-up instance does not serve it.

The wrong login is a real one, for a user that does not exist, so the shared
admin's per-user login budget is not spent.
"""
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

FIELD_STATE = """() => {
    const pw = document.getElementById('password');
    const box = document.getElementById('errorMessage');
    return {
        text: box.innerText.trim(),
        shown: !box.classList.contains('hidden'),
        role: box.getAttribute('role'),
        invalid: pw.getAttribute('aria-invalid'),
        describedby: pw.getAttribute('aria-describedby'),
    };
}"""


@pytest.fixture
def anonymous(browser_page):
    """A page with no session: /login is what it gets."""
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    page = context.new_page()
    yield page
    context.close()


@pytest.fixture
def signed_in(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    context.close()


def _ax_role(page, selector):
    """The role the browser's accessibility tree gives the element, or None when it is ignored."""
    cdp = page.context.new_cdp_session(page)
    root = cdp.send('DOM.getDocument', {'depth': 0})['root']['nodeId']
    node_id = cdp.send('DOM.querySelector', {'nodeId': root, 'selector': selector})['nodeId']
    node = cdp.send('Accessibility.getPartialAXTree', {'nodeId': node_id, 'fetchRelatives': False})['nodes'][0]
    return None if node.get('ignored') else node.get('role', {}).get('value')


def test_a_wrong_password_is_announced_and_marks_the_password_field(anonymous):
    page = anonymous
    page.goto(f'{BASE_URL}/login', wait_until='networkidle')
    page.fill('#username', 'b9-nobody-at-all')
    page.fill('#password', 'not-the-password')
    page.press('#password', 'Enter')
    page.wait_for_function("() => !document.getElementById('errorMessage').classList.contains('hidden')",
                           timeout=10000)
    state = page.evaluate(FIELD_STATE)
    assert state['text'] == 'Invalid credentials', state
    assert state['role'] == 'alert', state
    assert state['invalid'] == 'true', state
    assert 'errorMessage' in (state['describedby'] or '').split(), state
    assert _ax_role(page, '#errorMessage') == 'alert'


def test_an_empty_form_is_announced_too_and_a_new_attempt_clears_the_mark(anonymous):
    page = anonymous
    page.goto(f'{BASE_URL}/login', wait_until='networkidle')
    # The fields are `required`: the page's own check runs when the browser's does not.
    page.evaluate("() => { document.getElementById('username').required = false;"
                  " document.getElementById('password').required = false; }")
    page.click('#loginBtn')
    page.wait_for_function("() => !document.getElementById('errorMessage').classList.contains('hidden')",
                           timeout=5000)
    state = page.evaluate(FIELD_STATE)
    assert state['text'] == 'Please enter both username and password', state
    assert state['role'] == 'alert' and state['invalid'] == 'true', state

    # A new attempt hides the box first: the field is not left marked by an
    # answer that is no longer on screen.
    page.route('**/api/auth/login', lambda route: None)  # never answers: the attempt stays open
    page.fill('#username', 'b9-nobody-at-all')
    page.fill('#password', 'x')
    page.click('#loginBtn')
    page.wait_for_function("() => document.getElementById('errorMessage').classList.contains('hidden')",
                           timeout=5000)
    state = page.evaluate(FIELD_STATE)
    assert state['invalid'] in (None, 'false'), state
    assert not (state['describedby'] or '').strip(), state


USERNAME_ATTRS = """sel => {
    const el = document.querySelector(sel);
    return el && {
        autocapitalize: el.getAttribute('autocapitalize'),
        autocorrect: el.getAttribute('autocorrect'),
        spellcheck: el.spellcheck,
    };
}"""


def test_the_login_username_field_does_not_capitalise_or_correct_what_is_typed(anonymous):
    page = anonymous
    page.goto(f'{BASE_URL}/login', wait_until='networkidle')
    attrs = page.evaluate(USERNAME_ATTRS, '#username')
    assert attrs == {'autocapitalize': 'none', 'autocorrect': 'off', 'spellcheck': False}, attrs


def test_the_new_user_username_field_does_not_capitalise_or_correct_what_is_typed(signed_in):
    page = signed_in
    page.goto(f'{BASE_URL}/settings#users', wait_until='networkidle')
    attrs = page.evaluate(USERNAME_ATTRS, '#newUserUsername')
    assert attrs == {'autocapitalize': 'none', 'autocorrect': 'off', 'spellcheck': False}, attrs


def test_a_single_sign_on_failure_is_announced_without_marking_the_password(anonymous):
    """A single sign-on failure has nothing to do with the password field."""
    page = anonymous
    page.goto(f'{BASE_URL}/login?error=oidc_state_mismatch', wait_until='networkidle')
    page.wait_for_selector('#errorMessage:not(.hidden)', timeout=5000)
    assert 'Single sign-on failed' in page.inner_text('#errorMessage')
    assert page.get_attribute('#password', 'aria-invalid') is None
    assert page.get_attribute('#password', 'aria-describedby') is None
