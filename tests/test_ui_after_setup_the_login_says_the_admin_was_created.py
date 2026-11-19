"""After setup the login page says the admin was created and fills in its
name, and the wizard starts with the email given at setup.

UX perception audit, 2026-11-18 (P58): "Complete Initial Setup" went to a
blank login page in under a second, with no word that the account existed and
an empty username, and the wizard's email field was empty although an email
had just been typed at setup. Decided: the login page says so with the
username filled in; no automatic sign-in, no change to authentication.

The name is not carried in the URL. The decision named /login?created=<name>,
and the image's gunicorn writes every request line to its access log
(Dockerfile: --access-logfile -), measured: "GET /login?created=probeuser7731
HTTP/1.1" 200. The setup page hands it over in sessionStorage instead, which
this tab alone can read.

Driven through the real pages in Chromium, against a fresh instance in setup
mode (the fixture of tests/test_ui_the_first_admin_can_be_given_an_email.py).
"""
import pytest

from tests.conftest import _REQUIRE_BROWSER

if _REQUIRE_BROWSER:
    import importlib.util
    if importlib.util.find_spec("playwright") is None:
        raise RuntimeError("playwright is not installed but CERTMATE_UI_REQUIRE_BROWSER=1")
else:
    pytest.importorskip("playwright")

from tests import test_ui_the_first_admin_can_be_given_an_email as first_admin

# Its fixtures: a fresh instance in setup mode, and Chromium.
instance = first_admin.instance
chromium = first_admin.chromium
PASSWORD = first_admin.PASSWORD

pytestmark = [pytest.mark.ui]

NAME = 'first-operator'


def _setup(page, base, email=None):
    page.goto(base + '/', wait_until='load')
    page.fill('#username', NAME)
    if email is not None:
        page.fill('#email', email)
    page.fill('#password', PASSWORD)
    page.click('#setupBtn')
    page.wait_for_url('**/login', timeout=15000)
    page.wait_for_load_state('load')


def _created_message(page):
    box = page.locator('#createdMessage')
    return box.inner_text() if box.count() and box.is_visible() else ''


def test_after_setup_the_login_page_says_the_admin_was_created_and_fills_in_its_name(instance, chromium):
    base, _ = instance
    page = chromium.new_page()
    try:
        _setup(page, base)
        assert '?' not in page.url, page.url
        message = _created_message(page)
        assert NAME in message and 'created' in message, message
        assert page.input_value('#username') == NAME
        assert page.evaluate('() => document.activeElement.id') == 'password'
    finally:
        page.close()


def test_a_plain_visit_to_the_login_page_says_nothing_about_an_account(instance, chromium):
    base, _ = instance
    page = chromium.new_page()
    try:
        _setup(page, base)
        # Reloaded, or opened anew: the message was for the first view only.
        page.reload(wait_until='load')
        assert _created_message(page) == ''
        assert page.input_value('#username') == ''
    finally:
        page.close()
    other = chromium.new_page()
    try:
        other.goto(base + '/login', wait_until='load')
        assert _created_message(other) == ''
        assert other.input_value('#username') == ''
    finally:
        other.close()


def test_a_crafted_name_is_shown_as_text(instance, chromium):
    base, _ = instance
    page = chromium.new_page()
    try:
        _setup(page, base)
        crafted = '<img src=x onerror="window.__injected=1">'
        page.evaluate("v => sessionStorage.setItem('certmate_setup_created', v)", crafted)
        page.goto(base + '/login', wait_until='load')
        page.wait_for_timeout(300)
        assert crafted in _created_message(page)
        assert page.locator('#createdMessage img').count() == 0
        assert page.evaluate('() => window.__injected') is None
        assert page.input_value('#username') == crafted
    finally:
        page.close()


def _sign_in_to_the_wizard(page):
    page.fill('#username', NAME)
    page.fill('#password', PASSWORD)
    page.click('#loginBtn')
    page.wait_for_selector('#wizEmail', state='visible', timeout=15000)


def test_the_wizard_starts_with_the_email_given_at_setup(instance, chromium):
    base, _ = instance
    page = chromium.new_page()
    try:
        _setup(page, base, email='  ops@example.org ')
        _sign_in_to_the_wizard(page)
        assert page.input_value('#wizEmail') == 'ops@example.org'
    finally:
        page.close()


def test_without_an_email_at_setup_the_wizard_starts_empty(instance, chromium):
    """CONTROL: nothing is made up when setup was given no email."""
    base, _ = instance
    page = chromium.new_page()
    try:
        _setup(page, base)
        _sign_in_to_the_wizard(page)
        assert page.input_value('#wizEmail') == ''
    finally:
        page.close()
