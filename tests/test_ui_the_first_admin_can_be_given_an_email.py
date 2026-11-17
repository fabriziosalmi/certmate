"""The setup page can give the first admin an email (#1466, part 1).

OIDC's `link_by_email` matches an SSO login to a local account by its email,
and the setup page created the first admin with a username and a password
only. An operator turning SSO on for the first time usually wants that admin
linked, and had to edit the account first. The field is optional and is sent
only when filled in, so an empty field creates the admin exactly as before.

Driven through the real page in Chromium, against a real instance in setup
mode served on a local port: what is asserted is the user the instance stored.
"""
import secrets
import threading
from pathlib import Path

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

pytestmark = [pytest.mark.ui]

CHECKOUT = Path(__file__).resolve().parent.parent
PASSWORD = 'First-admin-' + secrets.token_hex(6) + '!1'


@pytest.fixture
def instance(tmp_path, monkeypatch):
    """A fresh instance in setup mode, served on 127.0.0.1."""
    from werkzeug.serving import make_server

    from modules.factory import create_app

    # The factory keeps its data beside its own file; the anchor moves it into
    # tmp_path, and the checkout's pages and assets are linked in beside it.
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True, exist_ok=True)
    (root / 'factory.py').write_text('# anchor\n')
    for name in ('templates', 'static'):
        (root.parent / name).symlink_to(CHECKOUT / name, target_is_directory=True)
    monkeypatch.setattr('modules.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.delenv('API_BEARER_TOKEN', raising=False)
    application, container = create_app()
    auth = container.managers['auth']
    assert auth.is_setup_mode() and not auth.list_users()

    server = make_server('127.0.0.1', 0, application, threaded=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f'http://127.0.0.1:{server.server_port}', auth
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture
def chromium():
    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch(headless=True)
    except Exception as e:  # reported as a skip, as conftest does
        pw.stop()
        if _REQUIRE_BROWSER:
            raise
        pytest.skip(f'Chromium not available: {e}')
    try:
        yield browser
    finally:
        browser.close()
        pw.stop()


def _complete_setup(chromium, base, email):
    page = chromium.new_page()
    try:
        page.goto(base + '/', wait_until='load')
        page.fill('#username', 'operator')
        if email is not None:
            page.fill('#email', email)
        page.fill('#password', PASSWORD)
        page.click('#setupBtn')
        page.wait_for_url('**/login', timeout=15000)
    finally:
        page.close()


def test_the_email_typed_at_setup_is_the_admin_s(instance, chromium):
    base, auth = instance
    _complete_setup(chromium, base, '  Ops@Example.com ')
    user = auth.list_users()['operator']
    assert user['role'] == 'admin'
    assert user['email'] == 'Ops@Example.com'


def test_an_empty_field_creates_the_admin_as_before(instance, chromium):
    """CONTROL: the field is optional, and an empty one is not sent at all,
    so the admin is created exactly as the page did before."""
    base, auth = instance
    _complete_setup(chromium, base, None)
    user = auth.list_users()['operator']
    assert user['role'] == 'admin'
    assert not user['email']


def test_the_field_is_optional_and_says_what_it_is_for(instance, chromium):
    base, _ = instance
    page = chromium.new_page()
    try:
        page.goto(base + '/', wait_until='load')
        field = page.locator('#email')
        assert field.get_attribute('type') == 'email'
        assert field.get_attribute('required') is None
        assert field.get_attribute('autocomplete') == 'email'
        label = page.locator('label[for="email"]').inner_text()
        assert 'optional' in label.lower(), label
        help_text = page.locator('#' + field.get_attribute('aria-describedby')).inner_text()
        assert 'sign-on' in help_text, help_text
    finally:
        page.close()
