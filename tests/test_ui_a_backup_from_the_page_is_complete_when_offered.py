"""What the settings page asks for when it creates a backup.

The server renders the "include credentials and private keys" box only when
CERTMATE_BACKUP_PASSPHRASE is set (tests/test_a_restorable_backup_is_offered_
with_a_passphrase.py). The shared test instance has no passphrase, so the box
is put in the page here as the server would render it; the create request is
answered in the browser, so no backup is written.
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
BOX = """() => {
    const label = document.createElement('label');
    label.innerHTML = '<input type="checkbox" id="backupIncludeSecrets" checked> include';
    document.querySelector('[data-click="createBackup"]').after(label);
}"""


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _create(page, before=None):
    sent = []

    def handle(route):
        sent.append(json.loads(route.request.post_data or '{}'))
        route.fulfill(status=200, content_type='application/json',
                      body=json.dumps({'message': 'ok', 'backups': []}))
    page.route('**/api/backups/create', handle)
    page.goto(f'{BASE_URL}/settings#backup', wait_until='networkidle')
    if before:
        page.evaluate(before)
    page.click('[data-click="createBackup"]')
    page.wait_for_timeout(800)
    assert len(sent) == 1
    return sent[0]


def test_without_a_passphrase_the_page_asks_for_a_masked_backup_and_says_why(page):
    body = _create(page)
    assert body['include_secrets'] is False
    assert page.is_visible('#backupNoPassphrase')


def test_the_offered_box_asks_for_a_complete_backup(page):
    body = _create(page, BOX)
    assert body['include_secrets'] is True


def test_the_box_cleared_asks_for_a_masked_one(page):
    """CONTROL: the request follows the box, not the box's presence."""
    cleared = BOX[:-1] + "    document.getElementById('backupIncludeSecrets').checked = false;\n}"
    body = _create(page, cleared)
    assert body['include_secrets'] is False
