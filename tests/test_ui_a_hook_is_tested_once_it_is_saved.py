"""A hook is tested once it is saved, and a refused save points at the field.

UX perception audit, 2026-11-18 (#1511, P40): Test on a hook that had not been
saved answered "Hook aec6ea19-... is no longer in settings. This usually means
the page is out of sync ... or rejected by the safety validator ... Refresh the
Settings page" (a 404): the test runs the hook the server has, and the server
had none. A save refused for a `;` said only "contains dangerous shell
metacharacters", and no field was marked.

Now Test is disabled, saying "Save the hook first", until the hook is saved as
it stands; a refused save names what it refused and marks the command field.

Against the real server: the refusal is the server's own. The deploy
configuration is read first and put back after.
"""
import os

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

from playwright.sync_api import expect

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"


@pytest.fixture
def deploy_tab(browser_page, ui_session_cookie):
    session = requests.Session()
    session.cookies.set('certmate_session', ui_session_cookie)
    before = session.get(f'{BASE_URL}/api/deploy/config', headers=e2e_auth_headers(), timeout=10)
    assert before.status_code == 200, before.text[:200]
    original = before.json()

    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    page.emulate_media(reduced_motion='reduce')
    page.goto(f'{BASE_URL}/settings', wait_until='networkidle')
    page.click('#settings-tab-deploy')
    panel = page.locator('#settings-panel-deploy')
    panel.wait_for(state='visible')
    master = panel.locator('input[aria-label="Enable deploy hooks"]')
    if not master.is_checked():
        master.locator('xpath=..').click()
    panel.get_by_role('button', name='Global Hooks').click()
    panel.get_by_role('button', name='Add Global Hook').click()
    try:
        yield page, panel
    finally:
        context.close()
        restored = session.post(f'{BASE_URL}/api/deploy/config', json=original,
                                headers=dict(e2e_auth_headers(), Origin=BASE_URL), timeout=10)
        assert restored.status_code == 200, f'could not restore the deploy config: {restored.text[:200]}'


def _new_hook(panel):
    command = panel.locator('textarea[aria-label="Hook command"]').last
    card = command.locator('xpath=..')
    return card, command, card.locator('button:has-text("Test")')


def _save(page, panel):
    with page.expect_response(lambda r: r.url.endswith('/api/deploy/config')
                              and r.request.method == 'POST') as answered:
        panel.get_by_role('button', name='Save Deploy Settings').click()
    return answered.value


def test_a_hook_that_is_not_saved_cannot_be_tested_and_says_why(deploy_tab):
    page, panel = deploy_tab
    card, command, test = _new_hook(panel)
    assert test.is_disabled(), 'Test is offered on a hook the server does not have'
    hint = card.get_by_text('Save the hook first')
    expect(hint).to_be_visible()

    card.locator('input[aria-label="Hook name"]').fill('b12 hook')
    command.fill('echo ok')
    assert _save(page, panel).status == 200
    expect(test).to_be_enabled()
    expect(hint).to_be_hidden()

    command.fill('echo changed')
    expect(test).to_be_disabled()
    expect(hint).to_be_visible()


def test_a_refused_save_names_the_character_and_marks_the_command(deploy_tab):
    page, panel = deploy_tab
    card, command, _test = _new_hook(panel)
    card.locator('input[aria-label="Hook name"]').fill('b12 hook')
    command.fill('echo a; echo b')
    answer = _save(page, panel)
    assert answer.status == 400
    toast = page.locator('#cm-toasts').get_by_text("';'")
    toast.first.wait_for(state='visible')
    assert command.get_attribute('aria-invalid') == 'true', 'the refused command is not marked'

    command.fill('echo fine')
    assert _save(page, panel).status == 200
    expect(command).not_to_have_attribute('aria-invalid', 'true')
