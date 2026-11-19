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


def test_a_saved_hook_whose_name_or_timeout_changed_waits_for_the_save_too(deploy_tab):
    """The run uses the saved name (it is in the run record and the audit
    entry) and the saved timeout, not the ones on screen."""
    page, panel = deploy_tab
    card, command, test = _new_hook(panel)
    name = card.locator('input[aria-label="Hook name"]')
    timeout = card.locator('input[title="Timeout in seconds"]')
    name.fill('b12 hook')
    command.fill('echo ok')
    assert _save(page, panel).status == 200
    expect(test).to_be_enabled()

    name.fill('b12 hook renamed')
    expect(test).to_be_disabled()
    name.fill('b12 hook')
    expect(test).to_be_enabled()

    timeout.fill('7')
    expect(test).to_be_disabled()


def test_while_a_save_is_on_its_way_the_hook_fields_take_no_edits(deploy_tab):
    """The save reads the configuration back into the fields. An edit typed
    while the POST was on its way was overwritten by that read-back, and Test
    was then offered for the old name: so the fields hold still until the
    save settles."""
    page, panel = deploy_tab
    card, command, test = _new_hook(panel)
    name = card.locator('input[aria-label="Hook name"]')
    name.fill('first name')
    command.fill('echo ok')
    held = []
    page.route('**/api/deploy/config', lambda route: held.append(route)
               if route.request.method == 'POST' else route.continue_())
    save = panel.locator('#deploy-hooks-save')
    save.click()
    expect(save).to_have_attribute('aria-busy', 'true')
    # "Saving…" stands beside the Save, as on every section (settings-unsaved.js).
    expect(save.locator('xpath=..')).to_contain_text('Saving')
    expect(name).to_have_js_property('readOnly', True)
    assert save.evaluate('el => el === document.activeElement'), 'focus moved off the Save button'
    name.click()
    page.keyboard.type(' second')
    assert name.input_value() == 'first name', 'an edit was taken while the save was on its way'
    hooks = panel.locator('textarea[aria-label="Hook command"]')
    before = hooks.count()
    panel.get_by_role('button', name='Add Global Hook').click()
    assert hooks.count() == before, 'a hook was added while the save was on its way'
    assert len(held) == 1
    with page.expect_response(lambda r: r.url.endswith('/api/deploy/config') and r.request.method == 'GET'):
        held[0].continue_()
    expect(save).not_to_have_attribute('aria-busy', 'true')
    expect(save.locator('xpath=..')).not_to_contain_text('Saving')
    expect(name).to_have_js_property('readOnly', False)
    expect(name).to_have_value('first name')
    expect(test).to_be_enabled()
    page.unroute('**/api/deploy/config')


def test_a_save_whose_values_cannot_be_read_back_says_so_and_keeps_what_was_sent(deploy_tab):
    page, panel = deploy_tab
    card, command, test = _new_hook(panel)
    card.locator('input[aria-label="Hook name"]').fill('b12 hook')
    command.fill('echo ok')

    def answer(route):
        if route.request.method == 'GET':
            return route.fulfill(status=503, content_type='application/json',
                                 body='{"error": "Deploy manager not available"}')
        return route.continue_()

    page.route('**/api/deploy/config', answer)
    assert _save(page, panel).status == 200
    expect(page.locator('#cm-toasts').get_by_text('could not read them back')).to_be_visible()
    expect(test).to_be_enabled()
    page.unroute('**/api/deploy/config')


@pytest.mark.parametrize('typed, saved', [('500', '300'), ('0', '1'), ('', '30')])
def test_after_a_save_the_fields_show_what_the_server_saved(deploy_tab, typed, saved):
    """The server limits the timeout to 1..300 and takes 30 for an empty one.
    The page remembered what it sent, so Test was offered while the field
    said 500 and the run would use 300."""
    page, panel = deploy_tab
    card, command, test = _new_hook(panel)
    timeout = card.locator('input[title="Timeout in seconds"]')
    card.locator('input[aria-label="Hook name"]').fill('b12 hook')
    command.fill('echo ok')
    timeout.fill(typed)
    assert _save(page, panel).status == 200
    expect(timeout).to_have_value(saved)
    expect(test).to_be_enabled()
