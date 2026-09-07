"""The maintenance window is configurable from the UI (#632).

The feature is worthless if the only way to set a window is to hand-edit
`settings.json`, and its correctness is not visible from the JS source. Three
things are pinned here, in the browser, against the real page:

* the toggle exists and reveals the fields;
* the window reaches the POST body, which is what the server validates and
  stores — the DOM having the right values proves nothing on its own;
* turning the toggle back off REMOVES the window rather than leaving an empty
  object behind. That one matters more than it looks: the server treats any
  window object as a reason to defer, so a leftover `{}` would hold every
  deploy of that hook for a window with no hours in it.
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

EXISTING = {
    'enabled': True,
    'global_hooks': [{
        'id': 'hook-1', 'name': 'reload nginx', 'command': 'echo reload',
        'enabled': True, 'timeout': 30, 'on_events': ['created', 'renewed'],
    }],
    'domain_hooks': {},
    'targets': [],
}


def _open_deploy_tab(page, config=None):
    """Settings → Deploy, with a known hook already configured.

    /api/deploy/config is intercepted on GET so the panel has a hook to edit
    without touching real settings; the POST is what the assertions read.
    """
    body = json.dumps(config if config is not None else EXISTING)

    def _handle(route, request):
        if request.method == 'GET':
            route.fulfill(status=200, content_type='application/json',
                          body=body)
        else:
            route.fulfill(status=200, content_type='application/json',
                          body=json.dumps({'success': True}))

    page.route('**/api/deploy/config', _handle)
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); }"
        " catch (e) {}")
    page.goto(f'{BASE_URL}/settings')
    page.click('#settings-tab-deploy')
    page.wait_for_selector('#settings-panel-deploy', state='visible')


def _capture_posts(page):
    seen = []
    page.on('request', lambda r: (
        seen.append((r.url, r.post_data))
        if r.method == 'POST' and '/api/deploy/config' in r.url else None))
    return seen


def _open_global_hooks(page, config=None):
    """Settings -> Deploy, with the Global Hooks accordion expanded.

    Opening the tab is part of this on purpose: the panel is behind
    `x-show="tab === 'deploy'"`, and a locator that resolves inside a hidden
    panel simply never becomes clickable — a 30-second timeout that reads like
    a missing element.
    """
    _open_deploy_tab(page, config)
    panel = page.locator('#settings-panel-deploy')
    panel.locator('button:has-text("Global Hooks")').first.click()
    page.wait_for_timeout(200)
    return panel


def test_the_hook_editor_offers_a_maintenance_window(browser_page):
    panel = _open_global_hooks(browser_page)
    toggle = panel.locator(
        'label:has-text("Only deploy during a maintenance window") '
        'input[type="checkbox"]')
    assert toggle.count() >= 1, (
        'the deploy hook editor has no maintenance-window control, so a window '
        'can only be set by hand-editing settings.json'
    )


def test_the_fields_are_hidden_until_the_window_is_switched_on(browser_page):
    """CONTROL: a window that is always visible would suggest every hook has
    one, and the default — deploy immediately — is what nearly every hook
    wants."""
    panel = _open_global_hooks(browser_page)
    start = panel.locator('input[aria-label="Maintenance window start"]')
    assert start.count() == 0, (
        'the window fields exist for a hook that has no window. They are '
        'behind x-if rather than x-show for a reason: x-show leaves the '
        'bindings live, so `hook.window.start` is evaluated for every '
        'window-less hook and Alpine logs an error per binding per hook.'
    )

    panel.locator('label:has-text("Only deploy during a maintenance window") '
                  'input[type="checkbox"]').first.click()
    browser_page.wait_for_timeout(300)
    assert start.count() >= 1 and start.first.is_visible(), (
        'the toggle did not reveal the fields'
    )


def test_the_window_reaches_the_saved_configuration(browser_page):
    """The fields existing is not the feature; the window arriving is."""
    panel = _open_global_hooks(browser_page)
    posts = _capture_posts(browser_page)

    panel.locator('label:has-text("Only deploy during a maintenance window") '
                  'input[type="checkbox"]').first.click()
    browser_page.wait_for_timeout(200)
    panel.locator('input[aria-label="Maintenance window start"]').first.fill('23:00')
    panel.locator('input[aria-label="Maintenance window end"]').first.fill('01:30')
    panel.locator('input[aria-label="Maintenance window timezone"]').first.fill(
        'Europe/Rome')
    panel.locator('label:has-text("Maintenance window on sat"), '
                  'input[aria-label="Maintenance window on sat"]').last.click()
    browser_page.wait_for_timeout(200)

    browser_page.locator(
        '#settings-panel-deploy button:has-text("Save")').first.click()
    browser_page.wait_for_timeout(600)

    assert posts, 'the deploy configuration was never saved'
    hook = json.loads(posts[-1][1] or '{}')['global_hooks'][0]
    assert hook.get('window') == {
        'start': '23:00', 'end': '01:30', 'days': ['sat'],
        'timezone': 'Europe/Rome',
    }, f'the window did not reach the request body: {hook.get("window")!r}'


def test_switching_the_window_off_removes_it_rather_than_emptying_it(
        browser_page):
    """The one that would be silent. The server defers on the PRESENCE of a
    window object, so a hook left with `window: {}` would be held for a window
    that has no hours in it — every deploy, forever, with nothing logged.
    """
    with_window = json.loads(json.dumps(EXISTING))
    with_window['global_hooks'][0]['window'] = {
        'start': '02:00', 'end': '04:00', 'days': [], 'timezone': 'UTC'}

    panel = _open_global_hooks(browser_page, with_window)
    posts = _capture_posts(browser_page)

    toggle = panel.locator(
        'label:has-text("Only deploy during a maintenance window") '
        'input[type="checkbox"]').first
    assert toggle.is_checked(), 'the stored window was not reflected in the UI'
    toggle.click()
    browser_page.wait_for_timeout(200)

    browser_page.locator(
        '#settings-panel-deploy button:has-text("Save")').first.click()
    browser_page.wait_for_timeout(600)

    assert posts, 'the deploy configuration was never saved'
    hook = json.loads(posts[-1][1] or '{}')['global_hooks'][0]
    assert 'window' not in hook, (
        f'switching the window off left {hook.get("window")!r} behind, which '
        f'the server reads as a window and defers on'
    )
