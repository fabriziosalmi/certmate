"""Settings asks before leaving with changes nobody saved.

Found by the UX audit of 2026-11-17: the renewal threshold changed from 30 to
21, then a click elsewhere, and no prompt; the server still had 30. A webhook
added on Notifications was lost the same way. The page has seven save buttons
and some sections apply at once (users, API keys, probe targets), so
static/js/settings-unsaved.js is told in the markup which parts a Save button
saves; an edit there marks that part changed until its own save succeeds.

The tests write back the values they found, and the main form's save is
answered in the browser, so the shared instance is left as it was: the guard
tracks edits, not values.
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
THRESHOLD = '#renewal_threshold_days'


@pytest.fixture
def page(browser_page, ui_session_cookie):
    context = browser_page.context.browser.new_context(viewport={'width': 1280, 'height': 900})
    context.add_cookies([{'name': 'certmate_session', 'value': ui_session_cookie, 'url': BASE_URL}])
    page = context.new_page()
    yield page
    # A routed answer still in flight when the context closes is reported at
    # the next test's setup; let it go quietly here.
    if not page.is_closed():
        page.unroute_all(behavior='ignoreErrors')
    context.close()


def _open(page, tab):
    page.goto(f'{BASE_URL}/settings#{tab}', wait_until='networkidle')
    page.wait_for_function("() => typeof window.CertMate.unsavedSettings === 'function'")


def _unsaved(page):
    return page.evaluate('() => window.CertMate.unsavedSettings()')


def _would_ask(page):
    return page.evaluate("""() => {
        const event = new Event('beforeunload', {cancelable: true});
        window.dispatchEvent(event);
        return event.defaultPrevented;
    }""")


def _settings_answered_in_the_browser(page):
    """The main form saves the whole settings document, and this instance has
    no CA email, which the page refuses to save without. The settings the page
    reads carry one, and its save is answered here: the guard sees a write
    that succeeded, and the shared instance is not written."""
    import json

    def handle(route):
        if route.request.method == 'GET':
            answer = route.fetch()
            settings = answer.json()
            settings['email'] = settings.get('email') or 'ops@example.test'
            return route.fulfill(response=answer, body=json.dumps(settings))
        return route.fulfill(status=200, content_type='application/json',
                             body=json.dumps({'message': 'Settings saved'}))
    page.route('**/api/web/settings', handle)


def _threshold(page):
    page.wait_for_function(f"() => document.querySelector('{THRESHOLD}').value !== ''")
    return page.input_value(THRESHOLD)


def test_an_edit_nobody_saved_makes_the_browser_ask(page):
    _open(page, 'general')
    original = _threshold(page)
    page.fill(THRESHOLD, '21' if original != '21' else '22')
    assert _unsaved(page) == ['dns, ca, general and storage']

    asked = []
    page.on('dialog', lambda dialog: (asked.append(dialog.type), dialog.dismiss()))
    page.close(run_before_unload=True)
    page.wait_for_timeout(500)
    assert asked == ['beforeunload']


def test_saving_the_section_stops_the_question(page):
    _settings_answered_in_the_browser(page)
    _open(page, 'general')
    original = _threshold(page)
    page.fill(THRESHOLD, original)          # an edit, back to the value it had
    assert _would_ask(page)
    with page.expect_response(lambda r: r.request.method == 'POST' and r.url.endswith('/api/web/settings') and r.ok):
        page.click('#saveBtn')
    page.wait_for_function('() => window.CertMate.unsavedSettings().length === 0')
    assert not _would_ask(page)


def test_a_page_only_looked_at_does_not_ask(page):
    """CONTROL: the values the page fills in itself are not edits."""
    for tab in ('general', 'dns', 'notifications', 'deploy', 'oidc', 'acme', 'apikeys'):
        _open(page, tab)
        page.wait_for_timeout(300)
        assert _unsaved(page) == [], tab
    assert not _would_ask(page)


def test_a_section_that_applies_at_once_does_not_ask(page):
    """A new API key is created by its own button and nothing else saves it."""
    _open(page, 'apikeys')
    page.fill('#apikey-new-name', 'typed, not created')
    assert _unsaved(page) == []


def test_each_section_is_saved_by_its_own_button(page):
    """An edit on Notifications is not saved by the main form's Save, and
    stays pending after it."""
    _settings_answered_in_the_browser(page)
    _open(page, 'notifications')
    switch = page.locator('label:has(input[title="Enable notifications"])')
    switch.click()
    switch.click()                          # back to the value it had
    assert _unsaved(page) == ['notifications']

    page.click('#settings-tab-general')
    original = _threshold(page)
    page.fill(THRESHOLD, original)
    with page.expect_response(lambda r: r.request.method == 'POST' and r.url.endswith('/api/web/settings') and r.ok):
        page.click('#saveBtn')
    page.wait_for_function("() => !window.CertMate.unsavedSettings().includes('dns, ca, general and storage')")
    assert _unsaved(page) == ['notifications']
    assert _would_ask(page)
