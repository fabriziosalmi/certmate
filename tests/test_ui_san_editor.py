"""The SAN field is a chip editor, and it has to survive a pasted list (#725).

Asked for twice, independently, by the same operator (#600, then #631): the SAN
field was a single `<input type="text">` holding a comma-separated string. With
three names that is awkward; at the ~20 real certificates carry it is unusable,
because you cannot see what you typed and changing one in the middle means
retyping the lot.

These are browser tests rather than source assertions because everything that
can go wrong here is behavioural. The chips are a view over `#san_domains`,
which stays the hidden single source of truth so the eight existing readers and
writers of its `.value` keep working. Nothing about that arrangement is visible
to a test that only reads the JS: the failure modes are a chip that renders but
never reaches the field, a field the form clears without the chips noticing, and
an Enter key that submits the whole form instead of adding a name.

The paste case is the one the widget exists for. A chip editor that accepts one
name at a time would be *worse* than the text field it replaces at exactly the
size that prompted the request.
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


def _open_form(page):
    # The first-run wizard is a fixed overlay (#setupWizard, z-[110]) that
    # swallows pointer events on a fresh instance. Deleting the node is not
    # enough — setup-wizard.js renders it from an async /api/web/settings
    # response, so it comes back after the delete. Set the skip flag the
    # wizard's own "Skip" button sets, before any script runs.
    page.add_init_script(
        "try { window.localStorage.setItem('certmate_wizard_skipped', '1'); }"
        " catch (e) {}")
    page.goto(BASE_URL)
    page.wait_for_selector('#createCertFormContainer')
    assert page.locator('#setupWizard').count() == 0, (
        'the setup wizard is still on the page and will swallow clicks'
    )

    # The create form lives in a slide-over drawer behind the "+ New" button.
    # Without opening it the fields are reachable by keyboard but sit under the
    # dashboard, so a click test would be measuring the wrong page state.
    page.click('button[title="New certificate"]')
    page.wait_for_function(
        "() => !document.getElementById('createCertFormContainer')"
        "        .classList.contains('translate-x-full')")
    page.wait_for_selector('#san_entry', state='visible')
    return page.locator('#san_entry')


def _chips(page):
    return page.locator('#san_chips > span > span:first-child').all_text_contents()


def _field_value(page):
    return page.eval_on_selector('#san_domains', 'el => el.value')


class TestSanChipEditor:

    def test_enter_turns_what_was_typed_into_a_chip(self, browser_page):
        entry = _open_form(browser_page)
        entry.fill('www.example.com')
        entry.press('Enter')

        assert _chips(browser_page) == ['www.example.com']
        assert entry.input_value() == '', 'the entry field was not cleared'

    def test_enter_does_not_submit_the_form(self, browser_page):
        """The field sits inside #createCertForm. Without preventDefault, Enter
        fires the form's submit handler and issues a half-filled certificate
        request — worse than the problem being fixed.

        Two earlier versions of this test were measured to be blind. Asserting
        "the page did not navigate" sees nothing, because the submit handler
        calls preventDefault itself. Asserting "no create request fired" sees
        nothing either while #domain is empty, because the handler's own
        validation stops before the request.

        So the primary domain is filled first — which is the realistic order
        anyway, since nobody types SANs for a certificate they have not named —
        and then the request is the thing observed. Verified by mutation:
        removing the preventDefault makes this POST /api/certificates/create.
        """
        posted = []
        browser_page.on('request', lambda r: (
            posted.append(r.url) if r.method == 'POST' else None))

        entry = _open_form(browser_page)
        browser_page.fill('#domain', 'example.com')
        entry.fill('www.example.com')
        entry.press('Enter')
        browser_page.wait_for_timeout(400)

        creates = [u for u in posted if 'certificates/create' in u]
        assert not creates, (
            f'Enter in the SAN field submitted the create form: {creates}'
        )
        assert _chips(browser_page) == ['www.example.com'], (
            'and it did not add the chip either'
        )

    def test_a_comma_also_commits(self, browser_page):
        entry = _open_form(browser_page)
        entry.fill('mail.example.com')
        entry.press(',')

        assert _chips(browser_page) == ['mail.example.com']

    def test_the_chips_reach_the_hidden_field(self, browser_page):
        """The chips are a view; the request body is built from
        `#san_domains`. A chip that renders without updating the field looks
        correct and issues the wrong certificate."""
        entry = _open_form(browser_page)
        for name in ('a.example.com', 'b.example.com'):
            entry.fill(name)
            entry.press('Enter')

        assert _field_value(browser_page) == 'a.example.com, b.example.com'

    # -- the case this exists for --------------------------------------- #

    @pytest.mark.parametrize('pasted', [
        'a.example.com, b.example.com, c.example.com',
        'a.example.com b.example.com c.example.com',
        'a.example.com\nb.example.com\nc.example.com',
        'a.example.com;b.example.com;c.example.com',
        '  a.example.com ,, b.example.com ,\n c.example.com ,  ',
    ])
    def test_a_pasted_list_becomes_separate_chips(self, browser_page, pasted):
        """Commas, spaces, newlines, semicolons, and a trailing separator with
        stray whitespace — the shapes an operator actually has on the
        clipboard."""
        entry = _open_form(browser_page)
        entry.focus()
        # Playwright's insert_text does not fire a paste event; drive the real
        # clipboard path so the paste handler is what is under test.
        browser_page.evaluate(
            """(text) => {
                const el = document.getElementById('san_entry');
                el.focus();
                const dt = new DataTransfer();
                dt.setData('text/plain', text);
                el.dispatchEvent(new ClipboardEvent('paste', {
                    clipboardData: dt, bubbles: true, cancelable: true }));
            }""", pasted)

        assert _chips(browser_page) == [
            'a.example.com', 'b.example.com', 'c.example.com'], (
            f'pasting {pasted!r} did not split into three names'
        )

    def test_a_duplicate_is_not_added_twice(self, browser_page):
        entry = _open_form(browser_page)
        for name in ('a.example.com', 'A.Example.com  '):
            entry.fill(name)
            entry.press('Enter')

        assert _chips(browser_page) == ['a.example.com']

    # -- removal ---------------------------------------------------------- #

    def test_a_chip_can_be_removed_without_touching_its_neighbours(
            self, browser_page):
        entry = _open_form(browser_page)
        for name in ('a.example.com', 'b.example.com', 'c.example.com'):
            entry.fill(name)
            entry.press('Enter')

        browser_page.click('button[aria-label="Remove b.example.com"]')

        assert _chips(browser_page) == ['a.example.com', 'c.example.com']
        assert _field_value(browser_page) == 'a.example.com, c.example.com'

    def test_backspace_on_an_empty_entry_removes_the_last_chip(self, browser_page):
        entry = _open_form(browser_page)
        for name in ('a.example.com', 'b.example.com'):
            entry.fill(name)
            entry.press('Enter')

        entry.press('Backspace')

        assert _chips(browser_page) == ['a.example.com']

    def test_backspace_while_typing_edits_the_text_instead(self, browser_page):
        """CONTROL: the shortcut must not eat a chip mid-word."""
        entry = _open_form(browser_page)
        entry.fill('a.example.com')
        entry.press('Enter')
        entry.fill('bb')
        entry.press('Backspace')

        assert _chips(browser_page) == ['a.example.com'], 'a chip was eaten'
        assert entry.input_value() == 'b'

    # -- the form still owns the field ------------------------------------ #

    def test_blur_does_not_discard_what_was_typed(self, browser_page):
        """Someone types the last name and clicks Create. Losing it there is
        silent and issues a certificate missing a name."""
        entry = _open_form(browser_page)
        entry.fill('typed.example.com')
        browser_page.locator('#domain').click()

        assert _chips(browser_page) == ['typed.example.com']
        assert _field_value(browser_page) == 'typed.example.com'

    def test_the_wildcard_helper_still_sees_changes(self, browser_page):
        """`updateDnsAliasHelp` listens for 'input' on #san_domains. Assigning
        `.value` from script fires no event, so the editor dispatches one; if
        that stops, dependent UI silently freezes on stale values."""
        fired = 'window.__sanInputEvents = (window.__sanInputEvents || 0) + 1'
        _open_form(browser_page)
        browser_page.evaluate(
            f"""() => document.getElementById('san_domains')
                     .addEventListener('input', () => {{ {fired} }})""")

        entry = browser_page.locator('#san_entry')
        entry.fill('a.example.com')
        entry.press('Enter')

        assert browser_page.evaluate('window.__sanInputEvents || 0') >= 1, (
            'no input event was dispatched on #san_domains'
        )
