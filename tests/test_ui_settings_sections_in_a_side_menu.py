"""The Settings sections are a side menu in three groups, and a list on a phone (#1423).

Twelve tabs in one row needed a horizontal scroll bar at most widths. From lg (1024 px)
up they are a side menu: Certificates, Access, System, each a tablist of its own (a
tablist may hold only tabs), with the arrow keys moving through all three, since only the
selected tab is in the Tab order. Below lg the sections are a native list.

The selected tab is marked by a bar as well as by colour (WCAG 1.4.1).
"""

import os

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"


def _open(page, width, fragment='general'):
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{BASE_URL}/settings#{fragment}", wait_until="networkidle")
    page.wait_for_timeout(500)


def test_the_sections_are_three_named_groups_and_nothing_scrolls_sideways(browser_page):
    page = browser_page
    _open(page, 1440)

    names = page.eval_on_selector_all(
        '[data-settings-sections] [role="tablist"]',
        "lists => lists.map(l => document.getElementById(l.getAttribute('aria-labelledby')).textContent.trim())")
    assert names == ['Certificates', 'Access', 'System']
    assert page.locator('[data-settings-sections] [role="tab"]').count() == 12
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")


def test_the_arrow_keys_cross_from_one_group_to_the_next(browser_page):
    page = browser_page
    _open(page, 1440, 'acme')

    page.locator('#settings-tab-acme').focus()
    page.keyboard.press('ArrowDown')
    page.wait_for_timeout(300)
    assert page.locator('#settings-tab-users').get_attribute('aria-selected') == 'true'
    assert page.evaluate("document.activeElement.id") == 'settings-tab-users'
    assert page.evaluate("location.hash") == '#users'

    page.locator('#settings-tab-general').click()
    page.keyboard.press('ArrowUp')
    page.wait_for_timeout(300)
    assert page.evaluate("document.activeElement.id") == 'settings-tab-backup', 'Up from the first should wrap to the last'


def test_the_selected_section_is_marked_by_more_than_colour(browser_page):
    page = browser_page
    _open(page, 1440, 'dns')

    def bar(tab):
        return page.eval_on_selector(f'#settings-tab-{tab}', """el => {
            const s = getComputedStyle(el);
            return [s.borderLeftWidth, s.borderLeftColor, el.getBoundingClientRect().width];
        }""")

    selected, other = bar('dns'), bar('ca')
    assert selected[0] == '2px' and selected[1] != 'rgba(0, 0, 0, 0)'
    assert other[1] == 'rgba(0, 0, 0, 0)', 'an unselected tab shows a bar'
    assert selected[2] == other[2], 'selecting a tab changed its size'


def test_a_phone_gets_a_list_of_sections(browser_page):
    page = browser_page
    _open(page, 390, 'general')

    assert not page.locator('[data-settings-sections]').is_visible()
    choice = page.locator('#settings-section')
    assert choice.is_visible()
    choice.select_option('apikeys')
    page.wait_for_timeout(400)
    assert page.locator('#settings-panel-apikeys').is_visible()
    assert page.evaluate("location.hash") == '#apikeys'
    assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
