"""The Server, Client and ACME buttons stay where they are when the view changes (#1423).

The toggle cluster in the topbar is centred. On the ACME view it used to lose two
things: the counter strip (there was none for ACME) and the "New" button with its
divider (x-show removed them). The cluster got narrower, re-centred, and the three
buttons moved under the pointer that had just clicked one of them.

The ACME view now has counters of its own, and "New" is made invisible there rather
than removed, so it keeps its width. These tests measure the buttons in a real
browser, at a width where the cluster sits in the bar and at one where it wraps onto
its own row, because the two layouts centre differently.
"""

import os

import pytest

pytestmark = [pytest.mark.e2e, pytest.mark.ui]

BASE_URL = f"http://localhost:{os.environ.get('CERTMATE_TEST_PORT', '18888')}"
BUTTONS = ("#certViewServerBtn", "#certViewClientBtn", "#certViewAcmeBtn")
VIEWS = ("#certViewAcmeBtn", "#certViewClientBtn", "#certViewServerBtn")


def _positions(page):
    # Both axes: a strip too wide for the bar wraps under the toggle, which keeps
    # x and moves everything up (measured with four ACME counters at 1440 px).
    def where(button):
        box = page.locator(button).bounding_box()
        return round(box["x"]), round(box["y"])
    return {button: where(button) for button in BUTTONS}


@pytest.mark.parametrize("width", [1440, 800])
def test_the_view_buttons_do_not_move_when_the_view_changes(browser_page, width):
    page = browser_page
    page.set_viewport_size({"width": width, "height": 900})
    page.goto(f"{BASE_URL}/", wait_until="networkidle")
    page.wait_for_timeout(400)
    start = _positions(page)

    for view in VIEWS:
        page.locator(view).click()
        page.wait_for_timeout(400)
        assert page.locator(view).get_attribute("aria-pressed") == "true"
        assert _positions(page) == start, (
            f"at {width}px the view buttons moved when {view} was chosen: "
            f"{start} -> {_positions(page)}")


def test_the_acme_view_has_counters_and_no_new_button(browser_page):
    page = browser_page
    page.set_viewport_size({"width": 1440, "height": 900})
    page.goto(f"{BASE_URL}/#acme", wait_until="networkidle")
    page.wait_for_timeout(600)

    strip = page.locator("#acmeStatsCards")
    assert strip.is_visible(), "the ACME view shows no counters"
    total = strip.locator("span").first.inner_text()
    assert total.isdigit(), f"the ACME total reads {total!r}"

    new = page.locator('button[title="New certificate"]')
    assert not new.is_visible(), "the New button is offered on the ACME view"
    # display:none has no box; visibility:hidden keeps its place in the layout.
    box = new.bounding_box()
    assert box is not None and box["width"] > 0, \
        "the New button was removed rather than hidden, so the cluster loses its width"
