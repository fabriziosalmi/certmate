"""An absolutely-positioned menu cannot live inside an ancestor that clips.

Reported as #758: the snooze dropdown on the notifications page "will hide
behind element under, its not on top". It reads like a z-index problem and is
not one. The panel carries `z-10`, and no z-index escapes `overflow: hidden` —
an ancestor with it clips its descendants at its own box, whatever they paint
above.

Measured in a real browser against a running instance, opening the snooze menu
on the last row of the list:

    panel            y 376 -> 470   (94px tall)
    clipping ancestor .bg-surface.shadow-card.rounded-xl.overflow-hidden
                     bottom edge at y 392
    -> 78 of the panel's 94 pixels were cut off

Only the first option was partly visible; hit-testing the three buttons with
`document.elementFromPoint` returned false for all of them, so they were not
merely hard to see, they were not clickable.

The `overflow-hidden` was there to keep children inside the card's rounded
corners. It was not doing that job for anyone: every direct child of that card
has a transparent background — checked in the browser across the page's states,
including the "Show snoozed" section with its tinted header — and the card's
own `bg-surface` is clipped by its own `border-radius` without help. So the
class was clipping the one thing that needed to escape and nothing that needed
clipping.

After removing it: no clipping ancestor, and all three options hit-test as
reachable.
"""
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

TEMPLATE = (pathlib.Path(__file__).resolve().parent.parent
            / 'templates' / 'notifications.html')


def _card_wrapper(source):
    """The `<div>` that wraps the notifications list.

    Matched on the class combination rather than a line number so that moving
    the block does not silently stop this from checking anything.
    """
    match = re.search(r'<div class="(bg-surface shadow-card rounded-xl[^"]*)"',
                      source)
    assert match, (
        'the notifications card wrapper is gone or its classes changed, so '
        'this test is no longer looking at the element it is about')
    return match.group(1)


def test_the_card_holding_the_menu_does_not_clip():
    """THE regression. `overflow-hidden` here cuts the snooze panel off."""
    classes = _card_wrapper(TEMPLATE.read_text(encoding='utf-8'))

    assert 'overflow-hidden' not in classes, (
        'the notifications card clips its children again, which cuts off the '
        'snooze menu — the panel is absolutely positioned inside a row and no '
        'z-index escapes an overflow:hidden ancestor (#758)')


def test_the_card_still_has_its_rounded_corners():
    """CONTROL: the fix is removing the clipping, not the rounding. Dropping
    `rounded-xl` too would make the test above pass while changing the look."""
    assert 'rounded-xl' in _card_wrapper(TEMPLATE.read_text(encoding='utf-8'))


def test_the_menu_is_still_absolutely_positioned():
    """The premise. If the menu is ever rebuilt as an inline block, it no
    longer needs to escape anything and the assertion above stops meaning what
    it says — better to fail here and have someone delete this file than to
    keep a green test guarding a condition that no longer applies."""
    source = TEMPLATE.read_text(encoding='utf-8')
    panel = re.search(r"'<div class=\"absolute right-0[^\"]*\"", source)
    assert panel, (
        'the snooze menu is no longer an absolutely-positioned panel; if that '
        'is deliberate, this whole file can go')


def test_the_reason_is_written_where_the_class_was():
    """A removed class leaves no trace, and the next person tidying the
    template has every reason to add `overflow-hidden` back to a card that
    visibly has rounded corners. The comment is the only thing standing
    between them and reintroducing #758."""
    source = TEMPLATE.read_text(encoding='utf-8')
    head = source[:source.index('bg-surface shadow-card rounded-xl')]
    assert 'overflow-hidden' in head and '758' in head, (
        'nothing next to the card explains why it must not clip')
