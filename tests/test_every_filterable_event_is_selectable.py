"""An event you can filter on is an event you can tick.

Item 7 of #876. Both checkbox rows in the notification settings offered six
events. The system publishes and names seven filterable ones:
`certificate_deployed` was missing from both, so an operator who ticked any box
silently excluded an event they were never shown — and nothing anywhere said
so.

The backend already holds both halves of the answer:

* `modules/core/factory.py::_EVENT_TITLES` is effectively the set of notifiable
  events. Its own comment says why: an event without a title makes
  `build_notification_message` return None, "and the notifier was never
  reached, so the event nobody could silence was silent".
* `modules/core/notifier.py::_ALWAYS_NOTIFY_EVENTS` is the set that ignores the
  filter. Those must NOT have a checkbox — offering one implies a choice that
  does not exist, which is a different way of lying to the same operator.

So the selectable set is the first minus the second, and this file is what
keeps the three in step. It is the gap that hid `deploy_hook_failed` once
already; that was closed by exempting the event rather than by noticing the
lists could drift.

The template no longer carries the list at all: both rows read
`notifiableEvents` from the Alpine component, so there is one copy to check
rather than two to keep equal.
"""
import pathlib
import re

import pytest

from modules.core.factory import _EVENT_TITLES
from modules.core.notifier import _ALWAYS_NOTIFY_EVENTS

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
COMPONENT = REPO / 'static' / 'js' / 'settings-notifications.js'
TEMPLATE = REPO / 'templates' / 'partials' / 'settings_notifications.html'


def _selectable_in_the_ui():
    """The `notifiableEvents` array the settings component exposes."""
    source = COMPONENT.read_text(encoding='utf-8')
    match = re.search(r'notifiableEvents:\s*\[(.*?)\]', source, re.S)
    assert match, 'notifiableEvents is gone from the notification settings'
    return set(re.findall(r"'([a-z_]+)'", match.group(1)))


def _filterable_in_the_backend():
    return set(_EVENT_TITLES) - set(_ALWAYS_NOTIFY_EVENTS)


def test_both_sides_are_non_empty():
    """Guard the guard: either side coming back empty would make the
    comparison below pass by describing nothing."""
    assert len(_selectable_in_the_ui()) >= 5
    assert len(_filterable_in_the_backend()) >= 5


def test_every_filterable_event_can_be_selected():
    missing = _filterable_in_the_backend() - _selectable_in_the_ui()
    assert not missing, (
        f'these events are published and filterable, and the settings page '
        f'does not offer them: {sorted(missing)}. Ticking any box excludes '
        f'them without saying so.'
    )


def test_nothing_selectable_is_invented():
    """The other direction. A checkbox for an event the backend never
    publishes is a filter that silently matches nothing."""
    invented = _selectable_in_the_ui() - set(_EVENT_TITLES)
    assert not invented, sorted(invented)


def test_an_event_that_ignores_the_filter_gets_no_checkbox():
    """`deploy_hook_failed` and `certificate_deploy_incomplete` are sent
    whatever is selected. A checkbox would offer a choice that does not
    exist — the same lie as the missing one, told the other way round."""
    offered = _selectable_in_the_ui() & set(_ALWAYS_NOTIFY_EVENTS)
    assert not offered, (
        f'{sorted(offered)} would appear as filterable and are not; unticking '
        f'them changes nothing and the operator would not know'
    )


def test_certificate_deployed_specifically(scenario='the one that was missing'):
    """Named on its own, because a set comparison passing tells you nothing
    about which event it was that people could not select."""
    assert 'certificate_deployed' in _selectable_in_the_ui(), scenario
    assert 'certificate_deployed' in _EVENT_TITLES


def test_the_template_no_longer_carries_its_own_copy():
    """Two hardcoded arrays, both wrong in the same way, is how this happened.
    Both checkbox rows read the component's array now, so there is one copy to
    keep correct."""
    html = TEMPLATE.read_text(encoding='utf-8')
    assert html.count('x-for="evt in notifiableEvents"') == 2
    assert "'certificate_created'," not in html.replace(' ', ''), (
        'the template has a literal event list again'
    )
