"""A deploy hook can be asked for every event that can trigger it.

Item 5 of #876, which asked for a decision — "either implement it or drop the
promise" — and had already been decided. #883 wired `certificate_revoked` into
`DeployManager.on_certificate_event`, so a hook with `revoked` in its
`on_events` does run. `docs/deploy-hooks.md` has promised it all along.

What was left was the settings page, which offered two checkboxes for three
events. A hook could be given `revoked` through the API, and the UI would store
it, display it back, and never let anyone add or remove it.

That is the same shape as item 7, in a different panel: the backend accepts an
event and the interface does not offer it. Two panels, two occurrences, so this
file checks the property rather than the one checkbox — the accepted set comes
from `on_certificate_event`'s own map, so a fourth event wired there is caught
here on the day it is wired.

`revoked` stays opt-in. `DEFAULT_ON_EVENTS` is `['created', 'renewed']`,
deliberately: as `docs/deploy-hooks.md` puts it, adding a hook must not start
running commands on revocations nobody wrote it for. Offering the checkbox is
not the same as ticking it, and a test holds that apart.
"""
import ast
import inspect
import pathlib
import re

import pytest

from modules.core.deployer import DEFAULT_ON_EVENTS, DeployManager

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
PANEL = REPO / 'templates' / 'partials' / 'settings_deploy.html'


def _events_that_trigger_a_hook():
    """The values of `event_map` in `on_certificate_event`.

    Read from the function rather than listed here: that map is what actually
    decides whether a hook runs, and a list in a test is one more copy to go
    stale.
    """
    source = inspect.getsource(DeployManager.on_certificate_event)
    tree = ast.parse(source.strip())
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                getattr(t, 'id', None) == 'event_map' for t in node.targets):
            return {element.value for element in node.value.values}
    raise AssertionError('event_map is gone from on_certificate_event')


def _events_the_panel_offers():
    return set(re.findall(r"toggleEvent\(hook, '([a-z_]+)'\)",
                          PANEL.read_text(encoding='utf-8')))


def test_both_sides_are_non_empty():
    """Guard the guard: either side reading empty would make the comparison
    below agree about nothing."""
    assert len(_events_that_trigger_a_hook()) >= 3
    assert len(_events_the_panel_offers()) >= 3


def test_every_event_that_runs_a_hook_can_be_ticked():
    missing = _events_that_trigger_a_hook() - _events_the_panel_offers()
    assert not missing, (
        f'a hook runs on {sorted(missing)} and the settings page has no '
        f'checkbox for it, so it can only be set through the API'
    )


def test_the_panel_offers_nothing_that_cannot_run():
    """The other direction: a checkbox for an event `on_certificate_event`
    does not map is a switch that stores a preference nothing reads."""
    invented = _events_the_panel_offers() - _events_that_trigger_a_hook()
    assert not invented, sorted(invented)


def test_both_hook_rows_offer_the_same_events():
    """There are two hook editors on the page — global and per-domain — and
    they carried their own copies of the checkbox list. One was never going to
    be updated without the other being forgotten."""
    html = PANEL.read_text(encoding='utf-8')
    for event in _events_that_trigger_a_hook():
        assert html.count(f"toggleEvent(hook, '{event}')") == 2, (
            f'{event} appears in {html.count(chr(39))} places rather than in '
            f'both hook editors'
        )


def test_revoked_is_offered_but_not_default():
    """Offering the checkbox is not ticking it. Adding a hook must not start
    running commands on revocations nobody wrote it for, which is why
    DEFAULT_ON_EVENTS is what it is."""
    assert 'revoked' in _events_the_panel_offers()
    assert 'revoked' not in DEFAULT_ON_EVENTS
    assert list(DEFAULT_ON_EVENTS) == ['created', 'renewed']


def test_the_page_still_promises_it():
    """`docs/deploy-hooks.md` named `revoked` while nothing ran it, and #883
    made that true. If the promise is ever removed, this fails next to the
    tests that assume it."""
    doc = (REPO / 'docs' / 'deploy-hooks.md').read_text(encoding='utf-8')
    assert '"revoked"' in doc or '`revoked`' in doc
