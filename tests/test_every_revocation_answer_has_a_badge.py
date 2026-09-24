"""The inventory renders five revocation answers, not four.

`modules/core/revocation.py` returns one of five statuses. The badge map in
`static/js/inventory.js` listed four, so `map[rev.status]` came back undefined
for a self-signed certificate and `revocationBadge` returned the empty string.
The cell went blank — which in that column already means "never checked", so a
certificate that CANNOT be revoked looked exactly like one nobody had asked
about.

The second half is wording. `unavailable` is what the checker returns when it
DID ask and could not get an answer it trusts: an unreachable responder, a
signature that did not verify, a response too old to believe. The badge said
"Revocation not checked", which reports a failure as an omission.

The test compares the two sources rather than pinning a list, so a sixth status
added in Python fails here instead of rendering as nothing in the browser.
"""
import pathlib
import re

import pytest

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent
JS = REPO / 'static' / 'js' / 'inventory.js'


def _badge_map_keys():
    """The keys of the `map` object literal inside `revocationBadge`."""
    source = JS.read_text(encoding='utf-8')
    start = source.index('function revocationBadge')
    body = source[start:]
    body = body[:body.index('\n    }')]
    keys = set(re.findall(r'^\s+(\w+): \[', body, re.M))
    assert keys, 'the badge map was not found — this test is reading the wrong thing'
    return keys


def _backend_statuses():
    from modules.core import revocation

    return {value for name, value in vars(revocation).items()
            if name.startswith('STATUS_') and isinstance(value, str)}


def test_every_status_the_checker_returns_can_be_rendered():
    """THE regression. `not_applicable` was missing and rendered as nothing."""
    missing = _backend_statuses() - _badge_map_keys()

    assert not missing, (
        f'revocation.py returns {sorted(missing)}, which the inventory badge '
        f'cannot render — the cell will be blank'
    )


def test_the_badge_invents_no_status_of_its_own():
    """CONTROL, and the other direction: a key here that Python never returns
    is dead code that looks like coverage. It also proves the extraction above
    is finding real keys rather than matching nothing."""
    invented = _badge_map_keys() - _backend_statuses()

    assert not invented, (
        f'the badge renders {sorted(invented)}, which revocation.py never '
        f'returns'
    )


def test_a_failed_check_is_not_reported_as_no_check():
    """`unavailable` means the answer could not be verified, not that nobody
    looked. The distinction is the whole point of having the status."""
    source = JS.read_text(encoding='utf-8')

    assert 'Revocation not checked' not in source
    assert 'Revocation unverified' in source


def test_the_documented_statuses_are_the_ones_the_code_returns():
    """The API reference lists them by hand; this is where that list goes
    stale."""
    page = (REPO / 'docs' / 'api.md').read_text(encoding='utf-8')

    for status in _backend_statuses():
        assert f'`{status}`' in page, f'docs/api.md does not mention {status}'
