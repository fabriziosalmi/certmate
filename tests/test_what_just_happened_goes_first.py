"""The activity feed opens on what just happened (#941).

`/activity` opened on the oldest thing that ever happened. On a seventeen-day
log the first six rows were from seventeen days ago, and today's events were
below the fold.

Both methods behind it already documented the opposite:

* `search_entries` — "Recent entries matching filters, **newest first** …"
* `get_recent_entries` — "List of audit entries (parsed JSON), **newest first**"

and both returned `entries[-limit:]`. The slice picks the right WINDOW — the
most recent N, not the first N — and nothing reversed it, so the direction
within the window was oldest to newest.

Two things are separable here and both are tested: **which** entries come back
and **in what order**. They are separable in one direction only — a change that
takes the head of the file instead of its tail produces a list that looks
newest-first and is made of the oldest entries.
"""
import pathlib
import re
import tempfile

import pytest

from modules.core.audit import AuditLogger

pytestmark = [pytest.mark.unit]

REPO = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def log():
    """Twelve entries, written oldest to newest, named so order is readable."""
    logger = AuditLogger(audit_log_dir=pathlib.Path(tempfile.mkdtemp()))
    for index in range(12):
        logger.log_operation(operation='create', resource_type='certificate',
                             resource_id=f'dom{index:02d}.example.com',
                             status='success')
    return logger


def _ids(entries):
    return [entry.get('resource_id') for entry in entries]


def test_the_newest_entry_is_the_first_one_returned(log):
    ids = _ids(log.get_recent_entries(limit=5))
    assert ids[0] == 'dom11.example.com', (
        f'the feed opens on {ids[0]}, not on the newest entry'
    )
    assert ids == [f'dom{i:02d}.example.com' for i in range(11, 6, -1)]


def test_a_filtered_search_answers_the_same_way(log):
    """The two methods must not disagree: the page uses one when unfiltered and
    the other the moment a filter is applied, and a reader switching between
    them would see the list turn over."""
    found = log.search_entries(limit=5, operation='create')
    assert _ids(found['entries']) == [f'dom{i:02d}.example.com'
                                      for i in range(11, 6, -1)]


def test_the_window_is_still_the_most_recent_entries(log):
    """CONTROL, and the part that was already right.

    `limit` selects the most recent N, not the first N — taking the head of
    the file and reversing that would put a plausible-looking newest-first
    list on screen made entirely of the OLDEST entries.

    This docstring first claimed the hazard was "reverse the whole file, then
    take the head". That is not a hazard: `x[-n:][::-1]` and `x[::-1][:n]` are
    the same list for every x and n, so the mutation written to prove this test
    could not be proved by it. The real hazard is the head of the file, and
    that is what is mutated against now."""
    ids = set(_ids(log.get_recent_entries(limit=5)))
    assert ids == {f'dom{i:02d}.example.com' for i in range(7, 12)}
    assert 'dom00.example.com' not in ids, 'the oldest entry came back'


def test_asking_for_more_than_exists_returns_everything_newest_first(log):
    ids = _ids(log.get_recent_entries(limit=500))
    assert len(ids) == 12
    assert ids[0] == 'dom11.example.com'
    assert ids[-1] == 'dom00.example.com'


def test_the_docstrings_and_the_code_now_say_the_same_thing():
    """The defect was not the order alone — it was that the code contradicted
    its own written promise, in two places, and nothing compared them. If
    someone decides oldest-first later, this fails and the docstrings have to
    be changed deliberately rather than left lying."""
    source = (REPO / 'modules' / 'core' / 'audit.py').read_text(encoding='utf-8')
    for method in ('search_entries', 'get_recent_entries'):
        body = source.split(f'def {method}(', 1)[1]
        doc = body.split('"""', 2)[1]
        assert 'newest first' in doc.lower(), f'{method} no longer claims it'
    assert source.count('[-limit:][::-1]') == 2, (
        'both methods reverse their window; one of them stopped'
    )


def test_the_published_reference_states_the_order():
    """It never did. `docs/api.md` described the window — "the most recent
    entries" — and said nothing about the direction, which is why calling this
    a fix rather than a contract break is defensible: no reader was promised
    ascending."""
    page = (REPO / 'docs' / 'api.md').read_text(encoding='utf-8')
    section = page.split('`GET /api/activity?limit=N`', 1)[1][:600]
    assert 'newest first' in section.lower()

    from modules.core.constants import API_CONTRACT_VERSION
    stated = re.search(r'contract \*\*(\d+\.\d+)\*\*', section)
    assert stated, 'the page does not say which contract stated the ordering'
    assert tuple(map(int, stated.group(1).split('.'))) <= tuple(
        map(int, API_CONTRACT_VERSION.split('.'))), (
        f'the page claims contract {stated.group(1)}, which is ahead of '
        f'{API_CONTRACT_VERSION}'
    )
