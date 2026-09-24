"""`/api/activity` can be asked a question, and says when it did not finish.

The audit trail could only be read as a tail: `get_recent_entries(limit)` with
`limit` capped at 500, no way to narrow. On an instance with history that makes
the record unanswerable for anything older than the last few hundred
operations — including the bootstrap entries `docs/compliance.md` now tells
operators to go and look for. A record you cannot query is half a record.

**The trap this file exists to hold shut.** The obvious implementation filters
what the tail already returned, which answers "matches among the last hundred".
For an old or absent match that returns nothing, and nothing reads as "there
were none" — the exact wrong answer, delivered confidently, to the question the
compliance page asks people to ask.

So the stop condition counts **matches**, not entries, and walks back to the
start of the file when it has to. `complete` says which happened:

* `complete: true` — the search reached the beginning. Empty means there are
  none.
* `complete: false` — it stopped at `limit` matches. Empty means it gave up,
  or it could not read the log at all.

Only the first is safe to act on, which is the same distinction this project
keeps having to make between "no" and "I do not know".
"""
import pytest

from modules.core.audit import AuditLogger

pytestmark = [pytest.mark.unit]


@pytest.fixture
def audit(tmp_path):
    instance = AuditLogger(tmp_path / 'logs', chain_dir=tmp_path / 'chain')
    yield instance
    if instance.file_handler is not None:
        instance.audit_logger.removeHandler(instance.file_handler)
        instance.file_handler.close()


def _fill(audit, count=400):
    """More entries than any tail read would cover, with one needle at the
    very beginning — the shape an instance has months after setup."""
    audit.log_operation('create', 'user', 'admin', 'success', user='setup_user')
    for i in range(count):
        audit.log_operation('renew', 'certificate', f'd{i}.example.com',
                            'success', user='system')


def test_the_needle_is_older_than_any_tail_would_reach(audit):
    """Guard the guard. If the fixture were small enough for the tail to
    cover, every assertion below would pass without the search doing
    anything, and the defect it prevents would be back."""
    _fill(audit)
    tail = audit.get_recent_entries(limit=100)
    assert len(tail) == 100
    assert not any(e.get('user') == 'setup_user' for e in tail), (
        'the bootstrap entry is inside the tail; this fixture no longer '
        'reproduces the case the search exists for'
    )


def test_the_search_finds_what_the_tail_cannot(audit):
    _fill(audit)
    found = audit.search_entries(limit=100, user='setup_user')

    assert len(found['entries']) == 1
    assert found['entries'][0]['resource_id'] == 'admin'
    assert found['complete'] is True, (
        'the search stopped early; an operator reading this cannot tell '
        'one match from the first of many'
    )


def test_an_absent_match_is_reported_as_absent_not_as_unknown(audit):
    _fill(audit)
    found = audit.search_entries(limit=100, user='nobody@example.com')

    assert found['entries'] == []
    assert found['complete'] is True, (
        'an empty result that does not claim to be complete tells the '
        'operator nothing at all'
    )


def test_stopping_at_the_limit_says_so(audit):
    """The other half. Without this an operator who asked for 5 and got 5
    would read it as "there are 5"."""
    _fill(audit)
    found = audit.search_entries(limit=5, operation='renew')

    assert len(found['entries']) == 5
    assert found['complete'] is False


def test_several_filters_narrow_together(audit):
    _fill(audit, count=20)
    audit.log_operation('create', 'user', 'second', 'failure', user='admin')

    assert len(audit.search_entries(limit=50, operation='create')['entries']) == 2
    narrowed = audit.search_entries(limit=50, operation='create', status='failure')
    assert [e['resource_id'] for e in narrowed['entries']] == ['second']


def test_an_unknown_filter_is_refused(audit):
    """A typo that silently matched everything would be a worse answer than
    an error — it would look like a search that found a lot."""
    with pytest.raises(ValueError, match='(?i)unknown filter'):
        audit.search_entries(limit=10, operatoin='create')


def test_an_empty_filter_value_narrows_nothing(audit):
    """`?user=` from a form with an untouched field must not be read as
    "entries whose user is the empty string", which matches none."""
    _fill(audit, count=5)
    found = audit.search_entries(limit=50, user='', operation='renew')
    assert len(found['entries']) == 5


def test_a_log_that_cannot_be_read_is_not_an_empty_result(audit, tmp_path):
    """"I could not look" and "there are none" must not be the same answer.
    Only one of them is safe to act on.

    Driven with a real unreadable path — a directory, which exists and has a
    size and refuses to be opened — rather than by patching. The first version
    monkeypatched `Path.stat` on the class and broke pytest's own traceback
    machinery, which is a lot of blast radius for one branch.
    """
    unreadable = tmp_path / 'not-a-file'
    unreadable.mkdir()
    audit.audit_log_file = unreadable

    found = audit.search_entries(limit=10, operation='renew')
    assert found['entries'] == []
    assert found['complete'] is False


def test_an_empty_log_is_complete(audit):
    found = audit.search_entries(limit=10, operation='renew')
    assert found == {'entries': [], 'complete': True}


def test_both_readers_share_one_parser():
    """The tail reader and the search must agree about what an entry is.
    They had the same fifteen lines twice, and the copy that gets changed is
    never both of them."""
    import inspect

    source = inspect.getsource(AuditLogger.get_recent_entries)
    assert '_parse_entries(' in source
    assert 'json.loads' not in source, (
        'get_recent_entries parses entries itself again'
    )


def test_the_page_explains_what_an_empty_answer_means():
    """The table in docs/api.md is the whole point of `complete` reaching a
    caller. A page that documented the filter and not the flag would leave
    "no results" ambiguous, which is the state this replaced."""
    import pathlib as _pathlib

    page = (_pathlib.Path(__file__).resolve().parent.parent / 'docs' /
            'api.md').read_text(encoding='utf-8')
    section = page[page.index('### Reading the audit log over the API'):]
    section = section[:section.index('### ', 3)]
    assert 'complete' in section
    assert 'not' in section and 'there are none' in section, (
        'the page no longer distinguishes an empty result from an unreadable '
        'log, which is the distinction the flag exists for'
    )


def test_the_newest_match_is_first_from_the_callers_point_of_view(audit):
    """`get_recent_entries` documents "newest first" and the activity page
    renders in that order; a search that came back oldest-first would put the
    least interesting row at the top."""
    _fill(audit, count=3)
    audit.log_operation('revoke', 'certificate', 'newest.example.com', 'success')

    found = audit.search_entries(limit=10, resource_type='certificate')
    assert found['entries'][-1]['resource_id'] == 'newest.example.com'
