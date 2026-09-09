"""The activity page read 827 KiB to show 100 lines.

`get_recent_entries` walks the audit log backwards in 8 KiB blocks, which is
the right shape — the file rotates at megabytes and the caller wants the end of
it. The stop condition was the wrong quantity:

    while remaining > 0 and len(blocks) <= limit:

One block per entry *asked for*, not per entry *found*. An audit line is a
timestamp, a level and a JSON object: around 170 bytes. So 100 entries live in
two blocks and the loop read a hundred and one.

Measured on a 3.2 MiB log of 20,000 entries:

    limit=10    90,112 bytes ->    8,192
    limit=100  827,392 bytes ->   24,576
    limit=500  3,377,780 bytes (the whole file) -> 90,112

The counter is now the entry marker itself — the same string the parse splits
on — rather than newlines, so a traceback or a non-INFO line in the tail cannot
make the read stop short of the entries it was asked for. And `len(blocks) <=
limit` stays as a second condition, so the pathological case of a tail
containing no entries at all reads exactly what it read before rather than
walking to the start of the file.
"""
import json

import pytest

from modules.core.audit import AuditLogger

pytestmark = [pytest.mark.unit]

PREFIX = '2026-09-09 10:00:00 - audit - INFO - '


class _CountingPath:
    """A path whose opened file reports how many bytes were actually read."""

    def __init__(self, path):
        self._path = path
        self.bytes_read = 0

    def __getattr__(self, name):
        return getattr(self._path, name)

    def open(self, *args, **kwargs):
        return self._wrap(self._path.open(*args, **kwargs))

    def _wrap(self, handle):
        counter = self

        class _Handle:
            def __enter__(self_inner):
                handle.__enter__()
                return self_inner

            def __exit__(self_inner, *exc):
                return handle.__exit__(*exc)

            def seek(self_inner, *args):
                return handle.seek(*args)

            def read(self_inner, size=-1):
                data = handle.read(size)
                counter.bytes_read += len(data)
                return data

        return _Handle()


@pytest.fixture
def log(tmp_path, monkeypatch):
    """An audit log of 20,000 entries, and a byte counter over it."""
    path = tmp_path / 'audit.log'
    with path.open('w', encoding='utf-8') as handle:
        for n in range(20000):
            handle.write(PREFIX + json.dumps({
                'action': 'certificate_created',
                'n': n,
                'user': 'admin',
                'resource': f'{n}.example.com',
            }) + '\n')

    counting = _CountingPath(path)
    reader = AuditLogger.__new__(AuditLogger)
    reader.audit_log_file = counting

    import builtins
    real_open = builtins.open

    def _open(target, mode='r', *args, **kwargs):
        if target is counting:
            return counting.open(mode, *args, **kwargs)
        return real_open(target, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, 'open', _open)
    return reader, counting


# --- THE regression -------------------------------------------------------

@pytest.mark.parametrize('limit,ceiling', [
    (10, 16 * 1024),
    (100, 48 * 1024),
    (500, 128 * 1024),
])
def test_the_read_is_sized_by_what_it_finds(log, limit, ceiling):
    """Before: 90 KiB, 827 KiB and the entire 3.2 MiB file respectively."""
    reader, counting = log

    entries = reader.get_recent_entries(limit=limit)

    assert len(entries) == limit
    assert counting.bytes_read <= ceiling, (
        f'{counting.bytes_read} bytes read to return {limit} entries')


def test_the_newest_entries_are_the_ones_returned(log):
    """CONTROL. A read that stops early must stop at the RIGHT end: this walks
    backwards from EOF, and an off-by-one in the new stop condition would show
    up as the wrong entries rather than as an error."""
    reader, _ = log

    entries = reader.get_recent_entries(limit=5)

    assert [entry['n'] for entry in entries] == [19995, 19996, 19997, 19998, 19999]


def test_a_partial_first_line_is_still_dropped(log):
    """The block boundary lands mid-line almost always. That half line is not
    parseable JSON and must not be counted or returned."""
    reader, _ = log

    entries = reader.get_recent_entries(limit=100)

    assert len(entries) == 100
    assert all('n' in entry for entry in entries)


# --- what the marker-counting buys ---------------------------------------

def test_noise_in_the_tail_does_not_shorten_the_answer(tmp_path):
    """Counting newlines would stop at `limit` LINES. A traceback, a WARNING,
    a rotated-file header — anything the parse skips — would then come out of
    the caller's allowance and the page would show fewer rows than it asked
    for, with nothing to say why."""
    path = tmp_path / 'audit.log'
    with path.open('w', encoding='utf-8') as handle:
        for n in range(500):
            handle.write(PREFIX + json.dumps({'action': 'x', 'n': n}) + '\n')
            handle.write('2026-09-09 10:00:00 - audit - WARNING - not an entry\n')
            handle.write('  File "somewhere.py", line 1, in <module>\n')

    reader = AuditLogger.__new__(AuditLogger)
    reader.audit_log_file = path

    assert len(reader.get_recent_entries(limit=100)) == 100


def test_a_tail_with_no_entries_reads_no_more_than_before(tmp_path):
    """CONTROL on the worst case. Counting entries alone would walk to the
    start of a file that has none; `len(blocks) <= limit` is still there, so
    the ceiling is exactly the old behaviour."""
    path = tmp_path / 'audit.log'
    path.write_text('x' * (8192 * 40), encoding='utf-8')

    counting = _CountingPath(path)
    reader = AuditLogger.__new__(AuditLogger)
    reader.audit_log_file = counting

    import builtins
    real_open = builtins.open

    def _open(target, mode='r', *args, **kwargs):
        if target is counting:
            return counting.open(mode, *args, **kwargs)
        return real_open(target, mode, *args, **kwargs)

    original = builtins.open
    builtins.open = _open
    try:
        assert reader.get_recent_entries(limit=5) == []
    finally:
        builtins.open = original

    assert counting.bytes_read <= 6 * 8192


# --- unchanged behaviour --------------------------------------------------

def test_a_short_log_returns_everything_it_has(tmp_path):
    path = tmp_path / 'audit.log'
    with path.open('w', encoding='utf-8') as handle:
        for n in range(3):
            handle.write(PREFIX + json.dumps({'action': 'x', 'n': n}) + '\n')

    reader = AuditLogger.__new__(AuditLogger)
    reader.audit_log_file = path

    assert [e['n'] for e in reader.get_recent_entries(limit=100)] == [0, 1, 2]


@pytest.mark.parametrize('limit', [0, -1])
def test_a_useless_limit_reads_nothing(tmp_path, limit):
    path = tmp_path / 'audit.log'
    path.write_text(PREFIX + '{"action": "x"}\n', encoding='utf-8')

    reader = AuditLogger.__new__(AuditLogger)
    reader.audit_log_file = path

    assert reader.get_recent_entries(limit=limit) == []


def test_the_counter_and_the_parser_use_one_marker():
    """They must not drift: a scan counting something the parse rejects stops
    the read early and returns fewer entries than were asked for, silently."""
    import inspect

    from modules.core import audit

    source = inspect.getsource(audit.AuditLogger.get_recent_entries)

    assert source.count('_ENTRY_MARKER') >= 2
    assert " - INFO - " not in source, (
        'the marker is spelled out again inside the function, so the byte '
        'scan and the text parse can drift apart')
    assert audit._ENTRY_MARKER == audit._ENTRY_MARKER_TEXT.encode('utf-8')
