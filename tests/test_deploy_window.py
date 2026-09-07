"""When a deploy hook is allowed to run (#632).

A certificate renews when it is due — 02:00 with an hour of jitter, and only
for whatever is inside the threshold that night. The deploy hook then ran
immediately, so a hook that restarts a database or reloads a load balancer
caused an outage at an hour nobody chose. A maintenance window holds the deploy
until the next time it is open, without touching when the certificate renews.

Every case here is a calendar case: a window that wraps past midnight, a day
filter, a timezone, and the two DST transitions where local time either skips
an hour or repeats one. Those are exactly the cases that would be untestable if
this decision lived inside the deploy manager, so it lives in
`modules/core/deploy_window` as pure functions over an explicit `now`.
"""
import datetime

import pytest

from modules.core.deploy_window import (
    WindowError,
    describe,
    is_open,
    next_open,
    normalize_window,
)

pytestmark = [pytest.mark.unit]

UTC = datetime.timezone.utc


def _at(year, month, day, hour, minute=0):
    return datetime.datetime(year, month, day, hour, minute, tzinfo=UTC)


# ---------------------------------------------------------------------------
# No window means what it always meant
# ---------------------------------------------------------------------------

@pytest.mark.parametrize('absent', [None, {}, ''])
def test_no_window_normalizes_to_none(absent):
    assert normalize_window(absent) is None


def test_no_window_is_always_open():
    """The behaviour every existing hook has, and keeps. A release that
    silently started deferring un-windowed hooks would be an outage of a
    different shape."""
    assert is_open(None, _at(2026, 9, 8, 13, 37))
    assert next_open(None, _at(2026, 9, 8, 13, 37)) == _at(2026, 9, 8, 13, 37)
    assert describe(None) == 'immediately'


# ---------------------------------------------------------------------------
# The ordinary window
# ---------------------------------------------------------------------------

SIMPLE = {'start': '02:00', 'end': '04:00'}


@pytest.mark.parametrize('hour,minute,expected', [
    (1, 59, False),
    (2, 0, True),     # inclusive at the start
    (3, 0, True),
    (3, 59, True),
    (4, 0, False),    # exclusive at the end, so 02:00-04:00 and 04:00-06:00
    (4, 1, False),    # are adjacent rather than overlapping
    (23, 0, False),
])
def test_the_edges_of_a_simple_window(hour, minute, expected):
    assert is_open(SIMPLE, _at(2026, 9, 8, hour, minute)) is expected


def test_next_open_from_before_the_window():
    assert next_open(SIMPLE, _at(2026, 9, 8, 0, 30)) == _at(2026, 9, 8, 2, 0)


def test_next_open_from_inside_the_window_is_now():
    """A drain that runs while the window is open must not defer another day."""
    now = _at(2026, 9, 8, 3, 0)
    assert next_open(SIMPLE, now) == now


def test_next_open_from_after_the_window_is_tomorrow():
    assert next_open(SIMPLE, _at(2026, 9, 8, 5, 0)) == _at(2026, 9, 9, 2, 0)


# ---------------------------------------------------------------------------
# Wrapping past midnight
# ---------------------------------------------------------------------------

WRAPPED = {'start': '22:00', 'end': '04:00', 'days': ['fri']}


@pytest.mark.parametrize('day,hour,expected,why', [
    (11, 21, False, 'Friday, before it opens'),
    (11, 22, True, 'Friday, open'),
    (11, 23, True, 'Friday, still open'),
    (12, 1, True, 'Saturday 01:00 belongs to the Friday window'),
    (12, 3, True, 'Saturday 03:00 still belongs to it'),
    (12, 4, False, 'Saturday 04:00, closed'),
    (12, 22, False, 'Saturday 22:00 is not a Friday window'),
])
def test_a_wrapped_window_belongs_to_the_day_it_starts_on(day, hour, expected, why):
    """2026-09-11 is a Friday.

    The alternative reading — the window belongs to the day it ENDS on — would
    make a "Friday night" window silently require Saturday to be selected too,
    and an operator who checked only Friday would find their deploy held for a
    week.
    """
    assert is_open(WRAPPED, _at(2026, 9, day, hour)) is expected, why


def test_next_open_crosses_a_week_to_reach_a_single_day_window():
    # Saturday 05:00: the Friday window just closed.
    assert next_open(WRAPPED, _at(2026, 9, 12, 5, 0)) == _at(2026, 9, 18, 22, 0)


# ---------------------------------------------------------------------------
# Days
# ---------------------------------------------------------------------------

def test_a_day_filter_closes_the_other_days():
    weekdays = {'start': '02:00', 'end': '04:00',
                'days': ['mon', 'tue', 'wed', 'thu', 'fri']}
    assert is_open(weekdays, _at(2026, 9, 11, 3))       # Friday
    assert not is_open(weekdays, _at(2026, 9, 12, 3))   # Saturday
    assert next_open(weekdays, _at(2026, 9, 12, 3)) == _at(2026, 9, 14, 2, 0)


@pytest.mark.parametrize('written', ['Monday', 'MON', ' mon ', 'monday'])
def test_day_names_are_forgiving_about_spelling(written):
    assert normalize_window(
        {'start': '02:00', 'end': '03:00', 'days': [written]})['days'] == ['mon']


def test_an_omitted_day_list_means_every_day():
    assert normalize_window(SIMPLE)['days'] == list(
        ('mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun'))


# ---------------------------------------------------------------------------
# Timezones
# ---------------------------------------------------------------------------

def test_the_window_is_read_in_its_own_timezone():
    """The point of the field. 02:00 in Rome is 00:00 UTC in September, so a
    UTC-only implementation would run this deploy two hours early."""
    rome = {'start': '02:00', 'end': '04:00', 'timezone': 'Europe/Rome'}
    assert is_open(rome, _at(2026, 9, 8, 0, 30))
    assert not is_open(rome, _at(2026, 9, 8, 2, 30))


def test_next_open_returns_utc_whatever_the_window_says():
    """The queue stores instants, not wall clocks, so anything that leaks a
    local time into it would compare wrong against the next drain."""
    rome = {'start': '02:00', 'end': '04:00', 'timezone': 'Europe/Rome'}
    when = next_open(rome, _at(2026, 9, 8, 12, 0))
    assert when.tzinfo == UTC
    assert when == _at(2026, 9, 9, 0, 0)


def test_a_naive_moment_is_read_as_utc():
    naive = datetime.datetime(2026, 9, 8, 3, 0)
    assert is_open(SIMPLE, naive)


# ---------------------------------------------------------------------------
# Daylight saving, both directions
# ---------------------------------------------------------------------------

def test_a_window_inside_the_hour_that_does_not_exist_still_opens():
    """Europe/Rome springs forward at 02:00 on 2026-03-29: local 02:00-02:59
    never happens. A 02:00-04:00 window must open at 03:00 that day, not be
    skipped for the year.
    """
    rome = {'start': '02:00', 'end': '04:00', 'timezone': 'Europe/Rome'}
    # 2026-03-29 00:30 UTC is 01:30 local, just before the jump.
    when = next_open(rome, _at(2026, 3, 29, 0, 30))
    assert when == _at(2026, 3, 29, 1, 0), (
        f'expected the window to open at the local 03:00 (01:00 UTC), got {when}'
    )


def test_a_window_inside_the_hour_that_happens_twice_is_open_for_both():
    """Europe/Rome falls back at 03:00 on 2026-10-25: local 02:00-02:59 runs
    twice. Both are inside the window, and a drain landing in either must
    deploy rather than decide it already missed it.
    """
    rome = {'start': '02:00', 'end': '04:00', 'timezone': 'Europe/Rome'}
    assert is_open(rome, _at(2026, 10, 25, 0, 30)), 'first pass (CEST)'
    assert is_open(rome, _at(2026, 10, 25, 1, 30)), 'second pass (CET)'


# ---------------------------------------------------------------------------
# What is refused, and why
# ---------------------------------------------------------------------------

def test_a_window_whose_ends_are_equal_is_refused():
    """It reads equally well as "always open" and "never open". An operator
    must not have to discover by experiment which one was implemented."""
    with pytest.raises(WindowError, match='same time'):
        normalize_window({'start': '02:00', 'end': '02:00'})


@pytest.mark.parametrize('window,message', [
    ({'start': '2:00', 'end': '04:00'}, 'HH:MM'),
    ({'start': '25:00', 'end': '04:00'}, 'HH:MM'),
    ({'start': '02:60', 'end': '04:00'}, 'HH:MM'),
    ({'start': '02:00', 'end': '04:00\n05:00'}, 'HH:MM'),
    ({'start': 200, 'end': '04:00'}, 'must be a string'),
    ({'end': '04:00'}, 'must be a string'),
    ({'start': '02:00', 'end': '04:00', 'days': 'mon'}, 'must be a list'),
    ({'start': '02:00', 'end': '04:00', 'days': ['funday']}, 'unknown day'),
    ({'start': '02:00', 'end': '04:00', 'timezone': 'Europe/Milano'},
     'unknown timezone'),
    ({'start': '02:00', 'end': '04:00', 'timezone': 'Europe/Genova'},
     'unknown timezone'),
    ('02:00-04:00', 'must be an object'),
])
def test_what_a_window_may_not_say(window, message):
    with pytest.raises(WindowError, match=message):
        normalize_window(window)


def test_an_unusable_timezone_is_refused_at_validation_not_at_drain_time():
    """CONTROL for the case above. A typo'd zone that failed silently later
    would hold every deploy for a window that never opens, and the failure
    would surface days after the change that caused it.
    """
    with pytest.raises(WindowError) as excinfo:
        normalize_window({'start': '02:00', 'end': '04:00',
                          'timezone': 'Not/AZone'})
    assert 'Not/AZone' in str(excinfo.value), (
        'the message does not name the zone the operator typed'
    )


def test_utc_is_accepted_by_name():
    assert normalize_window(
        {'start': '02:00', 'end': '04:00', 'timezone': 'utc'})['timezone'] == 'UTC'


@pytest.mark.parametrize('field,written', [
    ('start', ' 02:00 '), ('end', ' 04:00\t'), ('timezone', ' Europe/Rome '),
])
def test_surrounding_whitespace_is_trimmed_not_refused(field, written):
    """A form field picks up spaces; that is a typing accident, not an attack
    surface. The `\\Z` anchor still refuses a value with a newline INSIDE it —
    `test_what_a_window_may_not_say` covers that — so this trims the outside
    without widening what the pattern accepts.
    """
    window = dict(SIMPLE, timezone='Europe/Rome')
    window[field] = written
    assert normalize_window(window)[field] == written.strip()


# ---------------------------------------------------------------------------
# The horizon
# ---------------------------------------------------------------------------

def test_next_open_crosses_days_for_a_weekly_window():
    """A Monday-only window asked about on a Monday afternoon resolves to next
    Monday rather than reporting "never"."""
    monday_only = {'start': '02:00', 'end': '04:00', 'days': ['mon']}
    # 2026-09-07 is a Monday; 15:00 is after that day's window.
    assert next_open(monday_only, _at(2026, 9, 7, 15, 0)) == _at(2026, 9, 14, 2, 0)


def test_the_worst_case_wait_fits_inside_the_search_horizon():
    """Measured rather than asserted from the constant, because the constant is
    the thing that could be wrong.

    Every window recurs weekly and is at least a minute long, so the longest
    possible wait is a week minus the window's length. The narrowest window
    this module accepts — one minute, one day, wrapping midnight — is the worst
    case, and it must still resolve.
    """
    narrowest = {'start': '23:59', 'end': '00:00', 'days': ['mon']}
    # A minute after it closes, which is the furthest any caller can be from it.
    when = next_open(narrowest, _at(2026, 9, 8, 0, 0))
    assert when is not None, 'the worst-case window resolved to "never"'
    assert when == _at(2026, 9, 14, 23, 59)
    assert when - _at(2026, 9, 8, 0, 0) < datetime.timedelta(days=7)


def test_describe_says_what_the_operator_configured():
    assert describe(SIMPLE) == '02:00-04:00 UTC (every day)'
    assert describe(WRAPPED) == '22:00-04:00 UTC (fri)'
