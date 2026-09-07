"""Maintenance windows for deploy hooks (#632).

A certificate renews when it is due, which is a time nobody chose: the renewal
sweep fires at 02:00 with an hour of jitter, and only for the certificates that
happen to be inside the threshold that night. The deploy hook then runs
immediately. For a hook that restarts a database or reloads a load balancer,
that is an outage at an unpredictable hour.

A window separates the two. The certificate still renews whenever it is due —
that is not negotiable, it is driven by expiry — but the *deploy* is held until
the next time the window is open.

The whole decision is here, as pure functions over an explicit `now`, because
the interesting cases are all calendar edge cases: a window that wraps past
midnight, a window on days the queue was not drained, a DST transition that
makes 02:30 happen twice or not at all. Testing those through a scheduler and a
pending queue would mean staging a renewal to ask what time it is.

Shape of a window::

    {"start": "02:00", "end": "04:00",
     "days": ["mon", "tue", "wed", "thu", "fri"],   # optional, default: all
     "timezone": "Europe/Rome"}                      # optional, default: UTC

`start == end` is rejected rather than read as "always" or "never" — both
readings are defensible, which is exactly why an operator must not have to
guess which one was implemented.
"""
import datetime
import re

# Order matters: index is what datetime.weekday() returns.
_DAYS = ('mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun')
_DAY_INDEX = {name: i for i, name in enumerate(_DAYS)}

_TIME_RE = re.compile(r'\A([01]\d|2[0-3]):([0-5]\d)\Z')

# A window can be held at most this long before it is reported as stuck. Not a
# limit on deferral — the operator asked for a window and waiting for it is the
# feature — but a pending deploy older than a week means the window has never
# opened since, and something is misconfigured (a Sunday-only window on an
# instance that is stopped at weekends, a timezone nobody meant).
STALE_AFTER_DAYS = 7


class WindowError(ValueError):
    """A maintenance window that cannot be applied as written."""


def _parse_hhmm(value, field):
    if not isinstance(value, str):
        raise WindowError(f"{field} must be a string like '02:00'")
    match = _TIME_RE.match(value.strip())
    if not match:
        raise WindowError(
            f"{field} must be HH:MM in 24-hour form, got {value!r}")
    return int(match.group(1)), int(match.group(2))


def _resolve_timezone(name):
    """An IANA zone name, or UTC.

    The image resolves these from the system tzdata rather than the `tzdata`
    wheel, so an unknown name is refused here with the name in the message —
    an operator typing 'CET' or 'Europe/Milano' should be told that at save
    time, not have their deploys held for a window that never opens.
    """
    if name is None or name == '':
        return datetime.timezone.utc
    if not isinstance(name, str):
        raise WindowError('timezone must be a string like "Europe/Rome"')
    name = name.strip()
    if name.upper() == 'UTC':
        return datetime.timezone.utc
    try:
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
    except ImportError:  # pragma: no cover - stdlib since 3.9
        raise WindowError('named timezones are unavailable on this platform')
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        raise WindowError(
            f"unknown timezone {name!r} — use an IANA name such as "
            f"'Europe/Rome' or 'America/New_York'")


def normalize_window(window):
    """Validate *window* and return it in canonical form, or raise.

    Returns None for an absent window, which means "deploy immediately" — the
    behaviour every existing hook has and keeps.
    """
    if window is None or window == {} or window == '':
        return None
    if not isinstance(window, dict):
        raise WindowError('window must be an object')

    start = _parse_hhmm(window.get('start'), 'window.start')
    end = _parse_hhmm(window.get('end'), 'window.end')
    if start == end:
        raise WindowError(
            'window.start and window.end are the same time, which could mean '
            'either "always open" or "never open" — use 00:00 to 23:59 for a '
            'whole day instead')

    days = window.get('days')
    if days in (None, []):
        day_set = set(range(7))
    else:
        if not isinstance(days, list):
            raise WindowError('window.days must be a list of day names')
        day_set = set()
        for day in days:
            key = str(day).strip().lower()[:3]
            if key not in _DAY_INDEX:
                raise WindowError(
                    f"unknown day {day!r} — use mon, tue, wed, thu, fri, sat, "
                    f"sun")
            day_set.add(_DAY_INDEX[key])

    timezone_name = window.get('timezone') or 'UTC'
    if isinstance(timezone_name, str):
        timezone_name = timezone_name.strip() or 'UTC'
        if timezone_name.upper() == 'UTC':
            timezone_name = 'UTC'
    _resolve_timezone(timezone_name)  # raises if unusable

    return {
        'start': '%02d:%02d' % start,
        'end': '%02d:%02d' % end,
        'days': [_DAYS[i] for i in sorted(day_set)],
        'timezone': timezone_name,
    }


def _local(window, moment):
    """*moment* (aware) as a naive local time in the window's zone."""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    return moment.astimezone(_resolve_timezone(window.get('timezone')))


def is_open(window, moment):
    """True when *moment* falls inside *window*.

    A window that wraps past midnight (22:00 to 04:00) belongs to the day its
    START falls on, so a Friday 22:00-04:00 window is open at 02:00 on
    Saturday. Reading it the other way would make a Friday-night window
    silently require Saturday to be selected too.
    """
    if window is None:
        return True
    window = normalize_window(window)
    local = _local(window, moment)
    start_h, start_m = (int(x) for x in window['start'].split(':'))
    end_h, end_m = (int(x) for x in window['end'].split(':'))
    days = {_DAY_INDEX[d] for d in window['days']}

    minutes = local.hour * 60 + local.minute
    start = start_h * 60 + start_m
    end = end_h * 60 + end_m

    if start < end:
        return local.weekday() in days and start <= minutes < end
    # Wrapped. Either late on a selected day, or early on the day after one.
    if minutes >= start:
        return local.weekday() in days
    if minutes < end:
        return (local.weekday() - 1) % 7 in days
    return False


def next_open(window, moment, horizon_days=8):
    """The first instant at or after *moment* when *window* is open.

    Returns an aware UTC datetime, or None if the window does not open within
    *horizon_days*. Seven days is provably enough for any window this module
    accepts — the longest possible wait is a week minus the window's own
    length, since every window recurs weekly and is at least a minute long. The
    default is 8 as margin, not because 7 is known to be short, and None is
    therefore a "this should not happen" answer rather than a routine one.

    Minute resolution: a window is a maintenance period, and searching by the
    minute over eight days is 11520 cheap comparisons — small enough not to
    matter and simple enough to be obviously right, which a closed-form
    calculation across a DST boundary is not.
    """
    if window is None:
        return moment
    window = normalize_window(window)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.timezone.utc)
    probe = moment.replace(second=0, microsecond=0)
    if probe < moment:
        probe += datetime.timedelta(minutes=1)
    for _ in range(horizon_days * 24 * 60):
        if is_open(window, probe):
            return probe.astimezone(datetime.timezone.utc)
        probe += datetime.timedelta(minutes=1)
    return None


def describe(window):
    """One line an operator can check against what they meant."""
    if window is None:
        return 'immediately'
    window = normalize_window(window)
    days = window['days']
    when = 'every day' if len(days) == 7 else ', '.join(days)
    return (f"{window['start']}-{window['end']} {window['timezone']} "
            f"({when})")
