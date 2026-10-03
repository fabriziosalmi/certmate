"""When a certificate renews: one rule, decided by CertMate, executed by certbot (#393).

Before this, two rules decided and they disagreed. CertMate called a certificate due when
`days_left <= renewal_threshold_days`; certbot, run without `--force-renewal`, applied its own:
in 2.10 a fixed 30 days, in 5.8 two thirds of the lifetime (half under 10 days) or the CA's ARI
window. The two coincide for a 90-day certificate and for nothing else, so a 45-day certificate
was "due" for two weeks of nightly no-op runs before certbot renewed it, and the API said so the
whole time. certbot changed its rule between versions and nothing noticed, because 90 days hid
it; and its ARI postponement does not last (measured: a second call inside `ari_retry_after`
renews). So the decision is made here, from the certificate itself, and certbot is told to renew
(`--force-renewal`) when it is made.

The rule, for a certificate of lifetime L (`notBefore`..`notAfter`) and the operator's threshold
T (`renewal_threshold_days`):

* **margin**: T days before expiry, when T is at most L/2; otherwise the lifetime rule, L/3, or L/2 when L is under
  10 days (certbot 5.8's rule). The threshold is honoured wherever it means something for this
  certificate: 30 or 45 days of a 90-day certificate, as before (#966). Where it does not (30
  days of a 45-day or a 160-hour certificate) the lifetime decides: 15 days, 3.3 days. Nothing
  changes for a 90-day certificate, nor for a longer one.
* **with a recorded ARI window** for this very certificate (#962): its `renew_at`, earlier or
  later than the margin, but never with less than L/6 left and never after the window's end. A
  window that is wrong, hostile or stale cannot make a certificate expire, and the record is on
  disk, so a postponement lasts from one sweep to the next.

Pure functions of instants: no clock, no files, no settings. The callers read those.
"""
from datetime import UTC, datetime, timedelta

DAY = 86400

# Under this lifetime the lifetime rule renews at half of it, as certbot 5.8 does: a third of a
# 6-day certificate is two days, and a nightly sweep that misses one night has one left.
SHORT_LIFETIME_SECONDS = 10 * DAY

# The most an ARI window can postpone: down to a sixth of the lifetime left. 15 days of 90, 7.5
# of 45, about a day of 160 hours, so even then several nightly sweeps remain to renew in.
ARI_FLOOR_FRACTION = 6

# A renewal the operator's threshold brings ahead of the lifetime rule is guarded (#966): at most
# so many per sweep, and never for a certificate younger than this or a third of its lifetime,
# whichever is less. A fixed 7 days would never let a 160-hour certificate through.
EARLY_MIN_AGE_SECONDS = 7 * DAY

REASON_THRESHOLD = 'threshold'      # the operator's threshold, meaningful for this lifetime
REASON_LIFETIME = 'lifetime'        # the lifetime rule, where the threshold is not meaningful
REASON_ARI = 'ari'                  # the CA's window
REASON_ARI_FLOOR = 'ari_floor'      # the CA's window, held back by the floor
REASON_ARI_ENDED = 'ari_window_ended'


def lifetime_seconds(not_before: datetime, not_after: datetime) -> int:
    return max(0, int((not_after - not_before).total_seconds()))


def lifetime_margin_seconds(lifetime: int) -> float:
    """certbot 5.8's rule: a third of the lifetime, half under 10 days."""
    return lifetime / 2 if lifetime < SHORT_LIFETIME_SECONDS else lifetime / 3


def margin(lifetime: int, threshold_days: int) -> tuple[float, str]:
    """(seconds before expiry, reason) at which the certificate renews without ARI.

    T days exactly, which is when renewals actually happened before: `needs_renewal` used the
    whole days left (`days_left <= T`, rounding down), so it said "due" up to a night early, and
    that night certbot answered "not yet due" (inside its 30 days) or the #966 forced path, which
    measures seconds, waited for T days exactly. The renewal is where it was; the API stops
    announcing it a night before it happens.
    """
    if threshold_days * DAY <= lifetime / 2:
        return float(threshold_days * DAY), REASON_THRESHOLD
    return lifetime_margin_seconds(lifetime), REASON_LIFETIME


def ari_floor_seconds(lifetime: int) -> float:
    return lifetime / ARI_FLOOR_FRACTION


def early_min_age_seconds(lifetime: int) -> float:
    return min(EARLY_MIN_AGE_SECONDS, lifetime / 3)


def parse_instant(text) -> datetime | None:
    """A recorded instant (`2026-11-03T08:41:10Z`, or without the Z) as naive UTC, or None."""
    if not isinstance(text, str) or not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace('Z', '+00:00'))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC).replace(tzinfo=None)
    return parsed


def _whole_second(instant: datetime) -> datetime:
    """Rounded up, as `ari.due_at` does (#962): the instant shown is the instant decided on, and a
    sweep at exactly the shown second renews."""
    if instant.microsecond:
        instant += timedelta(microseconds=1_000_000 - instant.microsecond)
    return instant


def renews_at(not_before: datetime, not_after: datetime, threshold_days: int,
              window: dict | None = None) -> tuple[datetime, str]:
    """(the instant the certificate renews at, reason). All instants naive UTC.

    `window` is the recorded ARI answer as `get_certificate_info` shows it (`renewal_info`), and
    counts only when its status is `window` and it carries `renew_at`: the record is matched to
    the certificate (its `cert_id`) before it is shown, so a window of the predecessor never
    arrives here.
    """
    lifetime = lifetime_seconds(not_before, not_after)
    seconds, reason = margin(lifetime, threshold_days)
    planned = _whole_second(not_after - timedelta(seconds=seconds))
    if not isinstance(window, dict) or window.get('status') != 'window':
        return planned, reason
    ari_at = parse_instant(window.get('renew_at'))
    if ari_at is None:
        return planned, reason
    latest = _whole_second(not_after - timedelta(seconds=ari_floor_seconds(lifetime)))
    end = parse_instant(window.get('window_end'))
    if end is not None and end < latest:
        latest, ended = end, True
    else:
        ended = False
    if ari_at <= latest:
        return ari_at, REASON_ARI
    return latest, (REASON_ARI_ENDED if ended else REASON_ARI_FLOOR)


def is_early(not_before: datetime, not_after: datetime, threshold_days: int, now: datetime) -> bool:
    """Due only because the operator's threshold is wider than the lifetime rule: the renewal the
    #966 guards (per-sweep cap, minimum age) exist for."""
    lifetime = lifetime_seconds(not_before, not_after)
    seconds, reason = margin(lifetime, threshold_days)
    if reason != REASON_THRESHOLD:
        return False
    left = (not_after - now).total_seconds()
    return lifetime_margin_seconds(lifetime) < left <= seconds


def stamp(instant: datetime) -> str:
    """An instant for the API, with the Z a browser needs to read it as UTC. `renews_at` already
    returns whole seconds; one that is not is rounded up, never down."""
    return _whole_second(instant).isoformat() + 'Z'


# --- reading the decision back from a certificate's answer ---------------------------------
#
# digest.py, metrics.py and expiry_watch.py used to redo `days_left <= threshold` on their own,
# which is how a rule ends up in four copies that disagree. They read the instant instead.

EXPIRY_FORMAT = '%Y-%m-%d %H:%M:%S'


def due(info, now: datetime | None = None) -> bool | None:
    """Is the certificate due for renewal by time? None when the answer carries no instant."""
    instant = parse_instant((info or {}).get('renews_at'))
    if instant is None:
        return None
    return (now or datetime.now(UTC).replace(tzinfo=None)) >= instant


def margin_days(info) -> float | None:
    """Days between the planned renewal and expiry, or None."""
    instant = parse_instant((info or {}).get('renews_at'))
    expiry = (info or {}).get('expiry_date')
    if instant is None or not isinstance(expiry, str):
        return None
    try:
        expires = datetime.strptime(expiry, EXPIRY_FORMAT)
    except ValueError:
        return None
    return (expires - instant).total_seconds() / DAY
