"""Presentation helpers for the certificate inventory dashboard (#471).

Pure, offline transforms over inventory records (as returned by
:meth:`cert_inventory.CertInventory.list_all`): compute days-until-expiry and an
at-a-glance expiry status, split issued-vs-discovered, and roll up an expiry
forecast across *everything* — issued and discovered alike. Kept free of Flask
and SQLite so it is trivially testable and reusable by the API layer and the
readiness report.
"""

from datetime import datetime, timezone

# Expiry status thresholds (days). Ordered most-severe first.
EXPIRY_EXPIRED = 'expired'
EXPIRY_CRITICAL = 'critical'   # <= 7 days
EXPIRY_WARNING = 'warning'     # <= 30 days
EXPIRY_OK = 'ok'

CRITICAL_DAYS = 7
WARNING_DAYS = 30
# Forecast buckets reported in the summary (days).
FORECAST_BUCKETS = (7, 30, 90)


def record_in_scope(record, can_access):
    """True if an API-key scope covers any domain an inventory *record* names.

    *can_access* is ``callable(domain) -> bool`` (the endpoint wires in
    ``auth_manager.domain_matches_scope`` bound to the current user's scope,
    which returns True for every domain when the caller is unrestricted). A record is
    visible if the caller can access its subject CN or any SAN; a record with no
    names is visible only to an unrestricted caller (tested via the empty
    domain, which an unrestricted scope matches and a scoped one does not).

    Kept here, pure and auth-free, so the discovered-cert visibility boundary is
    unit-testable without standing up the auth stack.
    """
    names = []
    if record.get('subject_cn'):
        names.append(record['subject_cn'])
    names.extend(record.get('san_dns') or [])
    if not names:
        return can_access('')
    return any(can_access(n) for n in names)


def _parse_iso(value):
    """Parse an inventory ISO timestamp (``...Z`` or offset) to naive UTC.

    Returns None on anything unparseable so a malformed stored value degrades to
    "unknown expiry" rather than raising in a dashboard handler.
    """
    if not value:
        return None
    text = str(value).strip()
    if text.endswith('Z'):
        text = text[:-1]
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is not None:
        # Normalise to naive UTC (NOT local time) to match datetime.utcnow().
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def days_until_expiry(not_after, now=None):
    """Whole days from *now* until *not_after* (negative if expired), or None."""
    dt = _parse_iso(not_after)
    if dt is None:
        return None
    now = now or datetime.utcnow()
    return (dt - now).days


def expiry_status(days):
    """Map a days-until-expiry integer to an at-a-glance status string."""
    if days is None:
        return 'unknown'
    if days < 0:
        return EXPIRY_EXPIRED
    if days <= CRITICAL_DAYS:
        return EXPIRY_CRITICAL
    if days <= WARNING_DAYS:
        return EXPIRY_WARNING
    return EXPIRY_OK


def build_inventory_view(records, now=None):
    """Return ``{'certificates': [...], 'summary': {...}}`` for the dashboard.

    Each certificate is the stored record plus a live ``days_until_expiry``,
    ``expiry_status`` and ``group`` (``issued`` when managed, else
    ``discovered``). The summary rolls up totals, source breakdown, and an
    expiry forecast (expired + within 7/30/90 days) across every record.
    """
    now = now or datetime.utcnow()
    certificates = []
    summary = {
        'total': 0,
        'issued': 0,
        'discovered': 0,
        'by_source': {},
        'expiry': {'expired': 0, '7': 0, '30': 0, '90': 0, 'unknown': 0},
    }

    for record in records:
        days = days_until_expiry(record.get('not_after'), now)
        status = expiry_status(days)
        group = 'issued' if record.get('managed') else 'discovered'
        item = dict(record)
        item['days_until_expiry'] = days
        item['expiry_status'] = status
        item['group'] = group
        certificates.append(item)

        summary['total'] += 1
        summary[group] += 1
        source = record.get('source') or 'unknown'
        summary['by_source'][source] = summary['by_source'].get(source, 0) + 1

        if days is None:
            summary['expiry']['unknown'] += 1
        elif days < 0:
            summary['expiry']['expired'] += 1
        else:
            # Cumulative buckets: a cert expiring in 5 days counts in 7, 30, 90.
            for bucket in FORECAST_BUCKETS:
                if days <= bucket:
                    summary['expiry'][str(bucket)] += 1

    return {'certificates': certificates, 'summary': summary}
