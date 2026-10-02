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


def superseded_fingerprints(records):
    """The certificates that have been replaced everywhere they were seen (#1044).

    The inventory is a history by fingerprint, on purpose: it is how "a renewed
    certificate that was never deployed" is caught (the new one exists and the
    endpoint still serves the old one). So nothing is forgotten when a renewal
    arrives. What an operator wants from the list is to tell the certificates in
    use from the ones that are not any more, and the data for that is already
    stored: each endpoint records when it last served each certificate.

    A certificate is superseded when it has at least one endpoint and, at EVERY
    endpoint it was seen on, a different certificate has been seen more recently.
    So:

    * one still served on any endpoint is never superseded;
    * one with no endpoint (found in a CT log, or issued here and never probed)
      is never superseded: there is nothing to compare;
    * two certificates last seen at the same instant on an endpoint are both
      current, and a ``last_seen`` that cannot be read is never taken as evidence
      of replacement;
    * the latest sighting decides, so an endpoint that alternates between two
      certificates (a rollout across a load balancer) marks whichever it served
      earlier. That is what "has since been seen serving a different certificate"
      says, and it corrects itself on the next scan.

    Computed from the records it is given, so the caller passes the whole
    inventory and filters afterwards: a newer certificate that a ``source`` or
    scope filter would hide still replaced the old one. Host names compare
    case-insensitively.
    """
    def key(endpoint):
        return (str(endpoint.get('host') or '').lower(), endpoint.get('port'))

    seen = {}
    for record in records:
        for endpoint in record.get('endpoints') or []:
            seen.setdefault(key(endpoint), {})[record.get('fingerprint')] = _parse_iso(endpoint.get('last_seen'))

    def replaced_at(fingerprint, endpoint):
        sightings = seen[key(endpoint)]
        mine = sightings[fingerprint]
        newest = max((t for t in sightings.values() if t is not None), default=None)
        return mine is not None and newest is not None and mine < newest

    return {record.get('fingerprint') for record in records
            if record.get('endpoints')
            and all(replaced_at(record.get('fingerprint'), endpoint) for endpoint in record['endpoints'])}


def build_inventory_view(records, now=None, include_superseded=True, superseded=None):
    """Return ``{'certificates': [...], 'summary': {...}}`` for the dashboard.

    Each certificate is the stored record plus a live ``days_until_expiry``,
    ``expiry_status``, ``group`` (``issued`` when managed, else ``discovered``)
    and ``superseded`` (:func:`superseded_fingerprints`). The summary rolls up
    totals, source breakdown, an expiry forecast (expired + within 7/30/90 days)
    and the revocation answers across every record it counts.

    With ``include_superseded=False`` the superseded certificates are left out of
    the list AND of the summary, so the cards describe what the list shows;
    ``summary['superseded']`` is how many of the given records are superseded,
    whether they were left out or not. *superseded* is the set to use when the
    caller worked it out from the whole inventory before filtering ``records``.
    """
    now = now or datetime.utcnow()
    if superseded is None:
        superseded = superseded_fingerprints(records)
    certificates = []
    summary = {
        'total': 0,
        'issued': 0,
        'discovered': 0,
        'superseded': sum(1 for record in records if record.get('fingerprint') in superseded),
        'by_source': {},
        'expiry': {'expired': 0, '7': 0, '30': 0, '90': 0, 'unknown': 0},
        # Last revocation answer per certificate; 'unchecked' = never asked.
        'revocation': {'revoked': 0, 'good': 0, 'unknown': 0,
                       'unavailable': 0, 'not_applicable': 0, 'unchecked': 0},
    }

    for record in records:
        is_superseded = record.get('fingerprint') in superseded
        if is_superseded and not include_superseded:
            continue
        days = days_until_expiry(record.get('not_after'), now)
        status = expiry_status(days)
        group = 'issued' if record.get('managed') else 'discovered'
        item = dict(record)
        item['days_until_expiry'] = days
        item['expiry_status'] = status
        item['group'] = group
        item['superseded'] = is_superseded
        certificates.append(item)

        summary['total'] += 1
        summary[group] += 1
        source = record.get('source') or 'unknown'
        summary['by_source'][source] = summary['by_source'].get(source, 0) + 1

        rev_status = (record.get('revocation') or {}).get('status') or 'unchecked'
        if rev_status not in summary['revocation']:
            rev_status = 'unavailable'
        summary['revocation'][rev_status] += 1

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


REGISTRATION_FORECAST_BUCKETS = (30, 60, 90)


def build_registrations_view(records, now=None):
    """Return ``{'domains': [...], 'summary': {...}}`` for domain registrations.

    Each record gains ``days_until_expiry`` and ``expiry_status`` — the same
    thresholds as certificates — computed only when the registry published an
    expiry. ``not_published`` and ``unavailable`` stay ``unknown`` rather than
    being given a number nobody stated.
    """
    now = now or datetime.utcnow()
    domains = []
    summary = {
        'total': 0,
        'by_status': {'ok': 0, 'not_published': 0, 'not_registered': 0, 'unavailable': 0},
        'expiry': {'expired': 0, '30': 0, '60': 0, '90': 0},
    }
    for record in records:
        item = dict(record)
        days = days_until_expiry(record.get('expires_at'), now) if record.get('expires_at') else None
        item['days_until_expiry'] = days
        item['expiry_status'] = expiry_status(days)
        domains.append(item)

        summary['total'] += 1
        status = record.get('status') or 'unavailable'
        summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
        if days is None:
            continue
        if days < 0:
            summary['expiry']['expired'] += 1
        else:
            for bucket in REGISTRATION_FORECAST_BUCKETS:
                if days <= bucket:
                    summary['expiry'][str(bucket)] += 1
    return {'domains': domains, 'summary': summary}
