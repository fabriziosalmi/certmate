"""Saying that something is about to expire, once per threshold.

`certificate_expiring` has been offered in the notification settings, named in
the README and in docs/webhooks.md, and listed as one of the events a channel
can filter on. Nothing ever published it. The weekly digest was the
only warning an operator got, and a certificate that fails to renew on a
Monday was first mentioned the following Sunday.

This is the job that says it, for both dates that end a service:

* a **certificate** that is close to expiry. With auto-renew on, the renewal
  sweep runs nightly from ``renewal_threshold_days`` out, so a certificate
  still close to expiry means renewal has been failing for days: the warning
  starts at 14 days, well inside the window, where it cannot fire in normal
  operation. With auto-renew off nobody is going to renew it, so the first
  warning is at the renewal threshold itself.
* a **domain registration** that is close to expiry (see
  ``domain_registration.py``). Nothing here renews it — a registrar does, on
  its own schedule — so the notice starts far earlier.

Each threshold speaks once. The state is a table in the inventory database,
keyed by what was said about which expiry date, so:

* a renewed certificate has a new expiry and warns again from scratch;
* a repeated run says nothing new;
* an operator who never fixes it is told at each threshold, not every day.
"""

import logging
from datetime import datetime, timedelta, timezone

from .constants import DEFAULT_RENEWAL_THRESHOLD_DAYS

logger = logging.getLogger(__name__)

KIND_CERTIFICATE = 'certificate'
KIND_DOMAIN = 'domain'

EVENT_CERTIFICATE_EXPIRING = 'certificate_expiring'
EVENT_DOMAIN_EXPIRING = 'domain_expiring'

# Days before expiry at which a certificate is worth a message. The first one
# is deliberately well inside the renewal window: with auto-renew on, anything
# still unrenewed at 14 days has failed roughly a dozen nightly attempts.
CERTIFICATE_THRESHOLDS = (14, 7, 3, 1, 0)
# With auto-renew off, the renewal threshold is when a human would have to act.
# 0 is "expired": said once, on the day it lapses.
DOMAIN_THRESHOLDS = (60, 30, 14, 7, 1, 0)


def thresholds_for_certificate(auto_renew, renewal_threshold_days=DEFAULT_RENEWAL_THRESHOLD_DAYS):
    """The days-left marks a certificate is announced at."""
    if auto_renew:
        return CERTIFICATE_THRESHOLDS
    first = max(int(renewal_threshold_days or DEFAULT_RENEWAL_THRESHOLD_DAYS),
                CERTIFICATE_THRESHOLDS[0])
    return (first,) + CERTIFICATE_THRESHOLDS


def due_threshold(days_left, thresholds):
    """The threshold *days_left* has reached, or None.

    The smallest threshold at or above the remaining days, so a gap — a
    stopped instance, a lookup that failed for a week — still produces one
    message rather than none, and the message names the mark that was crossed.
    """
    if days_left is None:
        return None
    candidates = [t for t in thresholds if days_left <= t]
    return min(candidates) if candidates else None


class ExpiryWatch:
    """Publishes expiry events for certificates and domain registrations.

    The event bus is what carries them: the notifier turns them into messages
    on every configured channel, the dashboard receives them over SSE. Nothing
    here talks to a channel directly.
    """

    def __init__(self, settings_manager, certificates, inventory, event_bus,
                 now=None):
        self.settings_manager = settings_manager
        self.certificates = certificates
        self.inventory = inventory
        self.event_bus = event_bus
        self._now = now or (lambda: datetime.now(timezone.utc))

    def run(self):
        """One pass. Returns ``{'announced': [...], 'checked': n}``."""
        settings = self.settings_manager.load_settings() or {}
        announced = []
        announced += self._certificates(settings)
        announced += self._domains()
        if announced:
            logger.info("Expiry watch: %d new warning(s).", len(announced))
        self.inventory.prune_expiry_notices(before=self._now() - timedelta(days=120))
        return {'announced': announced}

    # -- certificates -------------------------------------------------------- #

    def _certificates(self, settings):
        from .inventory_sources import auto_renew_for, collect_domain_sources

        threshold_days = settings.get('renewal_threshold_days', DEFAULT_RENEWAL_THRESHOLD_DAYS)
        announced = []
        for domain in collect_domain_sources(settings, self.certificates.cert_dir):
            info = self.certificates.get_certificate_info(domain, settings=settings)
            if not info or not info.get('exists'):
                continue
            days_left = info.get('days_left')
            auto_renew = auto_renew_for(settings, domain)
            threshold = due_threshold(days_left, thresholds_for_certificate(
                auto_renew, threshold_days))
            if threshold is None:
                continue
            event = self._announce(KIND_CERTIFICATE, domain, info.get('expiry_date'),
                                   threshold, EVENT_CERTIFICATE_EXPIRING, {
                                       'domain': domain,
                                       'days_left': days_left,
                                       'days_until_expiry': days_left,
                                       'expires_at': info.get('expiry_date'),
                                       'expired': bool(info.get('expired')),
                                       'auto_renew': auto_renew,
                                       'threshold_days': threshold,
                                   })
            if event:
                announced.append(event)
        return announced

    # -- domain registrations ------------------------------------------------ #

    def _domains(self):
        announced = []
        for record in self.inventory.list_registrations():
            if record.get('status') != 'ok' or not record.get('expires_at'):
                continue
            days_left = _days_until(record['expires_at'], self._now())
            threshold = due_threshold(days_left, DOMAIN_THRESHOLDS)
            if threshold is None:
                continue
            event = self._announce(KIND_DOMAIN, record['domain'], record['expires_at'],
                                   threshold, EVENT_DOMAIN_EXPIRING, {
                                       'domain': record['domain'],
                                       'days_left': days_left,
                                       'days_until_expiry': days_left,
                                       'expires_at': record['expires_at'],
                                       'expired': days_left < 0,
                                       'registrar': record.get('registrar'),
                                       'source': record.get('source'),
                                       'threshold_days': threshold,
                                   })
            if event:
                announced.append(event)
        return announced

    # -- once per threshold -------------------------------------------------- #

    def _announce(self, kind, name, expires_at, threshold, event, payload):
        """Publish *event* unless this threshold was already announced for this
        expiry date. Returns the record, or None when nothing was said."""
        if not self.inventory.record_expiry_notice(
                kind=kind, name=name, expires_at=expires_at, threshold=threshold,
                noticed_at=self._now().isoformat()):
            return None
        self.event_bus.publish(event, payload)
        return {'kind': kind, 'name': name, 'threshold_days': threshold,
                'days_left': payload.get('days_left')}


def _days_until(expires_at, now):
    try:
        dt = datetime.fromisoformat(str(expires_at).replace('Z', '+00:00'))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - now).days
