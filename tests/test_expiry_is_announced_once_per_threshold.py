"""Something about to expire is said out loud, once per threshold.

`certificate_expiring` was offered in the notification settings, named in the
README and in docs/webhooks.md, and listed as one of the events a channel can
filter on. **Nothing published it**, and nothing could have rendered it if it
had: `_EVENT_TITLES` had no entry, so `build_notification_message` returned
None and the notifier was never reached. The weekly digest was the only warning
an operator got.

This covers the job that says it, the thresholds it says it at, the state that
keeps it from repeating, and the rendering — plus `domain_expiring` for the
registration itself, and the gate that keeps an unrenderable event from being
declared unsilenceable again.
"""
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from modules.core.cert_inventory import CertInventory
from modules.core.expiry_watch import (
    CERTIFICATE_THRESHOLDS,
    DOMAIN_THRESHOLDS,
    ExpiryWatch,
    due_threshold,
    thresholds_for_certificate,
)
from modules.core.factory import _EVENT_TITLES, build_notification_message

pytestmark = [pytest.mark.unit]

NOW = datetime(2026, 9, 22, 7, 0, tzinfo=timezone.utc)


# --------------------------------------------------------------------------- #
# Which marks, and when
# --------------------------------------------------------------------------- #

def test_auto_renew_is_only_announced_well_inside_the_renewal_window():
    """With auto-renew on, the sweep runs nightly from the renewal threshold.
    A warning at 30 days would fire for every certificate every cycle; one at
    14 means roughly a dozen nightly attempts have already failed."""
    assert thresholds_for_certificate(True) == CERTIFICATE_THRESHOLDS
    assert max(CERTIFICATE_THRESHOLDS) < 30


def test_without_auto_renew_the_first_warning_is_when_a_human_must_act():
    assert thresholds_for_certificate(False, 30)[0] == 30
    assert thresholds_for_certificate(False, 45)[0] == 45
    # A threshold below the automatic ones does not silence them.
    assert thresholds_for_certificate(False, 5)[0] == max(CERTIFICATE_THRESHOLDS)


@pytest.mark.parametrize('days_left, expected', [
    (90, None), (15, None), (14, 14), (13, 14), (8, 14), (7, 7), (4, 7),
    (3, 3), (1, 1), (0, 0), (-3, 0),
])
def test_the_mark_that_was_crossed(days_left, expected):
    """The most recently crossed mark: the smallest threshold still at or
    above what is left. At 13 days the mark that was crossed is 14, not 7 —
    and since each mark speaks once, 13 says nothing new after 14 did.

    It is written this way so a gap still produces a message: an instance that
    was off from day 15 to day 8 comes back and announces 14, rather than
    missing it because the exact day passed unobserved."""
    assert due_threshold(days_left, CERTIFICATE_THRESHOLDS) == expected


def test_an_unknown_number_of_days_says_nothing():
    assert due_threshold(None, CERTIFICATE_THRESHOLDS) is None


def test_domains_are_warned_about_far_earlier_than_certificates():
    """Nothing here renews a registration: a registrar does, and an operator
    has to decide to let it."""
    assert max(DOMAIN_THRESHOLDS) > max(CERTIFICATE_THRESHOLDS)
    assert due_threshold(45, DOMAIN_THRESHOLDS) == 60
    assert due_threshold(45, CERTIFICATE_THRESHOLDS) is None


# --------------------------------------------------------------------------- #
# The job
# --------------------------------------------------------------------------- #

class _Bus:
    def __init__(self):
        self.published = []

    def publish(self, event, data):
        self.published.append((event, data))


def _watch(tmp_path, certificates=None, settings=None, inventory=None, bus=None,
           now=NOW):
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = settings if settings is not None else {
        'domains': ['a.example.com']}
    inventory = inventory or CertInventory(tmp_path / 'data')
    bus = bus or _Bus()
    watch = ExpiryWatch(settings_manager, certificates or _Certificates(tmp_path),
                        inventory, bus, now=lambda: now)
    return watch, bus, inventory


class _Certificates:
    """Just enough of CertificateManager: a cert_dir and per-domain info."""

    def __init__(self, tmp_path, info=None):
        self.cert_dir = tmp_path / 'certs'
        self.cert_dir.mkdir(parents=True, exist_ok=True)
        self.info = info or {}

    def get_certificate_info(self, domain, settings=None, use_cache=True):
        return self.info.get(domain)


def _cert(days_left, expires='2026-10-06 07:00:00', exists=True, expired=False):
    return {'exists': exists, 'days_left': days_left, 'expiry_date': expires,
            'expired': expired}


def test_a_certificate_inside_the_window_is_announced_once(tmp_path):
    certs = _Certificates(tmp_path, {'a.example.com': _cert(7)})
    watch, bus, inventory = _watch(tmp_path, certs)

    first = watch.run()
    assert [e for e, _d in bus.published] == ['certificate_expiring']
    event, payload = bus.published[0]
    assert payload['domain'] == 'a.example.com'
    assert payload['days_left'] == 7
    assert payload['threshold_days'] == 7
    assert payload['auto_renew'] is True
    assert first['announced'][0]['name'] == 'a.example.com'

    # The next morning, nothing has changed and nothing is said.
    assert watch.run()['announced'] == []
    assert len(bus.published) == 1


def test_each_threshold_speaks_once(tmp_path):
    certs = _Certificates(tmp_path, {'a.example.com': _cert(14)})
    watch, bus, _inv = _watch(tmp_path, certs)
    watch.run()
    for days in (13, 8, 7, 4, 3, 2, 1, 0):
        certs.info['a.example.com'] = _cert(days)
        watch.run()
    thresholds = [d['threshold_days'] for _e, d in bus.published]
    assert thresholds == [14, 7, 3, 1, 0]


def test_a_renewed_certificate_starts_again(tmp_path):
    certs = _Certificates(tmp_path, {'a.example.com': _cert(7, expires='2026-10-06 07:00:00')})
    watch, bus, _inv = _watch(tmp_path, certs)
    watch.run()
    # Renewed: a new expiry, and a long time left.
    certs.info['a.example.com'] = _cert(89, expires='2026-12-20 07:00:00')
    watch.run()
    assert len(bus.published) == 1
    # ... and months later it is worth saying again, about the new date.
    certs.info['a.example.com'] = _cert(7, expires='2026-12-20 07:00:00')
    watch.run()
    assert [d['expires_at'] for _e, d in bus.published] == [
        '2026-10-06 07:00:00', '2026-12-20 07:00:00']


def test_a_healthy_certificate_says_nothing(tmp_path):
    certs = _Certificates(tmp_path, {'a.example.com': _cert(60)})
    watch, bus, _inv = _watch(tmp_path, certs)
    assert watch.run()['announced'] == []
    assert bus.published == []


@pytest.mark.parametrize('info', [
    None,                                          # nothing could be read
    {'exists': False},                             # the domain is registered, the files are not there
    {'exists': False, 'days_left': 3,              # a stale number beside "not there"
     'expiry_date': '2026-09-25 07:00:00'},
])
def test_a_certificate_that_is_not_there_says_nothing(tmp_path, info):
    """A domain in settings with no certificate on disk is not an expiry
    warning; it has nothing to expire. The third case is the one that matters:
    without the guard, a leftover day count is announced as if it were real."""
    certs = _Certificates(tmp_path, {'a.example.com': info})
    watch, bus, _inv = _watch(tmp_path, certs)
    assert watch.run()['announced'] == []
    assert bus.published == []


def test_an_expired_certificate_says_so(tmp_path):
    certs = _Certificates(tmp_path, {'a.example.com': _cert(-4, expired=True)})
    watch, bus, _inv = _watch(tmp_path, certs)
    watch.run()
    _event, payload = bus.published[0]
    assert payload['expired'] is True
    assert payload['threshold_days'] == 0


def test_auto_renew_off_is_warned_at_the_renewal_threshold(tmp_path):
    settings = {'domains': [{'domain': 'a.example.com', 'auto_renew': False}],
                'renewal_threshold_days': 30}
    certs = _Certificates(tmp_path, {'a.example.com': _cert(29)})
    watch, bus, _inv = _watch(tmp_path, certs, settings=settings)
    watch.run()
    _event, payload = bus.published[0]
    assert payload['auto_renew'] is False
    assert payload['threshold_days'] == 30


def test_the_same_certificate_with_auto_renew_on_is_silent_at_29_days(tmp_path):
    """The control for the test above: 29 days with auto-renew on is the
    renewal sweep's ordinary business, not something to wake anyone for."""
    certs = _Certificates(tmp_path, {'a.example.com': _cert(29)})
    watch, bus, _inv = _watch(tmp_path, certs)
    watch.run()
    assert bus.published == []


# --------------------------------------------------------------------------- #
# Domain registrations
# --------------------------------------------------------------------------- #

def _registration(inventory, domain, days_from_now, status='ok', now=NOW):
    inventory.record_registration({
        'domain': domain, 'status': status,
        'expires_at': (now + timedelta(days=days_from_now)).isoformat().replace('+00:00', 'Z')
        if days_from_now is not None else None,
        'registrar': 'Example Registrar', 'registry_status': ['ok'],
        'source': 'rdap', 'error': None, 'checked_at': now.isoformat(),
    })


def test_a_registration_close_to_expiry_is_announced(tmp_path):
    inventory = CertInventory(tmp_path / 'data')
    _registration(inventory, 'example.it', 29)
    watch, bus, _inv = _watch(tmp_path, _Certificates(tmp_path), settings={},
                              inventory=inventory)
    watch.run()
    event, payload = bus.published[0]
    assert event == 'domain_expiring'
    assert payload['domain'] == 'example.it'
    assert payload['threshold_days'] == 30
    assert payload['registrar'] == 'Example Registrar'
    assert payload['source'] == 'rdap'
    assert watch.run()['announced'] == []


def test_a_registry_that_publishes_no_expiry_is_not_a_warning(tmp_path):
    """`.de` and `.eu` say a domain is registered and nothing more. That is an
    answer, not a date, and it must not turn into "expires today"."""
    inventory = CertInventory(tmp_path / 'data')
    _registration(inventory, 'example.de', None, status='not_published')
    watch, bus, _inv = _watch(tmp_path, _Certificates(tmp_path), settings={},
                              inventory=inventory)
    watch.run()
    assert bus.published == []


def test_a_failed_lookup_is_not_a_warning(tmp_path):
    inventory = CertInventory(tmp_path / 'data')
    _registration(inventory, 'example.it', 3, status='unavailable')
    watch, bus, _inv = _watch(tmp_path, _Certificates(tmp_path), settings={},
                              inventory=inventory)
    watch.run()
    assert bus.published == []


def test_old_notices_are_forgotten(tmp_path):
    inventory = CertInventory(tmp_path / 'data')
    inventory.record_expiry_notice(kind='certificate', name='gone.example.com',
                                   expires_at='2025-01-01T00:00:00+00:00',
                                   threshold=7, noticed_at='2025-01-01T07:00:00')
    watch, _bus, _inv = _watch(tmp_path, _Certificates(tmp_path), settings={},
                               inventory=inventory)
    watch.run()
    assert inventory.expiry_notices() == []


# --------------------------------------------------------------------------- #
# What an operator actually reads
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('event', ['certificate_expiring', 'domain_expiring'])
def test_the_message_carries_the_number(event):
    """The whole line, not fragments of it: an operator reads one sentence,
    and asserting the exact text is also what keeps it from drifting."""
    title, message = build_notification_message(event, {
        'domain': 'a.example.com', 'days_left': 7, 'expires_at': '2026-10-06 07:00:00'})
    assert message == f'{title}: a.example.com — 7 days left (2026-10-06 07:00:00)'


def test_the_message_says_today_and_expired_plainly():
    _t, today = build_notification_message('certificate_expiring', {
        'domain': 'a', 'days_left': 0, 'expires_at': '2026-09-22 07:00:00'})
    assert today == 'Certificate Expiring: a — expires today (2026-09-22 07:00:00)'
    _t, gone = build_notification_message('certificate_expiring', {
        'domain': 'a', 'days_left': -2, 'expired': True, 'expires_at': '2026-09-20 07:00:00'})
    assert gone == 'Certificate Expiring: a — expired (2026-09-20 07:00:00)'
    _t, one = build_notification_message('domain_expiring', {
        'domain': 'a', 'days_left': 1, 'expires_at': '2026-09-23'})
    assert '1 day left' in one and '1 days' not in one


def test_an_event_nobody_can_silence_must_be_renderable():
    """`certificate_deploy_incomplete` is in the notifier's
    _ALWAYS_NOTIFY_EVENTS, which exists so an operator cannot filter it away by
    accident. It had no title, so build_notification_message returned None and
    the notifier was never reached: the event nobody could silence was silent.
    """
    from modules.core.notifier import _ALWAYS_NOTIFY_EVENTS
    missing = sorted(e for e in _ALWAYS_NOTIFY_EVENTS if e not in _EVENT_TITLES)
    assert missing == [], (
        'these events are delivered whatever the filter says, but have no '
        'title, so nothing renders them and nobody is told: ' + ', '.join(missing))


def test_every_event_the_settings_ui_offers_can_be_rendered():
    """A filter chip for an event that cannot be rendered is a switch wired to
    nothing — which is what certificate_expiring was.

    The list moved. It used to be two hardcoded arrays in
    `settings_notifications.html`, both missing `certificate_deployed` in the
    same way (#876 item 7); both checkbox rows now read `notifiableEvents`
    from the Alpine component, so there is one copy. This reads it there.

    The guard below is why that move did not go unnoticed: emptied of its
    literal, the template made this control cover nothing, and it said so
    rather than passing.
    """
    import re
    component = (
        __import__('pathlib').Path(__file__).resolve().parent.parent
        / 'static' / 'js' / 'settings-notifications.js'
    ).read_text(encoding='utf-8')
    match = re.search(r'notifiableEvents:\s*\[(.*?)\]', component, re.S)
    assert match, 'notifiableEvents is gone; this control no longer checks anything'
    offered = set(re.findall(r"'([a-z_]+)'", match.group(1)))
    assert offered, 'the event list is empty; this control no longer checks anything'
    assert offered <= set(_EVENT_TITLES), sorted(offered - set(_EVENT_TITLES))


# --------------------------------------------------------------------------- #
# Through the real application
# --------------------------------------------------------------------------- #

@pytest.fixture
def real_app(tmp_path, monkeypatch):
    import secrets
    from modules.core.factory import create_app
    root = tmp_path / 'certmate' / 'modules' / 'core'
    root.mkdir(parents=True)
    (root / 'factory.py').write_text('# anchor\n')
    monkeypatch.setattr('modules.core.factory.__file__', str(root / 'factory.py'))
    monkeypatch.setenv('FLASK_ENV', 'testing')
    monkeypatch.setenv('TESTING', 'true')
    monkeypatch.setenv('API_BEARER_TOKEN', secrets.token_urlsafe(32))
    return create_app()


@pytest.mark.parametrize('event, extra', [
    ('certificate_expiring', {'auto_renew': True}),
    ('domain_expiring', {'registrar': 'Example Registrar'}),
])
def test_the_event_reaches_the_notifier_in_a_real_instance(real_app, event, extra):
    """The wiring that was missing. Publishing on the bus must end in a call to
    the notifier with a rendered title and message; a missing entry in
    _EVENT_TITLES silently stopped exactly here."""
    _application, container = real_app
    notifier = container.managers['notifier']
    sent = []
    notifier.notify = lambda ev, title, message, details=None: sent.append(
        (ev, title, message, details))

    bus = container.managers['events']
    bus.publish(event, dict(
        {'domain': 'a.example.com', 'days_left': 3,
         'expires_at': '2026-09-25 07:00:00', 'threshold_days': 3}, **extra))

    # Listeners run on the bus's worker pool, never on the publisher's thread
    # (a listener can run deploy hooks). Wait for the queue to drain rather
    # than sleeping a guessed interval.
    deadline = time.time() + 10
    while (bus.pending_dispatches() or not sent) and time.time() < deadline:
        time.sleep(0.02)

    assert len(sent) == 1
    ev, title, message, details = sent[0]
    assert ev == event
    assert 'Expiring' in title
    assert '3 days left' in message
    assert details['threshold_days'] == 3


def test_the_watch_is_wired_and_scheduled(real_app):
    _application, container = real_app
    assert container.managers['expiry_watch'] is not None
    job_ids = {job.id for job in container.scheduler.get_jobs()} if container.scheduler else set()
    assert 'expiry_watch' in job_ids
