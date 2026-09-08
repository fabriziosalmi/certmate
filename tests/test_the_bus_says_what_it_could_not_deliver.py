"""What the event bus could not dispatch is drained, counted and named.

The dispatch workers are daemon threads on purpose: joining them would let a
300-second deploy hook hold shutdown open until the container runtime killed it
anyway, and that trade is written into the bus. The cost of it was invisible.
A container stopped during or just after a renewal sweep discarded whatever was
still queued — typically the deploy hook for a certificate that HAD been
renewed — so the service kept serving the old certificate, the dashboard showed
a success, `deploy_hook_failed` never fired (the hook had not failed, it had
never started), and nothing anywhere recorded it. The bus had no stop, drain,
close or join at all.

`stop()` does not change the daemon decision. It bounds the loss and names it:
queued work gets a deadline to start, and what is left is taken off the queue
and logged with its event and its domain, so an operator reading the log after
a restart knows which certificates to redeploy by hand.

The property that matters is the count and the naming, not the timing, so that
is what these assert.
"""
import logging
import threading
import time

import pytest

from modules.core.events import EventBus

pytestmark = [pytest.mark.unit]

LOGGER = 'modules.core.events'


def _blocking_listener(started, release):
    """A listener that occupies its worker until released."""
    def listener(event, data):
        started.set()
        release.wait(timeout=5)
    return listener


# --- the count -----------------------------------------------------------

def test_what_never_started_is_counted(caplog):
    """THE regression. One worker, one listener held open, five events: the
    four that never reached a worker are reported rather than discarded."""
    bus = EventBus(workers=1)
    started, release = threading.Event(), threading.Event()
    bus.add_listener(_blocking_listener(started, release))
    try:
        for index in range(5):
            bus.publish('certificate_renewed', {'domain': f'd{index}.example.com'})
        assert started.wait(timeout=5), 'the worker never picked anything up'

        undelivered = bus.stop(timeout=0.05)
    finally:
        release.set()

    assert undelivered == 4, (
        f'{undelivered} reported undelivered; four never reached a worker')


def test_an_empty_queue_reports_nothing_and_returns_immediately():
    """The ordinary case: nothing queued, so stop() costs nothing and says so.
    A drain that slept its full timeout on every shutdown would be the reason
    somebody deletes it."""
    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: None)

    started = time.monotonic()
    assert bus.stop(timeout=5) == 0
    assert time.monotonic() - started < 1.0


def test_work_that_starts_within_the_deadline_is_not_reported(caplog):
    """CONTROL: a bus that reported everything queued, delivered or not, would
    turn every clean shutdown into a false alarm."""
    bus = EventBus(workers=2)
    seen = []
    bus.add_listener(lambda event, data: seen.append(data.get('domain')))

    for index in range(4):
        bus.publish('certificate_renewed', {'domain': f'ok{index}.example.com'})

    assert bus.stop(timeout=5) == 0
    assert len(seen) == 4


# --- the naming ----------------------------------------------------------

def _reported_names(caplog):
    """The undelivered items the warning named, as exact elements.

    Read out of the log record's ARGUMENTS rather than out of the rendered
    string: `'something' in message` is both weaker than it looks — it passes
    when the name turns up anywhere at all, including inside another name —
    and the shape this repository has already agreed to stop writing.
    """
    for record in caplog.records:
        if record.levelno == logging.WARNING and record.args:
            sample = record.args[1]
            return set(str(sample).split(', '))
    return set()


def test_the_undelivered_are_named_with_their_domain(caplog):
    bus = EventBus(workers=1)
    started, release = threading.Event(), threading.Event()
    bus.add_listener(_blocking_listener(started, release))
    try:
        bus.publish('certificate_renewed', {'domain': 'first.example.com'})
        assert started.wait(timeout=5)
        bus.publish('certificate_renewed', {'domain': 'lost.example.com'})

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            bus.stop(timeout=0.05)
    finally:
        release.set()

    assert _reported_names(caplog) == {'certificate_renewed(lost.example.com)'}, (
        'the log names a count but not which certificate, which is the half '
        'an operator can act on')


def test_a_payload_without_a_domain_is_still_named(caplog):
    """CONTROL: not every event carries a domain, and a KeyError in the
    shutdown reporter would lose the very report it exists to make."""
    bus = EventBus(workers=1)
    started, release = threading.Event(), threading.Event()
    bus.add_listener(_blocking_listener(started, release))
    try:
        bus.publish('certificate_renewed', {'domain': 'first.example.com'})
        assert started.wait(timeout=5)
        bus.publish('backup_completed', None)

        with caplog.at_level(logging.WARNING, logger=LOGGER):
            assert bus.stop(timeout=0.05) == 1
    finally:
        release.set()

    assert _reported_names(caplog) == {'backup_completed(no domain)'}


# --- after stopping ------------------------------------------------------

def test_publishing_after_stop_is_refused_rather_than_queued(caplog):
    """Accepting work after the report would put it in a report that has
    already been made — which is how a shutdown loses something quietly for a
    second time."""
    bus = EventBus(workers=1)
    dispatched = []
    bus.add_listener(lambda event, data: dispatched.append(event))
    bus.stop(timeout=0)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        bus.publish('certificate_renewed', {'domain': 'late.example.com'})

    assert bus.pending_dispatches() == 0
    assert not dispatched
    refusals = [record for record in caplog.records
                if record.msg.startswith('Event bus is stopping')]
    assert len(refusals) == 1, 'the refusal was not reported'
    assert refusals[0].args == ('certificate_renewed', 1)


def test_sse_subscribers_still_receive_after_stop():
    """CONTROL for the refusal above: it is the LISTENER dispatch that is
    refused. A browser holding an SSE stream open during shutdown should still
    see the last event rather than have it silently dropped."""
    bus = EventBus(workers=1)
    subscriber = bus.subscribe()
    bus.add_listener(lambda event, data: None)
    bus.stop(timeout=0)

    bus.publish('certificate_renewed', {'domain': 'sse.example.com'})

    message = subscriber.get_nowait()
    assert message['event'] == 'certificate_renewed'


def test_stop_is_idempotent():
    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: None)

    assert bus.stop(timeout=0) == 0
    assert bus.stop(timeout=0) == 0


# --- the wiring ----------------------------------------------------------

def test_the_drain_deadline_is_configurable(monkeypatch):
    monkeypatch.setenv('CERTMATE_EVENT_DRAIN_SECONDS', '12')
    assert EventBus._drain_timeout() == 12.0


@pytest.mark.parametrize('value', ['not-a-number', '', '-3', '900'])
def test_a_broken_deadline_is_clamped_not_obeyed(monkeypatch, value):
    """A typo must not make shutdown hang for fifteen minutes, and must not
    make the drain zero either — both would be silent."""
    monkeypatch.setenv('CERTMATE_EVENT_DRAIN_SECONDS', value)

    timeout = EventBus._drain_timeout()

    assert 0.0 <= timeout <= 60.0


def test_the_application_registers_the_drain_at_exit():
    """The property, not the mechanism: something must call stop() when the
    process goes away. There is no gunicorn config file to hang an on_exit
    hook on, and app.py's KeyboardInterrupt path only covers `python app.py`,
    so atexit is what both deployment shapes have in common.
    """
    import inspect

    from modules.core import factory

    source = inspect.getsource(factory._drain_event_bus_at_exit)
    assert 'atexit.register' in source
    assert '.stop' in source

    entrypoint = inspect.getsource(factory.create_app)
    assert '_drain_event_bus_at_exit(container)' in entrypoint, (
        'the drain is defined but nothing calls it during app creation')
