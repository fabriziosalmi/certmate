"""Thread count must be a property of the process, not of event volume.

Every `publish()` started one new thread per registered listener — no pool, no
queue, no ceiling. So a renewal sweep across many domains, each publishing to
several listeners, decided how many threads the process had. Nothing in
CertMate chose that number, and nothing reported it.

The replacement is a fixed set of daemon workers reading one queue. Three
properties were chosen deliberately, and each one is a test below because each
could reasonably have gone the other way:

**The publisher never blocks.** It is a request thread on the issuance path and
the scheduler on the renewal path. `DeployManager.on_certificate_event` runs
deploy hooks, each up to a 300-second timeout — putting that on the publisher's
thread would trade a thread problem for a latency problem on the product's main
job.

**Nothing is dropped.** The SSE path drops the oldest message and then the
subscriber, which is right for a browser that fell behind and wrong for a
deploy that has to happen. Certificate events are rare and each matters, so the
backlog is unbounded in length and bounded in cost — one small tuple per
queued call.

**The backlog is visible.** An instance past its capacity says so, once, rather
than being inferred from latency.

The workers stay daemon, as the per-event threads were. A `ThreadPoolExecutor`
would have been fewer lines, but its threads are joined at interpreter exit,
which would let a 300-second deploy hook hold up shutdown until the container
runtime SIGKILLs it anyway.
"""
import logging
import threading
import time

import pytest

from modules.core.events import (
    BACKLOG_WARN_AT, DEFAULT_DISPATCH_WORKERS, EventBus,
)

pytestmark = [pytest.mark.unit]


def _eventually(predicate, timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# --- the ceiling ---------------------------------------------------------

def test_two_hundred_events_do_not_start_two_hundred_threads():
    """The finding, measured — and measured WHILE the work is outstanding.

    The first version of this test counted threads after the events had been
    delivered. Under the old thread-per-event dispatch that passes: the
    threads finish as fast as they are created and the count is back to
    baseline by the time anything looks. Mutating the code back to
    `threading.Thread(...).start()` did not fail it, which is how the
    measurement was found to be wrong rather than the code right.

    Holding every listener open makes the peak observable, which is the number
    the finding is actually about.
    """
    release = threading.Event()
    before = threading.active_count()
    bus = EventBus(workers=4)
    seen = []

    def listener(event, data):
        release.wait(20)
        seen.append(data)

    bus.add_listener(listener)
    try:
        for i in range(200):
            bus.publish('certificate_renewed', {'domain': f'd{i}.example.com'})

        # Every listener is blocked, so whatever threads exist now are the
        # peak. Give the pool a moment to be fully occupied.
        time.sleep(0.3)
        peak = threading.active_count() - before
        assert peak <= 4 + 1, (
            f'{peak} threads for 200 outstanding events; the dispatch is not '
            f'bounded'
        )
    finally:
        release.set()

    assert _eventually(lambda: len(seen) == 200, timeout=20), (
        f'only {len(seen)} delivered')


def test_the_worker_count_is_configurable_and_clamped(monkeypatch):
    assert EventBus(workers=8)._worker_count == 8
    assert EventBus(workers=0)._worker_count == 1
    assert EventBus(workers=1000)._worker_count == 32

    monkeypatch.setenv('CERTMATE_EVENT_WORKERS', '7')
    assert EventBus()._worker_count == 7

    monkeypatch.setenv('CERTMATE_EVENT_WORKERS', 'not a number')
    assert EventBus()._worker_count == DEFAULT_DISPATCH_WORKERS


def test_a_bus_with_no_listeners_starts_no_threads():
    """Most of the test suite builds one of these. A pool that materialises
    on construction would put four idle threads behind every app."""
    before = threading.active_count()
    bus = EventBus()
    for i in range(10):
        bus.publish('certificate_created', {'domain': f'd{i}.example.com'})
    assert threading.active_count() == before


# --- the publisher never blocks -----------------------------------------

def test_publishing_returns_before_a_slow_listener_finishes():
    """The property that matters most: issuance must not wait on a deploy."""
    started = threading.Event()
    release = threading.Event()

    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: (started.set(), release.wait(10)))

    began = time.time()
    bus.publish('certificate_created', {'domain': 'slow.example.com'})
    elapsed = time.time() - began

    assert started.wait(5), 'the listener never ran'
    assert elapsed < 1.0, (
        f'publish() took {elapsed:.2f}s — it is waiting for the listener, so '
        f'a deploy hook now delays the issuance that triggered it'
    )
    release.set()


def test_a_saturated_pool_does_not_block_the_publisher_either():
    """With every worker busy, publish() still returns immediately; the work
    waits in the queue instead of on the caller's thread."""
    release = threading.Event()
    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: release.wait(10))

    bus.publish('certificate_created', {'domain': 'first.example.com'})
    began = time.time()
    for i in range(20):
        bus.publish('certificate_created', {'domain': f'd{i}.example.com'})
    elapsed = time.time() - began

    assert elapsed < 1.0, f'publishing into a busy pool blocked for {elapsed:.2f}s'
    assert bus.pending_dispatches() > 0
    release.set()


# --- nothing is dropped --------------------------------------------------

def test_every_event_reaches_every_listener():
    bus = EventBus(workers=2)
    first, second = [], []
    bus.add_listener(lambda event, data: first.append(data['domain']))
    bus.add_listener(lambda event, data: second.append(data['domain']))

    for i in range(50):
        bus.publish('certificate_renewed', {'domain': f'd{i}.example.com'})

    assert _eventually(lambda: len(first) == 50 and len(second) == 50), (
        f'delivered {len(first)} and {len(second)} of 50 — events were dropped'
    )
    assert sorted(first) == sorted(second)


def test_work_queued_before_the_pool_drains_is_still_delivered():
    """CONTROL for the choice not to drop: a bounded queue with a discard
    policy would silently lose deploys here."""
    release = threading.Event()
    delivered = []
    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: (release.wait(10),
                                          delivered.append(data['domain'])))

    for i in range(100):
        bus.publish('certificate_renewed', {'domain': f'd{i}.example.com'})
    release.set()

    assert _eventually(lambda: len(delivered) == 100, timeout=20), (
        f'{len(delivered)} of 100 arrived after the pool was released'
    )


# --- a bad listener must not cost capacity ------------------------------

def test_a_listener_that_raises_does_not_kill_its_worker():
    """One worker, one exploding listener, then real work. Without the
    try/except the pool bleeds capacity one bad event at a time until nothing
    is dispatched and nothing says why."""
    calls = []

    def listener(event, data):
        calls.append(data['domain'])
        if data['domain'] == 'boom.example.com':
            raise RuntimeError('listener exploded')

    bus = EventBus(workers=1)
    bus.add_listener(listener)

    bus.publish('certificate_created', {'domain': 'boom.example.com'})
    assert _eventually(lambda: len(calls) == 1)
    assert calls == ['boom.example.com']

    bus.publish('certificate_created', {'domain': 'after.example.com'})
    assert _eventually(lambda: len(calls) == 2), (
        'the worker died with the listener, so every later event is lost'
    )
    # Exact, and in order: the second event must be delivered ONCE, by the
    # worker that survived — not re-delivered by a replacement, and not
    # swallowed. Membership would accept both.
    assert calls == ['boom.example.com', 'after.example.com']


def test_a_failing_listener_is_logged_at_error(caplog):
    bus = EventBus(workers=1)
    bus.add_listener(
        lambda event, data: (_ for _ in ()).throw(RuntimeError('nope')))

    with caplog.at_level(logging.ERROR):
        bus.publish('certificate_created', {'domain': 'x.example.com'})
        _eventually(lambda: any(r.levelno >= logging.ERROR
                                for r in caplog.records))

    assert any('certificate_created' in str(r.args or ())
               for r in caplog.records), 'the failure did not name the event'


# --- the backlog is visible ---------------------------------------------

def test_a_backlog_is_reported_once(caplog):
    release = threading.Event()
    bus = EventBus(workers=1)
    bus.add_listener(lambda event, data: release.wait(10))

    with caplog.at_level(logging.WARNING):
        for i in range(BACKLOG_WARN_AT + 20):
            bus.publish('certificate_renewed', {'domain': f'd{i}.example.com'})

    warnings = [r for r in caplog.records
                if 'backlog' in r.getMessage().lower()]
    assert warnings, 'an instance past its capacity said nothing'
    assert len(warnings) == 1, (
        f'{len(warnings)} backlog warnings for one episode — a line per event '
        f'is a line nobody reads'
    )
    assert 'CERTMATE_EVENT_WORKERS' in warnings[0].getMessage(), (
        'the warning does not say what to do about it'
    )
    release.set()


def test_an_ordinary_publish_says_nothing(caplog):
    """CONTROL: a warning on normal traffic would train an operator to ignore
    the one that matters."""
    bus = EventBus(workers=4)
    bus.add_listener(lambda event, data: None)

    with caplog.at_level(logging.WARNING):
        for i in range(10):
            bus.publish('certificate_renewed', {'domain': f'd{i}.example.com'})
        time.sleep(0.2)

    assert not [r for r in caplog.records
                if 'backlog' in r.getMessage().lower()]


# --- what must not change -----------------------------------------------

def test_sse_subscribers_still_receive_events():
    """CONTROL: the SSE path and the listener path are separate, and this
    change touched only one of them."""
    bus = EventBus(workers=1)
    q = bus.subscribe()
    bus.publish('certificate_created', {'domain': 'sse.example.com'})

    message = q.get(timeout=5)
    assert message['event'] == 'certificate_created'
    assert message['data']['domain'] == 'sse.example.com'


def test_sse_still_drops_the_oldest_when_a_subscriber_falls_behind():
    """The queue is bounded at 50 on purpose: a browser that stopped reading
    must not grow the process. Unchanged, and asserted so it stays that way
    while the listener path deliberately does the opposite."""
    bus = EventBus(workers=1)
    q = bus.subscribe()
    for i in range(80):
        bus.publish('certificate_renewed', {'domain': f'd{i}.example.com'})

    assert q.qsize() <= 50
    assert q.get_nowait()['data']['domain'] != 'd0.example.com', (
        'the oldest message survived, so the SSE queue is no longer bounded'
    )


def test_the_workers_are_daemon_threads():
    """A ThreadPoolExecutor would join at interpreter exit, letting a
    300-second deploy hook hold up shutdown until the runtime SIGKILLs it."""
    bus = EventBus(workers=2)
    bus.add_listener(lambda event, data: None)
    assert bus._workers, 'no workers started'
    assert all(worker.daemon for worker in bus._workers)
