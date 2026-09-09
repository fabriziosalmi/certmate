"""Two workers and an unbounded queue is a promise the process cannot keep.

`IssuanceExecutor.submit` accepted everything. The pool has two workers by
default, each one running a certbot subprocess that takes tens of seconds to
minutes, and the queue behind them had no limit — so a client in a retry loop,
or a script walking a domain list, could park hundreds of jobs there. Every one
of those callers got `202 Accepted` and a job id for a certificate that would
not be attempted for hours.

The registry's own bound did not help. `_evict_locked` drops the oldest
*terminal* jobs once over the history cap and deliberately never evicts a job
that has not finished, so a backlog of queued work is not bounded by that cap
either — it is exactly the case the cap declines to touch.

A 429 is the honest answer: the caller learns now, and can come back, instead
of holding a job id that means nothing. The depth behind the refusal is a
gauge, along with the event bus's backlog — whose `pending_dispatches()` had no
caller at all, a number computed for nobody.
"""
import threading

import pytest

from modules.core.cert_jobs import IssuanceExecutor, IssuanceQueueFull

pytestmark = [pytest.mark.unit]


@pytest.fixture
def blocked():
    """An executor whose single worker is stuck, so everything else queues."""
    executor = IssuanceExecutor(app=None, event_bus=None, max_workers=1,
                                queue_limit=3)
    release = threading.Event()
    running = threading.Event()
    executor.submit('create', 'busy.example.com',
                    lambda: (running.set(), release.wait(timeout=5)))
    assert running.wait(timeout=5)
    try:
        yield executor, release
    finally:
        release.set()
        executor.shutdown()


# --- THE regression -------------------------------------------------------

def test_the_queue_refuses_past_its_limit(blocked):
    executor, _ = blocked
    executor.submit('create', 'a.example.com', lambda: None)
    executor.submit('create', 'b.example.com', lambda: None)

    with pytest.raises(IssuanceQueueFull) as caught:
        executor.submit('create', 'c.example.com', lambda: None)

    assert caught.value.depth == 3
    assert caught.value.limit == 3


def test_a_refused_job_leaves_no_record(blocked):
    """A rejected submission must not appear as work in flight: the caller has
    no job id for it, so a record would be a job nobody can ever ask about."""
    executor, _ = blocked
    executor.submit('create', 'a.example.com', lambda: None)
    executor.submit('create', 'b.example.com', lambda: None)

    with pytest.raises(IssuanceQueueFull):
        executor.submit('create', 'refused.example.com', lambda: None)

    assert 'refused.example.com' not in {job['domain']
                                         for job in executor.list_active()}


def test_room_reappears_as_jobs_finish(blocked):
    """CONTROL, and the reason this is a queue limit and not a rate limit: it
    is about how much is outstanding, not how fast requests arrive."""
    executor, release = blocked
    executor.submit('create', 'a.example.com', lambda: None)
    executor.submit('create', 'b.example.com', lambda: None)
    with pytest.raises(IssuanceQueueFull):
        executor.submit('create', 'c.example.com', lambda: None)

    release.set()

    assert _eventually(lambda: executor.pending() == 0)
    assert executor.submit('create', 'later.example.com', lambda: None)


def test_finished_jobs_do_not_count_against_the_limit(blocked):
    """The history cap keeps 200 finished jobs around by default. If those
    counted, an instance would refuse issuance after 200 successful ones."""
    executor, release = blocked
    release.set()
    assert _eventually(lambda: executor.pending() == 0)

    for n in range(10):
        executor.submit('create', f'{n}.example.com', lambda: None)
        assert _eventually(lambda: executor.pending() == 0)

    assert len(executor._jobs) == 11
    assert executor.pending() == 0


def test_two_callers_arriving_together_cannot_both_take_the_last_slot():
    """The check and the registration are under one lock. Read the depth,
    then register, and both threads see one below the limit."""
    executor = IssuanceExecutor(app=None, event_bus=None, max_workers=1,
                                queue_limit=4)
    release = threading.Event()
    running = threading.Event()
    executor.submit('create', 'busy.example.com',
                    lambda: (running.set(), release.wait(timeout=5)))
    assert running.wait(timeout=5)
    executor.submit('create', 'a.example.com', lambda: None)
    executor.submit('create', 'b.example.com', lambda: None)

    start = threading.Barrier(8)
    accepted = []
    refused = []

    def racer(n):
        start.wait(timeout=5)
        try:
            executor.submit('create', f'race{n}.example.com', lambda: None)
            accepted.append(n)
        except IssuanceQueueFull:
            refused.append(n)

    threads = [threading.Thread(target=racer, args=(n,)) for n in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    release.set()
    executor.shutdown()

    assert len(accepted) == 1, (
        f'{len(accepted)} submissions took the last slot; the depth check and '
        f'the registration are not atomic')
    assert len(refused) == 7


# --- what an operator can see --------------------------------------------

def test_the_depth_and_the_limit_are_readable(blocked):
    """A 429 with no number behind it leaves an operator guessing whether to
    raise the limit or find what is stuck."""
    executor, _ = blocked

    assert executor.pending() == 1
    assert executor.queue_limit() == 3


def test_the_gauges_are_fed_from_the_accessors():
    """`EventBus.pending_dispatches` had no caller in the tree. The collector
    is now it, for both queues."""
    from modules.core import metrics

    class _Executor:
        def pending(self):
            return 7

        def queue_limit(self):
            return 20

    class _Bus:
        def pending_dispatches(self):
            return 3

    metrics.metrics_collector._collect_queue_metrics(
        {'cert_executor': _Executor(), 'events': _Bus()})

    assert metrics.issuance_queue_depth._value.get() == 7
    assert metrics.issuance_queue_limit._value.get() == 20
    assert metrics.event_dispatch_backlog._value.get() == 3


def test_the_metrics_endpoint_passes_both_queues():
    """CONTROL. The gauges exist and read zero forever if the context the
    collector receives does not carry the objects."""
    import inspect

    from modules.web import misc_routes

    source = inspect.getsource(misc_routes.register_misc_routes)
    context = source[source.index("app_context = {"):]

    assert "'cert_executor': managers.get('cert_executor')" in context
    assert "'events': managers.get('events')" in context


# --- the API says 429, not 202 -------------------------------------------

def test_the_api_turns_a_full_queue_into_429():
    from modules.api import resources_lifecycle

    class _Executor:
        def submit(self, *args, **kwargs):
            raise IssuanceQueueFull(20, 20)

    class _Ctx:
        cert_executor = _Executor()

    body, status = resources_lifecycle._submit(
        _Ctx(), 'create', 'x.example.com', lambda: None)

    assert status == 429
    assert body['code'] == 'ISSUANCE_QUEUE_FULL'
    assert '20' in body['hint']


def test_an_accepted_submission_still_answers_202():
    """CONTROL: the ordinary path is unchanged, and the job id still points at
    the endpoint that reports on it."""
    from modules.api import resources_lifecycle

    class _Executor:
        def submit(self, kind, domain, fn):
            return 'abc123'

    class _Ctx:
        cert_executor = _Executor()

    body, status = resources_lifecycle._submit(
        _Ctx(), 'create', 'x.example.com', lambda: None)

    assert status == 202
    assert body['job_id'] == 'abc123'
    assert body['status_url'] == '/api/certificates/jobs/abc123'


def test_every_async_path_goes_through_the_helper():
    """Create, renew and reissue. A path submitting directly would keep the
    unbounded behaviour and nobody would notice until the queue was deep."""
    import inspect

    from modules.api import resources_lifecycle

    source = inspect.getsource(
        resources_lifecycle.create_lifecycle_resources)

    assert source.count('_submit(ctx,') == 3
    assert 'cert_executor.submit(' not in source


def _eventually(predicate, timeout=5):
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False
