"""Two stop handles were published and never called.

`IssuanceExecutor.shutdown()` had no caller anywhere in the tree, and the
slow-request watchdog's `stop_event` was handed to the container and never set.
Both read in review like a safety net — a reader finds a shutdown method and
stops asking what happens on SIGTERM — and neither ran.

What was actually wired was half of it: app.py's KeyboardInterrupt path stopped
the scheduler and drained the event bus, and only for `python app.py`. Under
gunicorn, which is how the image runs, an atexit hook drained the bus and
nothing else. So a container stopped during an async issuance left the pool's
queued jobs unrecorded anywhere: the registry is in memory, it dies with the
process, and the certificate the operator asked for simply never appeared.

`stop_background_work(container)` is now the single ordered shutdown, called
from atexit (both deployment shapes) and from app.py's Ctrl-C path.

Order is the substance of it. Producers stop before consumers — the scheduler
queues renewals, a renewal publishes an event, an event dispatches a deploy
hook — so draining the bus first would drain a queue still being filled. And
nothing waits: certbot subprocesses and deploy hooks are bounded or abandoned,
never joined, because a shutdown that outlives the container runtime's patience
is a SIGKILL with extra steps.
"""
import logging
import threading
import time

import pytest

from modules.core import factory
from modules.core.cert_jobs import IssuanceExecutor

pytestmark = [pytest.mark.unit]

LOGGER = 'modules.core.cert_jobs'


def _executor(**kw):
    return IssuanceExecutor(app=None, event_bus=None, **kw)


def _wait_for(predicate, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return False


# --- the issuance pool says what it abandoned -----------------------------

def test_a_job_still_running_is_named_on_the_way_out(caplog):
    """THE regression. The registry dies with the process, so the log line is
    the only place a half-done issuance can be recorded."""
    executor = _executor(max_workers=1)
    release = threading.Event()
    started = threading.Event()

    def blocking():
        started.set()
        release.wait(timeout=5)

    executor.submit('create', 'slow.example.com', blocking)
    assert started.wait(timeout=5)

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        abandoned = executor.shutdown()
    release.set()

    assert [job['domain'] for job in abandoned] == ['slow.example.com']
    assert abandoned[0]['status'] == 'running'
    assert any('slow.example.com' in record.getMessage()
               for record in caplog.records), (
        'the abandoned job was returned but never logged, so nothing survives '
        'the process that says which certificate was not issued')


def test_a_queued_job_no_worker_reached_is_cancelled_and_named():
    """One worker, two jobs: the second never starts. Before, it sat at
    'queued' in a registry nobody would ever read again."""
    executor = _executor(max_workers=1)
    release = threading.Event()
    started = threading.Event()
    second_ran = threading.Event()

    executor.submit('create', 'first.example.com',
                    lambda: (started.set(), release.wait(timeout=5)))
    assert started.wait(timeout=5)
    executor.submit('create', 'second.example.com', second_ran.set)

    abandoned = executor.shutdown()
    release.set()

    assert {job['domain'] for job in abandoned} == {
        'first.example.com', 'second.example.com'}
    assert not second_ran.wait(timeout=0.5), (
        'the queued job ran after shutdown; cancel_futures is not in effect')


def test_a_finished_job_is_not_reported_as_abandoned():
    """CONTROL. A shutdown that named every job ever submitted would be noise,
    and an operator would learn to ignore the line."""
    executor = _executor(max_workers=1)
    executor.submit('create', 'done.example.com', lambda: None)
    assert _wait_for(lambda: not executor.list_active())

    assert executor.shutdown() == []


def test_a_submission_after_shutdown_does_not_sit_at_queued(caplog):
    """The consequence of calling shutdown for the first time: the pool starts
    refusing work. The job record must not be left at 'queued', because
    /certificates/jobs/<id> would then report work that will never happen."""
    executor = _executor(max_workers=1)
    executor.shutdown()

    with caplog.at_level(logging.WARNING, logger=LOGGER):
        with pytest.raises(RuntimeError):
            executor.submit('create', 'late.example.com', lambda: None)

    late = [job for job in executor._jobs.values()
            if job['domain'] == 'late.example.com']
    assert late and late[0]['status'] == 'failed'
    assert late[0]['error_code'] == 'SHUTTING_DOWN'


# --- the ordered shutdown -------------------------------------------------

class _Recorder:
    """A container shaped like the real one, whose parts record being stopped."""

    def __init__(self, scheduler_raises=False):
        self.calls = []
        self.shutdown_complete = False
        self.scheduler = self._Scheduler(self.calls, scheduler_raises)
        self.stop_event = threading.Event()
        self.request_watchdog = {'thread': None, 'stop_event': self.stop_event}
        self.managers = {
            'cert_executor': self._Executor(self.calls),
            'events': self._Bus(self.calls),
        }

    class _Scheduler:
        def __init__(self, calls, raises):
            self.calls, self.raises = calls, raises
            self.wait = None

        def shutdown(self, wait=True):
            self.calls.append('scheduler')
            self.wait = wait
            if self.raises:
                raise RuntimeError('scheduler is not running')

    class _Executor:
        def __init__(self, calls):
            self.calls = calls

        def shutdown(self):
            self.calls.append('executor')
            return [{'operation': 'create', 'domain': 'x.example.com',
                     'status': 'queued'}]

    class _Bus:
        def __init__(self, calls):
            self.calls = calls

        def stop(self):
            self.calls.append('bus')
            return 3


def test_producers_stop_before_consumers():
    """The scheduler queues renewals, a renewal publishes, a publish dispatches
    a deploy hook. Draining the bus first drains a queue still being filled."""
    container = _Recorder()

    factory.stop_background_work(container)

    assert container.calls == ['scheduler', 'executor', 'bus']


def test_the_scheduler_is_not_waited_for():
    """A renewal sweep runs for minutes. Holding exit open for it only means
    the container runtime kills the process instead."""
    container = _Recorder()

    factory.stop_background_work(container)

    assert container.scheduler.wait is False


def test_the_watchdog_is_told_to_stop():
    """The other handle that had no caller. It is a daemon thread, so this does
    not decide whether the process exits — it decides whether the thread is
    torn down halfway through formatting another thread's stack."""
    container = _Recorder()

    factory.stop_background_work(container)

    assert container.stop_event.is_set()


def test_what_was_lost_is_reported_to_the_caller():
    """app.py prints from this, so it has to carry both losses, not just the
    bus's."""
    container = _Recorder()

    summary = factory.stop_background_work(container)

    assert summary['scheduler'] == 'stopped'
    assert summary['undelivered'] == 3
    assert [job['domain'] for job in summary['issuance']] == ['x.example.com']


def test_a_scheduler_that_never_started_is_not_a_warning():
    """The atexit handler runs for every process that built an app, including
    the many in this suite that never start a scheduler. A WARNING on every
    clean exit is how the real one stops being read."""
    class _NeverStarted(_Recorder):
        def __init__(self):
            super().__init__()
            self.scheduler.running = False

    container = _NeverStarted()

    summary = factory.stop_background_work(container)

    assert summary['scheduler'] == 'not running'
    assert container.calls == ['executor', 'bus'], (
        'a scheduler that is not running was asked to stop anyway')


def test_one_component_refusing_does_not_strand_the_others():
    """Ctrl-C is already on its way out. A scheduler that will not stop must
    not turn into a traceback that skips the bus drain."""
    container = _Recorder(scheduler_raises=True)

    summary = factory.stop_background_work(container)

    assert container.calls == ['scheduler', 'executor', 'bus']
    assert 'not stopped cleanly' in summary['scheduler']


def test_it_runs_once():
    """app.py calls it on Ctrl-C and atexit calls it again on the way out.
    Stopping an already-stopped scheduler logs a warning that reads like a
    fault, and draining an empty bus twice reports nothing twice."""
    container = _Recorder()

    factory.stop_background_work(container)
    factory.stop_background_work(container)

    assert container.calls == ['scheduler', 'executor', 'bus']


def test_a_container_with_nothing_running_is_not_an_error():
    """CONTROL: most of the test suite builds partial containers, and the
    atexit handler runs for them too."""
    class _Bare:
        shutdown_complete = False
        scheduler = None
        managers = None
        request_watchdog = None

    assert factory.stop_background_work(_Bare()) == {
        'scheduler': None, 'issuance': [], 'undelivered': 0}


# --- it is actually wired -------------------------------------------------

def test_atexit_registers_the_whole_shutdown_not_just_the_bus():
    """The property this file exists for: under gunicorn there is no other
    hook, and what was registered there stopped only the event bus."""
    import inspect

    source = inspect.getsource(factory._stop_background_work_at_exit)

    assert 'atexit.register(stop_background_work, container)' in source
    assert '_stop_background_work_at_exit(container)' in inspect.getsource(
        factory.create_app)


def test_the_interactive_entrypoint_uses_the_same_path():
    """Two shutdown sequences that must stay in the same order is how one of
    them drifts. app.py had its own, and it stopped two of the four things."""
    import pathlib

    # From this file, not from factory.__file__: the suite redirects the
    # application's state directories by monkeypatching that attribute.
    repo = pathlib.Path(__file__).resolve().parent.parent
    source = (repo / 'app.py').read_text(encoding='utf-8')

    assert 'stop_background_work(container)' in source
    assert 'container.scheduler.shutdown()' not in source, (
        'app.py still stops the scheduler on its own, so the order lives in '
        'two places')


def test_no_other_caller_reaches_past_it():
    """CONTROL against the handles going unused again: the pool is shut down
    through the executor's own method, and nothing else touches the pool."""
    import inspect

    source = inspect.getsource(IssuanceExecutor)

    assert source.count('self._pool.shutdown') == 1
