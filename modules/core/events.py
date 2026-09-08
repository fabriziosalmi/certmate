"""
Server-Sent Events (SSE) event bus for CertMate.
Provides real-time updates to connected browser clients.
"""

import json
import logging
import os
import queue
import time
import threading
from contextlib import contextmanager
from typing import Optional, Dict, Any

from .structured_logging import current_correlation_id

logger = logging.getLogger(__name__)


@contextmanager
def _nothing():
    """A do-nothing context, for work published outside any correlated unit —
    a manual publish from a shell, say. Entering LogContext(request_id=None)
    would set the field to null and hide an id an outer context had set."""
    yield


# How many listener invocations run at once. A listener can be slow on
# purpose: DeployManager.on_certificate_event runs deploy hooks, each of which
# may take up to MAX_TIMEOUT (300s), so one worker would serialise a burst of
# renewals behind the slowest target. Four is a working default; the ceiling is
# what matters, not the number.
DEFAULT_DISPATCH_WORKERS = 4

# Log when the backlog passes this, so "the listeners cannot keep up" is a line
# in the log rather than something an operator infers from latency.
BACKLOG_WARN_AT = 50


class EventBus:
    """Simple in-process event bus with SSE streaming support."""

    def __init__(self, workers: Optional[int] = None):
        self._subscribers = []
        self._listeners = []
        self._lock = threading.Lock()

        # Listener dispatch used to be `threading.Thread(...).start()` per
        # listener per event, with no pool, no queue and no ceiling — so the
        # process's thread count was a function of event volume rather than of
        # anything it controlled. A renewal sweep over many domains, each
        # publishing to several listeners, decided how many threads existed.
        #
        # This is a fixed set of daemon workers reading one queue. Three
        # properties are deliberate:
        #
        # * the publisher NEVER blocks. It is a request thread on the issuance
        #   path and the scheduler on the renewal path; making certificate
        #   issuance wait behind a deploy hook would trade a thread problem
        #   for a latency problem on the product's main job.
        # * nothing is dropped. The SSE path drops the oldest message and then
        #   the subscriber, which is right for a browser that fell behind and
        #   wrong for a deploy that has to happen. Certificate events are rare
        #   and each one matters, so the backlog is unbounded in length and
        #   bounded in *cost* — a small dict per queued call.
        # * the backlog is visible. An instance past its capacity says so.
        #
        # Workers stay daemon, as the per-event threads were: a
        # ThreadPoolExecutor's threads are joined at interpreter exit, which
        # would let a 300-second deploy hook hold up shutdown until the
        # container runtime SIGKILLs it anyway.
        self._work = queue.Queue()
        self._workers = []
        self._worker_count = self._resolve_worker_count(workers)
        self._backlog_warned = False

    @staticmethod
    def _resolve_worker_count(workers) -> int:
        if workers is None:
            workers = os.environ.get('CERTMATE_EVENT_WORKERS',
                                     DEFAULT_DISPATCH_WORKERS)
        try:
            return max(1, min(32, int(workers)))
        except (TypeError, ValueError):
            return DEFAULT_DISPATCH_WORKERS

    def _ensure_workers(self) -> None:
        """Start the dispatch workers on first use.

        Lazily, because a bus with no listeners — which is what most of the
        test suite builds — should cost no threads at all.
        """
        if self._workers:
            return
        for index in range(self._worker_count):
            worker = threading.Thread(
                target=self._dispatch_forever,
                name=f'certmate-events-{index}',
                daemon=True,
            )
            worker.start()
            self._workers.append(worker)

    def _dispatch_forever(self) -> None:
        from .structured_logging import LogContext
        while True:
            listener, event, data, correlation_id = self._work.get()
            try:
                # contextvars do NOT cross a thread boundary — a worker starts
                # with an empty context, not a copy of the publisher's — so
                # the id is carried in the queued item and re-entered here.
                # Without this a renewal and the deploy it triggered are two
                # unrelated sets of log lines.
                with LogContext(request_id=correlation_id) if correlation_id \
                        else _nothing():
                    listener(event, data)
            except Exception as e:
                # A listener that raises must not take the worker with it, or
                # the pool bleeds capacity one bad event at a time until
                # nothing is dispatched and nothing says why.
                logger.error(
                    "Event listener failed for %s: %s", event, e, exc_info=True)
            finally:
                self._work.task_done()

    def add_listener(self, callback) -> None:
        """Register a callback invoked on every publish(). Signature: callback(event, data)."""
        with self._lock:
            self._listeners.append(callback)
        self._ensure_workers()

    def pending_dispatches(self) -> int:
        """How many listener invocations are waiting for a worker."""
        return self._work.qsize()

    def subscribe(self) -> queue.Queue:
        """Create a new subscriber queue."""
        q = queue.Queue(maxsize=50)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        """Remove a subscriber queue."""
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def publish(self, event: str, data: Optional[Dict[str, Any]] = None) -> None:
        """
        Publish an event to all subscribers.

        Args:
            event: Event type (e.g. certificate_created, certificate_renewed)
            data: Event payload
        """
        message = {
            'event': event,
            'data': data or {},
            'timestamp': time.time()
        }

        with self._lock:
            dead = []
            for q in self._subscribers:
                try:
                    q.put_nowait(message)
                except queue.Full:
                    # Drop oldest message to make room
                    try:
                        q.get_nowait()
                        q.put_nowait(message)
                    except (queue.Empty, queue.Full):
                        dead.append(q)

            for q in dead:
                try:
                    self._subscribers.remove(q)
                except ValueError:
                    pass

        # Snapshot listeners under lock, then hand them to the worker pool.
        # Never inline: a listener runs deploy hooks, and running one on the
        # publisher's thread would put a 300-second timeout on the issuance
        # request that triggered it.
        with self._lock:
            listeners = list(self._listeners)
        if not listeners:
            return
        self._ensure_workers()

        payload = message.get('data', {})
        correlation_id = current_correlation_id()
        for listener in listeners:
            self._work.put((listener, event, payload, correlation_id))

        backlog = self._work.qsize()
        if backlog >= BACKLOG_WARN_AT and not self._backlog_warned:
            self._backlog_warned = True
            logger.warning(
                "Event listener backlog is %d with %d worker(s): listeners "
                "are not keeping up with events. Deploy hooks and cache "
                "invalidations will lag. Raise CERTMATE_EVENT_WORKERS or find "
                "the slow listener.", backlog, self._worker_count)
        elif backlog == 0:
            self._backlog_warned = False

    def stream(self, q: queue.Queue):
        """
        Generator that yields SSE-formatted events from a subscriber queue.
        Use with Flask's Response(stream_with_context(...)).
        """
        try:
            # Send initial keepalive
            yield f': connected\n\n'

            while True:
                try:
                    msg = q.get(timeout=30)
                    event_type = msg.get('event', 'message')
                    payload = json.dumps(msg.get('data', {}))
                    yield f'event: {event_type}\ndata: {payload}\n\n'
                except queue.Empty:
                    # Send keepalive comment to prevent connection timeout
                    yield f': keepalive\n\n'
        finally:
            self.unsubscribe(q)
