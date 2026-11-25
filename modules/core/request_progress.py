"""Whether the HTTP server still answers requests, told from inside (#1463).

A health check served on its own thread answers however busy the request
threads are, which is the point of it, and also its danger: a server whose
threads are all stuck for good would go on reporting healthy and never be
restarted. This module is the other half. It counts the requests in flight and
remembers when one last finished, so the health report can tell "every thread
busy, and requests still finish" (a slow listing) from "every thread busy, and
nothing has finished for a long time" (stuck).

Counted at the WSGI layer rather than in before/after_request: a streamed
response (the event and log streams) holds its thread until the server closes
the body, long after after_request has run.
"""
import os
import threading
import time

from werkzeug.wsgi import ClosingIterator

DEFAULT_THREADS = 8
# gunicorn's own default in the image; a request may run this long by design.
DEFAULT_REQUEST_TIMEOUT_SECONDS = 300
STALL_MARGIN_SECONDS = 60


def _env_int(name, default, low, high):
    try:
        return max(low, min(high, int(os.environ.get(name, default))))
    except (TypeError, ValueError):
        return default


def configured_threads():
    """The request threads gunicorn runs: GUNICORN_THREADS, as the image's
    command line reads it, 8 when unset."""
    return _env_int('GUNICORN_THREADS', DEFAULT_THREADS, 1, 256)


def configured_stall_seconds():
    """How long every thread may stay busy with nothing finishing before the
    server counts as stuck: CERTMATE_HEALTH_STALL_SECONDS, or a minute past
    GUNICORN_TIMEOUT (360 s in the image).

    Not less than GUNICORN_TIMEOUT, because a request may run that long by
    design: issuance waits for DNS-01 propagation, up to 5 minutes on slow
    providers. Every thread busy with such requests is slow, not stuck, and a
    restart would throw their work away. A cold listing of 2,000 certificates
    takes 45 s (measured), well inside it."""
    request_timeout = _env_int('GUNICORN_TIMEOUT', DEFAULT_REQUEST_TIMEOUT_SECONDS, 1, 86400)
    return _env_int('CERTMATE_HEALTH_STALL_SECONDS', request_timeout + STALL_MARGIN_SECONDS, 10, 86400)


class RequestProgress:
    """Requests in flight, and since when nothing has moved."""

    def __init__(self, threads=None, stall_seconds=None, clock=time.monotonic):
        self.threads = threads if threads is not None else configured_threads()
        self.stall_seconds = stall_seconds if stall_seconds is not None else configured_stall_seconds()
        self._clock = clock
        self._lock = threading.Lock()
        self._in_flight = 0
        # When the last free thread was taken, and when a request last
        # finished; movement is whichever is later.
        self._saturated_since = None
        self._last_finished = None

    def started(self):
        with self._lock:
            self._in_flight += 1
            if self._in_flight >= self.threads and self._saturated_since is None:
                self._saturated_since = self._clock()

    def finished(self):
        with self._lock:
            self._in_flight = max(0, self._in_flight - 1)
            self._last_finished = self._clock()
            if self._in_flight < self.threads:
                self._saturated_since = None

    def state(self):
        with self._lock:
            waited = 0.0
            if self._saturated_since is not None:
                moved = max(self._saturated_since, self._last_finished or self._saturated_since)
                waited = self._clock() - moved
            return {
                'in_flight': self._in_flight,
                'threads': self.threads,
                'stalled': waited > self.stall_seconds,
                'busy_without_progress_s': round(waited, 1),
            }

    def wrap(self, wsgi_app):
        """*wsgi_app*, counted: a request is in flight from the call until its
        body is closed, or until the call raises."""
        def counted(environ, start_response):
            self.started()
            handed_over = False
            try:
                body = wsgi_app(environ, start_response)
                handed_over = True
                return ClosingIterator(body, [self.finished])
            finally:
                if not handed_over:
                    self.finished()
        return counted
