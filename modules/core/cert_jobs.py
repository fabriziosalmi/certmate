"""In-process async certificate issuance for the single-instance MIT build.

Moves the blocking certbot call off the gunicorn request threads onto a small
bounded thread pool, so a burst of concurrent create/renew requests cannot
starve SSE, the dashboard or ``/health``. Jobs are tracked in an in-memory,
bounded registry — acceptable because the MIT deployment is single-process
(scale-out is CertMate-ng's job). A job in flight at restart is lost, but the
per-domain lock plus create/renew idempotency make a re-submit safe.

This is opt-in: the synchronous create/renew path is unchanged. Adapters call
``CertificateService.prepare_*`` inline (cheap, immediate 4xx on bad input)
and submit the blocking ``issue_*`` half here.
"""
import logging
import os
import threading
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor

from .utils import utc_now_iso
from .certificates import DomainOperationInProgress

logger = logging.getLogger(__name__)

_TERMINAL = ('succeeded', 'failed')

# Success event per issuance kind, mirroring the synchronous routes. Renewal
# failures (other than "busy") emit certificate_failed like the sync API renew
# route; create failures emit nothing, also matching the sync create route.
# Reissue (#267) emits certificate_renewed: the domain's certificate was
# refreshed, and consumers (deploy hooks, notifications) must react exactly
# as they do for a renewal.
_SUCCESS_EVENT = {
    'create': 'certificate_created',
    'renew': 'certificate_renewed',
    'reissue': 'certificate_renewed',
}


def _clamp_env_int(name, default, lo, hi):
    try:
        n = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        n = default
    return max(lo, min(hi, n))


class IssuanceExecutor:
    """Bounded thread pool + in-memory job registry for async issuance.

    Pool size: ``CERTMATE_ISSUANCE_WORKERS`` (default 2, clamped 1-16) — kept
    small to bound concurrent certbot processes. History cap:
    ``CERTMATE_ISSUANCE_JOB_HISTORY`` (default 200, clamped 20-2000).
    """

    def __init__(self, app, event_bus=None, max_workers=None, capacity=None):
        self._app = app
        self._event_bus = event_bus
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers or _clamp_env_int('CERTMATE_ISSUANCE_WORKERS', 2, 1, 16),
            thread_name_prefix='cert-issue',
        )
        self._capacity = capacity or _clamp_env_int('CERTMATE_ISSUANCE_JOB_HISTORY', 200, 20, 2000)
        self._jobs = OrderedDict()  # job_id -> record (insertion-ordered for eviction)
        self._lock = threading.Lock()

    def submit(self, kind, domain, fn):
        """Register a job and run *fn* (a zero-arg callable performing the
        blocking issuance) on the pool. Returns the job_id immediately."""
        job_id = uuid.uuid4().hex
        with self._lock:
            self._jobs[job_id] = {
                'job_id': job_id,
                'operation': kind,
                'domain': domain,
                'status': 'queued',
                'submitted_at': utc_now_iso(),
                'started_at': None,
                'finished_at': None,
                'result': None,
                'error': None,
                'error_code': None,
            }
            self._evict_locked()
        self._pool.submit(self._run, job_id, kind, domain, fn)
        return job_id

    def get(self, job_id):
        """Return a copy of the job record, or None if unknown."""
        with self._lock:
            job = self._jobs.get(job_id)
            return dict(job) if job else None

    def _set(self, job_id, **fields):
        with self._lock:
            job = self._jobs.get(job_id)
            if job:
                job.update(fields)

    def _evict_locked(self):
        """Drop the oldest terminal jobs once over capacity; never evict an
        in-flight (queued/running) job. Caller holds the lock."""
        while len(self._jobs) > self._capacity:
            for jid, job in self._jobs.items():
                if job['status'] in _TERMINAL:
                    del self._jobs[jid]
                    break
            else:
                break  # nothing terminal to evict yet

    def _run(self, job_id, kind, domain, fn):
        self._set(job_id, status='running', started_at=utc_now_iso())
        # Background threads have no Flask app/request context; push one so
        # Flask-bound code (settings cache via flask.g, etc.) behaves like the
        # scheduler's _run_manager_job rather than raising "outside app context".
        ctx = self._app.app_context() if self._app is not None else None
        if ctx is not None:
            ctx.push()
        try:
            result = fn()
            sanitized = self._sanitize_result(result)
            # Publish the completion event BEFORE marking the job terminal, so a
            # poller that observes 'succeeded' is guaranteed the event has fired.
            self._publish(_SUCCESS_EVENT.get(kind), {'domain': domain})
            self._set(job_id, status='succeeded', finished_at=utc_now_iso(),
                      result=sanitized)
        except Exception as e:  # record every failure on the job, never crash the worker
            busy = isinstance(e, DomainOperationInProgress)
            logger.error("Async %s job %s failed for %s: %s", kind, job_id, domain, e)
            # Mirror the sync renew route: a real renewal failure emits
            # certificate_failed, but "domain busy" does not (busy != failure).
            if kind in ('renew', 'reissue') and not busy:
                self._publish('certificate_failed', {'domain': domain, 'error': str(e)})
            self._set(job_id, status='failed', finished_at=utc_now_iso(),
                      error=str(e),
                      error_code='DOMAIN_OPERATION_IN_PROGRESS' if busy else None)
        finally:
            if ctx is not None:
                ctx.pop()

    def _publish(self, event, data):
        if event and self._event_bus is not None:
            try:
                self._event_bus.publish(event, data)
            except Exception:
                logger.exception("Async issuance event publish failed for %s", event)

    @staticmethod
    def _sanitize_result(result):
        """The manager returns a small dict of scalars; pass it through but
        drop any private (underscore-prefixed) keys defensively."""
        if isinstance(result, dict):
            return {k: v for k, v in result.items() if not str(k).startswith('_')}
        return None

    def shutdown(self, wait=False):
        self._pool.shutdown(wait=wait)
