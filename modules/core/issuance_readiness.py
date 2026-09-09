"""Is certbot actually able to run? Answered at startup, not at first renewal.

CertMate drives certbot as a subprocess. It is the one dependency without
which nothing the product exists for works — and it was the one dependency
nothing checked. A broken certbot produced an instance that started, reported
`/health` 200 and `/health/ready` 200, scheduled its renewals, and discovered
the problem at the first one: hours later, in a log line, on a certificate
that was by then closer to expiry.

"Broken" here is not hypothetical and not usually "not installed". The failure
this project has actually hit twice is subtler: pip resolves the dependency
set cleanly, the binary is present and executable, and then

    certbot --version

dies on `AttributeError: module 'OpenSSL.crypto' has no attribute 'X509Req'`

because a `cryptography` or `pyOpenSSL` version moved under the pinned ACME
stack. Nothing short of running it detects that — a path check, an `os.access`
or an `importlib.util.find_spec` all say the installation is fine.

So the probe runs the command. Three properties keep that affordable:

* **Once per process.** certbot does not change under a running interpreter,
  so the result is a module-level value. Repeated `create_app()` calls — the
  test suite makes dozens — pay for one subprocess between them.
* **Bounded.** A timeout, and a timeout is a failure: a certbot that cannot
  answer `--version` inside the bound cannot issue a certificate. The bound is
  thirty seconds, which is not generous — it is measured. `certbot --version`
  in the published image imports the whole ACME stack and takes 2-3 seconds
  cold; the first version of this probe used five, and the full test suite
  (many containers on one host) drove it past that and reported a working
  certbot as broken. A startup probe that produces false failures is worse
  than no probe, because the next person to see it red learns to ignore it.
* **Never fatal.** A failed probe records `failed` and lets the app start.
  Refusing to boot would take away the UI an operator needs to diagnose it,
  and would take a working instance offline over a probe that might itself be
  wrong. `/health/ready` returning 503 is the loud part: an orchestrator flips
  the pod out of rotation, for the same reason a dead scheduler does.

A `MockShellExecutor` reports `produces_artifacts = False` — it answers from a
canned script rather than running anything, so its answer about certbot means
nothing. That case records `skipped`, which readiness treats as ready: a
probe that did not run must not be reported as a probe that failed.
"""
import logging
import os
import threading
import time

logger = logging.getLogger(__name__)

# certbot lives in the venv in a source checkout and on PATH in the image.
CERTBOT_CANDIDATES = ('.venv/bin/certbot', 'certbot')
PROBE_TIMEOUT_SECONDS = 30

# How long an answer about certbot stays good for. The probe used to run once
# per process and the answer was then frozen for the life of that process,
# which is wrong in both directions: a transient failure at boot — a filesystem
# still settling, a fork refused under memory pressure — made the instance
# permanently unready, and under an orchestrator that means a restart loop
# rolling the same dice; and a certbot that broke AFTER boot (a volume
# remounted, a dependency changed inside the container) never turned readiness
# red, so the endpoint an orchestrator uses to decide rotation went on saying
# yes while nothing could be issued.
#
# The TTL is what keeps a re-probe cheap: readiness is scraped every few
# seconds, and running certbot that often would be its own problem. Clamped so
# a typo cannot mean "never re-probe" or "probe on every scrape".
DEFAULT_PROBE_TTL_SECONDS = 300
_PROBE_TTL_MIN, _PROBE_TTL_MAX = 30, 3600

# States. `ok` and `skipped` are ready; `failed` is not.
OK = 'ok'
FAILED = 'failed'
SKIPPED = 'skipped'
UNKNOWN = 'unknown'

_status = None
_probed_at = 0.0
_probe_lock = threading.Lock()


def probe_ttl_seconds() -> float:
    """Seconds before a recorded answer is re-checked. CERTMATE_CERTBOT_PROBE_TTL."""
    try:
        return max(_PROBE_TTL_MIN, min(_PROBE_TTL_MAX, float(os.environ.get(
            'CERTMATE_CERTBOT_PROBE_TTL', DEFAULT_PROBE_TTL_SECONDS))))
    except (TypeError, ValueError):
        return float(DEFAULT_PROBE_TTL_SECONDS)


def reset():
    """Forget the cached probe result. For tests, and for nothing else."""
    global _status, _probed_at
    _status = None
    _probed_at = 0.0


def get_status():
    """The recorded probe result, or an `unknown` placeholder before it runs."""
    if _status is None:
        return {'state': UNKNOWN, 'version': None, 'error': None,
                'timestamp': None}
    return dict(_status)


def is_ready(status=None):
    """Whether issuance readiness should hold a probe out of rotation.

    Only a probe that ran and failed says no. `unknown` (not yet probed) and
    `skipped` (nothing real was run) are both "no evidence of a problem", and
    reporting no-evidence as a failure would flip every test app and every
    startup window out of rotation.
    """
    return (status or get_status()).get('state') != FAILED


def _read_version(result):
    """certbot prints its version to stdout on current releases and to stderr
    on older ones; take whichever carries text."""
    out = ''
    for stream in (getattr(result, 'stdout', ''), getattr(result, 'stderr', '')):
        if isinstance(stream, str):
            out += stream
    return out.strip()


def _run_once(shell_executor, path):
    """Try one candidate. Returns (version, error); exactly one is truthy."""
    try:
        result = shell_executor.run([path, '--version'],
                                    timeout=PROBE_TIMEOUT_SECONDS)
    except Exception as error:                     # FileNotFoundError, timeout
        return None, f'{path}: {error}'

    text = _read_version(result)
    code = getattr(result, 'returncode', 0)
    if code:
        # The failure that matters most lands here: certbot is installed,
        # starts, and dies importing its own ACME stack. Keep the tail of the
        # output — the exception type and message are in it, and an operator
        # reading /health should not have to go and reproduce it.
        return None, f'{path}: exited {code}: {text[-400:] or "no output"}'
    if not text:
        return None, f'{path}: exited 0 but printed no version'
    return text, None


def is_fresh() -> bool:
    """Is there a recorded answer that has not aged past the TTL?"""
    return _status is not None and (time.monotonic() - _probed_at) < probe_ttl_seconds()


def probe(shell_executor, force=False):
    """Answer whether certbot can run, re-checking when the answer has aged.

    Returns the status dict. Never raises: every failure mode this can hit is
    a thing to report, not a thing to crash the application over.

    Called from startup and from the readiness endpoint. The TTL is what makes
    the second one safe: an orchestrator scraping every few seconds runs certbot
    at most once per TTL, and the rest of the time reads the recorded answer.
    """
    if is_fresh() and not force:
        return dict(_status)

    with _probe_lock:
        # Re-checked under the lock: two threads arriving together on an
        # expired answer should run certbot once between them, not twice.
        if is_fresh() and not force:
            return dict(_status)
        return _probe_locked(shell_executor)


def _probe_locked(shell_executor):
    global _status, _probed_at
    from .utils import utc_now_iso
    stamp = utc_now_iso()
    _probed_at = time.monotonic()

    if shell_executor is None or not getattr(shell_executor,
                                             'produces_artifacts', True):
        _status = {'state': SKIPPED, 'version': None, 'timestamp': stamp,
                   'error': 'no executing shell was available to probe with'}
        return dict(_status)

    errors = []
    for path in CERTBOT_CANDIDATES:
        version, error = _run_once(shell_executor, path)
        if version:
            logger.info("certbot is available: %s (via %s)", version, path)
            _status = {'state': OK, 'version': version, 'error': None,
                       'timestamp': stamp}
            return dict(_status)
        errors.append(error)

    detail = '; '.join(e for e in errors if e)
    logger.critical(
        "certbot cannot run, so this instance cannot issue or renew any "
        "certificate: %s. /health/ready will report 503 until this is fixed.",
        detail)
    _status = {'state': FAILED, 'version': None, 'error': detail,
               'timestamp': stamp}
    return dict(_status)
