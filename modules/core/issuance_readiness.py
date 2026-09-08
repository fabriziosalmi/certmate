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

logger = logging.getLogger(__name__)

# certbot lives in the venv in a source checkout and on PATH in the image.
CERTBOT_CANDIDATES = ('.venv/bin/certbot', 'certbot')
PROBE_TIMEOUT_SECONDS = 30

# States. `ok` and `skipped` are ready; `failed` is not.
OK = 'ok'
FAILED = 'failed'
SKIPPED = 'skipped'
UNKNOWN = 'unknown'

_status = None


def reset():
    """Forget the cached probe result. For tests, and for nothing else."""
    global _status
    _status = None


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


def probe(shell_executor, force=False):
    """Run `certbot --version` once per process and record what happened.

    Returns the status dict. Never raises: every failure mode this can hit is
    a thing to report, not a thing to crash the application over.
    """
    global _status
    if _status is not None and not force:
        return dict(_status)

    from .utils import utc_now_iso
    stamp = utc_now_iso()

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
