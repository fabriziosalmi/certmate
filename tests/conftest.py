"""
Shared fixtures for CertMate test suite.

Manages a Docker container lifecycle and provides an HTTP client
pre-configured to talk to the running CertMate instance.

Environment variables:
    CERTMATE_TEST_PORT      Port to expose (default: 18888)
    CERTMATE_IMAGE          Docker image name (default: certmate:test)
    CLOUDFLARE_API_TOKEN    Cloudflare API token for DNS-01 challenges
    CERTMATE_TEST_DOMAIN    Domain for real cert tests (default: test.gpfree.org)
    CERTMATE_TEST_EMAIL     ACME email (default: test@gpfree.org)
    CERTMATE_SKIP_BUILD     Set to "1" to skip docker build
"""

import os
import sys
import secrets
import time
import subprocess
import pytest
import requests

# ---------------------------------------------------------------------------
# Test isolation
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _no_inherited_proxy():
    """No test inherits the developer's outbound proxy.

    The TLS probes honour `HTTPS_PROXY`/`NO_PROXY` through `urllib`, and
    `urllib.request.getproxies()` is `getproxies_environment() or
    getproxies_macosx_sysconf()`: on a Mac with a system proxy configured, an
    EMPTY environment makes urllib fall through to System Settings, and a
    probe test that expects a direct connection quietly takes the tunnel.

    Clearing the variables is therefore not enough. Setting `no_proxy` is,
    and for a reason worth writing down: `getproxies_environment()` collects
    every variable whose name ends in `_proxy`, `no_proxy` included, so the
    dict is non-empty and the macOS fallback is never reached — while
    `proxies.get('https')` is still None. One variable, deterministic on
    every platform.

    A test that wants a proxy removes `no_proxy` and sets `https_proxy`
    itself; `proxy_bypass` reads the same environment, so leaving `no_proxy`
    in place would bypass the proxy it just configured.
    """
    saved = {name: value for name, value in os.environ.items()
             if name.lower().endswith('_proxy')}
    for name in saved:
        del os.environ[name]
    os.environ['no_proxy'] = '*'
    yield
    os.environ.pop('no_proxy', None)
    os.environ.update(saved)


@pytest.fixture(scope="session", autouse=True)
def _isolate_runtime_dirs(tmp_path_factory):
    """Keep `create_app()` out of the checkout's real runtime directories.

    `setup_directories` resolves cert/data/backup/log paths from
    `modules.factory.__file__` — two levels up — and honours no
    override. So any in-process `create_app()` reads and writes the working
    tree's own `data/`, `certificates/`, `backups/` and `logs/`, whatever
    tmp_path the test set up. Thirteen test files do that, and a suite run was
    measurably changing three of those four directories (#702).

    Two consequences, and the second is the dangerous one: running the tests
    mutates the developer's instance, and a test can pass on state an earlier
    run left behind. An assertion that passes for that reason looks exactly
    like one that passes because the code is right.

    Anchoring `__file__` at a temporary tree is the pattern this repo already
    uses in test_csp_img_src_airgap.py and test_advertised_endpoints_exist.py;
    doing it here applies it everywhere without touching production paths, and
    the container image and systemd unit keep resolving exactly as before.

    `templates/` and `static/` are linked back to the real ones, because the
    same `__file__` also locates them (factory.py:1305) — an anchor without
    them would break every test that renders a page, silently at first, since
    a missing template directory is only a warning at startup.
    """
    # Applied to every test, including the container-backed ones: those talk to
    # CertMate over HTTP and never build an app in this process, so the anchor
    # is inert for them. An earlier version skipped `slow` tests on the
    # assumption they were all container-backed. They are not — several run
    # in-process, and they were the ones still writing to the checkout.
    root = tmp_path_factory.mktemp("runtime")
    # `modules/factory.py`, mirroring where the composition root actually
    # lives. It was `modules/core/factory.py` until #668 moved it one level
    # up, and the anchor has to move with it: the resolution is two levels
    # up from this file, so a stale `modules/core/` here put every state
    # directory one level too deep — inside a fake `modules/`, not beside it.
    module_dir = root / "modules"
    module_dir.mkdir(parents=True)
    anchor = module_dir / "factory.py"
    anchor.write_text("# test path anchor\n", encoding="utf-8")
    for shared in ("templates", "static"):
        source = os.path.join(PROJECT_ROOT, shared)
        if os.path.isdir(source):
            os.symlink(source, root / shared)

    # Session-scoped, and that is the whole point. As a function-scoped
    # fixture this lost a race: a fixture defined in a test module runs BEFORE
    # a function-scoped autouse fixture from conftest, so the app was already
    # built against the real tree by the time the anchor was applied. Measured,
    # not assumed — the two fixtures were made to print their order.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("modules.factory.__file__", str(anchor),
                      raising=False)
        # The four directories are now relocatable with CERTMATE_*_DIR, which
        # takes precedence over the anchor above. Unset them for the whole
        # session so a developer who has them exported — pointing at their own
        # running instance — cannot have the suite write there, and so the
        # per-test anchors in the twenty-odd files that set their own keep
        # deciding.
        for _var in ('CERTMATE_CERT_DIR', 'CERTMATE_DATA_DIR',
                     'CERTMATE_BACKUP_DIR', 'CERTMATE_LOGS_DIR'):
            patch.delenv(_var, raising=False)
        yield


@pytest.fixture(scope="session", autouse=True)
def _caa_never_asks_real_dns():
    """The suite never sends a CAA query to the real DNS.

    A failed issuance asks what the CAA records say (modules/core/caa.py), and
    dozens of tests fail certbot on purpose — with a MagicMock executor, which
    answers True to `produces_artifacts` like any other attribute, so nothing
    upstream can tell a scripted failure from a real one. Left alone, each of
    those tests would resolve `example.com` and its parents against whatever
    resolver the machine has: slower, dependent on the network, and answering
    a question about a CA that was never contacted.

    Replaced with a resolver that finds no records, so the answer is "no CAA
    policy" and no explanation is added. Tests about CAA pass their own
    `resolve` and are unaffected.
    """
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr("modules.core.caa.resolver_factory",
                      lambda timeout, nameservers=None: (lambda name: []))
        yield


# The applications built in this process and not yet stopped.
_APPLICATIONS = []


@pytest.fixture(scope="session", autouse=True)
def _applications_are_remembered(_isolate_runtime_dirs):
    """Every `create_app()` in the suite is written down, so it can be stopped.

    `create_app()` starts a scheduler, an issuance pool, four event threads and
    a watchdog, and leaves stopping them to `atexit`: right for a server, which
    has one application and exits when it is done. A test process builds some
    ninety, and nothing stopped any of them before the last test. Their
    schedulers went on running: each fires `deploy_window_drain` at every
    minute, and the daily sweeps at 02:00 to 07:00, in the middle of whatever
    test is running by then.
    """
    import functools

    import modules.factory as factory
    register_at_exit = factory._stop_background_work_at_exit

    # `wraps`, so that a test which reads the source of the hook reads the
    # application's and not this.
    @functools.wraps(register_at_exit)
    def remember(container):
        _APPLICATIONS.append(container)
        register_at_exit(container)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(factory, '_stop_background_work_at_exit', remember)
        yield


@pytest.fixture(scope="module", autouse=True)
def _an_application_stops_with_its_module(_applications_are_remembered):
    """An application lives no longer than the module that built it.

    Whatever fixture built it, of whatever scope: by the time the next module
    runs, its scheduler, its pool and its threads are stopped, the way the
    application stops itself (`stop_background_work`). A module that needs an
    application gets one from its own fixture, as all of them do.

    Measured before this: 22 schedulers running after the first 76 modules.
    Idle they allocate nothing, and at the minute they allocated 666 KB between
    them, which a test that measures the memory of something else (the audit
    chain's verifier, 25 KB on its own) read as its own and failed on.
    """
    yield
    from modules.factory import stop_background_work
    failed = []
    while _APPLICATIONS:
        container = _APPLICATIONS.pop()
        try:
            stop_background_work(container)
        except Exception as error:                      # every one is tried, then all are reported
            failed.append(repr(error))
    assert failed == [], f'an application built in this module did not stop: {failed}'


# certbot invocations that only read the local installation.
_CERTBOT_LOCAL_ONLY = {'--version', '--help', '-h', 'plugins'}
_REAL_CERTBOT = {'allowed': False, 'refused': [], 'session_over': False}


class _NoRealCertbot:
    """`subprocess` as `modules/core/shell.py` sees it, minus the real certbot.

    Every test that issues or renews replaces `ShellExecutor.run` with a
    stand-in, so a certbot that reaches this point is one that escaped its
    stand-in. That happened: a reissue queued by a test ran on a worker thread
    after the test's fixture had closed the stand-in, and the real certbot
    registered an account with Let's Encrypt staging. Nothing failed, and the
    log line was the only trace. Here it is refused, and recorded so the run
    fails even when the call happened on a thread no test was waiting for.

    It sits below the stand-ins (which replace `ShellExecutor.run` whole and
    never reach `subprocess`), so it cannot get in their way, and for the whole
    process, because a thread can outlive the test that started it and the
    session too. Tests
    marked `e2e` are the ones meant to reach a CA, and the guard stands aside
    for them.
    """

    def __init__(self, real):
        self._real = real

    def __getattr__(self, name):
        return getattr(self._real, name)

    def run(self, cmd, *args, **kwargs):
        program = os.path.basename(str(cmd[0])) if cmd else ''
        if (program == 'certbot' and not _REAL_CERTBOT['allowed']
                and not set(map(str, cmd[1:])) <= _CERTBOT_LOCAL_ONLY):
            _REAL_CERTBOT['refused'].append(' '.join(map(str, cmd[:2])))
            if _REAL_CERTBOT['session_over']:
                # Too late to fail the run: say it where a person reading the log will see it.
                print(f'\nThe real certbot was refused after the last test ({" ".join(map(str, cmd[:2]))}): '
                      'a test left a job running.', file=sys.__stderr__, flush=True)
            raise RuntimeError(
                'the test suite refused to run the real certbot '
                f'({" ".join(map(str, cmd[:2]))}): use a stand-in, or mark the test e2e')
        return self._real.run(cmd, *args, **kwargs)


def pytest_sessionstart(session):
    """Put the guard in for the life of the process, not of the session.

    It was a session fixture, and a session fixture is taken out when the last
    test ends. A job a test has queued can still be on a worker thread then,
    while the interpreter closes: it found the real `subprocess` back in place
    and ran the real certbot, with nothing left to refuse it or to report it.
    """
    import modules.core.shell as shell
    if not isinstance(shell.subprocess, _NoRealCertbot):
        shell.subprocess = _NoRealCertbot(shell.subprocess)


@pytest.fixture(autouse=True)
def _real_certbot_for_e2e(request):
    _REAL_CERTBOT['allowed'] = request.node.get_closest_marker('e2e') is not None
    yield
    _REAL_CERTBOT['allowed'] = False


def pytest_sessionfinish(session, exitstatus):
    _REAL_CERTBOT['session_over'] = True
    if _REAL_CERTBOT['refused']:
        print('\nThe real certbot was refused outside an e2e test '
              f'{len(_REAL_CERTBOT["refused"])} time(s): {_REAL_CERTBOT["refused"][:5]}')
        session.exitstatus = 1


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TEST_PORT = int(os.environ.get("CERTMATE_TEST_PORT", "18888"))
IMAGE_NAME = os.environ.get("CERTMATE_IMAGE", "certmate:test")
CONTAINER_NAME = "certmate-test-suite"
BASE_URL = f"http://localhost:{TEST_PORT}"

# The shared test container runs with an operator bearer token, like any
# instance past its first minutes. It used to run in setup mode, where every
# request is served as admin; setup mode now refuses deploy hooks, backups and
# private-key downloads to that anonymous admin, and the tests that exercise
# those surfaces (the release gate's real-certificate ones among them) need a
# credential. Tests about setup mode itself build an in-process instance of
# their own. For an external instance (CERTMATE_E2E_BASE_URL), pass its token
# in CERTMATE_E2E_API_TOKEN.
E2E_API_TOKEN = (os.environ.get("CERTMATE_E2E_API_TOKEN")
                 or (None if os.environ.get("CERTMATE_E2E_BASE_URL")
                     else secrets.token_urlsafe(32)))
if E2E_API_TOKEN:
    # The SDK and the CLI read it from here.
    os.environ.setdefault("CERTMATE_TOKEN", E2E_API_TOKEN)


def e2e_auth_headers():
    """The Authorization header the shared test instance expects, if any."""
    return {"Authorization": f"Bearer {E2E_API_TOKEN}"} if E2E_API_TOKEN else {}


def _only_browser_tests(session):
    """True when every selected test is a UI test.

    The browser suite starts the way a person does: a fresh instance with no
    token, the first admin created on the setup page, a login. It also
    exercises what that bootstrap state implies (turning login off would
    reopen setup mode), which a token would change. The API suite
    authenticates like an integration, with a token. They run as separate
    invocations in CI and in release.sh; when mixed, the token wins.
    """
    items = getattr(session, "items", None) or []
    return bool(items) and all(item.get_closest_marker("ui") for item in items)
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

TEST_DOMAIN = os.environ.get("CERTMATE_TEST_DOMAIN", "test.gpfree.org")
TEST_EMAIL = os.environ.get("CERTMATE_TEST_EMAIL", "test@gpfree.org")


def _docker(*args, check=True, capture=True):
    """Run a docker command.

    The timeout must absorb a cold-cache image build while the
    multiplatform release workflows hammer the same self-hosted docker
    daemon — the v2.12.0 main-branch CI run failed exactly that way
    (the test-image build timed out at 300s next to two concurrent
    buildx runs for main and the release tag).
    """
    cmd = ["docker", *args]
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        timeout=int(os.environ.get("CERTMATE_TEST_DOCKER_TIMEOUT", "900")),
    )


def _wait_healthy(timeout=60, base_url=BASE_URL):
    """Wait until the container health endpoint responds 200."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=10)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(1)
    raise TimeoutError(f"Container not healthy after {timeout}s")


def _disable_rate_limiting(base_url=BASE_URL):
    """Turn off API rate limiting for the whole test session.

    All non-specific /api/* paths share one per-IP 'default' bucket (100 req /
    60s). A full browser suite drives many pages that each fan out several API
    calls from one IP, so the shared bucket trips a 429 mid-suite — a pure test
    volume artifact, unrelated to what the functional tests verify (test_ui.py
    already filters 429 out of its JS-error checks). Content-rendering tests
    need the API to actually respond, so disable the limiter once, here, while
    the bucket is still empty (a later POST could itself be throttled). The
    fresh container is in setup-mode auth bypass, so this settings write is
    accepted. Best-effort: a failure just restores the old flaky-under-load
    behaviour, never blocks the run.
    """
    try:
        resp = requests.post(
            f"{base_url}/api/settings",
            json={"rate_limits": {"enabled": False}},
            headers=e2e_auth_headers(),
            timeout=10,
        )
        if resp.status_code != 200:
            print(f"[tests] Could not disable rate limiting (HTTP {resp.status_code}); "
                  "browser suite may see transient 429s under load.")
    except requests.RequestException as e:
        print(f"[tests] Could not disable rate limiting ({e}); "
              "browser suite may see transient 429s under load.")


# ---------------------------------------------------------------------------
# Session-scoped: one Docker container for the entire test run
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def docker_container(request):
    """Yield the base URL of a running CertMate instance.

    Default: build the image, start a container, tear it down at session
    end. With CERTMATE_E2E_BASE_URL set, target an already-running
    instance instead (no Docker required — e.g. a sandbox that cannot
    pull base images, or a developer's `python app.py` session) and skip
    all container lifecycle management.
    """
    external = os.environ.get("CERTMATE_E2E_BASE_URL")
    if external:
        external = external.rstrip("/")
        _wait_healthy(base_url=external)
        print(f"\n[tests] Using externally managed instance at {external}")
        yield external
        return

    # Build (unless told to skip)
    if os.environ.get("CERTMATE_SKIP_BUILD") != "1":
        print(f"\n[tests] Building Docker image {IMAGE_NAME} ...")
        _docker("build", "-t", IMAGE_NAME, PROJECT_ROOT)

    # Remove any stale container
    _docker("rm", "-f", CONTAINER_NAME, check=False)

    global E2E_API_TOKEN
    if _only_browser_tests(request.session):
        E2E_API_TOKEN = None
        os.environ.pop("CERTMATE_TOKEN", None)
    token_env = ["-e", f"API_BEARER_TOKEN={E2E_API_TOKEN}"] if E2E_API_TOKEN else []

    # Start container
    print(f"[tests] Starting container {CONTAINER_NAME} on port {TEST_PORT} ...")
    _docker(
        "run", "-d",
        "--name", CONTAINER_NAME,
        "-p", f"{TEST_PORT}:8000",
        *token_env,
        IMAGE_NAME,
    )

    try:
        _wait_healthy()
        print("[tests] Container is healthy.")
        _disable_rate_limiting()
        yield BASE_URL
    finally:
        # Dump logs for debugging on failure
        logs = _docker("logs", "--tail", "50", CONTAINER_NAME, check=False)
        if logs.stdout:
            print("\n--- Container logs (last 50 lines) ---")
            print(logs.stdout[-2000:])
        _docker("rm", "-f", CONTAINER_NAME, check=False)
        print("[tests] Container removed.")


@pytest.fixture(scope="session")
def api(docker_container):
    """Return a requests.Session pre-configured with the base URL."""
    base = docker_container

    class APIClient:
        """Thin wrapper around requests for CertMate API calls."""

        def __init__(self, base_url):
            self.base_url = base_url
            self.session = requests.Session()
            # gunicorn closes idle keep-alive connections after ~2s; a pooled
            # connection can therefore be stale on the next call (e.g. a job
            # poll loop that sleeps ~2s between requests), surfacing as a
            # RemoteDisconnected ConnectionError on connection reuse. Retry
            # idempotent requests transparently so the suite isn't flaky on
            # this HTTP keep-alive race (it is not a server fault).
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            _retry = Retry(total=5, connect=5, read=5, backoff_factor=0.3)
            _adapter = HTTPAdapter(max_retries=_retry)
            self.session.mount("http://", _adapter)
            self.session.mount("https://", _adapter)
            self.session.headers["Content-Type"] = "application/json"
            # The CSRF middleware (v2.3.8+) requires Origin/Referer on
            # cookie-authenticated state-changing requests. Real browsers
            # always send Origin on POSTs; the requests library does not.
            # Setting it here makes our test client behave like a same-origin
            # browser without each test needing to remember the header.
            self.session.headers["Origin"] = base_url
            self.session.headers.update(e2e_auth_headers())

        # --- HTTP verbs ---------------------------------------------------
        def get(self, path, **kw):
            if 'timeout' not in kw:
                kw['timeout'] = 10
            return self.session.get(f"{self.base_url}{path}", **kw)

        def post(self, path, **kw):
            return self.session.post(f"{self.base_url}{path}", **kw)

        def put(self, path, **kw):
            return self.session.put(f"{self.base_url}{path}", **kw)

        def delete(self, path, **kw):
            return self.session.delete(f"{self.base_url}{path}", **kw)

        # --- Helpers ------------------------------------------------------
        def get_json(self, path, **kw):
            r = self.get(path, **kw)
            r.raise_for_status()
            return r.json()

        def post_json(self, path, data, **kw):
            r = self.post(path, json=data, **kw)
            return r

        def put_json(self, path, data, **kw):
            r = self.put(path, json=data, **kw)
            return r

    return APIClient(base)


@pytest.fixture(scope="session")
def cloudflare_token():
    """Return the Cloudflare API token, or skip — loudly, and countably.

    Ten test files hang off this fixture. When the token is absent they all
    skip, and a skip in a green run is indistinguishable from a pass: the
    class had been reporting as "skipped" rather than as "never executed",
    which is how a test can rot for years while the board stays green.

    Two things change that. `CERTMATE_REQUIRE_CREDENTIALED=1` turns the skip
    into a failure, so a job that exists to run these cannot silently run
    none of them — the same mechanism `CERTMATE_UI_REQUIRE_BROWSER` already
    provides for the Playwright suite. And the skip reason carries a marker
    the terminal summary counts, so every ordinary run ends with a line
    saying how many tests were not executed and why.
    """
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        _credential_missing("CLOUDFLARE_API_TOKEN", "real DNS-01 tests")
    return token


# Marks a skip caused by an absent third-party credential, so
# pytest_terminal_summary can count them. Matched as a substring of the skip
# reason: pytest does not carry structured metadata on a skip.
CREDENTIAL_SKIP_MARK = "[no-credential]"
_REQUIRE_CREDENTIALED = os.environ.get("CERTMATE_REQUIRE_CREDENTIALED") == "1"


def _credential_missing(variable, what):
    """Fail when the credential is mandatory, skip countably when it is not."""
    if _REQUIRE_CREDENTIALED:
        pytest.fail(
            f"{variable} is not set, so {what} cannot run. "
            f"CERTMATE_REQUIRE_CREDENTIALED=1 means this must not be skipped."
        )
    pytest.skip(f"{CREDENTIAL_SKIP_MARK} {variable} not set — {what} not run")


CREDENTIALED_FIXTURES = frozenset({"cloudflare_token"})

# The same shape, for a TOOL rather than a credential. The frontend unit tests
# execute static/js through node, and a machine without node must not report
# them as passing. CI sets CERTMATE_REQUIRE_NODE=1, so the one job that exists
# to run them cannot run none.
TOOL_SKIP_MARK = "[no-tool]"
_REQUIRE_NODE = os.environ.get("CERTMATE_REQUIRE_NODE") == "1"


@pytest.fixture(scope="session")
def node():
    """Path to a node binary, or a countable skip."""
    import shutil

    found = shutil.which("node")
    if found:
        return found
    if _REQUIRE_NODE:
        pytest.fail(
            "node is not on PATH, so the frontend unit tests cannot run. "
            "CERTMATE_REQUIRE_NODE=1 means this must not be skipped."
        )
    pytest.skip(f"{TOOL_SKIP_MARK} node not on PATH — frontend unit tests not run")




def pytest_collection_modifyitems(config, items):
    """Mark every test that needs a third-party credential, by derivation.

    `-m credentialed` then selects exactly this class. Derived from the
    fixtures a test requests rather than written on each file: a marker
    maintained by hand drifts the first time someone adds the fixture and
    forgets the decorator, and the fixture is what actually gates the test.
    """
    for item in items:
        if CREDENTIALED_FIXTURES & set(getattr(item, "fixturenames", ())):
            item.add_marker(pytest.mark.credentialed)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """End every run by saying what it did not measure.

    pytest's own tail says "N skipped" without saying what N was, and a
    number with no subject reads as housekeeping. This names the class,
    counts it, and says how to run it — so the difference between "the suite
    passed" and "the suite passed the parts it could reach" is on the screen
    of whoever reads the run.
    """
    skipped = terminalreporter.stats.get("skipped", [])

    # Tools, same argument as credentials: a test that could not run is not a
    # test that passed, and the run has to say which.
    toolless = [r for r in skipped
                if TOOL_SKIP_MARK in str(getattr(r, "longrepr", ""))]
    if toolless:
        terminalreporter.write_sep("=", "not executed: missing tools",
                                   yellow=True, bold=True)
        terminalreporter.write_line(
            f"{len(toolless)} test(s) did not run because a required tool is "
            f"not installed. They are not passing; they are unmeasured. "
            f"CERTMATE_REQUIRE_NODE=1 makes their absence a failure."
        )

    missing = [r for r in skipped
               if CREDENTIAL_SKIP_MARK in str(getattr(r, "longrepr", ""))]
    if not missing:
        return

    variables = sorted({
        word for report in missing
        for word in str(report.longrepr).split()
        if word.isupper() and "_" in word
    })
    terminalreporter.write_sep("=", "not executed: missing credentials",
                               yellow=True, bold=True)
    terminalreporter.write_line(
        f"{len(missing)} test(s) did not run because "
        f"{', '.join(variables) or 'a credential'} is unset. They are not "
        f"passing; they are unmeasured."
    )
    terminalreporter.write_line(
        "Set the credential to run them, or CERTMATE_REQUIRE_CREDENTIALED=1 "
        "to make their absence a failure (used by the real-certificate gate)."
    )


# ---------------------------------------------------------------------------
# Playwright / UI
# ---------------------------------------------------------------------------
# Shared by every UI module. Keeping the fixture here rather than importing it
# from test_ui.py matters: an imported fixture is shadowed by the test's own
# parameter of the same name, which flake8 reports as F811 — correctly, since
# the import is genuinely unused at that point.

_REQUIRE_BROWSER = os.environ.get("CERTMATE_UI_REQUIRE_BROWSER") == "1"


def _no_browser(reason):
    """Fail when a browser is mandatory, skip when it is merely unavailable."""
    if _REQUIRE_BROWSER:
        pytest.fail(
            f"{reason} — CERTMATE_UI_REQUIRE_BROWSER=1 means this must not be "
            "skipped (install with `playwright install --with-deps chromium`)"
        )
    pytest.skip(reason)


def reopen_shared_container(api):
    """Put the session-wide container back the way the other modules expect
    it: local auth off (#986).

    A module that turns local auth on for its own tests must turn it off
    again, and must check that it did. Since #587 the server refuses to drop
    the last way in without `confirm_unauthenticated`, answering 409; the
    teardowns that posted `{"local_auth_enabled": false}` alone were refused
    in silence, and every module after them saw a different instance
    depending on file order.
    """
    import requests

    r = api.post_json("/api/auth/config", {
        "local_auth_enabled": False, "confirm_unauthenticated": True})
    assert r.status_code == 200, (
        f"could not restore the shared container: {r.status_code} {r.text[:200]}")
    state = requests.get(f"{api.base_url}/api/auth/config",
                         headers=e2e_auth_headers(), timeout=10)
    assert state.status_code == 200 and state.json().get("local_auth_enabled") is False, (
        f"local auth is still on after the teardown ({state.status_code}): "
        f"the modules after this one would see another instance")


@pytest.fixture(scope="session")
def ui_session_cookie(docker_container):
    """Log the UI suite in ONCE, for every module.

    This used to run per module, and that coupled the suite to the login rate
    limit: `modules/web/routes` allows 5 attempts per IP per 60 seconds, the
    whole UI suite runs in about two minutes, and every test module logged in
    again. The sixth UI test module therefore made the sixth login inside that
    window, which was refused — so the fixture got no cookie, every page
    redirected to /login, and the LAST module in alphabetical order failed with
    "the panel is empty" while the change that broke it was the addition of an
    unrelated test file.

    Session-scoped, so the number of UI modules no longer has anything to do
    with it. And a login that fails now fails the run loudly rather than
    yielding a cookie-less page: a browser suite silently testing the login
    screen is worse than a red fixture.
    """
    import requests

    # Setup mode: no auth required for these two.
    requests.post(f"{BASE_URL}/api/web/settings/users", json={
        "username": "admin", "password": "Password123!", "role": "admin"
    }, headers=e2e_auth_headers())
    requests.post(f"{BASE_URL}/api/auth/config", json={
        "local_auth_enabled": True
    }, headers=e2e_auth_headers())

    login_r = requests.post(f"{BASE_URL}/api/auth/login", json={
        "username": "admin", "password": "Password123!"
    })
    session_cookie = login_r.cookies.get("certmate_session")
    if not session_cookie:
        pytest.fail(
            f"UI suite could not log in (HTTP {login_r.status_code}): "
            f"{login_r.text[:200]}. Without a session every page redirects to "
            f"/login and the tests would silently exercise the login screen."
        )

    # The first-run wizard covers the page and takes every click. It is
    # dismissed here once, the way its own Skip button does it for every
    # browser, and the instance stays what it is: one whose setup is not
    # finished.
    #
    # This used to post the whole settings back with `setup_completed` set, and
    # the answer was never read. It was a 403 (a session request with no Origin
    # is refused), and with an Origin it would have been a 400 (the settings it
    # had just read carry `users` and `oidc`, which this route does not take).
    # So the wizard was on every page, and fourteen modules each hid it for
    # themselves; the one that did not raced it.
    s = requests.Session()
    s.cookies.set("certmate_session", session_cookie)
    dismissed = s.post(f"{BASE_URL}/api/web/settings", json={"wizard_dismissed": True},
                       headers={"Origin": BASE_URL})
    seen = s.get(f"{BASE_URL}/api/web/settings")
    if dismissed.status_code != 200 or seen.json().get("wizard_dismissed") is not True:
        pytest.fail(
            f"UI suite could not dismiss the first-run wizard (HTTP {dismissed.status_code}: "
            f"{dismissed.text[:200]}). It covers every page and takes the clicks."
        )
    return session_cookie


@pytest.fixture(scope="module")
def browser_page(docker_container, ui_session_cookie):
    """Provide a Playwright browser page, already logged in."""
    session_cookie = ui_session_cookie

    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        browser = pw.chromium.launch(headless=True)
    except Exception as e:
        pw.stop()
        _no_browser(f"Chromium not available: {e}")
    context = browser.new_context(ignore_https_errors=True)

    # Inject session cookie into Playwright browser context
    if session_cookie:
        context.add_cookies([{
            "name": "certmate_session",
            "value": session_cookie,
            "url": BASE_URL
        }])

    page = context.new_page()
    yield page
    context.close()
    browser.close()
    pw.stop()


@pytest.fixture
def infisical_sdk(monkeypatch):
    """`infisical_client` replaced by a stub with the SDK's real shape (see tests/infisical_sdk_stub.py)."""
    import sys
    from tests.infisical_sdk_stub import make_sdk_stub
    stub = make_sdk_stub()
    monkeypatch.setitem(sys.modules, 'infisical_client', stub)
    return stub
