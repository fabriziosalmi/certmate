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
import time
import subprocess
import pytest
import requests

# ---------------------------------------------------------------------------
# Test isolation
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def _isolate_runtime_dirs(tmp_path_factory):
    """Keep `create_app()` out of the checkout's real runtime directories.

    `setup_directories` resolves cert/data/backup/log paths from
    `modules.core.factory.__file__` — three levels up — and honours no
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
    module_dir = root / "modules" / "core"
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
        patch.setattr("modules.core.factory.__file__", str(anchor),
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


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TEST_PORT = int(os.environ.get("CERTMATE_TEST_PORT", "18888"))
IMAGE_NAME = os.environ.get("CERTMATE_IMAGE", "certmate:test")
CONTAINER_NAME = "certmate-test-suite"
BASE_URL = f"http://localhost:{TEST_PORT}"
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
def docker_container():
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

    # Start container
    print(f"[tests] Starting container {CONTAINER_NAME} on port {TEST_PORT} ...")
    _docker(
        "run", "-d",
        "--name", CONTAINER_NAME,
        "-p", f"{TEST_PORT}:8000",
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
    })
    requests.post(f"{BASE_URL}/api/auth/config", json={
        "local_auth_enabled": True
    })

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

    s = requests.Session()
    s.cookies.set("certmate_session", session_cookie)
    r = s.get(f"{BASE_URL}/api/web/settings")
    if r.status_code == 200:
        data = r.json()
        data["setup_completed"] = True
        s.post(f"{BASE_URL}/api/web/settings", json=data)
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
