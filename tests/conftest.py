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
import json
import subprocess
import pytest
import requests

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
    """Run a docker command."""
    cmd = ["docker", *args]
    return subprocess.run(
        cmd,
        check=check,
        capture_output=capture,
        text=True,
        timeout=300,
    )


def _wait_healthy(timeout=60):
    """Wait until the container health endpoint responds 200."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{BASE_URL}/health", timeout=3)
            if r.status_code == 200:
                return True
        except requests.ConnectionError:
            pass
        time.sleep(1)
    raise TimeoutError(f"Container not healthy after {timeout}s")


# ---------------------------------------------------------------------------
# Session-scoped: one Docker container for the entire test run
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session")
def docker_container():
    """Build image, start container, yield BASE_URL, then tear down."""
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
            self.session.headers["Content-Type"] = "application/json"

        # --- HTTP verbs ---------------------------------------------------
        def get(self, path, **kw):
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

    return APIClient(base)


@pytest.fixture(scope="session")
def cloudflare_token():
    """Return the Cloudflare API token or skip if not set."""
    token = os.environ.get("CLOUDFLARE_API_TOKEN")
    if not token:
        pytest.skip("CLOUDFLARE_API_TOKEN not set — skipping real DNS tests")
    return token
