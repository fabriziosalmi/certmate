"""End-to-end tests for the in-repo terminal clients (certmate-sdk + certmate-cli)
against the real container, plus a Swagger contract check that keeps the SDK's
endpoints in lockstep with the API it wraps.

Requires the clients to be installed (requirements-test.txt installs them
editable). Skipped cleanly if the SDK is not importable."""
import os
import shutil
import socket
import subprocess

import pytest

pytestmark = [pytest.mark.e2e]

certmate = pytest.importorskip("certmate", reason="certmate-sdk not installed")
from certmate import Client, NotFoundError  # noqa: E402


# --------------------------------------------------------------------------
# SDK against the live container (docker_container yields the base URL)
# --------------------------------------------------------------------------

@pytest.fixture
def sdk(docker_container):
    with Client(docker_container) as c:   # setup-mode container → open, no token
        yield c


def test_sdk_health(sdk):
    assert sdk.health().get("status") in {"healthy", "degraded"}


def test_sdk_list_certificates_is_a_list(sdk):
    assert isinstance(sdk.list_certificates(), list)


def test_sdk_audit_verify_fresh_is_ok_or_absent(sdk):
    """With the finding-#2 fix a fresh instance no longer 409s: audit_verify
    tolerates the endpoint and returns a dict with ok/state."""
    res = sdk.audit_verify()
    assert isinstance(res, dict) and "ok" in res
    # Fresh instance: either intact (something got audited) or explicitly absent.
    assert res["ok"] is True or res.get("state") == "absent"
    # SDK 0.1.2 always preserves the intact-vs-broken HTTP status.
    assert res.get("_http_status") == 200


def test_sdk_backup_create_and_list(sdk):
    created = sdk.create_backup()
    assert created.get("filename")
    listed = sdk.list_backups()
    # {"unified": [ {filename, metadata}, ... ]}
    names = [b.get("filename") for b in (listed or {}).get("unified", [])]
    assert created["filename"] in names


def test_sdk_dns_accounts_present(sdk):
    accounts = sdk.list_dns_accounts()
    assert accounts  # the server ships default accounts for every provider


def test_sdk_missing_cert_raises_not_found(sdk):
    with pytest.raises(NotFoundError):
        sdk.get_certificate("does-not-exist.example.com")


# --------------------------------------------------------------------------
# CLI binary against the live container
# --------------------------------------------------------------------------

@pytest.mark.skipif(shutil.which("certmate") is None, reason="certmate CLI not on PATH")
def test_cli_cert_ls_runs(docker_container):
    r = subprocess.run(["certmate", "--url", docker_container, "cert", "ls"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


@pytest.mark.skipif(shutil.which("certmate") is None, reason="certmate CLI not on PATH")
def test_cli_audit_verify_fresh_exit_zero(docker_container):
    # Finding #2: a fresh instance's audit verify must not fail the CLI.
    r = subprocess.run(["certmate", "--url", docker_container, "audit", "verify"],
                       capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr


# Must match CONTAINER_NAME in tests/conftest.py — the docker_container fixture
# only yields the base URL, so container-level tampering goes through docker
# exec on the well-known name.
_CONTAINER_NAME = "certmate-test-suite"
_AUDIT_DIR = "/app/data/audit"  # factory wires chain_dir = data_dir / "audit"
_CHAIN = f"{_AUDIT_DIR}/certificate_audit.chain.jsonl"
_CHECKPOINTS = f"{_AUDIT_DIR}/certificate_audit.checkpoints.jsonl"


def _container_sh(cmd: str):
    """Run a shell command inside the fixture container."""
    return subprocess.run(["docker", "exec", _CONTAINER_NAME, "sh", "-c", cmd],
                          capture_output=True, text=True, timeout=60)


@pytest.mark.skipif(shutil.which("certmate") is None, reason="certmate CLI not on PATH")
def test_cli_audit_verify_broken_after_chain_deletion(docker_container):
    """A chain file deleted AFTER signed checkpoints attested it existed is
    tampering: `audit verify` must exit non-zero (the 0.1.1 CLI treated the
    reason text as the benign fresh-instance case and exited 0)."""
    if os.environ.get("CERTMATE_E2E_BASE_URL"):
        pytest.skip("externally managed instance: no docker exec access")
    if shutil.which("docker") is None:
        pytest.skip("docker not available")
    probe = _container_sh(f"mkdir -p {_AUDIT_DIR}")
    if probe.returncode != 0:
        pytest.skip(f"docker exec unavailable for {_CONTAINER_NAME}: {probe.stderr}")

    # Snapshot the files this test mutates; the container is shared with the
    # rest of the session, so the exact pre-test state must come back.
    _container_sh(f"[ -f {_CHAIN} ] && cp -p {_CHAIN} {_CHAIN}.e2ebak; true")
    _container_sh(f"[ -f {_CHECKPOINTS} ] && cp -p {_CHECKPOINTS} {_CHECKPOINTS}.e2ebak; true")
    try:
        # Any parseable {seq, hash} record makes has_checkpoints() true; the
        # server then treats a missing chain file as a deletion (409), not a
        # fresh instance (200 + state='absent').
        fake_cp = ('{"seq": 0, "hash": "e2e-fake-checkpoint", "count": 1, '
                   '"timestamp": "2026-01-01T00:00:00Z"}')
        r = _container_sh(f"printf '%s\\n' '{fake_cp}' >> {_CHECKPOINTS}")
        assert r.returncode == 0, r.stderr
        r = _container_sh(f"rm -f {_CHAIN}")
        assert r.returncode == 0, r.stderr

        r = subprocess.run(["certmate", "--url", docker_container, "audit", "verify"],
                           capture_output=True, text=True, timeout=30)
        assert r.returncode != 0, (
            "audit verify must fail when the chain was deleted after "
            f"checkpoints; stdout={r.stdout!r} stderr={r.stderr!r}")
        assert "BROKEN" in r.stdout
        assert "Traceback" not in r.stdout + r.stderr
    finally:
        _container_sh(f"if [ -f {_CHAIN}.e2ebak ]; then mv {_CHAIN}.e2ebak {_CHAIN}; fi")
        _container_sh(f"if [ -f {_CHECKPOINTS}.e2ebak ]; "
                      f"then mv {_CHECKPOINTS}.e2ebak {_CHECKPOINTS}; "
                      f"else rm -f {_CHECKPOINTS}; fi")


@pytest.mark.skipif(shutil.which("certmate") is None, reason="certmate CLI not on PATH")
def test_cli_health_unreachable_server_clean_error():
    """`certmate health` against a closed port: one clean error line, exit 1,
    no traceback. Needs no container — the point is that nothing listens."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # freed again: nothing listens on this port
    r = subprocess.run(["certmate", "--url", f"http://127.0.0.1:{port}", "health"],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 1, r.stdout + r.stderr
    combined = r.stdout + r.stderr
    assert "Traceback" not in combined
    assert "cannot reach server" in combined
    assert "error" in combined.lower()


# --------------------------------------------------------------------------
# Contract: the SDK's REST endpoints must exist in the application
# --------------------------------------------------------------------------
#
# This lived here as nine endpoints in a literal list, checked against a
# running container's Swagger spec. It is now
# tests/test_the_sdk_calls_endpoints_that_exist.py, which reads the endpoints
# out of the SDK's own source with `ast` and compares them against the
# application's `url_map`.
#
# Why it moved: the list had drifted to nine of the SDK's nineteen calls, and
# it deliberately excluded the `/api/web/...` blueprint endpoints the SDK also
# uses — so the check written to catch a renamed endpoint could not see half
# the client. Neither side needs a container to be read, and a contract between
# two files in this repository does not belong in the slowest tier of the
# suite.
