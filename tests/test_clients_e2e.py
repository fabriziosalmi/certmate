"""End-to-end tests for the in-repo terminal clients (certmate-sdk + certmate-cli)
against the real container, plus a Swagger contract check that keeps the SDK's
endpoints in lockstep with the API it wraps.

Requires the clients to be installed (requirements-test.txt installs them
editable). Skipped cleanly if the SDK is not importable."""
import shutil
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


# --------------------------------------------------------------------------
# Contract: the SDK's REST endpoints must exist in the API's Swagger spec
# --------------------------------------------------------------------------

def _normalise(path: str) -> str:
    """Drop a leading /api and collapse {param}/<param> to {} for comparison."""
    import re
    if path.startswith("/api"):
        path = path[len("/api"):]
    return re.sub(r"[<{][^>}]*[>}]", "{}", path)


# The `/api/...` (flask-restx, Swagger-documented) endpoints the SDK relies on.
# Web-blueprint endpoints (test-provider, backups) are intentionally excluded —
# they are not part of the restx schema.
_SDK_RESTX_ENDPOINTS = [
    ("get", "/certificates"),
    ("post", "/certificates/create"),
    ("get", "/certificates/{}"),
    ("delete", "/certificates/{}"),
    ("post", "/certificates/{}/renew"),
    ("post", "/certificates/{}/reissue"),
    ("get", "/certificates/{}/download"),
    ("get", "/certificates/jobs/{}"),
    ("put", "/certificates/{}/auto-renew"),
]


def _fetch_spec(base_url: str):
    import httpx
    for path in ("/swagger.json", "/api/swagger.json", "/docs/swagger.json"):
        try:
            r = httpx.get(base_url.rstrip("/") + path, timeout=10)
            if r.status_code == 200 and isinstance(r.json(), dict) and r.json().get("paths"):
                return r.json()
        except Exception:
            continue
    return None


def test_sdk_endpoints_are_documented_in_swagger(docker_container):
    spec = _fetch_spec(docker_container)
    if not spec:
        pytest.skip("Swagger spec not exposed by this build")
    documented = set()
    for raw_path, methods in spec.get("paths", {}).items():
        norm = _normalise(raw_path)
        for method in methods:
            documented.add((method.lower(), norm))
    missing = [ep for ep in _SDK_RESTX_ENDPOINTS if ep not in documented]
    assert not missing, (
        "SDK calls endpoints absent from the API's Swagger spec (drift!): "
        f"{missing}"
    )
