"""Real-container readiness smoke: the scheduler must actually start.

``/health`` is a liveness probe — it returns 200 as soon as Flask serves,
even when APScheduler (the ONLY driver of automatic renewals) failed to
start; the body merely flips ``status`` to ``degraded``. A container whose
renewal loop is silently dead would therefore sail through any check that
only looks at ``/health``. ``/health/ready`` is the readiness probe that
returns 503 in that case.

These run against the real built image (the session ``docker_container``
fixture), need no Cloudflare token, and are NOT marked ``slow`` — so they
execute on every CI run as a boot regression net, catching "image builds and
serves pages but the scheduler never came up" before it ships.
"""
import pytest

pytestmark = [pytest.mark.e2e]


def test_health_liveness_200(api):
    """/health is always 200 once Flask serves (liveness)."""
    r = api.get("/health")
    assert r.status_code == 200, f"/health {r.status_code}: {r.text[:200]}"
    body = r.json()
    assert body.get("status") in ("healthy", "degraded"), body


def test_health_ready_scheduler_running(api):
    """/health/ready must be 200 with the scheduler running — proving the
    renewal driver actually started in the real container, which /health
    alone does not."""
    r = api.get("/health/ready")
    assert r.status_code == 200, (
        f"container not ready (scheduler down?): {r.status_code} {r.text[:300]}"
    )
    body = r.json()
    assert body.get("ready") is True, body
    assert body.get("scheduler") == "running", body


def test_health_ready_certbot_actually_runs(api):
    """The other half of "this container can do its job".

    A scheduler that runs and a certbot that cannot are the same outcome: no
    certificate ever renews. The startup probe runs `certbot --version` inside
    the container, which is the only check that catches the failure this
    project has actually hit twice — pip resolves cleanly, the binary is
    present, and certbot dies importing its own ACME stack because a
    `cryptography` or `pyOpenSSL` version moved under the pinned certbot.

    `skipped` is not accepted here. In the real image the shell executes, so
    anything other than `ok` means the probe did not measure what it claims.
    """
    body = api.get("/health/ready").json()
    assert body.get("certbot") == "ok", (
        f"certbot is not usable in the built image: {body}"
    )

    health = api.get("/health").json()
    version = health.get("checks", {}).get("certbot_version", "")
    assert version.startswith("certbot "), (
        f"the image reports certbot ok without a version: {health}"
    )
