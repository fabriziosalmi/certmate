"""Unit tests for certmate-sdk 0.1.2 wire-level fixes (no server required).

Each test pins the EXACT request the SDK sends (method, path, query, body) or
the exact error surface, using an httpx.MockTransport — these are the contracts
that were silently wrong in 0.1.1 (renew force dropped, dns test flat body,
download formats rejected, raw httpx tracebacks, audit 409 flattened into a
body indistinguishable from the benign fresh-instance case)."""
import json

import httpx
import pytest

certmate = pytest.importorskip("certmate", reason="certmate-sdk not installed")
from certmate import (Certificate, Client, Job, JobFailed,  # noqa: E402
                      NotFoundError, TransportError)

pytestmark = [pytest.mark.unit]

BASE = "http://testserver"


def _mock_client(handler) -> Client:
    """A Client whose HTTP layer is an httpx.MockTransport around ``handler``.

    The transport is swapped after construction so the SDK's public surface
    stays untouched (Client deliberately exposes no transport parameter)."""
    c = Client(BASE, token="test-token")
    c._http = httpx.Client(base_url=BASE, transport=httpx.MockTransport(handler),
                           headers={"Accept": "application/json"})
    return c


def _json_response(body, status=200):
    return httpx.Response(status, json=body)


# --------------------------------------------------------------------------
# BUG 2 / BUG 3 — renew: force travels in the JSON body, with a long timeout
# --------------------------------------------------------------------------

def test_renew_sends_force_in_json_body_not_query():
    seen = {}

    def handler(request):
        seen["params"] = dict(request.url.params)
        seen["body"] = json.loads(request.content)
        return _json_response({"message": "ok", "renewed": True})

    with _mock_client(handler) as c:
        res = c.renew_certificate("app.example.com", force=True)
    # The server reads payload.get('force') only; a query param is dropped.
    assert seen["body"] == {"force": True}
    assert "force" not in seen["params"]
    assert res["renewed"] is True


def test_renew_always_sends_a_body_even_without_force():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return _json_response({"message": "ok"})

    with _mock_client(handler) as c:
        c.renew_certificate("app.example.com")
    assert seen["body"] == {"force": False}


def test_renew_uses_long_per_request_timeout():
    # Real DNS-01 renewals take minutes; the default 30s read timeout used to
    # kill the CLI while the server kept renewing.
    seen = {}

    def handler(request):
        seen["timeout"] = request.extensions.get("timeout") or {}
        return _json_response({"message": "ok"})

    with _mock_client(handler) as c:
        c.renew_certificate("app.example.com", force=True)
    assert seen["timeout"].get("read") == 600.0


# --------------------------------------------------------------------------
# BUG 6 — download_certificate maps fmt to the query the API accepts
# --------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,expected_params", [
    ("json", {"format": "json"}),
    ("zip", {}),                          # bare request: zip is the default
    ("pem", {"file": "fullchain.pem"}),
    ("pfx", {"file": "cert.pfx"}),
])
def test_download_certificate_query_per_format(fmt, expected_params):
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["params"] = dict(request.url.params)
        if fmt == "json":
            return _json_response({"certificate_pem": "..."})
        return httpx.Response(200, content=b"BYTES",
                              headers={"content-type": "application/octet-stream"})

    with _mock_client(handler) as c:
        res = c.download_certificate("app.example.com", fmt=fmt)
    assert seen["path"] == "/api/certificates/app.example.com/download"
    assert seen["params"] == expected_params
    if fmt == "json":
        assert isinstance(res, dict)
    else:
        assert res == b"BYTES"


def test_download_certificate_unknown_format_raises_value_error():
    def handler(request):  # pragma: no cover - must never be reached
        raise AssertionError("no request may be sent for an unknown format")

    with _mock_client(handler) as c:
        with pytest.raises(ValueError):
            c.download_certificate("app.example.com", fmt="der")


# --------------------------------------------------------------------------
# BUG 5 — test_dns_provider nests credentials under "config"
# --------------------------------------------------------------------------

def test_dns_test_sends_nested_config_body():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return _json_response({"message": "ok"})

    with _mock_client(handler) as c:
        c.test_dns_provider("cloudflare")
        empty = seen["body"]
        c.test_dns_provider("cloudflare", api_token="tok")
        with_config = seen["body"]
    # Empty config asks v2.21.1+ servers to fall back to stored credentials.
    assert empty == {"provider": "cloudflare", "config": {}}
    assert with_config == {"provider": "cloudflare", "config": {"api_token": "tok"}}


# --------------------------------------------------------------------------
# BUG 1 (SDK side) — audit_verify preserves the HTTP status in the result
# --------------------------------------------------------------------------

def test_audit_verify_attaches_http_status_200():
    def handler(request):
        return _json_response({"ok": True, "reason": "intact"})

    with _mock_client(handler) as c:
        res = c.audit_verify()
    assert res["ok"] is True
    assert res["_http_status"] == 200


def test_audit_verify_409_payload_keeps_broken_distinction():
    # A chain file deleted AFTER signed checkpoints returns the SAME reason
    # text as a fresh instance; only the status (and state) tell them apart.
    def handler(request):
        return _json_response({"ok": False, "reason": "chain file does not exist"},
                              status=409)

    with _mock_client(handler) as c:
        res = c.audit_verify()
    assert res["ok"] is False
    assert res["_http_status"] == 409
    assert "state" not in res


def test_audit_verify_absent_state_is_a_200():
    def handler(request):
        return _json_response({"ok": False, "reason": "chain file does not exist",
                               "state": "absent"})

    with _mock_client(handler) as c:
        res = c.audit_verify()
    assert res["state"] == "absent"
    assert res["_http_status"] == 200


# --------------------------------------------------------------------------
# BUG 4 — httpx errors become TransportError (one clean SDK exception)
# --------------------------------------------------------------------------

def test_connect_error_becomes_transport_error():
    def handler(request):
        raise httpx.ConnectError("connection refused")

    with _mock_client(handler) as c:
        with pytest.raises(TransportError) as exc:
            c.health()
    assert "cannot reach server at" in str(exc.value)
    assert BASE in str(exc.value)


def test_read_timeout_becomes_transport_error_with_readable_detail():
    def handler(request):
        raise httpx.ReadTimeout("")  # httpx timeouts often stringify empty

    with _mock_client(handler) as c:
        with pytest.raises(TransportError) as exc:
            c.health()
    assert "cannot reach server at" in str(exc.value)
    # The empty str() must be replaced by a human-readable fallback.
    assert not str(exc.value).endswith(": ")


def test_transport_error_against_a_real_closed_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here any more
    with Client(f"http://127.0.0.1:{port}", token=None, timeout=2.0) as c:
        with pytest.raises(TransportError):
            c.health()


# --------------------------------------------------------------------------
# BUG 4 — wait_for_job resilience
# --------------------------------------------------------------------------

def _job(status, domain="app.example.com"):
    return Job.from_dict({"job_id": "j1", "status": status, "domain": domain})


def test_wait_for_job_tolerates_two_transient_blips(monkeypatch):
    c = Client(BASE)
    polls = iter([TransportError("blip"), TransportError("blip"), _job("succeeded")])

    def fake_get_job(job_id):
        item = next(polls)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(c, "get_job", fake_get_job)
    monkeypatch.setattr("time.sleep", lambda s: None)
    job = c.wait_for_job("j1", interval=0)
    assert job.succeeded


def test_wait_for_job_gives_up_after_three_consecutive_transport_errors(monkeypatch):
    c = Client(BASE)
    calls = {"n": 0}

    def fake_get_job(job_id):
        calls["n"] += 1
        raise TransportError("down")

    monkeypatch.setattr(c, "get_job", fake_get_job)
    monkeypatch.setattr("time.sleep", lambda s: None)
    with pytest.raises(TransportError):
        c.wait_for_job("j1", interval=0)
    assert calls["n"] == 3


def test_wait_for_job_transient_counter_resets_on_success(monkeypatch):
    # blip, ok, blip, blip, done: never three CONSECUTIVE failures.
    c = Client(BASE)
    polls = iter([TransportError("blip"), _job("running"), TransportError("blip"),
                  TransportError("blip"), _job("succeeded")])

    def fake_get_job(job_id):
        item = next(polls)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(c, "get_job", fake_get_job)
    monkeypatch.setattr("time.sleep", lambda s: None)
    assert c.wait_for_job("j1", interval=0).succeeded


def test_wait_for_job_evicted_job_checks_certificate(monkeypatch):
    # The job was seen once, then evicted (404). Its certificate exists, so
    # the SDK reports success instead of a spurious NotFoundError.
    c = Client(BASE)
    polls = iter([_job("running"), NotFoundError("gone", status=404)])

    def fake_get_job(job_id):
        item = next(polls)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(c, "get_job", fake_get_job)
    monkeypatch.setattr(c, "get_certificate",
                        lambda d: Certificate.from_dict({"domain": d}))
    monkeypatch.setattr("time.sleep", lambda s: None)
    job = c.wait_for_job("j1", interval=0)
    assert job.status == "succeeded"
    assert job.domain == "app.example.com"


def test_wait_for_job_evicted_job_without_certificate_still_fails(monkeypatch):
    c = Client(BASE)
    polls = iter([_job("running"), NotFoundError("gone", status=404)])

    def fake_get_job(job_id):
        item = next(polls)
        if isinstance(item, Exception):
            raise item
        return item

    def missing_cert(domain):
        raise NotFoundError("no such cert", status=404)

    monkeypatch.setattr(c, "get_job", fake_get_job)
    monkeypatch.setattr(c, "get_certificate", missing_cert)
    monkeypatch.setattr("time.sleep", lambda s: None)
    with pytest.raises(NotFoundError) as exc:
        c.wait_for_job("j1", interval=0)
    # The original job 404 propagates, not the certificate probe's.
    assert "gone" in str(exc.value)


def test_wait_for_job_not_found_on_first_poll_raises(monkeypatch):
    # Never seen the job at all: a 404 is a genuine unknown-job error.
    c = Client(BASE)

    def fake_get_job(job_id):
        raise NotFoundError("unknown job", status=404)

    monkeypatch.setattr(c, "get_job", fake_get_job)
    with pytest.raises(NotFoundError):
        c.wait_for_job("j1", interval=0)


def test_wait_for_job_still_raises_job_failed(monkeypatch):
    c = Client(BASE)
    monkeypatch.setattr(c, "get_job", lambda job_id: _job("failed"))
    with pytest.raises(JobFailed):
        c.wait_for_job("j1", interval=0)


# --------------------------------------------------------------------------
# BUG 7 — a boolean staging flag must not leak into the CA column
# --------------------------------------------------------------------------

def test_certificate_staging_flag_maps_to_staging_ca_name():
    c = Certificate.from_dict({"domain": "a.example.com", "staging": True})
    assert c.ca_provider == "letsencrypt-staging"


def test_certificate_explicit_ca_provider_wins_over_staging():
    c = Certificate.from_dict({"domain": "a.example.com",
                               "ca_provider": "letsencrypt", "staging": True})
    assert c.ca_provider == "letsencrypt"


def test_certificate_without_ca_or_staging_has_no_ca():
    c = Certificate.from_dict({"domain": "a.example.com", "staging": False})
    assert c.ca_provider is None
