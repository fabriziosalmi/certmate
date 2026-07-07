"""Synchronous HTTP client for the CertMate REST API.

Endpoints mirror the ones the MCP server drives (the working reference client),
so the SDK talks to the same `/api/...` surface the web UI and agents use.
"""
from __future__ import annotations

import os
import time
from typing import Any, Callable, Dict, List, Optional

import httpx

from .errors import (APIError, AuthError, CertMateError, ConflictError,
                     JobFailed, JobTimeout, NotFoundError, TransportError)
from .models import Certificate, Job

_DEFAULT_URL = "http://localhost:8000"

# Real DNS-01 renewals block on propagation and can take minutes; the client
# default (30s) would kill the call while the server keeps renewing.
_RENEW_TIMEOUT = 600.0

# Fallback text for httpx exceptions whose str() is empty (timeouts often are).
_TRANSPORT_DETAIL = {
    "ConnectError": "connection failed",
    "ConnectTimeout": "connection timed out",
    "ReadTimeout": "server did not respond in time",
    "WriteTimeout": "sending the request timed out",
    "PoolTimeout": "no free connection in the pool",
    "RemoteProtocolError": "server closed the connection unexpectedly",
}


class Client:
    """A thin CertMate API client.

    >>> with Client("https://certmate.example.com", token="...") as c:
    ...     for cert in c.list_certificates():
    ...         print(cert.domain, cert.days_until_expiry)

    ``base_url``/``token`` fall back to ``CERTMATE_URL`` / ``CERTMATE_TOKEN``.
    """

    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None,
                 *, timeout: float = 30.0, verify: bool = True):
        base_url = (base_url or os.getenv("CERTMATE_URL") or _DEFAULT_URL).rstrip("/")
        token = token if token is not None else os.getenv("CERTMATE_TOKEN")
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        # gunicorn closes idle keep-alive connections after ~2s. httpx must not
        # reuse a connection older than that or it surfaces as a
        # RemoteProtocolError ("Server disconnected without sending a
        # response"); expire pooled connections well under that window and
        # retry connection-level blips.
        transport = httpx.HTTPTransport(
            retries=3, verify=verify,
            limits=httpx.Limits(keepalive_expiry=1.0),
        )
        self._http = httpx.Client(base_url=base_url, headers=headers,
                                  timeout=timeout, transport=transport)
        self.base_url = base_url

    # -- lifecycle -----------------------------------------------------------
    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self._http.close()

    # -- low level -----------------------------------------------------------
    def _request(self, method: str, path: str, **kw) -> Any:
        try:
            resp = self._http.request(method, path, **kw)
        except httpx.HTTPError as e:
            # Network-level failures become one clean SDK exception instead of
            # a raw httpx traceback (connection refused, DNS, timeout, ...).
            detail = str(e).strip() or _TRANSPORT_DETAIL.get(
                type(e).__name__, type(e).__name__)
            raise TransportError(
                f"cannot reach server at {self.base_url}: {detail}") from e
        if resp.status_code // 100 == 2:
            if not resp.content:
                return None
            ctype = resp.headers.get("content-type", "")
            return resp.json() if "application/json" in ctype else resp.content
        # Error path: pull CertMate's {error, code} shape when present.
        payload: Any = None
        code = None
        message = f"HTTP {resp.status_code}"
        try:
            payload = resp.json()
            if isinstance(payload, dict):
                message = payload.get("error") or payload.get("message") or message
                code = payload.get("code")
        except Exception:
            payload = resp.text
        exc_cls = {401: AuthError, 403: AuthError, 404: NotFoundError,
                   409: ConflictError}.get(resp.status_code, APIError)
        raise exc_cls(message, status=resp.status_code, code=code, payload=payload)

    # -- certificates --------------------------------------------------------
    def list_certificates(self) -> List[Certificate]:
        data = self._request("GET", "/api/certificates")
        items = data.get("certificates", data) if isinstance(data, dict) else data
        return [Certificate.from_dict(d) for d in (items or [])]

    def get_certificate(self, domain: str) -> Certificate:
        data = self._request("GET", f"/api/certificates/{domain}")
        return Certificate.from_dict(data if isinstance(data, dict) else {"domain": domain})

    def create_certificate(self, domain: str, *, dns_provider: Optional[str] = None,
                           ca_provider: Optional[str] = None,
                           san_domains: Optional[List[str]] = None,
                           account_id: Optional[str] = None,
                           wait: bool = False,
                           on_progress: Optional[Callable[[Job], None]] = None,
                           **extra: Any) -> Job:
        """Submit an async issuance. Returns the accepted Job immediately;
        with ``wait=True`` polls until the job reaches a terminal state (and
        raises :class:`JobFailed` on failure)."""
        body: Dict[str, Any] = {"domain": domain, "async": True}
        if dns_provider:
            body["dns_provider"] = dns_provider
        if ca_provider:
            body["ca_provider"] = ca_provider
        if san_domains:
            body["san_domains"] = san_domains
        if account_id:
            body["account_id"] = account_id
        body.update(extra)
        data = self._request("POST", "/api/certificates/create", json=body)
        job = Job.from_dict(data if isinstance(data, dict) else {})
        if not job.job_id:
            # Server ran it synchronously (async not honoured): treat as done.
            job.status = job.status or "succeeded"
            return job
        return self.wait_for_job(job.job_id, on_progress=on_progress) if wait else job

    def renew_certificate(self, domain: str, *, force: bool = False) -> Dict[str, Any]:
        # The server reads force from the JSON body (payload.get('force')),
        # never from the query string. Always send a body — even when force is
        # False — so endpoints that read request.json don't 415 on a bodyless
        # POST. The per-request timeout covers multi-minute DNS-01 renewals.
        return self._request("POST", f"/api/certificates/{domain}/renew",
                             json={"force": bool(force)},
                             timeout=_RENEW_TIMEOUT) or {}

    def reissue_certificate(self, domain: str, **body: Any) -> Dict[str, Any]:
        return self._request("POST", f"/api/certificates/{domain}/reissue", json=body) or {}

    def delete_certificate(self, domain: str) -> None:
        self._request("DELETE", f"/api/certificates/{domain}")

    def download_certificate(self, domain: str, fmt: str = "json") -> Any:
        """Download the bundle. ``fmt`` is one of json/pem/zip/pfx (json returns
        a dict, the binary formats return bytes).

        The endpoint only accepts ``?format=json``; the other shapes are the
        bare default (zip) or selected via ``?file=``, so each fmt maps to the
        exact query the API understands:

        - ``json`` -> ``?format=json`` (dict, PEM strings inline)
        - ``zip``  -> no params (the endpoint's default bundle)
        - ``pem``  -> ``?file=fullchain.pem``
        - ``pfx``  -> ``?file=cert.pfx``
        """
        params_by_fmt: Dict[str, Optional[Dict[str, str]]] = {
            "json": {"format": "json"},
            "zip": None,
            "pem": {"file": "fullchain.pem"},
            "pfx": {"file": "cert.pfx"},
        }
        if fmt not in params_by_fmt:
            raise ValueError(
                f"unknown download format {fmt!r}; use one of json/pem/zip/pfx")
        return self._request("GET", f"/api/certificates/{domain}/download",
                             params=params_by_fmt[fmt])

    def set_auto_renew(self, domain: str, enabled: bool) -> Dict[str, Any]:
        return self._request("PUT", f"/api/certificates/{domain}/auto-renew",
                             json={"enabled": bool(enabled)}) or {}

    def deploy_certificate(self, domain: str) -> Dict[str, Any]:
        return self._request("POST", f"/api/certificates/{domain}/deploy", json={}) or {}

    # -- async jobs ----------------------------------------------------------
    def get_job(self, job_id: str) -> Job:
        return Job.from_dict(self._request("GET", f"/api/certificates/jobs/{job_id}") or {})

    def wait_for_job(self, job_id: str, *, interval: float = 2.0, timeout: float = 600.0,
                     on_progress: Optional[Callable[[Job], None]] = None) -> Job:
        start = time.monotonic()
        last: Optional[Job] = None       # last successfully polled state
        transient = 0                    # consecutive transport failures
        while True:
            try:
                job = self.get_job(job_id)
            except TransportError:
                # A blip mid-poll (server restart, proxy hiccup) must not
                # abort a multi-minute issuance; only a sustained outage —
                # three consecutive failed polls — gives up.
                transient += 1
                if transient >= 3:
                    raise
                if time.monotonic() - start > timeout:
                    raise JobTimeout(
                        f"job {job_id} did not finish within {timeout:.0f}s")
                time.sleep(interval)
                continue
            except NotFoundError:
                # Finished jobs can be evicted from the server's job table
                # between polls. If the job was seen at least once and its
                # certificate now exists, the eviction means "completed" —
                # confirm against the certificate before declaring failure.
                if last is not None and last.domain:
                    try:
                        self.get_certificate(last.domain)
                    except CertMateError:
                        pass
                    else:
                        last.status = "succeeded"
                        return last
                raise
            transient = 0
            last = job
            if on_progress:
                on_progress(job)
            if job.is_terminal:
                if job.failed:
                    raise JobFailed(job.error or f"job {job_id} failed", job=job)
                return job
            if time.monotonic() - start > timeout:
                raise JobTimeout(f"job {job_id} did not finish within {timeout:.0f}s")
            time.sleep(interval)

    # -- dns -----------------------------------------------------------------
    def list_dns_providers(self) -> Any:
        return self._request("GET", "/api/settings/dns-providers")

    def list_dns_accounts(self, provider: Optional[str] = None) -> Any:
        path = f"/api/dns/{provider}/accounts" if provider else "/api/dns/accounts"
        return self._request("GET", path)

    def test_dns_provider(self, provider: str, **config: Any) -> Dict[str, Any]:
        """Preflight a DNS provider without issuing. Backs the CLI ``--dry-run``.

        The endpoint expects ``{"provider": ..., "config": {...}}`` — the
        credentials nested under ``config``, never flattened into the top
        level. An empty config asks the server (v2.21.1+) to fall back to the
        provider's stored account credentials."""
        body = {"provider": provider, "config": config or {}}
        return self._request("POST", "/api/web/certificates/test-provider", json=body) or {}

    # -- audit / misc --------------------------------------------------------
    def audit_verify(self) -> Dict[str, Any]:
        """Verify the audit chain. The endpoint returns 200 when intact (or
        when a fresh instance has no chain yet — ``state == 'absent'``) and
        409 (WITH the full result body) when the chain is broken — both are
        valid verification results, so return the dict in either case and
        only raise on a genuine transport/auth error. Inspect ``result['ok']``.

        The returned dict always carries ``_http_status`` (int: 200 or 409) so
        callers never lose the intact-vs-broken distinction: the body reason
        can read the same in both cases ("chain file does not exist" is benign
        on a 200 with ``state='absent'`` but tampering on a 409 — a chain
        deleted after signed checkpoints attested it existed).
        """
        try:
            res = self._request("GET", "/api/audit/verify") or {}
            if isinstance(res, dict):
                res["_http_status"] = 200
            return res
        except ConflictError as e:
            if isinstance(e.payload, dict):
                res = dict(e.payload)
                res["_http_status"] = e.status
                return res
            raise

    def activity(self, limit: int = 100) -> Any:
        return self._request("GET", "/api/activity", params={"limit": limit})

    def health(self) -> Dict[str, Any]:
        return self._request("GET", "/health") or {}

    # -- backups -------------------------------------------------------------
    def list_backups(self) -> Any:
        return self._request("GET", "/api/web/backups")

    def create_backup(self, *, reason: str = "manual") -> Dict[str, Any]:
        return self._request("POST", "/api/web/backups/create", json={"reason": reason}) or {}
