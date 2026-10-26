"""Exception hierarchy for the CertMate SDK."""
from __future__ import annotations

from typing import Any, Optional


class CertMateError(Exception):
    """Base class for every SDK error."""


class TransportError(CertMateError):
    """The server could not be reached or the connection died mid-request
    (DNS failure, connection refused, timeout, protocol error).

    Wraps ``httpx.HTTPError`` so callers — the CLI in particular — can catch
    one SDK exception type and print a clean message instead of surfacing a
    raw httpx traceback."""


class APIError(CertMateError):
    """The API returned a non-2xx response.

    ``status`` is the HTTP status code; ``code`` is CertMate's machine-readable
    error code (e.g. ``DOMAIN_OUT_OF_SCOPE``) when present; ``payload`` is the
    parsed response body."""

    def __init__(self, message: str, *, status: int, code: Optional[str] = None,
                 payload: Any = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.payload = payload


class AuthError(APIError):
    """401/403 — missing, invalid, or insufficiently-scoped credentials."""


class NotFoundError(APIError):
    """404 — the domain / resource does not exist."""


class ConflictError(APIError):
    """409 — e.g. the certificate already exists, or an operation is in flight."""


class UnsupportedByServer(CertMateError):
    """The server's API contract is older than the one a request needs.

    Raised before the request is sent. A server does not refuse a field it does
    not know: it ignores it, and for some fields that does something else than
    what was asked (``name`` on create, contract 2.61: the certificate would be
    issued under its domain). ``needed`` is the contract the request needs and
    ``server`` the one the server reports, or None when it reports none."""

    def __init__(self, message: str, *, needed: str, server: str | None = None):
        super().__init__(message)
        self.needed = needed
        self.server = server


class JobFailed(CertMateError):
    """An async issuance/renewal job finished in a failed state."""

    def __init__(self, message: str, *, job: Any = None):
        super().__init__(message)
        self.job = job


class JobTimeout(CertMateError):
    """wait_for_job exceeded its timeout before the job reached a terminal state."""
