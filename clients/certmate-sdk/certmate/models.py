"""Light, tolerant dataclasses over the CertMate API responses.

Kept deliberately forgiving: the API is the source of truth, so every model
keeps the raw dict and only surfaces the well-known fields as typed
attributes. Unknown/absent fields never raise — the SDK must not break when
the server adds a field."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Certificate:
    domain: str
    expiry_date: Optional[str] = None
    days_until_expiry: Optional[int] = None
    # API contract 2.2. `days_until_expiry` is whole days and truncates, so a
    # certificate with hours left reports 0 and a client deriving validity from
    # it calls a valid certificate expired. `expired` is the server's answer,
    # and is None when the server could not parse the certificate at all, which
    # is neither expired nor fine. Both are None against a server older than
    # 2.2, so a caller that needs them should read the version header.
    expired: Optional[bool] = None
    seconds_left: Optional[int] = None
    needs_renewal: Optional[bool] = None
    ca_provider: Optional[str] = None
    dns_provider: Optional[str] = None
    auto_renew: Optional[bool] = None
    san_domains: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Certificate":
        d = d or {}
        return cls(
            domain=d.get("domain") or d.get("name") or "",
            expiry_date=d.get("expiry_date") or d.get("expires") or d.get("not_after"),
            days_until_expiry=d.get("days_until_expiry"),
            expired=d.get("expired"),
            seconds_left=d.get("seconds_left"),
            needs_renewal=d.get("needs_renewal"),
            # Older payloads carry a boolean `staging` flag instead of a CA
            # name; map it to the staging CA identifier rather than leaking
            # a bare True into the CA column.
            ca_provider=d.get("ca_provider")
            or ("letsencrypt-staging" if d.get("staging") else None),
            dns_provider=d.get("dns_provider"),
            auto_renew=d.get("auto_renew"),
            san_domains=list(d.get("san_domains") or []),
            raw=d,
        )

    def has_expired(self) -> Optional[bool]:
        """Has this certificate expired? None when it cannot be known.

        Exists so callers stop writing `days_until_expiry <= 0`, which is
        wrong and was wrong in CertMate's own dashboard until server 2.32.2:
        `days_until_expiry` is whole days and truncates, so a certificate with
        23 hours of life left reports 0 and that comparison calls it expired.
        step-ca issues 24-hour certificates by default, so on a private CA that
        was every certificate.

        Against a server on API contract 2.2 or later this is the server's own
        answer. Against an older one there is no better information than the
        day count, and this returns what that count can actually support:
        negative is definitely expired, positive is definitely not, and zero is
        the ambiguous day the whole defect lives in, so it answers None rather
        than guessing. None also covers a certificate the server could not
        parse, which is neither expired nor fine.
        """
        if self.expired is not None:
            return self.expired
        days = self.days_until_expiry
        if days is None or days == 0:
            return None
        return days < 0


# Terminal job states, normalised.
JOB_DONE = {"succeeded", "success", "completed", "done"}
JOB_FAILED = {"failed", "error"}


@dataclass
class Job:
    job_id: str
    operation: Optional[str] = None
    domain: Optional[str] = None
    status: Optional[str] = None
    error: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Job":
        d = d or {}
        return cls(
            job_id=d.get("job_id") or d.get("id") or "",
            operation=d.get("operation"),
            domain=d.get("domain"),
            status=(d.get("status") or d.get("state")),
            error=d.get("error"),
            raw=d,
        )

    @property
    def is_terminal(self) -> bool:
        s = (self.status or "").lower()
        return s in JOB_DONE or s in JOB_FAILED

    @property
    def succeeded(self) -> bool:
        return (self.status or "").lower() in JOB_DONE

    @property
    def failed(self) -> bool:
        return (self.status or "").lower() in JOB_FAILED
