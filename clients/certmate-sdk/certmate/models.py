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
            needs_renewal=d.get("needs_renewal"),
            ca_provider=d.get("ca_provider") or d.get("staging"),
            dns_provider=d.get("dns_provider"),
            auto_renew=d.get("auto_renew"),
            san_domains=list(d.get("san_domains") or []),
            raw=d,
        )


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
