"""certmate-sdk — a thin Python client for the CertMate REST API.

    from certmate import Client
    with Client("https://certmate.example.com", token="...") as c:
        job = c.create_certificate("app.example.com", dns_provider="cloudflare", wait=True)
"""
from .client import Client
from .errors import (APIError, AuthError, CertMateError, ConflictError,
                     JobFailed, JobTimeout, NotFoundError)
from .models import Certificate, Job

__version__ = "0.1.0"
__all__ = [
    "Client", "Certificate", "Job",
    "CertMateError", "APIError", "AuthError", "NotFoundError", "ConflictError",
    "JobFailed", "JobTimeout",
]
