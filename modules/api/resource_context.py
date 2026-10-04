"""The shared state and helpers the API resources need, made explicit.

`create_api_resources` is a single function holding 41 resource classes as
closures over ten managers and a handful of helpers. Nothing in it can be
imported on its own, which is why the HTTP layer is both the largest module in
the project and the least covered: reaching one route means constructing the
whole graph (#667).

This is the first step out of that: the state those classes capture becomes an
object that can be built and inspected, and the helpers that captured it become
functions that take it. Resource classes can then move into modules of their
own without each one dragging the closure along.

Nothing here changes behaviour. `build_context` reproduces exactly the lookups
and fallbacks the closure performed, including the `CertificateService`
fallback that lets tests pass a minimal manager dict.
"""
from dataclasses import dataclass
from typing import Any, Optional

from flask import request

from modules.core.auth import ROLE_HIERARCHY
from modules.core.cert_service import CertificateService
from modules.core.inventory_view import record_in_scope
from modules.core.structured_logging import scrub_log_value
import logging

logger = logging.getLogger(__name__)

# Values the ``async`` flag accepts in a request body. Kept with the helper
# that reads it rather than loose in the closure.
ASYNC_TRUTHY = (True, 1, '1', 'true', 'yes', 'on')


@dataclass(frozen=True)
class ApiContext:
    """The managers the API resources operate through.

    Frozen: resources read this, they do not reconfigure the application.
    """

    auth: Any
    settings: Any
    certificates: Any
    file_ops: Any
    cache: Any
    dns: Any
    deployer: Optional[Any]
    audit: Optional[Any]
    cert_service: Any
    cert_executor: Optional[Any]
    # The full manager mapping, for the long tail a diagnostics endpoint
    # legitimately reaches across (scheduler, storage, oidc, shell_executor...).
    # The named fields above stay the contract for everything else: enumerating
    # every optional manager as a field would be a fiction, since a diagnostics
    # snapshot is by nature a view over the whole application.
    managers: Any = None


def build_context(managers) -> ApiContext:
    """Resolve the manager set exactly as the closure used to.

    The required managers are looked up with ``[]`` and the optional ones with
    ``.get()``, preserving which absences are a programming error and which are
    a supported configuration.
    """
    auth = managers['auth']
    settings = managers['settings']
    certificates = managers['certificates']
    audit = managers.get('audit')

    # Shared create/renew orchestration. Production wires a single instance via
    # the container (factory.py); the fallback builds one from the manager set
    # so tests that call the factory with a minimal managers dict (no
    # 'cert_service'/'events') keep working.
    cert_service = managers.get('cert_service') or CertificateService(
        certificates, settings, auth, audit_logger=audit,
        event_bus=managers.get('events'),
    )

    return ApiContext(
        auth=auth,
        settings=settings,
        certificates=certificates,
        file_ops=managers['file_ops'],
        cache=managers['cache'],
        dns=managers['dns'],
        deployer=managers.get('deployer'),
        audit=audit,
        cert_service=cert_service,
        # Optional async issuance executor (single-instance, in-process).
        # Absent in minimal-managers unit tests, in which case create and renew
        # stay synchronous.
        cert_executor=managers.get('cert_executor'),
        managers=managers,
    )


def wants_async(payload) -> bool:
    """True when the caller opted into async issuance via the ``async`` body
    flag or the ``?async=`` query param."""
    if isinstance(payload, dict) and payload.get('async') in ASYNC_TRUTHY:
        return True
    return request.args.get('async', '').strip().lower() in (
        '1', 'true', 'yes', 'on')


def job_accepted(job_id, operation, domain, status_url) -> dict:
    """The 202 body for an accepted async job."""
    return {
        'job_id': job_id,
        'status': 'queued',
        'operation': operation,
        'domain': domain,
        'status_url': status_url,
    }


def check_domain_scope(ctx: ApiContext, domain, operation):
    """Reject the request if the caller's API-key allowed_domains does not
    cover *domain*. Returns (body, status) on denial, or None when permitted.

    Sessions and legacy bearer tokens have no allowed_domains on
    request.current_user, so they are unrestricted; only scoped API keys, which
    carry an allowed_domains list, can reach a 403.
    """
    user = getattr(request, 'current_user', None) or {}
    if ctx.auth.user_can_access_domain(user, domain):
        return None
    return _scope_denied(ctx, user, domain, operation)


def check_certificate_scope(ctx: ApiContext, domain, operation):
    """`check_domain_scope` for an operation on an existing certificate.

    The certificate filed as *domain* may cover other names, and whatever is
    done to it is done for all of them: its key serves every one. So the
    caller's scope must cover each name it carries, which is the rule
    creation has always applied to the names it is asked for.

    The answer names only *domain*, the name the caller sent: the other
    names are what the caller is not entitled to, so the one outside the
    scope is recorded in the server log and not handed back.
    """
    user = getattr(request, 'current_user', None) or {}
    if not ctx.auth.user_can_access_domain(user, domain):
        return _scope_denied(ctx, user, domain, operation)
    if user.get('allowed_domains') is None:
        # Unrestricted: no name can fall outside, so nothing is read.
        return None
    for name in ctx.certificates.names_covered(domain):
        if not ctx.auth.user_can_access_domain(user, name):
            logger.warning(
                "Scope denial: certificate %s also covers %s",
                scrub_log_value(domain), scrub_log_value(name))
            return _scope_denied(
                ctx, user, domain, operation,
                reason='certificate covers a name outside scoped key allowed_domains')
    return None


def certificate_in_scope(ctx: ApiContext, domain, scope) -> bool:
    """Whether *scope* covers every name of the certificate filed as *domain*.

    The question `check_certificate_scope` asks, for a caller that filters
    rather than refuses (the certificate list). Unrestricted reads nothing.
    """
    if scope is None:
        return True
    return all(ctx.auth.domain_matches_scope(name, scope)
               for name in ctx.certificates.names_covered(domain))


def _scope_denied(ctx: ApiContext, user, domain, operation,
                  reason='domain outside scoped key allowed_domains'):
    # Scrubbed exactly as cert_service does for the same denial log: the
    # username can carry a newline (create_user does not constrain it, and the
    # OIDC path takes it from an IdP claim), which under the non-JSON log
    # format forges a second, fully attacker-chosen record.
    logger.warning(
        "Scope denial: user=%s op=%s domain=%s scope=%s",
        scrub_log_value(user.get('username')), scrub_log_value(operation),
        scrub_log_value(domain), scrub_log_value(user.get('allowed_domains')),
    )
    if ctx.audit:
        ctx.audit.log_authz_denied(
            operation=operation,
            resource_type='certificate',
            resource_id=domain,
            reason=reason,
            user=user.get('username'),
            ip_address=request.remote_addr,
        )
    return {
        'error': f'API key not authorized for domain {domain}',
        'code': 'DOMAIN_OUT_OF_SCOPE',
    }, 403


def is_record_in_scope(ctx: ApiContext, record) -> bool:
    """True if the caller's scope covers any domain the inventory *record*
    names (subject CN or a SAN).

    Matches CertificateList exactly: scope comes from allowed_domains and is
    fed to domain_matches_scope, so an unrestricted caller (scope None,
    including a request whose current_user is unset) sees everything. Using
    user_can_access_domain here instead would be a regression — it returns
    False for an empty user dict and would hide the WHOLE inventory from a
    legitimate unrestricted caller.
    """
    user = getattr(request, 'current_user', None) or {}
    scope = user.get('allowed_domains')
    return record_in_scope(
        record, lambda d: ctx.auth.domain_matches_scope(d, scope)
    )


def scope_filter_records(ctx: ApiContext, records):
    return [r for r in records if is_record_in_scope(ctx, r)]


def user_has_role(user, min_role) -> bool:
    level = ROLE_HIERARCHY.get((user or {}).get('role'), -1)
    return level >= ROLE_HIERARCHY.get(min_role, 999)
