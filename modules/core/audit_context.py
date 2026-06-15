"""Audit attribution context resolver.

Turns the *authenticated* identity behind a request (``request.current_user``)
plus the optional, client-supplied agent-session header into the structured
``actor`` / ``trigger`` blocks that :meth:`AuditLogger.log_operation` records.

Threat model: ``actor.kind`` is derived ONLY from the authenticated identity.
The ``X-CertMate-Agent-Session`` / ``X-CertMate-Agent-Id`` headers are
client-supplied and unauthenticated, so they are recorded as an informational
*claim* under ``actor.agent_session`` / ``actor.agent_id`` and never promote a
non-agent caller to ``kind='agent'``. A trustworthy agent attribution requires
an ``is_agent``-flagged scoped API key.
"""

from typing import Any, Dict, Optional

# Client-supplied, unauthenticated headers. Informational only.
AGENT_SESSION_HEADER = 'X-CertMate-Agent-Session'
AGENT_ID_HEADER = 'X-CertMate-Agent-Id'

# Cap claimed header values so a hostile client cannot bloat an audit line.
_CLAIM_MAX = 128

# actor.kind -> trigger.cause for the request path. The scheduler path builds
# its own context (see audit_context_for_scheduler).
_CAUSE_BY_KIND = {
    'agent': 'agent',
    'api_token': 'api',
    'user': 'manual',
    'system': 'event',
}


def _system_context() -> Dict[str, Any]:
    return {
        'actor': {'kind': 'system', 'label': 'system'},
        'trigger': {'cause': 'event'},
        'user': None,
        'ip': 'unknown',
    }


def audit_context_from_user(
    user: Optional[Dict[str, Any]],
    headers: Any = None,
    ip: Optional[str] = None,
) -> Dict[str, Any]:
    """Build an audit context dict ``{actor, trigger, user, ip}`` from a
    resolved ``current_user`` dict (and optional request headers + ip).

    ``user`` is the dict produced by :class:`AuthManager` authentication:
    a scoped key carries ``api_key_id`` / ``token_prefix`` / ``is_agent``;
    the legacy global bearer token collapses to ``username='api_user'`` with
    no key id; sessions / OIDC carry the real username.
    """
    user = user or {}
    username = user.get('username')
    api_key_id = user.get('api_key_id')
    is_agent = bool(user.get('is_agent'))

    # Derive kind from the AUTHENTICATED identity only.
    if api_key_id:
        kind = 'agent' if is_agent else 'api_token'
    elif username == 'api_user':
        # Legacy global bearer token: a real caller, but no key id and no way
        # to prove it is an agent. Honest classification is api_token.
        kind = 'api_token'
    elif not username or username == 'system':
        kind = 'system'
    else:
        kind = 'user'  # session / OIDC human

    actor: Dict[str, Any] = {'kind': kind, 'label': username or 'system'}
    if api_key_id:
        actor['id'] = api_key_id
    token_prefix = user.get('token_prefix')
    if token_prefix:
        actor['token_prefix'] = token_prefix

    # Record the client-supplied agent claim (provenance: unauthenticated).
    if headers is not None and hasattr(headers, 'get'):
        agent_session = headers.get(AGENT_SESSION_HEADER)
        if agent_session:
            actor['agent_session'] = str(agent_session)[:_CLAIM_MAX]
        agent_id = headers.get(AGENT_ID_HEADER)
        if agent_id:
            actor['agent_id'] = str(agent_id)[:_CLAIM_MAX]

    trigger = {'cause': _CAUSE_BY_KIND.get(kind, 'event')}
    return {'actor': actor, 'trigger': trigger, 'user': username, 'ip': ip or 'unknown'}


def audit_context_from_request() -> Dict[str, Any]:
    """Resolve the audit context for the current Flask request. Safe to call
    outside a request context (returns a ``system`` context)."""
    try:
        from flask import request, has_request_context
        if not has_request_context():
            return _system_context()
        user = getattr(request, 'current_user', None) or {}
        return audit_context_from_user(user, headers=request.headers, ip=request.remote_addr)
    except Exception:
        # Attribution must never break the operation being audited.
        return _system_context()


def audit_context_for_scheduler(job_id: str) -> Dict[str, Any]:
    """Build the audit context for an unattended, scheduler-triggered action."""
    return {
        'actor': {'kind': 'scheduler', 'label': 'scheduler'},
        'trigger': {'cause': 'scheduled_renewal', 'job_id': job_id},
        'user': 'scheduler',
        'ip': 'localhost',
    }
