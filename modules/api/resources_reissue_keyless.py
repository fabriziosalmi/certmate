"""Reissue every certificate that lost its private key, at a pace (#966).

Step 3 of the decision recorded on #966 for scenario B. Restoring a share-safe
backup leaves certificates with no private key anywhere; renewal answers
REISSUE_REQUIRED for them, and the repair is a reissue. One by one through
Edit & Reissue is a chore nobody finishes on forty certificates, and all of
them at once is forty orders against the CA's limits in one go.

So this queues at most `limit` of them per call (default 10, at most 50) on the
async issuance executor, which runs two at a time: that is the pace. The answer
names what was queued and what remains, so the caller (the dashboard, a
script) comes back for the rest. A full queue stops the loop and says so
instead of pretending the rest were queued.

A module of its own because `create_lifecycle_resources` carries a complexity
budget that only comes down.
"""
import logging

from flask import request
from flask_restx import Resource

from ..core.cert_jobs import IssuanceQueueFull
from ..core.cert_service import DomainOutOfScope
from ..core.audit_context import audit_context_from_request
from .resource_context import ApiContext

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 10
MAX_LIMIT = 50


def _limit(payload):
    """`limit` from the body, clamped to [1, MAX_LIMIT]; the default otherwise."""
    raw = (payload or {}).get('limit', DEFAULT_LIMIT)
    try:
        return max(1, min(MAX_LIMIT, int(raw)))
    except (TypeError, ValueError):
        return DEFAULT_LIMIT


def queue_keyless_reissues(ctx, user, ip_address, audit_ctx, limit):
    """Queue up to *limit* reissues; return ``(queued, remaining, refused)``.

    ``refused`` carries the domains prepare_reissue turned down, with a fixed
    reason: they are not queued, and retrying will not change that.
    """
    queued, remaining, refused = [], [], []
    keyless = ctx.cert_service.keyless_domains(user)
    for index, domain in enumerate(keyless):
        if len(queued) >= limit:
            remaining.extend(keyless[index:])
            break
        try:
            prepared = ctx.cert_service.prepare_reissue(
                domain=domain, user=user, ip_address=ip_address, audit_ctx=audit_ctx)
        except DomainOutOfScope:
            refused.append({'domain': domain, 'reason': 'out of scope'})
            continue
        except (ValueError, FileNotFoundError):
            refused.append({'domain': domain,
                            'reason': 'cannot be reissued from its recorded configuration'})
            continue
        try:
            job_id = ctx.cert_executor.submit(
                'reissue', domain,
                lambda prepared=prepared: ctx.cert_service.issue_reissue(prepared))
        except IssuanceQueueFull:
            remaining.extend(keyless[index:])
            break
        queued.append({'domain': domain, 'job_id': job_id,
                       'status_url': f'/api/certificates/jobs/{job_id}'})
    return queued, remaining, refused


def create_reissue_keyless_resources(api, models, ctx: ApiContext) -> dict:
    """Build the reissue-keyless resource against *ctx*."""

    class ReissueKeyless(Resource):
        @api.doc(security='Bearer')
        @ctx.auth.require_role('operator')
        def post(self):
            """Queue reissues for certificates that lost their private key"""
            if ctx.cert_executor is None:
                return {'code': 'ASYNC_ISSUANCE_DISABLED',
                        'error': 'Async issuance is switched off, and this runs on it'}, 503
            user = getattr(request, 'current_user', None) or {}
            queued, remaining, refused = queue_keyless_reissues(
                ctx, user, request.remote_addr, audit_context_from_request(),
                _limit(api.payload))
            body = {'queued': queued, 'remaining': remaining, 'refused': refused}
            if remaining:
                body['next_step'] = (
                    f'{len(remaining)} more certificate(s) need a reissue. '
                    f'Call this again once the queued jobs finish.')
            return body, (202 if queued else 200)

    return {'ReissueKeyless': ReissueKeyless}
