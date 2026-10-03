"""An audit record says who acted, not "system", when someone did.

63 `log_operation` calls passed no `actor`, and the logger synthesised `{'kind': 'system'}` for
each: deleting a certificate, creating or revoking an API key, creating or deleting a user,
restoring a backup, changing the authentication configuration, all recorded as the system's own
doing, with the person only in `user`. Measured on the route walk: 36 of the 57 records it
produced. The logger now takes the actor from the request it runs in when there is an
authenticated identity there, the same derivation audit_context_from_request makes (from
`request.current_user`, never from a client header); outside a request, or without one, it is
`system` as before.
"""
from unittest.mock import MagicMock

import pytest
from flask import Flask, request

from modules.core.audit import AuditLogger

pytestmark = [pytest.mark.unit]


def _logger():
    audit = AuditLogger.__new__(AuditLogger)
    audit.audit_logger = MagicMock()
    audit._chain_append = MagicMock()
    audit._sink = None
    return audit


def _recorded(audit):
    import json
    return json.loads(audit.audit_logger.info.call_args.args[0])


def _call(audit, **kwargs):
    audit.log_operation(operation='delete', resource_type='certificate',
                        resource_id='shop.example.com', status='success', **kwargs)
    return _recorded(audit)


def _in_request(user, headers=None):
    app = Flask(__name__)
    context = app.test_request_context('/api/certificates/shop.example.com', method='DELETE',
                                       headers=headers or {}, environ_base={'REMOTE_ADDR': '10.0.0.9'})
    context.push()
    request.current_user = user
    return context


@pytest.mark.parametrize('user, kind, cause', [
    ({'username': 'ci', 'role': 'operator', 'api_key_id': 'k1', 'token_prefix': 'cm_ab'}, 'api_token', 'api'),
    ({'username': 'alice', 'role': 'admin', 'auth_method': 'session'}, 'user', 'manual'),
])
def test_an_action_in_a_request_is_attributed_to_who_made_it(user, kind, cause):
    audit = _logger()
    context = _in_request(user)
    try:
        entry = _call(audit)
    finally:
        context.pop()
    assert entry['actor']['kind'] == kind and entry['actor']['label'] == user['username']
    assert entry['trigger']['cause'] == cause
    assert entry['user'] == user['username'] and entry['ip_address'] == '10.0.0.9'


def test_outside_a_request_it_is_the_system():
    entry = _call(_logger(), user='scheduler')
    assert entry['actor'] == {'kind': 'system', 'label': 'scheduler'}
    assert entry['trigger'] == {'cause': 'event'}


def test_a_request_without_an_identity_is_not_attributed_to_anyone():
    """A failed login is recorded with the name that was tried, and no one acted."""
    audit = _logger()
    context = _in_request(None)
    try:
        entry = _call(audit, user='mallory')
    finally:
        context.pop()
    assert entry['actor'] == {'kind': 'system', 'label': 'mallory'}


def test_an_actor_the_caller_passes_is_kept():
    audit = _logger()
    context = _in_request({'username': 'ci', 'role': 'operator', 'api_key_id': 'k1'})
    try:
        entry = _call(audit, actor={'kind': 'scheduler', 'label': 'scheduler'},
                      trigger={'cause': 'scheduled_renewal'})
    finally:
        context.pop()
    assert entry['actor'] == {'kind': 'scheduler', 'label': 'scheduler'}
    assert entry['trigger'] == {'cause': 'scheduled_renewal'}


def test_a_client_header_cannot_make_an_action_an_agent_s():
    """The agent-session header is a claim, recorded, never the kind (audit_context's threat model)."""
    audit = _logger()
    context = _in_request({'username': 'ci', 'role': 'operator', 'api_key_id': 'k1'},
                          headers={'X-CertMate-Agent-Session': 'pretend'})
    try:
        entry = _call(audit)
    finally:
        context.pop()
    assert entry['actor']['kind'] == 'api_token'


# --- on the real routes ---------------------------------------------------------------------

def test_no_record_the_route_walk_produces_says_system():
    """Every record the walk produces comes from a call made with a token; none of them is the
    system's own doing. Read off GET /api/audit/export at the end of the walk."""
    from tests import contract_routes as routes
    from tests import contract_support as support

    entries = []
    original = routes.Plan.call

    def call(plan, verb, template, *args, **kwargs):
        response, payload = original(plan, verb, template, *args, **kwargs)
        if template == '/api/audit/export' and isinstance(payload, dict):
            entries[:] = [e.get('entry', e) for e in payload.get('entries', [])]
        return response, payload

    routes.Plan.call = call
    try:
        routes.run(*support.build_app())
    finally:
        routes.Plan.call = original

    assert entries, 'the walk recorded no audit entries to read'
    system = sorted({(e['operation'], e['resource_type']) for e in entries
                     if isinstance(e.get('actor'), dict) and e['actor'].get('kind') == 'system'})
    assert system == [], f'recorded as the system, though a token made them: {system}'
