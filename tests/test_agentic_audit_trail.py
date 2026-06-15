"""
Phase 1 of the agentic cert-lifecycle audit trail (l0 #408):

- ``actor`` / ``trigger`` attribution on every audit entry,
- the request -> (actor, trigger) resolver, with the client-supplied
  agent-session header treated as an informational claim only,
- emission on the previously-silent success/failure paths
  (cert_service create/renew/reissue),
- attribution of unattended, scheduler-driven renewals.
"""

import json

import pytest

from modules.core.audit import AuditLogger
from modules.core.audit_context import (
    audit_context_from_user,
    audit_context_for_scheduler,
)
from modules.core.cert_service import CertificateService
from modules.core.certificates import CertificateManager


@pytest.fixture
def audit(tmp_path):
    """An AuditLogger whose handler is detached again after the test so the
    shared 'certmate.audit' logger does not leak handlers across tests."""
    a = AuditLogger(tmp_path)
    try:
        yield a
    finally:
        a.audit_logger.removeHandler(a.file_handler)
        a.file_handler.close()


def _entries(audit):
    return audit.get_recent_entries(limit=100)


# --------------------------------------------------------------------------
# Resolver: actor.kind is derived from the AUTHENTICATED identity only.
# --------------------------------------------------------------------------

def test_kind_agent_for_is_agent_scoped_key():
    ctx = audit_context_from_user(
        {'username': 'api_key:bot', 'api_key_id': 'k1', 'is_agent': True,
         'token_prefix': 'cm_abc'},
        ip='10.0.0.9',
    )
    assert ctx['actor']['kind'] == 'agent'
    assert ctx['actor']['id'] == 'k1'
    assert ctx['actor']['token_prefix'] == 'cm_abc'
    assert ctx['trigger']['cause'] == 'agent'
    assert ctx['user'] == 'api_key:bot'
    assert ctx['ip'] == '10.0.0.9'


def test_kind_api_token_for_non_agent_scoped_key():
    ctx = audit_context_from_user(
        {'username': 'api_key:ci', 'api_key_id': 'k2', 'is_agent': False})
    assert ctx['actor']['kind'] == 'api_token'
    assert ctx['trigger']['cause'] == 'api'


def test_kind_api_token_for_legacy_global_bearer():
    # The legacy global bearer token collapses to 'api_user' with no key id;
    # honest classification is api_token, never 'agent'.
    ctx = audit_context_from_user({'username': 'api_user', 'role': 'admin'})
    assert ctx['actor']['kind'] == 'api_token'
    assert 'id' not in ctx['actor']
    assert ctx['trigger']['cause'] == 'api'


def test_kind_user_for_session_human():
    ctx = audit_context_from_user({'username': 'alice', 'role': 'operator'})
    assert ctx['actor']['kind'] == 'user'
    assert ctx['trigger']['cause'] == 'manual'


def test_kind_system_for_empty():
    ctx = audit_context_from_user(None)
    assert ctx['actor']['kind'] == 'system'
    assert ctx['trigger']['cause'] == 'event'


class _Headers(dict):
    """Minimal case-sensitive header bag exposing .get like werkzeug Headers."""


def test_agent_session_header_is_recorded_as_claim_not_promotion():
    # A plain human session that *claims* an agent session must NOT become an
    # agent; the claim is recorded separately for correlation.
    headers = _Headers({'X-CertMate-Agent-Session': 'sess-123',
                        'X-CertMate-Agent-Id': 'orchestrator-7'})
    ctx = audit_context_from_user({'username': 'alice'}, headers=headers)
    assert ctx['actor']['kind'] == 'user'           # not promoted
    assert ctx['actor']['agent_session'] == 'sess-123'
    assert ctx['actor']['agent_id'] == 'orchestrator-7'


def test_agent_session_claim_is_length_capped():
    headers = _Headers({'X-CertMate-Agent-Session': 'x' * 5000})
    ctx = audit_context_from_user({'username': 'api_key:bot', 'api_key_id': 'k',
                                   'is_agent': True}, headers=headers)
    assert len(ctx['actor']['agent_session']) == 128


def test_scheduler_context():
    ctx = audit_context_for_scheduler('certificate_renewal_check')
    assert ctx['actor']['kind'] == 'scheduler'
    assert ctx['trigger']['cause'] == 'scheduled_renewal'
    assert ctx['trigger']['job_id'] == 'certificate_renewal_check'


# --------------------------------------------------------------------------
# log_operation: actor/trigger are always present and back-compatible.
# --------------------------------------------------------------------------

def test_log_operation_synthesises_actor_and_trigger(audit):
    audit.log_operation('update', 'settings', 'settings', 'success', user='alice')
    entry = _entries(audit)[-1]
    assert entry['actor'] == {'kind': 'system', 'label': 'alice'}
    assert entry['trigger'] == {'cause': 'event'}


def test_log_operation_records_passed_actor_and_trigger(audit):
    audit.log_operation(
        'create', 'certificate', 'example.com', 'success',
        actor={'kind': 'agent', 'id': 'k1', 'label': 'api_key:bot'},
        trigger={'cause': 'agent'},
    )
    entry = _entries(audit)[-1]
    assert entry['actor']['kind'] == 'agent'
    assert entry['trigger']['cause'] == 'agent'


# --------------------------------------------------------------------------
# cert_service: emits attributed success/failure on the lifecycle choke point.
# --------------------------------------------------------------------------

class _FakeAuth:
    def user_can_access_domain(self, user, domain):
        return True


class _FakeSettings:
    def __init__(self):
        self._s = {'email': 'ops@example.com', 'dns_provider': 'cloudflare'}

    def load_settings(self):
        return dict(self._s)

    def update(self, mutator, _event):
        mutator(self._s)

    def migrate_domains_format(self, s):
        return s


class _FakeCerts:
    def __init__(self, fail=False):
        self.fail = fail

    def create_certificate(self, **kwargs):
        if self.fail:
            raise RuntimeError('certbot exploded')
        return {'dns_provider': 'cloudflare', 'ca_provider': 'letsencrypt', 'duration': 1.0}

    def renew_certificate(self, domain, force=False):
        if self.fail:
            raise RuntimeError('certbot exploded')
        return {'dns_provider': 'cloudflare', 'duration': 1.0}


def _service(audit, fail=False):
    return CertificateService(_FakeCerts(fail=fail), _FakeSettings(), _FakeAuth(),
                              audit_logger=audit)


def test_issue_create_emits_attributed_success(audit):
    svc = _service(audit)
    ctx = audit_context_from_user(
        {'username': 'api_key:bot', 'api_key_id': 'k1', 'is_agent': True}, ip='1.2.3.4')
    svc.issue_create(svc.prepare_create(domain='example.com', audit_ctx=ctx))
    entry = _entries(audit)[-1]
    assert entry['operation'] == 'create'
    assert entry['status'] == 'success'
    assert entry['resource_id'] == 'example.com'
    assert entry['actor']['kind'] == 'agent'
    assert entry['actor']['id'] == 'k1'
    assert entry['trigger']['cause'] == 'agent'
    assert entry['ip_address'] == '1.2.3.4'


def test_issue_create_emits_failure_and_reraises(audit):
    svc = _service(audit, fail=True)
    ctx = audit_context_from_user({'username': 'alice'})
    with pytest.raises(RuntimeError):
        svc.issue_create(svc.prepare_create(domain='example.com', audit_ctx=ctx))
    entry = _entries(audit)[-1]
    assert entry['operation'] == 'create'
    assert entry['status'] == 'failure'
    assert entry['actor']['kind'] == 'user'
    assert entry['error']


def test_issue_renew_emits_attributed_success(audit):
    svc = _service(audit)
    ctx = audit_context_from_user({'username': 'alice'})
    svc.issue_renew(svc.prepare_renew(domain='example.com', audit_ctx=ctx))
    entry = _entries(audit)[-1]
    assert entry['operation'] == 'renew'
    assert entry['status'] == 'success'
    assert entry['actor']['kind'] == 'user'
    assert entry['trigger']['cause'] == 'manual'


def test_emission_is_noop_without_audit_logger():
    # No audit logger wired -> issuance still works, nothing to assert beyond
    # "does not raise".
    svc = CertificateService(_FakeCerts(), _FakeSettings(), _FakeAuth(), audit_logger=None)
    ctx = audit_context_from_user({'username': 'alice'})
    assert svc.issue_renew(svc.prepare_renew(domain='example.com', audit_ctx=ctx))


# --------------------------------------------------------------------------
# Scheduler path: unattended renewals are attributed to actor.kind='scheduler'.
# --------------------------------------------------------------------------

def test_scheduled_renewal_is_attributed_to_scheduler(audit, tmp_path, monkeypatch):
    settings = {'auto_renew': True,
                'domains': [{'domain': 'sched.example.com', 'auto_renew': True}]}

    class _SM:
        def load_settings(self):
            return dict(settings)

        def migrate_domains_format(self, s):
            return s

    mgr = CertificateManager(tmp_path, _SM(), dns_manager=None)
    mgr.set_audit_logger(audit)
    monkeypatch.setattr(mgr, 'get_certificate_info',
                        lambda domain, settings=None, use_cache=True: {'needs_renewal': True})
    monkeypatch.setattr(mgr, 'renew_certificate', lambda domain, force=False: {'ok': True})

    summary = mgr.check_renewals()
    assert summary['renewed'] == 1

    entry = _entries(audit)[-1]
    assert entry['operation'] == 'renew'
    assert entry['resource_id'] == 'sched.example.com'
    assert entry['status'] == 'success'
    assert entry['actor']['kind'] == 'scheduler'
    assert entry['trigger']['cause'] == 'scheduled_renewal'
    assert entry['trigger']['job_id'] == 'certificate_renewal_check'


def test_scheduled_renewal_failure_is_attributed(audit, tmp_path, monkeypatch):
    settings = {'auto_renew': True,
                'domains': [{'domain': 'bad.example.com', 'auto_renew': True}]}

    class _SM:
        def load_settings(self):
            return dict(settings)

        def migrate_domains_format(self, s):
            return s

    mgr = CertificateManager(tmp_path, _SM(), dns_manager=None)
    mgr.set_audit_logger(audit)
    monkeypatch.setattr(mgr, 'get_certificate_info',
                        lambda domain, settings=None, use_cache=True: {'needs_renewal': True})

    def _boom(domain, force=False):
        raise RuntimeError('dns timeout')
    monkeypatch.setattr(mgr, 'renew_certificate', _boom)

    summary = mgr.check_renewals()
    assert summary['failed'] == 1

    entry = _entries(audit)[-1]
    assert entry['status'] == 'failure'
    assert entry['actor']['kind'] == 'scheduler'
    assert entry['error']
