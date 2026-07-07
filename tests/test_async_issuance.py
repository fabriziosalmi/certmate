"""Unit coverage for opt-in async certificate issuance.

Two layers:

* ``IssuanceExecutor`` (modules/core/cert_jobs.py): job lifecycle, result
  sanitisation, completion-event mapping (mirroring the synchronous routes),
  parallel distinct-domain execution, and bounded-registry eviction. Built with
  ``app=None`` so no Flask context is pushed.
* The RESTX adapters: ``async`` opt-in returns 202 + job id and does NOT block
  on certbot, while bad input / out-of-scope are rejected *synchronously*
  (4xx) before anything is enqueued. The default (no flag) stays synchronous.
"""
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask, request
from flask_restx import Api, Namespace

from modules.core.cert_jobs import IssuanceExecutor
from modules.core.certificates import DomainOperationInProgress
from modules.api.models import create_api_models
from modules.api.resources import create_api_resources


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# IssuanceExecutor
# ---------------------------------------------------------------------------

def _exec(event_bus=None, **kw):
    return IssuanceExecutor(app=None, event_bus=event_bus, **kw)


def _wait_terminal(ex, job_id, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = ex.get(job_id)
        if job and job['status'] in ('succeeded', 'failed'):
            return job
        time.sleep(0.005)
    raise AssertionError(f"job {job_id} did not finish within {timeout}s")


class TestIssuanceExecutorLifecycle:
    def test_success_records_result_and_publishes_created(self):
        bus = MagicMock()
        ex = _exec(event_bus=bus)
        jid = ex.submit('create', 'a.example.com',
                        lambda: {'success': True, 'domain': 'a.example.com',
                                 'dns_provider': 'cloudflare'})
        job = _wait_terminal(ex, jid)
        assert job['status'] == 'succeeded'
        assert job['operation'] == 'create'
        assert job['domain'] == 'a.example.com'
        assert job['result']['dns_provider'] == 'cloudflare'
        assert job['error'] is None
        assert job['started_at'] and job['finished_at']
        bus.publish.assert_called_once_with('certificate_created', {'domain': 'a.example.com'})

    def test_renew_success_publishes_renewed(self):
        bus = MagicMock()
        ex = _exec(event_bus=bus)
        jid = ex.submit('renew', 'a.example.com', lambda: {'success': True, 'message': 'ok'})
        _wait_terminal(ex, jid)
        bus.publish.assert_called_once_with('certificate_renewed', {'domain': 'a.example.com'})

    def test_noop_renew_does_not_publish_renewed(self):
        """A renew that no-oped (certbot 'not yet due', renewed=False) replaced
        nothing — deploy hooks must not fire, mirroring the sync route."""
        bus = MagicMock()
        ex = _exec(event_bus=bus)
        jid = ex.submit('renew', 'a.example.com',
                        lambda: {'success': True, 'renewed': False,
                                 'message': 'Certificate not yet due for renewal'})
        job = _wait_terminal(ex, jid)
        assert job['status'] == 'succeeded'
        assert job['result']['renewed'] is False
        bus.publish.assert_not_called()

    def test_get_unknown_returns_none(self):
        assert _exec().get('does-not-exist') is None

    def test_result_drops_private_keys(self):
        ex = _exec(event_bus=MagicMock())
        jid = ex.submit('create', 'a.example.com',
                        lambda: {'success': True, '_settings_dns_provider': 'internal'})
        job = _wait_terminal(ex, jid)
        assert '_settings_dns_provider' not in job['result']
        assert job['result']['success'] is True


class TestIssuanceExecutorFailure:
    def test_create_failure_records_error_and_publishes_nothing(self):
        bus = MagicMock()
        ex = _exec(event_bus=bus)

        def boom():
            raise RuntimeError('certbot blew up')

        job = _wait_terminal(ex, ex.submit('create', 'a.example.com', boom))
        assert job['status'] == 'failed'
        assert 'certbot blew up' in job['error']
        assert job['error_code'] is None
        bus.publish.assert_not_called()  # sync create emits no failure event either

    def test_renew_failure_publishes_certificate_failed(self):
        bus = MagicMock()
        ex = _exec(event_bus=bus)

        def boom():
            raise RuntimeError('renew failed')

        _wait_terminal(ex, ex.submit('renew', 'a.example.com', boom))
        events = [c.args[0] for c in bus.publish.call_args_list]
        assert 'certificate_failed' in events

    def test_renew_busy_sets_code_and_no_failure_event(self):
        bus = MagicMock()
        ex = _exec(event_bus=bus)

        def busy():
            raise DomainOperationInProgress('a.example.com')

        job = _wait_terminal(ex, ex.submit('renew', 'a.example.com', busy))
        assert job['status'] == 'failed'
        assert job['error_code'] == 'DOMAIN_OPERATION_IN_PROGRESS'
        events = [c.args[0] for c in bus.publish.call_args_list]
        assert 'certificate_failed' not in events  # busy is not a failure


class TestIssuanceExecutorConcurrencyAndBounds:
    def test_distinct_domains_run_in_parallel(self):
        ex = _exec(event_bus=MagicMock(), max_workers=2)
        # Both jobs must be running simultaneously for the barrier to release;
        # if the pool serialised them this would time out -> failed jobs.
        barrier = threading.Barrier(2, timeout=5)

        def fn():
            barrier.wait()
            return {'success': True}

        j1 = ex.submit('create', 'a.example.com', fn)
        j2 = ex.submit('create', 'b.example.com', fn)
        assert _wait_terminal(ex, j1)['status'] == 'succeeded'
        assert _wait_terminal(ex, j2)['status'] == 'succeeded'

    def test_capacity_evicts_oldest_terminal_job(self):
        ex = _exec(event_bus=MagicMock(), max_workers=1, capacity=5)
        ids = []
        for i in range(8):
            jid = ex.submit('create', f'd{i}.example.com', lambda: {'success': True})
            ids.append(jid)
            _wait_terminal(ex, jid)
        # 8 submitted, capacity 5: the oldest terminal jobs are gone, newest kept.
        assert ex.get(ids[0]) is None
        assert ex.get(ids[-1]) is not None


# ---------------------------------------------------------------------------
# RESTX adapters: async opt-in + jobs endpoint
# ---------------------------------------------------------------------------

def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


class _FakeExecutor:
    """Captures submit() calls without running fn, so adapter tests assert the
    202/enqueue behaviour deterministically (executor internals are covered
    above)."""

    def __init__(self):
        self.calls = []
        self._jobs = {}

    def submit(self, kind, domain, fn):
        jid = f'job-{len(self.calls)}'
        self.calls.append((kind, domain, fn))
        self._jobs[jid] = {
            'job_id': jid, 'operation': kind, 'domain': domain,
            'status': 'queued', 'submitted_at': 't', 'started_at': None,
            'finished_at': None, 'result': None, 'error': None, 'error_code': None,
        }
        return jid

    def get(self, jid):
        job = self._jobs.get(jid)
        return dict(job) if job else None


def _build_app(tmp_path, executor, allowed=True):
    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth.user_can_access_domain.return_value = allowed

    certs = MagicMock(cert_dir=Path(tmp_path))
    certs.create_certificate.return_value = {
        'success': True, 'domain': 'x', 'dns_provider': 'cloudflare', 'duration': 1.0}
    certs.renew_certificate.return_value = {
        'success': True, 'domain': 'x', 'message': 'ok'}

    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': 'ops@example.com', 'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01'}

    managers = {
        'auth': auth, 'settings': settings, 'certificates': certs,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)), 'cache': MagicMock(),
        'dns': MagicMock(), 'audit': None, 'cert_executor': executor,
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)
    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['CreateCertificate'], '/create')
    ns.add_resource(resources['RenewCertificate'], '/<string:domain>/renew')
    ns.add_resource(resources['CertificateJob'], '/jobs/<string:job_id>')

    @app.before_request
    def _attach_user():
        request.current_user = {'username': 'op', 'role': 'operator', 'allowed_domains': None}

    return app, managers


class TestAsyncCreateAdapter:
    def test_async_create_returns_202_without_blocking_certbot(self, tmp_path):
        ex = _FakeExecutor()
        app, managers = _build_app(tmp_path, ex)
        r = app.test_client().post('/api/certificates/create', json={
            'domain': 'x.example.com', 'dns_provider': 'cloudflare', 'async': True})
        assert r.status_code == 202, r.data
        body = r.get_json()
        assert body['job_id'] and body['status'] == 'queued'
        assert body['operation'] == 'create'
        assert body['domain'] == 'x.example.com'
        assert body['status_url'] == f"/api/certificates/jobs/{body['job_id']}"
        assert len(ex.calls) == 1 and ex.calls[0][0] == 'create'
        # certbot is deferred to the executor, not run on the request thread.
        managers['certificates'].create_certificate.assert_not_called()

    def test_async_via_query_param(self, tmp_path):
        ex = _FakeExecutor()
        app, _ = _build_app(tmp_path, ex)
        r = app.test_client().post('/api/certificates/create?async=true', json={
            'domain': 'x.example.com', 'dns_provider': 'cloudflare'})
        assert r.status_code == 202
        assert len(ex.calls) == 1

    def test_async_bad_domain_rejected_400_before_enqueue(self, tmp_path):
        ex = _FakeExecutor()
        app, _ = _build_app(tmp_path, ex)
        r = app.test_client().post('/api/certificates/create', json={
            'domain': '../evil', 'async': True})
        assert r.status_code == 400
        assert ex.calls == []  # prepare rejected synchronously; nothing enqueued

    def test_async_out_of_scope_rejected_403_before_enqueue(self, tmp_path):
        ex = _FakeExecutor()
        app, _ = _build_app(tmp_path, ex, allowed=False)
        r = app.test_client().post('/api/certificates/create', json={
            'domain': 'x.example.com', 'dns_provider': 'cloudflare', 'async': True})
        assert r.status_code == 403
        assert ex.calls == []

    def test_sync_default_unchanged(self, tmp_path):
        ex = _FakeExecutor()
        app, managers = _build_app(tmp_path, ex)
        r = app.test_client().post('/api/certificates/create', json={
            'domain': 'x.example.com', 'dns_provider': 'cloudflare'})
        assert r.status_code == 201
        managers['certificates'].create_certificate.assert_called_once()
        assert ex.calls == []  # sync path never touches the executor


class TestAsyncRenewAdapter:
    def test_async_renew_returns_202(self, tmp_path):
        ex = _FakeExecutor()
        app, managers = _build_app(tmp_path, ex)
        r = app.test_client().post('/api/certificates/x.example.com/renew', json={'async': True})
        assert r.status_code == 202
        assert ex.calls and ex.calls[0][0] == 'renew'
        managers['certificates'].renew_certificate.assert_not_called()

    def test_async_renew_traversal_domain_400_before_enqueue(self, tmp_path):
        ex = _FakeExecutor()
        app, _ = _build_app(tmp_path, ex)
        r = app.test_client().open('/api/certificates/..evil/renew', method='POST', json={'async': True})
        assert r.status_code == 400
        assert ex.calls == []


class TestJobStatusEndpoint:
    def test_poll_existing_job(self, tmp_path):
        ex = _FakeExecutor()
        app, _ = _build_app(tmp_path, ex)
        client = app.test_client()
        jid = client.post('/api/certificates/create', json={
            'domain': 'x.example.com', 'dns_provider': 'cloudflare', 'async': True}).get_json()['job_id']
        r = client.get(f'/api/certificates/jobs/{jid}')
        assert r.status_code == 200
        assert r.get_json()['job_id'] == jid

    def test_unknown_job_404(self, tmp_path):
        ex = _FakeExecutor()
        app, _ = _build_app(tmp_path, ex)
        r = app.test_client().get('/api/certificates/jobs/nope')
        assert r.status_code == 404

    def test_out_of_scope_job_403(self, tmp_path):
        ex = _FakeExecutor()
        # Pre-seed a job for a domain the (out-of-scope) caller cannot access.
        ex._jobs['j1'] = {
            'job_id': 'j1', 'operation': 'create', 'domain': 'secret.example.com',
            'status': 'succeeded', 'submitted_at': 't', 'started_at': None,
            'finished_at': None, 'result': None, 'error': None, 'error_code': None,
        }
        app, _ = _build_app(tmp_path, ex, allowed=False)
        r = app.test_client().get('/api/certificates/jobs/j1')
        assert r.status_code == 403
