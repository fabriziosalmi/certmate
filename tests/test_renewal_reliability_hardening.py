"""
Regression guards for the 2026-07-02 renewal-reliability audit fixes. Each
test pins one silent-failure mode a certificate manager must never regress on:

* P0-2  Batch-created certs are registered in settings['domains'] so
        check_renewals actually renews them (they used to expire silently
        ~90 days later because the batch path bypassed the only code that
        tracks a domain for renewal).
* P0-3a A renewal certbot call is bounded by a timeout, so one wedged renew
        cannot hang the (serial, max_instances=1) renewal job forever and
        silently stop ALL future automatic renewals.
* P0-3b The scheduled renewal jobs carry a generous misfire_grace_time +
        coalesce, so a restart straddling the 02:00 fire runs the check
        instead of dropping the day (APScheduler's default grace is 1s).
* P1-2  create_certificate verifies a certificate actually materialised
        before reporting success (certbot exit 0 with no live files must
        raise, not push empty state to the DR backend and return success).
* P1-3  A failed deploy hook publishes a dedicated failure event so the
        operator is alerted instead of the failure being swallowed while the
        create/renew response already said "success".
"""
import json
import os
import stat
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, request

from modules.core import factory
from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES
from modules.core.deployer import DeployManager
from modules.core.shell import MockShellExecutor
from modules.core.storage_backends import LocalFileSystemBackend
from modules.web.cert_routes import register_cert_routes


pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def _passthrough_decorator(*args, **kwargs):
    """Works as both ``@require_web_auth`` (called with the view fn) and
    ``@require_role('operator')`` (called with a string, returns a decorator)."""
    if len(args) == 1 and callable(args[0]) and not kwargs:
        return args[0]

    def _wrap(fn):
        return fn
    return _wrap


def _make_cert_mgr(tmp_path, shell):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'duckdns': 1},
        'default_key_type': 'ecdsa',
        'default_elliptic_curve': 'secp384r1',
    }
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (
        {'api_token': 'duck-token'}, 'default'
    )
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=dns_mgr,
        storage_manager=None,
        ca_manager=None,
        shell_executor=shell,
    )


# --------------------------------------------------------------------------
# P1-2 — create_certificate must verify a cert actually materialised
# --------------------------------------------------------------------------

class _NoFilesExecutor(MockShellExecutor):
    """certbot returns 0 but writes NO live files — the silent-failure bug
    (suffixed lineage / cert-name mismatch). produces_artifacts=True marks
    this as a "real" execution so the post-issue verification is active."""
    produces_artifacts = True


def test_create_raises_when_certbot_succeeds_but_writes_no_files(tmp_path):
    domain = 'no-files.example.duckdns.org'
    mgr = _make_cert_mgr(tmp_path, _NoFilesExecutor())
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        with pytest.raises(RuntimeError, match='expected certificate files are missing'):
            mgr.create_certificate(
                domain=domain, email='t@example.com',
                dns_provider='duckdns', staging=True,
            )


def test_create_does_not_store_empty_state_on_silent_failure(tmp_path):
    """The empty file set must never reach the external DR backend: the raise
    happens before store_certificate is called."""
    domain = 'no-store.example.duckdns.org'
    mgr = _make_cert_mgr(tmp_path, _NoFilesExecutor())
    storage = MagicMock()
    storage.get_backend_name.return_value = 'azure'
    mgr.storage_manager = storage
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        with pytest.raises(RuntimeError):
            mgr.create_certificate(
                domain=domain, email='t@example.com',
                dns_provider='duckdns', staging=True,
            )
    storage.store_certificate.assert_not_called()


def test_create_with_mock_executor_does_not_enforce_artifacts(tmp_path):
    """A non-artifact-producing double (produces_artifacts=False) must NOT trip
    the check — otherwise every command-construction unit test that mocks
    certbot without staging files would break."""
    domain = 'mock-ok.example.duckdns.org'
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)
    assert shell.produces_artifacts is False
    mgr = _make_cert_mgr(tmp_path, shell)
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = mgr.create_certificate(
            domain=domain, email='t@example.com',
            dns_provider='duckdns', staging=True,
        )
    assert result['success'] is True


# --------------------------------------------------------------------------
# P0-3a — renewal certbot call is bounded by a timeout
# --------------------------------------------------------------------------

class _RenewExecutor(MockShellExecutor):
    """Records run kwargs and, on success, stages the renewed live files so
    renew_certificate's copy loop completes."""

    def __init__(self, cert_dir, domain):
        super().__init__()
        self._cert_dir = Path(cert_dir)
        self._domain = domain
        self.last_kwargs = None
        self.set_next_result(returncode=0)

    def run(self, cmd, **kwargs):
        self.last_kwargs = kwargs
        result = super().run(cmd, **kwargs)
        if result.returncode == 0:
            live = self._cert_dir / self._domain / 'live' / self._domain
            live.mkdir(parents=True, exist_ok=True)
            for cert_file in CERTIFICATE_FILES:
                (live / cert_file).write_bytes(b'renewed-bytes\n')
        return result


def _prep_existing_cert(tmp_path, domain, metadata):
    d = tmp_path / domain
    d.mkdir(parents=True, exist_ok=True)
    (d / 'cert.pem').write_bytes(b'existing-cert\n')
    (d / 'metadata.json').write_text(json.dumps(metadata))
    return d


def test_renew_passes_timeout_to_shell_executor(tmp_path):
    domain = 'renew.example.com'
    # Empty metadata → no dns_provider → the DNS-config branch is skipped and
    # the renew goes straight to the certbot call.
    _prep_existing_cert(tmp_path, domain, metadata={})
    shell = _RenewExecutor(tmp_path, domain)
    mgr = _make_cert_mgr(tmp_path, shell)
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = mgr.renew_certificate(domain)
    assert result['success'] is True
    assert shell.last_kwargs.get('timeout') == 1800, (
        "renew must pass a timeout so a wedged certbot cannot hang the "
        "serial renewal job forever"
    )


def test_renew_times_out_cleanly_instead_of_hanging(tmp_path):
    domain = 'hang.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    shell = MockShellExecutor()
    shell.set_next_result(should_timeout=True)
    mgr = _make_cert_mgr(tmp_path, shell)
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        with pytest.raises(RuntimeError, match='timed out'):
            mgr.renew_certificate(domain)


# --------------------------------------------------------------------------
# P0-3b — scheduled renewal jobs carry a misfire grace + coalesce
# --------------------------------------------------------------------------

def test_scheduler_renewal_jobs_have_misfire_grace(monkeypatch, tmp_path):
    monkeypatch.setenv('DATA_DIR', str(tmp_path))
    factory._flask_app = None
    app, container = factory.create_app(test_config={'TESTING': True})
    try:
        assert container.scheduler is not None
        for job_id in ('certificate_renewal_check',
                       'client_certificate_renewal_check'):
            job = container.scheduler.get_job(job_id)
            assert job is not None, f"{job_id} not scheduled"
            assert job.misfire_grace_time == 21600, (
                f"{job_id} must tolerate a delayed fire (6h grace), not the "
                f"APScheduler 1s default that silently drops a missed day"
            )
            assert job.coalesce is True
    finally:
        if container.scheduler:
            container.scheduler.shutdown(wait=False)


# --------------------------------------------------------------------------
# P0-2 — batch-created domains are registered for automatic renewal
# --------------------------------------------------------------------------

def test_batch_create_registers_domains_for_renewal(tmp_path):
    app = Flask(__name__)
    app.config['TESTING'] = True

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'email': 'ops@example.com',
        'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
    }
    certificate_manager = MagicMock(cert_dir=Path(tmp_path))
    certificate_manager.create_certificate.return_value = {'success': True}

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.domain_matches_scope.return_value = True

    managers = {'audit': MagicMock(), 'cert_service': None}

    register_cert_routes(
        app, managers, _passthrough_decorator, auth_manager,
        certificate_manager, lambda d: d, MagicMock(),
        settings_manager, MagicMock(), CERTIFICATE_FILES,
    )

    @app.before_request
    def _attach_user():
        request.current_user = {
            'username': 'op', 'role': 'operator', 'allowed_domains': None,
        }

    client = app.test_client()
    resp = client.post('/api/web/certificates/batch', json={
        'domains': ['a.example.com', 'b.example.com'],
        'dns_provider': 'cloudflare',
    })
    assert resp.status_code == 200

    # The batch must persist the created domains so check_renewals sees them.
    settings_manager.update.assert_called_once()
    mutator, reason = settings_manager.update.call_args[0][:2]
    assert reason == 'certificate_created'

    s = {'domains': []}
    mutator(s)
    tracked = {d['domain'] for d in s['domains']}
    assert tracked == {'a.example.com', 'b.example.com'}


def test_batch_registration_is_idempotent(tmp_path):
    """Re-registering a domain that is already tracked must not duplicate it."""
    app = Flask(__name__)
    app.config['TESTING'] = True
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'email': 'ops@example.com', 'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
    }
    certificate_manager = MagicMock(cert_dir=Path(tmp_path))
    certificate_manager.create_certificate.return_value = {'success': True}
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.domain_matches_scope.return_value = True
    register_cert_routes(
        app, {'audit': MagicMock(), 'cert_service': None}, _passthrough_decorator,
        auth_manager, certificate_manager, lambda d: d, MagicMock(),
        settings_manager, MagicMock(), CERTIFICATE_FILES,
    )

    @app.before_request
    def _attach_user():
        request.current_user = {'username': 'op', 'role': 'operator', 'allowed_domains': None}

    client = app.test_client()
    client.post('/api/web/certificates/batch',
                json={'domains': ['a.example.com'], 'dns_provider': 'cloudflare'})
    mutator = settings_manager.update.call_args[0][0]
    s = {'domains': [{'domain': 'a.example.com', 'dns_provider': 'cloudflare'}]}
    mutator(s)
    assert [d['domain'] for d in s['domains']] == ['a.example.com']


# --------------------------------------------------------------------------
# P1-3 — a failed deploy hook is surfaced, not swallowed
# --------------------------------------------------------------------------

class _RecordingBus:
    def __init__(self):
        self.published = []

    def publish(self, event, data):
        self.published.append((event, data))

    def add_listener(self, fn):
        pass


def _make_deploy_mgr(tmp_path, shell):
    return DeployManager(
        settings_manager=MagicMock(),
        shell_executor=shell,
        audit_logger=MagicMock(),
        event_bus=_RecordingBus(),
        cert_dir=tmp_path,
        data_dir=str(tmp_path),
    )


def test_failed_deploy_hook_publishes_failure_event(tmp_path):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=1, stderr='nginx reload failed')
    dm = _make_deploy_mgr(tmp_path, shell)
    hook = {'id': 'h1', 'name': 'reload-nginx',
            'command': 'systemctl reload nginx', 'timeout': 5}

    result = dm._run_hook(hook, 'example.com', 'renewed')

    assert result['success'] is False
    failures = [d for e, d in dm.event_bus.published if e == 'deploy_hook_failed']
    assert len(failures) == 1, "a failed hook must publish deploy_hook_failed"
    assert failures[0]['hook_name'] == 'reload-nginx'
    assert failures[0]['domain'] == 'example.com'


def test_dry_run_hook_failure_does_not_publish_failure_event(tmp_path):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=1)
    dm = _make_deploy_mgr(tmp_path, shell)
    hook = {'id': 'h1', 'name': 'x', 'command': 'systemctl reload nginx', 'timeout': 5}

    dm._run_hook(hook, 'example.com', 'renewed', dry_run=True)

    events = {e for e, _ in dm.event_bus.published}
    assert 'deploy_hook_failed' not in events


def test_successful_deploy_hook_does_not_publish_failure_event(tmp_path):
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)
    dm = _make_deploy_mgr(tmp_path, shell)
    hook = {'id': 'h1', 'name': 'ok', 'command': 'systemctl reload nginx', 'timeout': 5}

    result = dm._run_hook(hook, 'example.com', 'renewed')

    assert result['success'] is True
    events = {e for e, _ in dm.event_bus.published}
    assert 'deploy_hook_failed' not in events


# --------------------------------------------------------------------------
# P1-5 — a renewed private key must keep mode 0600, not fall back to 0644
# --------------------------------------------------------------------------

class _RenewExecutorWithModes(MockShellExecutor):
    """Stages renewed live files with certbot's real modes: privkey 0600,
    the rest 0644."""

    def __init__(self, cert_dir, domain):
        super().__init__()
        self._cert_dir = Path(cert_dir)
        self._domain = domain
        self.set_next_result(returncode=0)

    def run(self, cmd, **kwargs):
        result = super().run(cmd, **kwargs)
        if result.returncode == 0:
            live = self._cert_dir / self._domain / 'live' / self._domain
            live.mkdir(parents=True, exist_ok=True)
            for cert_file in CERTIFICATE_FILES:
                p = live / cert_file
                p.write_bytes(b'renewed\n')
                os.chmod(p, 0o600 if cert_file == 'privkey.pem' else 0o644)
        return result


def test_renew_preserves_private_key_0600(tmp_path):
    domain = 'perm.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    mgr = _make_cert_mgr(tmp_path, _RenewExecutorWithModes(tmp_path, domain))
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = mgr.renew_certificate(domain)
    assert result['success'] is True
    privkey = tmp_path / domain / 'privkey.pem'
    assert stat.S_IMODE(os.stat(privkey).st_mode) == 0o600, (
        "the renewed private key must stay 0600 — the atomic copy must "
        "copymode from the source, not leave it at the umask default 0644"
    )


# --------------------------------------------------------------------------
# P1-6 — the default local backend writes atomically at the right mode
# --------------------------------------------------------------------------

def test_local_backend_store_is_atomic_and_secure(tmp_path):
    backend = LocalFileSystemBackend(tmp_path)
    ok = backend.store_certificate(
        'd.example.com',
        {'cert.pem': b'CERT-BYTES', 'privkey.pem': b'KEY-BYTES'},
        {'domain': 'd.example.com'},
    )
    assert ok is True
    dom = tmp_path / 'd.example.com'
    assert (dom / 'cert.pem').read_bytes() == b'CERT-BYTES'
    assert (dom / 'privkey.pem').read_bytes() == b'KEY-BYTES'
    assert stat.S_IMODE(os.stat(dom / 'privkey.pem').st_mode) == 0o600
    assert stat.S_IMODE(os.stat(dom / 'cert.pem').st_mode) == 0o644
    assert stat.S_IMODE(os.stat(dom / 'metadata.json').st_mode) == 0o600
    # No temp residue must survive a successful write.
    assert not any(p.name.startswith('.tmp-') for p in dom.iterdir())


# --------------------------------------------------------------------------
# P2: a scheduled renew must not report "renewed" when certbot no-ops
# --------------------------------------------------------------------------

def test_renew_reports_not_due_without_stamping(tmp_path):
    """certbot exits 0 with 'not yet due' when the threshold is wider than its
    own window. That must report renewed=False and NOT stamp renewed_at, or
    telemetry falsely shows a daily renewal that never happened."""
    domain = 'notdue.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0, stdout="Cert is not yet due for renewal; no action taken.")
    mgr = _make_cert_mgr(tmp_path, shell)
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        res = mgr.renew_certificate(domain)
    assert res['success'] is True
    assert res['renewed'] is False
    meta = json.loads((tmp_path / domain / 'metadata.json').read_text())
    assert 'renewed_at' not in meta


def test_renew_reports_renewed_when_certbot_acts(tmp_path):
    domain = 'due.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    shell = _RenewExecutor(tmp_path, domain)   # stages files, no "not due" text
    mgr = _make_cert_mgr(tmp_path, shell)
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        res = mgr.renew_certificate(domain)
    assert res['success'] is True
    assert res['renewed'] is True


# --------------------------------------------------------------------------
# No-op renewal detection must be output-independent (fingerprint-based).
# certbot 2.x under --quiet sends "not yet due for renewal" to /dev/null, so
# a production no-op renew exits 0 with EMPTY output; the artifact (live
# cert bytes) is the only signal certbot cannot suppress.
# --------------------------------------------------------------------------

class _SilentNoOpExecutor(MockShellExecutor):
    """certbot exits 0 with EMPTY output and touches NO files — the exact
    production shape of a --quiet no-op renew. produces_artifacts=True marks
    this as a real execution so the fingerprint comparison is active."""
    produces_artifacts = True

    def __init__(self):
        super().__init__()
        self.set_next_result(returncode=0)


class _SilentRenewExecutor(_RenewExecutor):
    """Real-execution semantics (fingerprint comparison active) AND stages
    changed live files, with empty output either way."""
    produces_artifacts = True


def _prep_live_cert(tmp_path, domain, content=b'live-cert-v1\n'):
    live = tmp_path / domain / 'live' / domain
    live.mkdir(parents=True, exist_ok=True)
    for cert_file in CERTIFICATE_FILES:
        (live / cert_file).write_bytes(content)
    return live


def test_renew_noop_detected_with_empty_output(tmp_path):
    """rc=0 + empty stdout/stderr + unchanged live cert -> renewed=False and
    renewed_at NOT stamped. The old sentinel-only check reported this as a
    successful renewal because the sentinel text never appears under --quiet."""
    domain = 'silent-noop.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    _prep_live_cert(tmp_path, domain)
    mgr = _make_cert_mgr(tmp_path, _SilentNoOpExecutor())
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        res = mgr.renew_certificate(domain)
    assert res['success'] is True
    assert res['renewed'] is False
    meta = json.loads((tmp_path / domain / 'metadata.json').read_text())
    assert 'renewed_at' not in meta


def test_renew_detected_when_cert_bytes_change(tmp_path):
    """rc=0 + empty output + CHANGED live cert bytes -> renewed=True with
    renewed_at stamped (a real renewal says nothing under --quiet either)."""
    domain = 'silent-renew.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    _prep_live_cert(tmp_path, domain)  # executor overwrites with new bytes
    mgr = _make_cert_mgr(tmp_path, _SilentRenewExecutor(tmp_path, domain))
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        res = mgr.renew_certificate(domain)
    assert res['success'] is True
    assert res['renewed'] is True
    meta = json.loads((tmp_path / domain / 'metadata.json').read_text())
    assert 'renewed_at' in meta


def test_renew_detected_when_live_cert_appears(tmp_path):
    """Missing-before but present-after live cert counts as a renewal."""
    domain = 'fresh-live.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    # No pre-existing live dir: the executor materialises it.
    mgr = _make_cert_mgr(tmp_path, _SilentRenewExecutor(tmp_path, domain))
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        res = mgr.renew_certificate(domain)
    assert res['renewed'] is True


def test_renew_sentinel_still_detected_for_mock_executors(tmp_path):
    """Non-artifact-producing doubles keep sentinel-based detection: the
    fingerprint would always read 'unchanged' for them and falsely no-op."""
    domain = 'mock-sentinel.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0, stdout='no renewals were attempted')
    mgr = _make_cert_mgr(tmp_path, shell)
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        res = mgr.renew_certificate(domain)
    assert res['renewed'] is False


def test_check_renewals_routes_silent_noop_to_skipped_not_due(tmp_path):
    """A silent no-op renew must be counted as skipped_not_due — never as
    renewed — and must fire NO deploy hook event and NO success audit."""
    domain = 'sched-noop.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    _prep_live_cert(tmp_path, domain)
    mgr = _make_cert_mgr(tmp_path, _SilentNoOpExecutor())
    mgr.settings_manager.load_settings.return_value = {
        'auto_renew': True, 'domains': [{'domain': domain}],
    }
    mgr.settings_manager.migrate_domains_format.side_effect = lambda s: s
    mgr._publish_renewed_event = MagicMock()
    mgr._audit_scheduled_renew = MagicMock()
    with patch.object(CertificateManager, 'get_certificate_info',
                      return_value={'needs_renewal': True}), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        summary = mgr.check_renewals()
    assert summary['skipped_not_due'] == 1
    assert summary['renewed'] == 0
    mgr._publish_renewed_event.assert_not_called()
    mgr._audit_scheduled_renew.assert_not_called()


def test_check_renewals_counts_real_renewal_and_fires_hook(tmp_path):
    domain = 'sched-renew.example.com'
    _prep_existing_cert(tmp_path, domain, metadata={})
    _prep_live_cert(tmp_path, domain)
    mgr = _make_cert_mgr(tmp_path, _SilentRenewExecutor(tmp_path, domain))
    mgr.settings_manager.load_settings.return_value = {
        'auto_renew': True, 'domains': [{'domain': domain}],
    }
    mgr.settings_manager.migrate_domains_format.side_effect = lambda s: s
    mgr._publish_renewed_event = MagicMock()
    mgr._audit_scheduled_renew = MagicMock()
    with patch.object(CertificateManager, 'get_certificate_info',
                      return_value={'needs_renewal': True}), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        summary = mgr.check_renewals()
    assert summary['renewed'] == 1
    assert summary['skipped_not_due'] == 0
    mgr._publish_renewed_event.assert_called_once_with(domain)


# --------------------------------------------------------------------------
# API/web honesty: the renew responses must carry 'renewed' and must not
# claim (or event-broadcast) a renewal that certbot no-oped.
# --------------------------------------------------------------------------

def _build_api_app(tmp_path, renew_result):
    from flask_restx import Api, Namespace
    from modules.api.models import create_api_models
    from modules.api.resources import create_api_resources

    auth = MagicMock()
    auth.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth.user_can_access_domain.return_value = True

    certs = MagicMock(cert_dir=Path(tmp_path))
    certs.renew_certificate.return_value = renew_result

    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': 'ops@example.com', 'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01'}

    managers = {
        'auth': auth, 'settings': settings, 'certificates': certs,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)), 'cache': MagicMock(),
        'dns': MagicMock(), 'audit': None, 'cert_executor': None,
    }

    app = Flask(__name__)
    app.config['TESTING'] = True
    app.config['EVENT_BUS'] = MagicMock()
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)
    ns = Namespace('certificates', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['RenewCertificate'], '/<string:domain>/renew')

    @app.before_request
    def _attach_user():
        request.current_user = {'username': 'op', 'role': 'operator', 'allowed_domains': None}

    return app


def test_api_renew_response_reports_noop_honestly(tmp_path):
    app = _build_api_app(tmp_path, {
        'success': True, 'renewed': False, 'domain': 'x.example.com',
        'message': 'Certificate not yet due for renewal'})
    r = app.test_client().post('/api/certificates/x.example.com/renew')
    assert r.status_code == 200
    body = r.get_json()
    assert body['renewed'] is False
    assert 'not yet due' in body['message']
    assert 'renewed successfully' not in body['message']
    # Nothing was replaced: deploy hooks must not fire.
    app.config['EVENT_BUS'].publish.assert_not_called()


def test_api_renew_response_reports_real_renewal(tmp_path):
    app = _build_api_app(tmp_path, {
        'success': True, 'renewed': True, 'domain': 'x.example.com',
        'message': 'Certificate renewed successfully'})
    r = app.test_client().post('/api/certificates/x.example.com/renew')
    assert r.status_code == 200
    body = r.get_json()
    assert body['renewed'] is True
    assert 'renewed successfully' in body['message']
    app.config['EVENT_BUS'].publish.assert_called_once_with(
        'certificate_renewed', {'domain': 'x.example.com'})


def test_api_renew_defaults_renewed_true_for_legacy_results(tmp_path):
    """Frozen compat contract: a manager result without the 'renewed' key
    (older shape) must keep reporting a successful renewal."""
    app = _build_api_app(tmp_path, {'success': True, 'domain': 'x.example.com'})
    r = app.test_client().post('/api/certificates/x.example.com/renew')
    assert r.status_code == 200
    assert r.get_json()['renewed'] is True


def _build_web_app(tmp_path, renew_result):
    app = Flask(__name__)
    app.config['TESTING'] = True

    certificate_manager = MagicMock(cert_dir=Path(tmp_path))
    certificate_manager.renew_certificate.return_value = renew_result
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.domain_matches_scope.return_value = True
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {'email': 'ops@example.com'}

    register_cert_routes(
        app, {'audit': MagicMock(), 'cert_service': None}, _passthrough_decorator,
        auth_manager, certificate_manager,
        lambda d, cert_dir: (Path(cert_dir) / d, None), MagicMock(cert_dir=Path(tmp_path)),
        settings_manager, MagicMock(), CERTIFICATE_FILES,
    )

    @app.before_request
    def _attach_user():
        request.current_user = {'username': 'op', 'role': 'operator', 'allowed_domains': None}

    return app


def test_web_renew_response_reports_noop_honestly(tmp_path):
    app = _build_web_app(tmp_path, {
        'success': True, 'renewed': False, 'domain': 'x.example.com',
        'message': 'Certificate not yet due for renewal'})
    r = app.test_client().post('/api/web/certificates/x.example.com/renew')
    assert r.status_code == 200
    body = r.get_json()
    assert body['renewed'] is False
    assert body['message'] == 'Certificate not yet due for renewal'


def test_web_renew_response_reports_real_renewal(tmp_path):
    app = _build_web_app(tmp_path, {
        'success': True, 'renewed': True, 'domain': 'x.example.com',
        'message': 'Certificate renewed successfully'})
    r = app.test_client().post('/api/web/certificates/x.example.com/renew')
    assert r.status_code == 200
    body = r.get_json()
    assert body['renewed'] is True
    assert body['message'] == 'Certificate renewed successfully'
