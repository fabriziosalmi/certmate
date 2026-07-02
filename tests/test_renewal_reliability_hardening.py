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
