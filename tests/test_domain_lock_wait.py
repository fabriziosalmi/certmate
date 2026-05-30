"""Coverage for the bounded per-domain lock wait + 409 mapping.

Behaviour under test (modules/core/certificates.py and the create/renew
routes):

1. create_certificate / renew_certificate acquire the per-domain lock with a
   bounded timeout (CERTMATE_DOMAIN_LOCK_TIMEOUT, default 5s). When the lock
   can't be acquired in time they raise DomainOperationInProgress, which
   carries the busy domain and subclasses RuntimeError (so legacy callers that
   only catch RuntimeError keep working instead of 500-crashing).

2. _domain_lock_timeout() reads/clamps the env override.

3. The four create/renew routes (web + API) surface the busy condition as
   HTTP 409 with machine code DOMAIN_OPERATION_IN_PROGRESS — distinct from the
   422 certbot-error bucket and the generic 500.

Most manager/helper tests pin the timeout to 0 so acquire returns immediately
(False) — fast and deterministic, no real threads needed. A separate group
(TestLockWaitGracePeriod) exercises the bounded WAIT with timeout > 0 using
real threads and bounded sleeps: it proves the call blocks until the holder
releases (then proceeds past the barrier) and, when nobody releases, blocks for
~the configured timeout before giving up. The route tests run in-process via
Flask's test client with mocked managers.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Namespace

from modules.core.certificates import CertificateManager, DomainOperationInProgress
from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
from modules.web.cert_routes import register_cert_routes


pytestmark = [pytest.mark.unit]


def _make_manager(tmp_path):
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=MagicMock(),
        dns_manager=MagicMock(),
        storage_manager=None,
        ca_manager=None,
    )


# ---------------------------------------------------------------------------
# Manager-level: lock wait -> DomainOperationInProgress
# ---------------------------------------------------------------------------


class TestLockWaitRaises:
    def test_create_certificate_raises_domain_in_progress(self, tmp_path, monkeypatch):
        """With the lock already held and timeout pinned to 0, create_certificate
        must raise DomainOperationInProgress carrying the busy domain."""
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "0")
        mgr = _make_manager(tmp_path)
        held = mgr._get_domain_lock("busy.example.com")
        assert held.acquire(blocking=False) is True
        try:
            with pytest.raises(DomainOperationInProgress) as exc:
                mgr.create_certificate(domain="busy.example.com",
                                       email="t@example.com")
            assert exc.value.domain == "busy.example.com"
            assert "already in progress" in str(exc.value)
        finally:
            held.release()

    def test_renew_certificate_raises_domain_in_progress(self, tmp_path, monkeypatch):
        """Same contract for renew_certificate."""
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "0")
        mgr = _make_manager(tmp_path)
        held = mgr._get_domain_lock("busy.example.com")
        assert held.acquire(blocking=False) is True
        try:
            with pytest.raises(DomainOperationInProgress) as exc:
                mgr.renew_certificate("busy.example.com")
            assert exc.value.domain == "busy.example.com"
        finally:
            held.release()

    def test_domain_operation_in_progress_is_runtime_error_subclass(self):
        """Backward-compat: routes that still only catch RuntimeError keep
        working (they degrade to their old status) instead of 500-crashing."""
        assert issubclass(DomainOperationInProgress, RuntimeError)
        err = DomainOperationInProgress("x.com")
        assert isinstance(err, RuntimeError)
        assert err.domain == "x.com"


# ---------------------------------------------------------------------------
# Bounded WAIT (timeout > 0) — the actual grace-period behaviour this PR adds.
# These use real threads + small sleeps; total added runtime is well under 1s.
# ---------------------------------------------------------------------------


class TestLockWaitGracePeriod:
    def test_create_waits_for_release_then_proceeds(self, tmp_path, monkeypatch):
        """Hold the lock from a helper thread that releases it after a short
        delay, with a generous timeout (2s). create_certificate must BLOCK
        until the release, acquire the lock, and proceed past the barrier into
        the normal flow — where the pre-staged cert.pem makes it raise
        FileExistsError. Getting FileExistsError (not DomainOperationInProgress)
        proves the wait succeeded and we got past the lock."""
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "2")
        mgr = _make_manager(tmp_path)
        domain = "wait.example.com"

        # Pre-stage cert.pem so the post-lock existence check fires.
        domain_dir = Path(tmp_path) / domain
        domain_dir.mkdir(parents=True, exist_ok=True)
        (domain_dir / "cert.pem").write_text("dummy")

        held = mgr._get_domain_lock(domain)
        assert held.acquire(blocking=False) is True
        released = threading.Event()

        def _release_after_delay():
            time.sleep(0.1)
            held.release()
            released.set()

        releaser = threading.Thread(target=_release_after_delay)
        releaser.start()
        try:
            with pytest.raises(FileExistsError):
                mgr.create_certificate(domain=domain, email="t@example.com")
            # By the time create_certificate returned, it must have acquired
            # the lock, which is only possible after the helper released it.
            assert released.is_set()
        finally:
            releaser.join(timeout=5)
            # Lock was acquired inside create_certificate; that flow releases
            # it in its own finally, so it should be free again here.
            assert held.acquire(blocking=False) is True
            held.release()

    def test_create_blocks_for_timeout_then_raises(self, tmp_path, monkeypatch):
        """Hold the lock for the whole test (never release) with a small
        timeout. create_certificate must BLOCK for ~the timeout before raising
        DomainOperationInProgress — proving it actually waited rather than
        instant-rejecting."""
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "0.2")
        mgr = _make_manager(tmp_path)
        domain = "stuck.example.com"

        held = mgr._get_domain_lock(domain)
        assert held.acquire(blocking=False) is True
        try:
            t0 = time.monotonic()
            with pytest.raises(DomainOperationInProgress) as exc:
                mgr.create_certificate(domain=domain, email="t@example.com")
            elapsed = time.monotonic() - t0
            assert exc.value.domain == domain
            # Allow a little slack below 0.2 for timer granularity, but it must
            # be clearly more than an instant reject.
            assert elapsed >= 0.18, f"expected to block ~0.2s, blocked {elapsed:.3f}s"
        finally:
            held.release()

    def test_renew_waits_for_release_then_proceeds(self, tmp_path, monkeypatch):
        """Same shape as the create wait test, for renew_certificate. With no
        cert staged, the first thing renew does after acquiring the lock is the
        existence check, which raises 'No certificate found...'. renew's broad
        try/except re-wraps that as a plain RuntimeError (the lock acquire sits
        BEFORE the try, so a DomainOperationInProgress would never be wrapped).
        Getting a RuntimeError carrying 'No certificate found' — and crucially
        NOT a DomainOperationInProgress — proves renew waited for the release
        and got past the barrier into its normal flow."""
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "2")
        mgr = _make_manager(tmp_path)
        domain = "renewwait.example.com"

        held = mgr._get_domain_lock(domain)
        assert held.acquire(blocking=False) is True
        released = threading.Event()

        def _release_after_delay():
            time.sleep(0.1)
            held.release()
            released.set()

        releaser = threading.Thread(target=_release_after_delay)
        releaser.start()
        try:
            with pytest.raises(RuntimeError) as exc:
                mgr.renew_certificate(domain)
            assert not isinstance(exc.value, DomainOperationInProgress)
            assert "No certificate found" in str(exc.value)
            assert released.is_set()
        finally:
            releaser.join(timeout=5)
            assert held.acquire(blocking=False) is True
            held.release()


# ---------------------------------------------------------------------------
# _domain_lock_timeout helper
# ---------------------------------------------------------------------------


class TestDomainLockTimeoutHelper:
    def test_default_is_five_seconds(self, monkeypatch):
        monkeypatch.delenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", raising=False)
        assert CertificateManager._domain_lock_timeout() == 5.0

    def test_respects_env_override(self, monkeypatch):
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "12.5")
        assert CertificateManager._domain_lock_timeout() == 12.5

    def test_clamps_to_zero_floor(self, monkeypatch):
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "-7")
        assert CertificateManager._domain_lock_timeout() == 0.0

    def test_clamps_to_sixty_ceiling(self, monkeypatch):
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "999")
        assert CertificateManager._domain_lock_timeout() == 60.0

    def test_falls_back_to_five_on_garbage(self, monkeypatch):
        monkeypatch.setenv("CERTMATE_DOMAIN_LOCK_TIMEOUT", "not-a-number")
        assert CertificateManager._domain_lock_timeout() == 5.0


# ---------------------------------------------------------------------------
# Route mapping -> 409 DOMAIN_OPERATION_IN_PROGRESS
# ---------------------------------------------------------------------------


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


def _make_route_managers(tmp_path):
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    # Scope check passes: user_can_access_domain returns truthy.
    auth_manager.user_can_access_domain.return_value = True

    cert_manager = MagicMock()
    cert_manager.cert_dir = Path(tmp_path)

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'email': 't@example.com',
        'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
    }

    file_ops = MagicMock(cert_dir=Path(tmp_path))

    return {
        'auth': auth_manager,
        'settings': settings_manager,
        'certificates': cert_manager,
        'file_ops': file_ops,
        'cache': MagicMock(),
        'dns': MagicMock(),
        'audit': None,
    }


def _build_api_app(managers):
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)
    ns = Namespace('certs', description='certs')
    api.add_namespace(ns)
    ns.add_resource(resources['CreateCertificate'], '/create')
    ns.add_resource(resources['RenewCertificate'], '/<string:domain>/renew')
    return app


def _build_web_app(managers, tmp_path):
    app = Flask(__name__)
    app.config['TESTING'] = True

    def _sanitize_domain(domain, _cert_dir):
        # Return a path whose .name is the domain and no error.
        return Path(tmp_path) / domain, None

    register_cert_routes(
        app,
        managers,
        require_web_auth=_passthrough_decorator,
        auth_manager=managers['auth'],
        certificate_manager=managers['certificates'],
        _sanitize_domain=_sanitize_domain,
        file_ops=managers['file_ops'],
        settings_manager=managers['settings'],
        dns_manager=managers['dns'],
        CERTIFICATE_FILES={},
    )
    return app


class TestApiRouteMapping:
    def test_create_returns_409(self, tmp_path):
        managers = _make_route_managers(tmp_path)
        managers['certificates'].create_certificate.side_effect = \
            DomainOperationInProgress('x.com')
        app = _build_api_app(managers)
        r = app.test_client().post(
            '/api/certs/create',
            json={'domain': 'x.com', 'dns_provider': 'cloudflare'},
        )
        assert r.status_code == 409
        body = r.get_json()
        assert body['code'] == 'DOMAIN_OPERATION_IN_PROGRESS'

    def test_renew_returns_409_without_failure_event(self, tmp_path):
        managers = _make_route_managers(tmp_path)
        managers['certificates'].renew_certificate.side_effect = \
            DomainOperationInProgress('x.com')
        event_bus = MagicMock()
        app = _build_api_app(managers)
        app.config['EVENT_BUS'] = event_bus
        r = app.test_client().post('/api/certs/x.com/renew', json={})
        assert r.status_code == 409
        body = r.get_json()
        assert body['code'] == 'DOMAIN_OPERATION_IN_PROGRESS'
        # Busy is not a failure: no certificate_failed event is published.
        published = [c.args[0] for c in event_bus.publish.call_args_list]
        assert 'certificate_failed' not in published


class TestWebRouteMapping:
    def test_create_web_returns_409(self, tmp_path):
        managers = _make_route_managers(tmp_path)
        managers['certificates'].create_certificate.side_effect = \
            DomainOperationInProgress('x.com')
        app = _build_web_app(managers, tmp_path)
        r = app.test_client().post(
            '/api/web/certificates/create',
            json={'domain': 'x.com', 'dns_provider': 'cloudflare'},
        )
        assert r.status_code == 409
        body = r.get_json()
        assert body['code'] == 'DOMAIN_OPERATION_IN_PROGRESS'

    def test_renew_web_returns_409(self, tmp_path):
        managers = _make_route_managers(tmp_path)
        managers['certificates'].renew_certificate.side_effect = \
            DomainOperationInProgress('x.com')
        app = _build_web_app(managers, tmp_path)
        r = app.test_client().post('/api/web/certificates/x.com/renew', json={})
        assert r.status_code == 409
        body = r.get_json()
        assert body['code'] == 'DOMAIN_OPERATION_IN_PROGRESS'


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
