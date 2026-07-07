"""
Regression tests for deployment-status cache invalidation on cert (re)issue/renew.

The deployment-status cache used to keep a stale "deployed & matching" verdict
for up to cache_ttl after a renewal, even though the load balancer might still
serve the OLD certificate (the deploy hook may not have run yet). The
CacheManager now subscribes to certificate_created / certificate_renewed on the
EventBus and evicts the affected domain, so the next dashboard read re-probes.
"""

import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
import modules.api.resources as api_resources_module
from modules.core.cache import CacheManager
from modules.core.events import EventBus


pytestmark = [pytest.mark.unit]


def _real_cache_manager():
    """A real CacheManager (not a mock) so eviction actually mutates state."""
    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {'cache_ttl': 300}
    return CacheManager(settings_manager)


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


def _build_app(managers):
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)
    ns = Namespace('certificates', description='Certificate operations')
    api.add_namespace(ns)
    ns.add_resource(
        resources['CertificateDeploymentStatus'],
        '/<string:domain>/deployment-status',
    )
    return app


def test_certificate_renewed_event_evicts_only_that_domain():
    """certificate_renewed for X drops X's cached verdict and leaves an
    unrelated domain's entry intact."""
    cache = _real_cache_manager()
    cache.set_deployment_status('example.com', {'domain': 'example.com', 'certificate_match': True})
    cache.set_deployment_status('example.net', {'domain': 'example.net', 'certificate_match': True})

    cache.on_certificate_event('certificate_renewed', {'domain': 'example.com'})

    assert cache.get_deployment_status('example.com') is None
    assert cache.get_deployment_status('example.net') == {
        'domain': 'example.net', 'certificate_match': True,
    }


def test_certificate_created_event_evicts_domain():
    """create (and, via cert_jobs, reissue) also invalidate."""
    cache = _real_cache_manager()
    cache.set_deployment_status('example.com', {'domain': 'example.com'})
    cache.on_certificate_event('certificate_created', {'domain': 'example.com'})
    assert cache.get_deployment_status('example.com') is None


def test_unrelated_events_leave_cache_intact():
    """Events that are not a (re)issue/renew, and payloads with no domain, must
    not evict anything (guard against over-invalidation)."""
    cache = _real_cache_manager()
    cache.set_deployment_status('example.com', {'domain': 'example.com'})

    cache.on_certificate_event('certificate_failed', {'domain': 'example.com'})
    cache.on_certificate_event('certificate_deleted', {'domain': 'example.com'})
    cache.on_certificate_event('certificate_renewed', {})  # missing domain

    assert cache.get_deployment_status('example.com') == {'domain': 'example.com'}


def test_event_bus_publish_invalidates_via_listener():
    """Wired exactly like factory.py: publishing certificate_renewed on the bus
    evicts the domain. Proves the single subscription covers every publisher —
    the API sync route, the async IssuanceExecutor, the web path, and the
    scheduled renewal all publish this event on this bus."""
    cache = _real_cache_manager()
    cache.set_deployment_status('example.com', {'domain': 'example.com'})
    cache.set_deployment_status('example.net', {'domain': 'example.net'})

    bus = EventBus()
    bus.add_listener(cache.on_certificate_event)
    bus.publish('certificate_renewed', {'domain': 'example.com'})

    # EventBus invokes listeners in daemon threads; poll until X is evicted.
    deadline = time.time() + 5
    while cache.get_deployment_status('example.com') is not None and time.time() < deadline:
        time.sleep(0.01)

    assert cache.get_deployment_status('example.com') is None
    assert cache.get_deployment_status('example.net') is not None


def test_deployment_status_reprobes_after_renewal(tmp_path, monkeypatch):
    """End-to-end: a cached 'matching' verdict is served without probing; after
    a certificate_renewed event the next dashboard read re-probes (the prober is
    called again). An unrelated domain keeps serving its cached verdict."""
    renewed, other = 'example.com', 'example.net'
    (tmp_path / renewed).mkdir(parents=True)
    (tmp_path / renewed / 'cert.pem').write_bytes(b'expected-cert-bytes')

    cache = _real_cache_manager()
    cache.set_deployment_status(renewed, {
        'domain': renewed, 'deployed': True, 'reachable': True, 'certificate_match': True,
    })
    cache.set_deployment_status(other, {
        'domain': other, 'deployed': True, 'reachable': True, 'certificate_match': True,
    })

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    certificate_manager = MagicMock(
        cert_dir=Path(tmp_path),
        storage_manager=None,
        get_certificate_info=MagicMock(return_value={'exists': True}),
        _load_metadata=MagicMock(return_value={}),
    )

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': certificate_manager,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': cache,
        'dns': MagicMock(),
    }

    monkeypatch.setattr(
        api_resources_module, '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'other',
    )
    prober = MagicMock(return_value={
        'reachable': True,
        'certificate_bytes': b'expected-cert-bytes',
        'port': 443,
        'protocol': 'https-tls',
    })
    monkeypatch.setattr(api_resources_module, '_probe_tls_certificate', prober)

    app = _build_app(managers)
    client = app.test_client()

    # 1) Cache hit — served straight from cache, prober NOT called.
    r1 = client.get(f'/api/certificates/{renewed}/deployment-status')
    assert r1.status_code == 200
    assert r1.get_json()['certificate_match'] is True
    assert prober.call_count == 0

    # 2) A renewal invalidates the domain's cached verdict (as factory wires it).
    cache.on_certificate_event('certificate_renewed', {'domain': renewed})

    # 3) The next read for the renewed domain re-probes.
    r2 = client.get(f'/api/certificates/{renewed}/deployment-status')
    assert r2.status_code == 200
    assert prober.call_count == 1

    # 4) An unrelated domain is still served from cache — no extra probe.
    r3 = client.get(f'/api/certificates/{other}/deployment-status')
    assert r3.status_code == 200
    assert r3.get_json()['domain'] == other
    assert prober.call_count == 1
