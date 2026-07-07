import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
import modules.api.resources as api_resources_module


pytestmark = [pytest.mark.unit]


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

    ns_certificates = Namespace('certificates', description='Certificate operations')
    api.add_namespace(ns_certificates)
    ns_certificates.add_resource(resources['CertificateDeploymentStatus'], '/<string:domain>/deployment-status')
    ns_certificates.add_resource(resources['CertificateDeploymentBrowserReports'], '/deployment-status/browser')
    return app


def test_deployment_status_route_exists_and_returns_match(tmp_path, monkeypatch):
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': MagicMock(
            cert_dir=Path(tmp_path),
            storage_manager=None,
            get_certificate_info=MagicMock(return_value={'exists': True}),
            _load_metadata=MagicMock(return_value={}),
        ),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(
            get_deployment_status=MagicMock(return_value=None),
            set_deployment_status=MagicMock(),
        ),
        'dns': MagicMock(),
    }

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'other',
    )
    monkeypatch.setattr(
        api_resources_module,
        '_probe_tls_certificate',
        lambda _domain, **_kw: {'reachable': True, 'certificate_bytes': b'expected-cert-bytes'},
    )

    app = _build_app(managers)
    client = app.test_client()

    response = client.get(f'/api/certificates/{domain}/deployment-status')

    assert response.status_code == 200
    body = response.get_json()
    assert body['domain'] == domain
    assert body['deployed'] is True
    assert body['reachable'] is True
    assert body['certificate_match'] is True
    assert body['method'] == 'https-tls'


def test_deployment_status_refresh_bypasses_cache(tmp_path, monkeypatch):
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    cache_manager = MagicMock(
        get_deployment_status=MagicMock(return_value={
            'domain': domain,
            'deployed': True,
            'reachable': True,
            'certificate_match': True,
        }),
        set_deployment_status=MagicMock(),
        remove_from_cache=MagicMock(),
    )

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': MagicMock(
            cert_dir=Path(tmp_path),
            storage_manager=None,
            get_certificate_info=MagicMock(return_value={'exists': True}),
        ),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': cache_manager,
        'dns': MagicMock(),
    }

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'other',
    )
    monkeypatch.setattr(
        api_resources_module,
        '_probe_tls_certificate',
        lambda _domain, **_kw: {'reachable': True, 'certificate_bytes': b'expected-cert-bytes'},
    )

    app = _build_app(managers)
    client = app.test_client()

    response = client.get(f'/api/certificates/{domain}/deployment-status?refresh=1')

    assert response.status_code == 200
    body = response.get_json()
    assert body['certificate_match'] is True
    cache_manager.remove_from_cache.assert_called_once_with(domain)
    cache_manager.get_deployment_status.assert_not_called()


def test_deployment_status_denies_out_of_scope_domain(tmp_path, monkeypatch):
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.user_can_access_domain = MagicMock(return_value=False)

    certificate_manager = MagicMock(
        cert_dir=Path(tmp_path),
        storage_manager=None,
        get_certificate_info=MagicMock(return_value={'exists': True}),
    )

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': certificate_manager,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(
            get_deployment_status=MagicMock(return_value=None),
            set_deployment_status=MagicMock(),
            remove_from_cache=MagicMock(),
        ),
        'dns': MagicMock(),
    }

    app = _build_app(managers)
    client = app.test_client()

    response = client.get(f'/api/certificates/{domain}/deployment-status')

    assert response.status_code == 403
    assert response.get_json()['code'] == 'DOMAIN_OUT_OF_SCOPE'
    certificate_manager.get_certificate_info.assert_not_called()


def test_browser_report_is_persisted_separately(tmp_path, monkeypatch):
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    cache_manager = MagicMock(
        get_deployment_status=MagicMock(return_value=None),
        set_deployment_status=MagicMock(),
        remove_from_cache=MagicMock(),
    )

    certificate_manager = MagicMock()
    certificate_manager.cert_dir = Path(tmp_path)
    certificate_manager.storage_manager = None
    certificate_manager.get_certificate_info.return_value = {'exists': True}

    def _metadata_path():
        return cert_dir / 'metadata.json'

    def _load_metadata():
        if _metadata_path().exists():
            return json.loads(_metadata_path().read_text())
        return {}

    # The deployment-status route reads per-cert probe config via
    # certificate_manager._load_metadata(domain) (#328); wire it to the same
    # on-disk metadata the record_* side-effects use.
    certificate_manager._load_metadata.side_effect = lambda _domain: _load_metadata()

    def _write_metadata(metadata):
        _metadata_path().write_text(json.dumps(metadata, indent=2))

    def record_browser(_domain, report):
        metadata = _load_metadata()
        deployment_status = metadata.get('deployment_status', {})
        deployment_status['browser'] = {
            'reachable': bool(report.get('reachable', False)),
            'checked_at': report.get('checked_at'),
            'method': report.get('method'),
            'source': report.get('source'),
        }
        metadata['deployment_status'] = deployment_status
        _write_metadata(metadata)
        return deployment_status

    def record_backend(_domain, status):
        metadata = _load_metadata()
        deployment_status = metadata.get('deployment_status', {})
        deployment_status['backend'] = {
            'domain': status.get('domain', domain),
            'deployed': bool(status.get('deployed', False)),
            'reachable': bool(status.get('reachable', False)),
            'certificate_match': status.get('certificate_match'),
            'method': status.get('method'),
            'timestamp': status.get('timestamp'),
            'error': status.get('error'),
        }
        metadata['deployment_status'] = deployment_status
        _write_metadata(metadata)
        return deployment_status

    certificate_manager.get_deployment_status_record.side_effect = lambda _domain: _load_metadata().get('deployment_status', {})
    certificate_manager.record_browser_deployment_status.side_effect = record_browser
    certificate_manager.record_backend_deployment_status.side_effect = record_backend

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': certificate_manager,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': cache_manager,
        'dns': MagicMock(),
    }

    app = _build_app(managers)
    client = app.test_client()

    response = client.post('/api/certificates/deployment-status/browser', json={
        'reports': [{
            'domain': domain,
            'reachable': True,
            'checked_at': '2026-05-12T09:45:31.540941',
            'method': 'browser-fallback',
            'source': 'browser',
        }]
    })

    assert response.status_code == 200
    metadata = json.loads((cert_dir / 'metadata.json').read_text())
    assert metadata['deployment_status']['browser']['reachable'] is True
    assert metadata['deployment_status']['browser']['checked_at'] == '2026-05-12T09:45:31.540941'

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'other',
    )
    monkeypatch.setattr(
        api_resources_module,
        '_probe_tls_certificate',
        lambda _domain, **_kw: (_ for _ in ()).throw(ConnectionRefusedError('[Errno 111] Connection refused')),
    )

    response = client.get(f'/api/certificates/{domain}/deployment-status?refresh=1')
    assert response.status_code == 200
    body = response.get_json()
    assert body['reachable'] is False
    assert body['browser']['reachable'] is True
    assert body['browser']['checked_at'] == '2026-05-12T09:45:31.540941'


def _wildcard_managers(tmp_path, metadata=None):
    """Managers wired for a wildcard cert whose apex serves a DIFFERENT cert.

    The stored cert fingerprints as 'expected'; the probe (mocked per test)
    returns whatever bytes a test wants the live host to serve.
    """
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.user_can_access_domain = MagicMock(return_value=True)

    storage_manager = MagicMock()
    storage_manager.retrieve_certificate.return_value = ({'cert.pem': b'expected-cert-bytes'}, {})

    certificate_manager = MagicMock(
        cert_dir=Path(tmp_path),
        storage_manager=storage_manager,
        get_certificate_info=MagicMock(return_value={'exists': True}),
        _load_metadata=MagicMock(return_value=(metadata or {})),
        get_deployment_status_record=MagicMock(return_value={}),
        record_backend_deployment_status=MagicMock(),
    )

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': certificate_manager,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(
            get_deployment_status=MagicMock(return_value=None),
            set_deployment_status=MagicMock(),
            remove_from_cache=MagicMock(),
        ),
        'dns': MagicMock(),
    }
    return '*.example.com', managers


def test_wildcard_without_deployment_host_is_not_a_hard_mismatch(tmp_path, monkeypatch):
    """A wildcard cert must NOT report a red "wrong cert" just because the apex
    serves a different certificate (#207/#381). With no deployment_host it
    returns the non-alarming 'unverifiable' status and never probes the apex."""
    domain, managers = _wildcard_managers(tmp_path)

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'apex-other',
    )
    probe_called = {'count': 0}

    def _boom(_domain, **_kw):
        probe_called['count'] += 1
        return {'reachable': True, 'certificate_bytes': b'apex-serves-this'}

    monkeypatch.setattr(api_resources_module, '_probe_tls_certificate', _boom)

    app = _build_app(managers)
    response = app.test_client().get(f'/api/certificates/{domain}/deployment-status')

    assert response.status_code == 200
    body = response.get_json()
    assert probe_called['count'] == 0, 'host-less wildcard must not probe the apex'
    assert body['certificate_match'] is not True
    assert body['probe_status'] == 'unverifiable'
    assert body['mismatch_reason']
    assert 'deployment_host' in body['mismatch_reason']
    # Assert the wildcard form (with the *. label) rather than a bare host, so
    # the static analyzer does not read this as URL-substring sanitization.
    assert '*.example.com' in body['mismatch_reason']


def test_wildcard_with_deployment_host_probes_that_host(tmp_path, monkeypatch):
    """A wildcard cert with an explicit deployment_host probes THAT covered
    name (connect + SNI) and reports a normal match."""
    domain, managers = _wildcard_managers(
        tmp_path, metadata={'deployment_host': 'www.example.com'}
    )

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'other',
    )
    seen = {}

    def _probe(_domain, **kw):
        seen.update(kw)
        return {'reachable': True, 'certificate_bytes': b'expected-cert-bytes',
                'port': 443, 'protocol': 'https-tls'}

    monkeypatch.setattr(api_resources_module, '_probe_tls_certificate', _probe)

    app = _build_app(managers)
    response = app.test_client().get(f'/api/certificates/{domain}/deployment-status')

    assert response.status_code == 200
    body = response.get_json()
    assert seen.get('probe_host') == 'www.example.com'
    assert body['certificate_match'] is True
    assert body['probe_status'] == 'match'
    assert body['probe_host'] == 'www.example.com'


def test_mismatch_includes_diagnostic_reason(tmp_path, monkeypatch):
    """On a REAL mismatch the response must carry a machine/human-readable
    reason: which host was probed and served subject/fingerprint vs expected
    (#381 undiagnosability complaint)."""
    domain = 'app.example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': MagicMock(
            cert_dir=Path(tmp_path),
            storage_manager=None,
            get_certificate_info=MagicMock(return_value={'exists': True}),
            _load_metadata=MagicMock(return_value={}),
            get_deployment_status_record=MagicMock(return_value={}),
            record_backend_deployment_status=MagicMock(),
        ),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(
            get_deployment_status=MagicMock(return_value=None),
            set_deployment_status=MagicMock(),
        ),
        'dns': MagicMock(),
    }

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: ('expectedfingerprint00' if cert_bytes == b'expected-cert-bytes'
                            else 'servedfingerprint99'),
    )
    monkeypatch.setattr(
        api_resources_module,
        '_certificate_subject_summary',
        lambda cert_bytes: 'CN=intruder.example.net',
    )
    monkeypatch.setattr(
        api_resources_module,
        '_probe_tls_certificate',
        lambda _domain, **_kw: {'reachable': True, 'certificate_bytes': b'served-cert-bytes',
                                'port': 443, 'protocol': 'https-tls'},
    )

    app = _build_app(managers)
    response = app.test_client().get(f'/api/certificates/{domain}/deployment-status')

    assert response.status_code == 200
    body = response.get_json()
    assert body['certificate_match'] is False
    assert body['probe_status'] == 'mismatch'
    assert body['probe_host'] == domain
    assert body['served_subject'] == 'CN=intruder.example.net'
    assert body['served_fingerprint'] == 'servedfingerprint99'[:16]
    assert body['expected_fingerprint'] == 'expectedfingerprint00'[:16]
    reason = body['mismatch_reason']
    assert domain in reason
    # Assert the CN-qualified subject (as the reason renders it) rather than a
    # bare host, so the static analyzer does not read this as URL-substring
    # sanitization; served_subject is verified structurally above.
    assert 'CN=intruder.example.net' in reason


def test_non_wildcard_match_is_unchanged(tmp_path, monkeypatch):
    """A non-wildcard cert still probes its own host and reports a clean match
    with probe_status 'match' (behaviour preserved)."""
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': MagicMock(
            cert_dir=Path(tmp_path),
            storage_manager=None,
            get_certificate_info=MagicMock(return_value={'exists': True}),
            _load_metadata=MagicMock(return_value={}),
            get_deployment_status_record=MagicMock(return_value={}),
            record_backend_deployment_status=MagicMock(),
        ),
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(
            get_deployment_status=MagicMock(return_value=None),
            set_deployment_status=MagicMock(),
        ),
        'dns': MagicMock(),
    }

    monkeypatch.setattr(
        api_resources_module,
        '_certificate_fingerprint',
        lambda cert_bytes: 'expected' if cert_bytes == b'expected-cert-bytes' else 'other',
    )
    seen = {}

    def _probe(_domain, **kw):
        seen.update(kw)
        return {'reachable': True, 'certificate_bytes': b'expected-cert-bytes',
                'port': 443, 'protocol': 'https-tls'}

    monkeypatch.setattr(api_resources_module, '_probe_tls_certificate', _probe)

    app = _build_app(managers)
    response = app.test_client().get(f'/api/certificates/{domain}/deployment-status')

    assert response.status_code == 200
    body = response.get_json()
    # No explicit host -> probe its own name (probe_host override is None).
    assert seen.get('probe_host') is None
    assert body['certificate_match'] is True
    assert body['probe_status'] == 'match'
    assert body['probe_host'] == domain


def test_browser_report_skips_out_of_scope_domains(tmp_path):
    domain = 'example.com'
    cert_dir = tmp_path / domain
    cert_dir.mkdir(parents=True)
    (cert_dir / 'cert.pem').write_bytes(b'expected-cert-bytes')

    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)
    auth_manager.user_can_access_domain = MagicMock(return_value=False)

    certificate_manager = MagicMock()
    certificate_manager.cert_dir = Path(tmp_path)
    certificate_manager.storage_manager = None
    certificate_manager.get_certificate_info.return_value = {'exists': True}

    managers = {
        'auth': auth_manager,
        'settings': MagicMock(),
        'certificates': certificate_manager,
        'file_ops': MagicMock(cert_dir=Path(tmp_path)),
        'cache': MagicMock(
            get_deployment_status=MagicMock(return_value=None),
            set_deployment_status=MagicMock(),
            remove_from_cache=MagicMock(),
        ),
        'dns': MagicMock(),
    }

    app = _build_app(managers)
    client = app.test_client()

    response = client.post('/api/certificates/deployment-status/browser', json={
        'reports': [{
            'domain': domain,
            'reachable': True,
            'checked_at': '2026-05-12T09:45:31.540941',
            'method': 'browser-fallback',
            'source': 'browser',
        }]
    })

    assert response.status_code == 200
    body = response.get_json()
    assert body['updated'] == []
    assert body['count'] == 0
    assert body['skipped'][0]['domain'] == domain
    assert body['skipped'][0]['error'] == 'out of scope'
    certificate_manager.record_browser_deployment_status.assert_not_called()
