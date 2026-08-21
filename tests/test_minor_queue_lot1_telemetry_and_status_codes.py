"""Findings from the 2026-08-18 audit's minor queue, each verified before fixing.

1. ``authenticate_api_token`` persisted ``last_used_at`` as a datetime object.
   ``json.dump`` refused it, the error was swallowed on purpose (auth must not
   fail on telemetry), and the column stayed empty for every key, forever.
2. The client-certificate resources wrapped their handlers in ``except
   Exception`` and re-aborted as 500. ``abort(4xx)`` raises HTTPException, a
   subclass of Exception, so every 400/403/404 the handler meant to send came
   out as a 500 — except the download handler, which had grown its own
   pass-through. Now they all have it.
"""
import json
from unittest.mock import MagicMock

import pytest
from flask import Flask, request
from flask_restx import Api, Namespace

from modules.api.client_certificates import (
    create_client_certificate_models, create_client_certificate_resources,
)
from modules.core.auth import AuthManager, ROLE_HIERARCHY
from modules.core.file_operations import FileOperations
from modules.core.settings import SettingsManager

pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------- #
# 1. last_used_at
# --------------------------------------------------------------------------- #

@pytest.fixture
def auth(tmp_path, monkeypatch):
    monkeypatch.setenv('CERTMATE_LAST_USED_PERSIST_SECONDS', '0')
    dirs = [tmp_path / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir()
    sm = SettingsManager(file_ops=FileOperations(*dirs), settings_file=dirs[1] / "settings.json")
    sm.load_settings()
    am = AuthManager(sm)
    am.set_hmac_key("test-secret-for-hmac")
    return am, sm, dirs[1] / "settings.json"


def test_last_used_at_is_persisted_as_iso_text(auth):
    am, sm, settings_file = auth
    ok, data = am.create_api_key('ci', role='viewer')
    assert ok, data
    token = data['token']

    who = am.authenticate_api_token(token)
    assert who and who['role'] == 'viewer'

    on_disk = json.loads(settings_file.read_text())
    stored = [k for k in on_disk['api_keys'].values() if k.get('name') == 'ci'][0]
    assert isinstance(stored['last_used_at'], str) and stored['last_used_at'], (
        "last_used_at never reached the disk: the datetime object could not be "
        "serialised and the failure was swallowed")
    assert stored['last_used_at'].startswith('20') and 'T' in stored['last_used_at']


# --------------------------------------------------------------------------- #
# 2. status codes
# --------------------------------------------------------------------------- #

@pytest.fixture
def client_cert_app():
    def require_role_factory(min_role):
        def deco(fn):
            def wrapped(*args, **kwargs):
                user = getattr(request, 'current_user', None) or {}
                if ROLE_HIERARCHY.get(user.get('role'), -1) < ROLE_HIERARCHY.get(min_role, 999):
                    from flask import abort
                    abort(403)
                return fn(*args, **kwargs)
            return wrapped
        return deco
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=require_role_factory)
    cert_manager = MagicMock()
    cert_manager.get_certificate_metadata.return_value = None          # unknown id
    cert_manager.get_certificate_file.return_value = None              # no such file
    cert_manager.revoke_certificate.return_value = (False, 'already revoked')
    cert_manager.renew_certificate.return_value = (False, 'revoked certificates cannot be renewed', None)
    managers = {'auth': auth_manager, 'client_certificates': cert_manager,
                'ocsp': MagicMock(), 'crl': MagicMock(), 'settings': MagicMock()}
    app = Flask(__name__)
    app.config['TESTING'] = True
    api = Api(app, prefix='/api')
    create_client_certificate_models(api)
    resources = create_client_certificate_resources(api, managers)
    ns = Namespace('client-certs')
    api.add_namespace(ns)
    ns.add_resource(resources['ClientCertificateCreate'], '/create')
    ns.add_resource(resources['ClientCertificateDetail'], '/<string:identifier>')
    ns.add_resource(resources['ClientCertificateDownload'], '/<string:identifier>/download/<string:file_type>')
    ns.add_resource(resources['ClientCertificateRevoke'], '/<string:identifier>/revoke')
    ns.add_resource(resources['ClientCertificateRenew'], '/<string:identifier>/renew')

    @app.before_request
    def _as_admin():
        request.current_user = {'username': 'admin', 'role': 'admin'}
    return app.test_client()


@pytest.mark.parametrize('method, path, body, expected', [
    ('get', '/api/client-certs/nope', None, 404),
    ('get', '/api/client-certs/../etc', None, 404),        # routing, still not 500
    ('post', '/api/client-certs/create', {}, 400),
    ('post', '/api/client-certs/create', {'common_name': 'x' * 65}, 400),
    ('post', '/api/client-certs/create', {'common_name': 'ok', 'days_valid': 'soon'}, 400),
    ('get', '/api/client-certs/nope/download/crt', None, 404),
    ('get', '/api/client-certs/abc/download/exe', None, 400),
    ('post', '/api/client-certs/abc/revoke', {}, 400),
    ('post', '/api/client-certs/abc/renew', None, 400),
])
def test_client_cert_handlers_send_the_status_they_meant(client_cert_app, method, path, body, expected):
    call = getattr(client_cert_app, method)
    r = call(path, json=body) if body is not None else call(path)
    assert r.status_code == expected, (r.status_code, r.get_data(as_text=True)[:200])
    assert r.status_code != 500


# --------------------------------------------------------------------------- #
# 3. /metrics renewal timestamps
# --------------------------------------------------------------------------- #

def _metrics_body(tmp_path, domain, cert_info):
    from types import SimpleNamespace
    from modules.web.misc_routes import register_misc_routes

    def passthrough(*_a, **_k):
        def deco(fn):
            return fn
        return deco
    (tmp_path / 'certs').mkdir(exist_ok=True)
    managers = {
        'settings': SimpleNamespace(load_settings=lambda: {
            'domains': [{'domain': domain}], 'renewal_threshold_days': 30,
            'dns_providers': {'cloudflare': {'default': {'api_token': 'x'}}}}),
        'file_ops': SimpleNamespace(cert_dir=tmp_path / 'certs'),
        'certificates': SimpleNamespace(get_certificate_info=lambda d, *a, **k: cert_info if d == domain else None),
        'cache': SimpleNamespace(get_stats=lambda: {'total_entries': 0}),
    }
    # The collector refreshes at most once per 30 s (should_collect); the
    # tests in this file scrape back to back, so make each scrape real.
    from modules.core import metrics as metrics_module
    metrics_module.metrics_collector.last_collection = 0
    app = Flask(__name__)
    register_misc_routes(app, managers, passthrough, SimpleNamespace(require_role=passthrough))
    body = app.test_client().get('/metrics').get_data(as_text=True)
    metrics_module.metrics_collector.last_collection = 0   # leave it fresh for the next test
    return body


def _sample(body, metric, domain):
    """Prometheus gauges are process-global and keep their label series across
    tests, so every test here uses its own domain label and the lookup is by
    line: the sample line for *metric* carrying *domain*."""
    needle = f'domain="{domain}"'
    for line in body.splitlines():
        if line.startswith(metric + '{') and needle in line:
            return float(line.rsplit(' ', 1)[1])
    return None


def test_last_renewal_is_the_recorded_event_not_a_guess_from_expiry(tmp_path):
    """'mock data for now' shipped: last_renewal was derived from the expiry
    date and, for a 90-day certificate with a 30-day threshold, pointed into
    the future. It is now the metadata's renewed_at (else created_at)."""
    body = _metrics_body(tmp_path, 'renewed.example.net', {
        'exists': True, 'days_left': 80, 'dns_provider': 'cloudflare',
        'created_at': '2026-08-01T08:00:00Z', 'renewed_at': '2026-08-20T03:00:00Z'})
    from datetime import datetime, timezone
    expected = datetime(2026, 8, 20, 3, 0, tzinfo=timezone.utc).timestamp()
    assert _sample(body, 'certmate_certificate_last_renewal_timestamp', 'renewed.example.net') == expected
    import time
    nxt = _sample(body, 'certmate_certificate_next_renewal_timestamp', 'renewed.example.net')
    assert abs(nxt - (time.time() + 50 * 86400)) < 120   # due when days_left hits 30


def test_no_timestamp_known_means_no_sample(tmp_path):
    body = _metrics_body(tmp_path, 'unknown-age.example.net',
                         {'exists': True, 'days_left': 10, 'dns_provider': 'cloudflare'})
    assert _sample(body, 'certmate_certificate_last_renewal_timestamp', 'unknown-age.example.net') is None
    import time
    # Inside the renewal window: due now, not in the past.
    assert abs(_sample(body, 'certmate_certificate_next_renewal_timestamp', 'unknown-age.example.net') - time.time()) < 120


def test_a_timestamp_that_becomes_unknown_removes_the_series_instead_of_freezing_it(tmp_path):
    """Prometheus gauges keep their last value until set again; a domain whose
    metadata was quarantined must lose its last_renewal series, not keep a
    stale date."""
    dom = 'quarantined.example.net'
    body = _metrics_body(tmp_path, dom, {'exists': True, 'days_left': 40, 'dns_provider': 'cloudflare',
                                         'renewed_at': '2026-08-20T03:00:00Z'})
    assert _sample(body, 'certmate_certificate_last_renewal_timestamp', dom) is not None
    body = _metrics_body(tmp_path, dom, {'exists': True, 'days_left': 40, 'dns_provider': 'cloudflare'})
    assert _sample(body, 'certmate_certificate_last_renewal_timestamp', dom) is None


# --------------------------------------------------------------------------- #
# 4. A quarantined metadata.json says what it lost
# --------------------------------------------------------------------------- #

def test_quarantine_names_the_keys_the_damaged_file_still_carries(tmp_path, caplog):
    """Knowing a file was corrupt is not knowing what to put back. The
    quarantine line lists the key names still readable in the damaged file
    (never values) — ca_provider among them, which is what a private-CA
    renewal silently runs without until the file is repaired."""
    import logging
    from unittest.mock import MagicMock
    from modules.core.certificates import CertificateManager
    from modules.core.file_operations import FileOperations
    from modules.core.settings import SettingsManager
    dirs = [tmp_path / n for n in ("certificates", "data", "backups", "logs")]
    for d in dirs:
        d.mkdir()
    sm = SettingsManager(file_ops=FileOperations(*dirs), settings_file=dirs[1] / "settings.json")
    cm = CertificateManager(cert_dir=dirs[0], settings_manager=sm, dns_manager=MagicMock(), shell_executor=MagicMock())
    dom = dirs[0] / "app.internal"
    dom.mkdir()
    (dom / "metadata.json").write_text(
        '{"domain": "app.internal", "ca_provider": "private_ca", "dns_provider": "cloudflare", '
        '"san_domains": ["a.app.internal"], "deployment_host": "10.0.0.9", "domain_alias": "acme.ex')
    with caplog.at_level(logging.ERROR):
        assert cm._load_metadata("app.internal") == {}
    line = "\n".join(r.getMessage() for r in caplog.records if "Corrupt metadata" in r.getMessage())
    for key in ("ca_provider", "dns_provider", "san_domains", "deployment_host", "domain_alias"):
        assert key in line, (key, line)
    assert "private_ca" not in line and "10.0.0.9" not in line, "names only, never values"
    assert list(dom.glob("metadata.json.corrupt-*"))
