"""The /metrics route must build an app_context so inventory metrics populate.

Before this fix the route called generate_metrics_response() with no context;
metrics.py gates all certificate/DNS/cache collection behind `if app_context`,
so the live endpoint emitted ONLY application_uptime and every labelled metric
the Grafana dashboard draws was 'No data'. These tests drive the REAL route and
assert the certificate inventory now carries samples.
"""
from types import SimpleNamespace

import pytest
from flask import Flask

from modules.web.misc_routes import register_misc_routes

pytestmark = [pytest.mark.unit]


def _passthrough(*_a, **_k):
    def deco(fn):
        return fn
    return deco


def _app(managers):
    app = Flask(__name__)
    auth_manager = SimpleNamespace(require_role=_passthrough)
    register_misc_routes(app, managers, _passthrough, auth_manager)
    return app


def test_metrics_endpoint_populates_certificate_inventory(tmp_path):
    (tmp_path / 'certs').mkdir()
    managers = {
        'settings': SimpleNamespace(load_settings=lambda: {
            'domains': [{'domain': 'example.com'}],
            'dns_providers': {'cloudflare': {'default': {'api_token': 'x'}}},
        }),
        'file_ops': SimpleNamespace(cert_dir=tmp_path / 'certs'),
        'certificates': SimpleNamespace(
            get_certificate_info=lambda domain, *a, **k: (
                {'exists': True, 'days_left': 45, 'dns_provider': 'cloudflare'}
                if domain == 'example.com' else None)),
        'cache': SimpleNamespace(get_stats=lambda: {'total_entries': 7}),
    }
    body = _app(managers).test_client().get('/metrics').get_data(as_text=True)

    # Previously all of these were absent (no samples) — now they carry values.
    assert 'certmate_domains_total 1.0' in body
    assert 'certmate_certificates_total 1.0' in body
    assert 'certmate_certificates_by_status{status="valid"} 1.0' in body
    # Assert the labelled metric string (a bare-host 'example.com' substring
    # check trips CodeQL's url-sanitization heuristic — a false positive on a
    # Prometheus exposition assertion — and the label form is more precise).
    assert 'certmate_certificate_expiry_days{' in body
    assert 'domain="example.com"' in body
    assert 'certmate_cache_entries 7.0' in body


def test_metrics_endpoint_without_context_still_serves(tmp_path):
    # No managers -> base metrics only, but never a 500.
    r = _app({}).test_client().get('/metrics')
    assert r.status_code == 200
    assert 'certmate_application_uptime_seconds' in r.get_data(as_text=True)
