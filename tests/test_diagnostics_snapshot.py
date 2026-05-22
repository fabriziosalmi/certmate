"""Unit tests for the DiagnosticsSnapshot resource (closes #150).

The endpoint powers the in-app "Report this issue" button. Its
correctness contract is:

  - admin-only (viewer/operator 403)
  - returns a fixed allowlist of operational scalars, never the full
    settings dict and never any secret
  - returns at most 5 audit-log entries, each stripped of resource_id,
    user, ip_address, details, error
  - tolerates partial failure (disk_usage raising, audit log missing,
    etc.) by reporting the working fields plus an `errors` map — never
    500s out the whole response

No Docker; runs in-process via Flask's test client.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from flask import Flask
from flask_restx import Api, Namespace

from modules.api.models import create_api_models
from modules.api.resources import create_api_resources
import modules.api.resources as api_resources_module


def _passthrough_decorator(_min_role):
    def deco(fn):
        return fn
    return deco


def _build_app(managers, *, data_dir=None):
    app = Flask(__name__)
    app.config['TESTING'] = True
    if data_dir is not None:
        app.config['DATA_DIR'] = str(data_dir)
    api = Api(app, prefix='/api')
    models = create_api_models(api)
    resources = create_api_resources(api, models, managers)

    ns = Namespace('diagnostics', description='diagnostics')
    api.add_namespace(ns)
    ns.add_resource(resources['DiagnosticsSnapshot'], '/snapshot')
    return app


def _audit_entries(*operations):
    """Build raw audit entries with all the fields the real logger emits
    so we can verify the sanitizer strips identifiers correctly."""
    return [
        {
            'timestamp': '2026-05-12T14:12:0{}Z'.format(i),
            'operation': op,
            'resource_type': 'certificate',
            'resource_id': 'secret.example.com',
            'status': 'success',
            'user': 'admin@example.com',
            'ip_address': '198.51.100.42',
            'details': {'common_name': 'secret.example.com',
                        'private_key_pem': 'should-never-leak'},
            'error': None,
        }
        for i, op in enumerate(operations)
    ]


@pytest.fixture
def managers(tmp_path):
    """Standard managers wired up enough to exercise the resource."""
    auth_manager = MagicMock()
    auth_manager.require_role = MagicMock(side_effect=_passthrough_decorator)

    cert_manager = MagicMock()
    cert_manager.cert_dir = Path(tmp_path)
    cert_manager.list_certificates.return_value = [
        {'domain': 'a.com'}, {'domain': 'b.com'}, {'domain': 'c.com'}
    ]

    audit_logger = MagicMock()
    audit_logger.get_recent_entries.return_value = _audit_entries(
        'create', 'renew', 'update', 'delete', 'access'
    )

    settings_manager = MagicMock()
    settings_manager.load_settings.return_value = {
        'dns_provider': 'cloudflare',
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'certificate_storage': {'backend': 'local_filesystem'},
        # Things that MUST NOT appear in the snapshot:
        'api_bearer_token': 'cm_supersecret_should_not_leak',
        'api_bearer_token_hash': 'hmac-sha256:should_not_leak',
        'cloudflare_token': 'cf_should_not_leak',
        'users': {'admin': {'password_hash': 'should_not_leak'}},
        'dns_providers': {'cloudflare': {'api_token': 'should_not_leak'}},
    }

    file_ops = MagicMock(cert_dir=Path(tmp_path))

    return {
        'auth': auth_manager,
        'settings': settings_manager,
        'certificates': cert_manager,
        'file_ops': file_ops,
        'cache': MagicMock(),
        'dns': MagicMock(),
        'audit': audit_logger,
    }


class TestSnapshotShape:
    """The response carries the expected top-level fields and never
    leaks anything outside the allowlist."""

    def test_basic_shape(self, managers, tmp_path):
        app = _build_app(managers, data_dir=tmp_path)
        r = app.test_client().get('/api/diagnostics/snapshot')
        assert r.status_code == 200
        body = r.get_json()

        # Required scalar fields
        for k in (
            'certmate_version', 'python_version', 'os_platform', 'container',
            'scheduler_running', 'certificate_count',
            'dns_provider', 'default_ca', 'challenge_type', 'storage_backend',
            'disk_free_bytes', 'disk_total_bytes', 'recent_audit',
            'cryptography_version', 'openssl_version', 'certbot_version',
            'storage_permissions', 'configured_domains_count', 'active_dns_providers',
            'sso_oidc_enabled', 'backup_count', 'backup_total_size', 'sanitized_logs',
        ):
            assert k in body, f"missing field: {k}"

    def test_certificate_count_matches_manager(self, managers, tmp_path):
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        assert body['certificate_count'] == 3

    def test_settings_scalars_propagated(self, managers, tmp_path):
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        assert body['dns_provider'] == 'cloudflare'
        assert body['default_ca'] == 'letsencrypt'
        assert body['challenge_type'] == 'dns-01'
        assert body['storage_backend'] == 'local_filesystem'

    def test_new_fields_content(self, managers, tmp_path):
        # Configure settings mock
        managers['settings'].load_settings.return_value = {
            'domains': ['example.com', 'test.com'],
            'dns_providers': {
                'cloudflare': {
                    'accounts': {
                        'primary': {
                            'name': 'Primary Cloudflare',
                            'description': 'Main Cloudflare Account',
                            'api_token': 'secret_token_123'
                        }
                    }
                }
            }
        }
        
        # Configure file_ops logs and backups mock
        log_dir = Path(tmp_path) / 'logs'
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / 'certmate.log'
        log_file.write_text(
            '{"timestamp": "2026-05-22", "message": "Starting server", "secret": "leaky_secret_value"}\n'
            'Plain text line with private_key=abc123secret\n'
            '-----BEGIN PRIVATE KEY-----MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7-----END PRIVATE KEY-----\n'
        )
        
        managers['file_ops'].logs_dir = log_dir
        managers['file_ops'].list_backups.return_value = {
            'unified': [
                {'filename': 'backup_1.zip', 'metadata': {'size': 1000}},
                {'filename': 'backup_2.zip', 'metadata': {'size': 2500}}
            ]
        }
        
        # Configure OIDC manager mock
        oidc_mock = MagicMock()
        oidc_mock.is_enabled.return_value = True
        managers['oidc'] = oidc_mock

        # Configure ShellExecutor mock for certbot version
        shell_mock = MagicMock()
        shell_mock.run.return_value = MagicMock(stdout='certbot 2.4.0', stderr='')
        managers['shell_executor'] = shell_mock

        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()

        # Check cryptography and openssl versions exist
        assert body['cryptography_version'] is not None
        assert body['openssl_version'] is not None
        assert body['certbot_version'] == 'certbot 2.4.0'

        # Check storage permissions
        perms = body['storage_permissions']
        assert 'cert_dir_readable' in perms
        assert 'cert_dir_writable' in perms
        assert 'data_dir_readable' in perms
        assert 'data_dir_writable' in perms

        # Check configuration summary
        assert body['configured_domains_count'] == 2
        assert 'cloudflare' in body['active_dns_providers']
        assert body['active_dns_providers']['cloudflare'][0]['id'] == 'primary'
        assert body['active_dns_providers']['cloudflare'][0]['name'] == 'Primary Cloudflare'
        # Crucial security check: api_token is omitted/redacted from the accounts list!
        assert 'api_token' not in body['active_dns_providers']['cloudflare'][0]
        assert body['sso_oidc_enabled'] is True

        # Check backups
        assert body['backup_count'] == 2
        assert body['backup_total_size'] == 3500

        # Check sanitized logs
        logs = body['sanitized_logs']
        assert len(logs) == 3
        # JSON parsed line sanitization:
        assert isinstance(logs[0], dict)
        assert logs[0]['secret'] == '[REDACTED]'
        # Plain text line sanitization:
        assert 'abc123secret' not in logs[1]
        assert '[REDACTED]' in logs[1]
        # PEM blocks:
        assert '[PEM REDACTED]' in logs[2]


class TestSnapshotSanitization:
    """The blacklist is the load-bearing security property: no secret
    field, no resource identifier, no user, no IP, no audit details
    may appear in any part of the response."""

    def _flatten_to_string(self, obj):
        """Walk the response and produce a single string of every value
        encountered. Used to assert 'X never appears anywhere'."""
        if isinstance(obj, dict):
            parts = []
            for k, v in obj.items():
                parts.append(str(k))
                parts.append(self._flatten_to_string(v))
            return ' '.join(parts)
        if isinstance(obj, list):
            return ' '.join(self._flatten_to_string(x) for x in obj)
        return '' if obj is None else str(obj)

    def test_response_has_no_secret_values(self, managers, tmp_path):
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        blob = self._flatten_to_string(body)

        # Things explicitly planted in settings + audit details that
        # must NEVER appear in the response.
        forbidden = [
            'cm_supersecret_should_not_leak',
            'hmac-sha256:should_not_leak',
            'cf_should_not_leak',
            'should-never-leak',   # audit detail
            'secret.example.com',  # audit resource_id
            'admin@example.com',   # audit user
            '198.51.100.42',       # audit ip_address
            'password_hash',
        ]
        for token in forbidden:
            assert token not in blob, f"secret/identifier leaked: {token}"

    def test_audit_entries_stripped_of_identifiers(self, managers, tmp_path):
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()

        entries = body['recent_audit']
        assert len(entries) == 5
        for entry in entries:
            # Only these four keys survive the sanitizer.
            assert set(entry.keys()) == {
                'timestamp', 'operation', 'resource_type', 'status'
            }, f"audit entry leaked extra fields: {set(entry.keys())}"

    def test_audit_entries_capped_at_five(self, managers, tmp_path):
        # The endpoint passes limit=5 to get_recent_entries.
        managers['audit'].get_recent_entries.return_value = _audit_entries(
            *['op' + str(i) for i in range(20)]
        )
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        assert len(body['recent_audit']) <= 5

    def test_full_settings_dict_not_exposed(self, managers, tmp_path):
        # Even the keys of the settings dict (which include 'users',
        # 'api_keys', 'dns_providers') must not appear as top-level
        # fields of the response.
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        for forbidden_key in ('users', 'api_keys', 'dns_providers',
                              'api_bearer_token', 'api_bearer_token_hash',
                              'deploy_hooks'):
            assert forbidden_key not in body, (
                f"settings field '{forbidden_key}' leaked into snapshot"
            )


class TestSnapshotPartialFailure:
    """A field that can't be computed must surface in `errors` rather
    than 500ing the whole call."""

    def test_certificate_count_failure(self, managers, tmp_path):
        managers['certificates'].list_certificates.side_effect = RuntimeError('disk gone')
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        assert body['certificate_count'] is None
        assert body.get('errors', {}).get('certificate_count') == 'failed_to_enumerate'
        # Other fields still populated.
        assert body['dns_provider'] == 'cloudflare'

    def test_audit_failure(self, managers, tmp_path):
        managers['audit'].get_recent_entries.side_effect = OSError('audit log missing')
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        assert body['recent_audit'] == []
        assert body.get('errors', {}).get('recent_audit') == 'failed_to_read'

    def test_disk_usage_failure(self, managers, monkeypatch, tmp_path):
        # Force shutil.disk_usage to raise.
        def boom(_path):
            raise PermissionError('denied')
        monkeypatch.setattr(api_resources_module.__dict__.get('shutil', None)
                            or __import__('shutil'), 'disk_usage', boom)
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        assert body['disk_free_bytes'] is None
        assert body['disk_total_bytes'] is None
        assert body.get('errors', {}).get('disk_usage') == 'permission_or_path_unavailable'

    def test_no_audit_logger_wired(self, managers, tmp_path):
        managers['audit'] = None
        app = _build_app(managers, data_dir=tmp_path)
        body = app.test_client().get('/api/diagnostics/snapshot').get_json()
        # No crash, empty list, no spurious error entry.
        assert body['recent_audit'] == []
