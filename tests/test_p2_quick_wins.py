"""P2 quick security wins (2026-07-02 audit):
1. GET /api/settings must not leak the user roster / API-key inventory to
   non-admins (mask_secrets only redacts secret-named leaves).
2. DNS credential files are created 0600 atomically (O_EXCL), no world-readable
   window, no symlink-follow.
3. The Google service-account key gets a per-op random name (no fixed
   predictable path, no concurrent clobber), 0600, and orphans are swept."""
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, request

from modules.core.utils import _create_config_file, create_google_config, _sweep_orphaned_files
from modules.web.settings_routes import register_settings_routes

pytestmark = [pytest.mark.unit]


# --- #1 GET /api/settings roster leak --------------------------------------

def _settings_app(caller):
    sm = MagicMock()
    sm.load_settings.return_value = {
        'email': 'ops@example.com',
        'domains': [],
        'users': {'admin': {'role': 'admin', 'email': 'a@example.com'}},
        'api_keys': [{'name': 'ci', 'role': 'operator', 'token_prefix': 'abcd'}],
    }
    sm.file_ops = SimpleNamespace(cert_dir=None)
    auth = MagicMock()
    auth.require_role = lambda role: (lambda fn: fn)
    auth.domain_matches_scope = lambda d, scope: True
    app = Flask(__name__)
    app.config['TESTING'] = True
    register_settings_routes(app, {'audit': MagicMock()}, (lambda f: f), auth, sm, MagicMock())

    @app.before_request
    def _u():
        request.current_user = caller

    return app


def test_viewer_settings_omits_users_and_api_keys():
    app = _settings_app({'username': 'v', 'role': 'viewer', 'allowed_domains': None})
    body = app.test_client().get('/api/settings').get_json()
    assert 'users' not in body
    assert 'api_keys' not in body
    assert body.get('email') == 'ops@example.com'   # non-roster settings still returned


def test_operator_settings_omits_users_and_api_keys():
    app = _settings_app({'username': 'o', 'role': 'operator', 'allowed_domains': None})
    body = app.test_client().get('/api/settings').get_json()
    assert 'users' not in body and 'api_keys' not in body


def test_admin_settings_still_includes_users_and_api_keys():
    app = _settings_app({'username': 'a', 'role': 'admin', 'allowed_domains': None})
    body = app.test_client().get('/api/settings').get_json()
    assert 'users' in body and 'api_keys' in body


# --- #2 DNS credential file is 0600 atomically -----------------------------

def test_create_config_file_is_0600(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)   # letsencrypt/config is CWD-relative
    p = _create_config_file('cloudflare', 'dns_cloudflare_api_token = secret\n')
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert p.read_text() == 'dns_cloudflare_api_token = secret\n'


# --- #3 Google SA key: random name, 0600, no fixed path, sweep --------------

def test_google_sa_file_is_random_and_0600(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    create_google_config('proj-1', '{"type":"service_account","private_key":"x"}')
    cfg = tmp_path / 'letsencrypt' / 'config'
    sa_files = list(cfg.glob('google-sa-*.json'))
    assert len(sa_files) == 1
    assert stat.S_IMODE(os.stat(sa_files[0]).st_mode) == 0o600
    assert not (cfg / 'google-service-account.json').exists()   # no fixed predictable path


def test_sweep_removes_orphaned_sa_files_only(tmp_path):
    old = tmp_path / 'google-sa-old.json'
    old.write_text('stale')
    fresh = tmp_path / 'google-sa-fresh.json'
    fresh.write_text('live')
    past = 1_000_000.0           # far in the past (deterministic, no time import)
    os.utime(old, (past, past))
    _sweep_orphaned_files(tmp_path, 'google-sa-*.json', max_age_seconds=3600)
    assert not old.exists()      # older than cutoff → swept
    assert fresh.exists()        # recent → kept


# --- S1 follow-up: the SA JSON is deleted WITH the operation, not left for
# the orphan sweep. create_google_config returns both paths, GoogleStrategy
# records the side file, and the create/renew finally blocks unlink it.

def test_create_google_config_returns_both_secret_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    config_file, sa_file = create_google_config('proj-1', '{"type":"service_account"}')
    assert config_file.exists() and sa_file.exists()
    assert sa_file.name.startswith('google-sa-')
    assert str(sa_file) in config_file.read_text()


def test_google_strategy_records_sa_file_for_cleanup(tmp_path, monkeypatch):
    from modules.core.dns_strategies import GoogleStrategy
    monkeypatch.chdir(tmp_path)
    strategy = GoogleStrategy()
    config_file = strategy.create_config_file(
        {'project_id': 'p', 'service_account_key': '{"type":"service_account"}'})
    assert config_file is not None
    assert [Path(p).name.startswith('google-sa-') for p in strategy.extra_credential_files] == [True]


def _google_cert_mgr(tmp_path, shell):
    from modules.core.certificates import CertificateManager
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
        'dns_propagation_seconds': {}, 'default_key_type': 'ecdsa',
        'default_elliptic_curve': 'secp384r1',
    }
    settings_mgr.get_domain_dns_provider.return_value = 'google'
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (
        {'project_id': 'p', 'service_account_key': '{"type":"service_account"}'},
        'default',
    )
    return CertificateManager(
        cert_dir=tmp_path / 'certs', settings_manager=settings_mgr,
        dns_manager=dns_mgr, storage_manager=None, ca_manager=None,
        shell_executor=shell,
    )


def test_create_unlinks_google_sa_json_in_finally(tmp_path, monkeypatch):
    from modules.core.certificates import CertificateManager
    from modules.core.shell import MockShellExecutor
    monkeypatch.chdir(tmp_path)
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)
    mgr = _google_cert_mgr(tmp_path, shell)
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        mgr.create_certificate(domain='g.example.com', email='t@example.com',
                               dns_provider='google', staging=True)
    cfg = tmp_path / 'letsencrypt' / 'config'
    assert not list(cfg.glob('google-sa-*.json')), (
        "the SA JSON (a live GCP private key) must not outlive the operation"
    )
    assert not list(cfg.glob('google-*.ini'))


def test_renew_unlinks_google_sa_json_in_finally(tmp_path, monkeypatch):
    import json as _json
    from modules.core.certificates import CertificateManager
    from modules.core.shell import MockShellExecutor
    monkeypatch.chdir(tmp_path)
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0, stdout='no renewals were attempted')
    mgr = _google_cert_mgr(tmp_path, shell)
    d = tmp_path / 'certs' / 'g.example.com'
    d.mkdir(parents=True)
    (d / 'cert.pem').write_bytes(b'existing\n')
    (d / 'metadata.json').write_text(_json.dumps({'dns_provider': 'google'}))
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        mgr.renew_certificate('g.example.com')
    cfg = tmp_path / 'letsencrypt' / 'config'
    assert not list(cfg.glob('google-sa-*.json'))
    assert not list(cfg.glob('google-*.ini'))
