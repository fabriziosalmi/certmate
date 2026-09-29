"""SCM-authorized identifiers can issue without CertMate serving a challenge."""

import json
import shlex
from unittest.mock import MagicMock, patch

import pytest
from acme import messages
from certbot._internal.auth_handler import AuthHandler
from flask import Flask, request

from modules.core.ca_manager import CAManager
from modules.core.cert_service import CertificateService
from modules.core.certificates import CertificateManager, _resolve_all_domains
from modules.core.constants import CERTIFICATE_FILES
from modules.core.shell import MockShellExecutor
from modules.web.cert_routes import register_cert_routes


pytestmark = pytest.mark.unit


@pytest.fixture
def issuer(tmp_path):
    settings = MagicMock()
    settings.load_settings.return_value = {
        'default_ca': 'sectigo', 'email': 'ops@example.com',
        'ca_providers': {'sectigo': {'accounts': {'scm': {
            'acme_url': 'https://acme.sectigo.com/v2/OV',
            'eab_kid': 'example-kid', 'eab_hmac': 'example-hmac',
        }}}},
    }
    dns = MagicMock()
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)
    manager = CertificateManager(
        cert_dir=tmp_path, settings_manager=settings, dns_manager=dns,
        ca_manager=CAManager(settings), storage_manager=None, shell_executor=shell)
    return manager, shell, dns


def test_sectigo_wildcard_issues_without_http_or_dns_credentials(issuer, tmp_path):
    manager, shell, dns = issuer
    manager.create_certificate(
        domain='example.com', email='ops@example.com',
        ca_provider='sectigo', ca_account_id='scm',
        challenge_type='prevalidated', san_domains=['*.example.com'])
    cmd = shlex.split(shell.commands_executed[0])
    for flag, value in [('--server', 'https://acme.sectigo.com/v2/OV'),
                        ('--eab-kid', 'example-kid'),
                        ('--eab-hmac-key', 'example-hmac'),
                        ('--manual-auth-hook', '/usr/bin/false')]:
        assert cmd[cmd.index(flag) + 1] == value
    assert '--manual' in cmd
    assert cmd[cmd.index('--preferred-challenges') + 1] == 'dns'
    assert cmd.count('-d') == 2
    assert '*.example.com' in cmd
    assert '--webroot' not in cmd
    assert '--dns-cloudflare' not in cmd
    dns.get_dns_provider_account_config.assert_not_called()
    metadata = json.loads((tmp_path / 'example.com' / 'metadata.json').read_text())
    assert metadata['ca_provider'] == 'sectigo'
    assert metadata['ca_account_id'] == 'scm'
    assert metadata['challenge_type'] == 'prevalidated'
    assert metadata['dns_provider'] is None


def test_certbot_skips_hooks_when_acme_authorizations_are_valid():
    auth = MagicMock()
    handler = AuthHandler(auth, MagicMock(), MagicMock(), ['dns-01'])
    valid = MagicMock()
    valid.body.status = messages.STATUS_VALID
    assert handler.handle_authorizations(MagicMock(authorizations=[valid]), MagicMock()) == [valid]
    auth.perform.assert_not_called()


def test_prevalidated_is_sectigo_only_and_rejects_dns_aliases(issuer):
    manager, _, _ = issuer
    with pytest.raises(ValueError, match='only for Sectigo'):
        manager.create_certificate('example.com', 'ops@example.com',
                                   ca_provider='letsencrypt', challenge_type='prevalidated')
    with pytest.raises(ValueError, match='does not use DNS'):
        manager.create_certificate('example.com', 'ops@example.com',
                                   ca_provider='sectigo', challenge_type='prevalidated',
                                   dns_provider='cloudflare')
    with pytest.raises(ValueError, match='does not use DNS'):
        manager.create_certificate('example.com', 'ops@example.com',
                                   ca_provider='sectigo', challenge_type='prevalidated',
                                   domain_alias='alias.example.com')


def test_service_preparation_needs_no_dns_account(issuer):
    manager, _, dns = issuer
    auth = MagicMock()
    auth.domain_matches_scope.return_value = True
    service = CertificateService(manager, manager.settings_manager, auth)
    prepared = service.prepare_create(
        domain='example.com', ca_provider='sectigo', challenge_type='prevalidated',
        user={}, ip_address='127.0.0.1')
    assert prepared['dns_provider'] is None
    assert prepared['challenge_type'] == 'prevalidated'
    dns.get_dns_provider_account_config.assert_not_called()
    with pytest.raises(ValueError, match='only for Sectigo'):
        service.prepare_create(domain='example.com', ca_provider='letsencrypt',
                               challenge_type='prevalidated', user={})


def test_reissue_from_dns_preserves_sectigo_account_without_dns(issuer, tmp_path):
    manager, _, dns = issuer
    domain_dir = tmp_path / 'example.com'
    domain_dir.mkdir()
    (domain_dir / 'cert.pem').write_bytes(b'original certificate')
    manager._load_metadata = lambda domain: {
        'ca_provider': 'sectigo', 'ca_account_id': 'scm',
        'dns_provider': 'cloudflare', 'account_id': 'old-dns',
        'challenge_type': 'dns-01', 'san_domains': ['*.example.com'],
    }
    service = CertificateService(manager, manager.settings_manager, MagicMock())
    prepared = service.prepare_reissue(domain='example.com', challenge_type='prevalidated',
                                       user={})
    assert prepared['ca_account_id'] == 'scm'
    assert prepared['dns_provider'] is None
    assert prepared['account_id'] is None
    assert prepared['san_domains'] == ['*.example.com']
    dns.get_dns_provider_account_config.assert_not_called()
    with patch.object(manager, 'create_certificate', return_value={'success': True}) as issue:
        service.issue_reissue(prepared)
    assert issue.call_args.kwargs['ca_account_id'] == 'scm'
    assert issue.call_args.kwargs['dns_provider'] is None


def test_prevalidated_renewal_skips_dns_account_lookup(issuer):
    manager, _, dns = issuer
    cmd = ['certbot', 'renew']
    assert manager._prepare_renewal_dns('example.com', {
        'ca_provider': 'sectigo', 'challenge_type': 'prevalidated',
        'dns_provider': None, 'ca_account_id': 'scm',
    }, cmd, {}, MagicMock()) == 'prevalidated'
    assert cmd == ['certbot', 'renew']
    dns.get_dns_provider_account_config.assert_not_called()


def test_http_01_wildcard_still_refused():
    with pytest.raises(ValueError, match='HTTP-01 challenge does not support wildcard'):
        _resolve_all_domains('example.com', ['*.example.com'], 'http-01')
    assert '*.example.com' in _resolve_all_domains(
        'example.com', ['*.example.com'], 'prevalidated')


@pytest.mark.parametrize('request_challenge', ['prevalidated', None])
def test_batch_prevalidated_skips_default_dns_and_tracks_renewal(tmp_path, request_challenge):
    app = Flask(__name__)
    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': 'ops@example.com', 'dns_provider': 'cloudflare',
        'default_ca': 'sectigo', 'challenge_type': 'prevalidated',
    }
    manager = MagicMock(cert_dir=tmp_path)
    manager.create_certificate.return_value = {
        'dns_provider': None, 'ca_provider': 'sectigo', 'success': True}
    auth = MagicMock()
    auth.require_role.side_effect = lambda role: lambda fn: fn
    auth.user_can_access_domain.return_value = True
    register_cert_routes(app, {}, None, auth, manager,
                         lambda domain: domain, MagicMock(), settings, MagicMock(),
                         CERTIFICATE_FILES)

    @app.before_request
    def attach_user():
        request.current_user = {'username': 'operator', 'allowed_domains': None}

    payload = {'domains': ['example.com'], 'ca_provider': 'sectigo'}
    if request_challenge:
        payload['challenge_type'] = request_challenge
    response = app.test_client().post('/api/web/certificates/batch', json=payload)

    assert response.status_code == 200
    assert response.get_json() == [
        {'domain': 'example.com', 'success': True, 'message': 'Certificate created'}]
    assert manager.create_certificate.call_args.kwargs['dns_provider'] is None
    assert manager.create_certificate.call_args.kwargs['challenge_type'] == 'prevalidated'
    tracked = {}
    settings.update.call_args.args[0](tracked)
    assert tracked['domains'] == [
        {'domain': 'example.com', 'dns_provider': None, 'dns_account_id': None}]


def test_batch_prevalidated_keeps_explicit_dns_provider_for_validation(tmp_path):
    app = Flask(__name__)
    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': 'ops@example.com', 'dns_provider': 'cloudflare',
    }
    manager = MagicMock(cert_dir=tmp_path)
    auth = MagicMock()
    auth.require_role.side_effect = lambda role: lambda fn: fn
    auth.user_can_access_domain.return_value = True
    register_cert_routes(app, {}, None, auth, manager,
                         lambda domain: domain, MagicMock(), settings, MagicMock(),
                         CERTIFICATE_FILES)
    response = app.test_client().post('/api/web/certificates/batch', json={
        'domains': ['example.com'], 'ca_provider': 'sectigo',
        'challenge_type': 'prevalidated', 'dns_provider': 'cloudflare',
    })
    assert response.status_code == 200
    assert response.get_json()[0]['success'] is False
    assert response.get_json()[0]['message'] == 'Invalid certificate request'
    manager.create_certificate.assert_not_called()
    settings.update.assert_not_called()
