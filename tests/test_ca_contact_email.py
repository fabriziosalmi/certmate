"""Create and reissue accept the resolved CA account's contact email."""
import shlex
from unittest.mock import MagicMock

import pytest
from flask import Flask

from modules.core.ca_manager import CAManager
from modules.core.cert_adopt import build_adoption_plan
from modules.core.cert_service import CertificateService
from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES
from modules.core.shell import MockShellExecutor
from modules.web.cert_routes import register_cert_routes
from tests.test_cert_adopt import _FakeDNS, _rec

pytestmark = pytest.mark.unit


@pytest.mark.parametrize('global_email,account_email,expected', [
    ('global@example.com', 'ca@example.com', 'ca@example.com'),
    ('', 'ca@example.com', 'ca@example.com'),
    ('global@example.com', '', 'global@example.com'),
    ('', '', None),
])
@pytest.mark.parametrize('account_id', [None, 'paid'])
def test_create_and_reissue_resolve_ca_contact_email(tmp_path, global_email, account_email, expected, account_id):
    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': global_email, 'default_ca': 'sectigo',
        'default_ca_accounts': {'sectigo': 'paid'},
        'ca_providers': {'sectigo': {'accounts': {'paid': {
            'email': account_email, 'acme_url': 'https://acme.sectigo.com/v2/OV',
            'eab_kid': 'kid', 'eab_hmac': 'hmac'}}}},
    }
    shell = MockShellExecutor()
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=MagicMock(), ca_manager=CAManager(settings), shell_executor=shell)
    service = CertificateService(manager, settings, MagicMock())
    for reissue in (False, True):
        if reissue:
            directory = tmp_path / 'example.com'
            directory.mkdir(exist_ok=True)
            (directory / 'cert.pem').write_bytes(b'old certificate')
            manager._save_metadata('example.com', {'ca_provider': 'sectigo', 'ca_account_id': 'paid',
                                                   'challenge_type': 'prevalidated'})
            def prepare():
                return service.prepare_reissue(domain='example.com', user={})
        else:
            def prepare():
                return service.prepare_create(domain='example.com', ca_account_id=account_id,
                                              challenge_type='prevalidated', user={})
        if expected is None:
            with pytest.raises(ValueError, match='Email not configured'):
                prepare()
            continue
        prepared = prepare()
        assert prepared['email'] == expected
        shell.set_next_result(returncode=0)
        (service.issue_reissue if reissue else service.issue_create)(prepared)
        assert manager._load_metadata('example.com')['email'] == expected
        command = shlex.split(shell.commands_executed[-1])
        assert command[command.index('--email') + 1] == expected


@pytest.mark.parametrize('provider', ['letsencrypt', 'letsencrypt_staging'])
def test_unconfigured_letsencrypt_keeps_global_email(tmp_path, provider):
    settings = MagicMock()
    settings.load_settings.return_value = {'email': 'global@example.com'}
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=MagicMock(), ca_manager=CAManager(settings))
    service = CertificateService(manager, settings, MagicMock())
    assert service.prepare_create(domain='example.com', ca_provider=provider,
                                  challenge_type='http-01', user={})['email'] == 'global@example.com'


@pytest.mark.parametrize('provider,accounts,account_id', [
    ('letsencrypt', {'work': {'email': 'work@example.com'}}, 'ghost'),
    ('letsencrypt', {}, None),
    ('letsencrypt_staging', {'work': {'email': 'work@example.com'}}, 'ghost'),
])
@pytest.mark.parametrize('reissue', [False, True])
def test_letsencrypt_unresolved_account_preserves_global_email(tmp_path, provider, accounts, account_id, reissue):
    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': 'global@example.com', 'default_ca': provider,
        'ca_providers': {'letsencrypt': {'accounts': accounts}},
    }
    shell = MockShellExecutor()
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=MagicMock(), ca_manager=CAManager(settings), shell_executor=shell)
    service = CertificateService(manager, settings, MagicMock())
    if reissue:
        directory = tmp_path / 'example.com'
        directory.mkdir()
        (directory / 'cert.pem').write_bytes(b'old certificate')
        manager._save_metadata('example.com', {'ca_provider': provider, 'ca_account_id': account_id,
                                               'challenge_type': 'http-01'})
        prepared = service.prepare_reissue(domain='example.com', user={})
        service.issue_reissue(prepared)
    else:
        prepared = service.prepare_create(domain='example.com', ca_provider=provider, ca_account_id=account_id,
                                          challenge_type='http-01', user={})
        service.issue_create(prepared)
    assert prepared['email'] == 'global@example.com'
    command = shlex.split(shell.commands_executed[-1])
    assert command[command.index('--email') + 1] == 'global@example.com'
    assert command[command.index('--server') + 1] == (
        'https://acme-staging-v02.api.letsencrypt.org/directory' if provider == 'letsencrypt_staging'
        else 'https://acme-v02.api.letsencrypt.org/directory')


@pytest.mark.parametrize('global_email,account_email,expected', [
    ('global@example.com', 'ca@example.com', 'ca@example.com'),
    ('', 'ca@example.com', 'ca@example.com'),
    ('global@example.com', '', 'global@example.com'),
    ('', '', None),
])
def test_batch_and_adoption_follow_the_single_create_email_rule(tmp_path, global_email, account_email, expected):
    settings = MagicMock()
    settings.load_settings.return_value = {
        'email': global_email, 'default_ca': 'sectigo', 'default_ca_accounts': {'sectigo': 'paid'},
        'ca_providers': {'sectigo': {'accounts': {'paid': {
            'email': account_email, 'acme_url': 'https://acme.sectigo.com/v2/OV',
            'eab_kid': 'kid', 'eab_hmac': 'hmac'}}}},
    }
    shell = MockShellExecutor()
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=MagicMock(), ca_manager=CAManager(settings), shell_executor=shell)
    auth = MagicMock()
    auth.require_role.side_effect = lambda role: lambda function: function
    app = Flask(__name__)
    register_cert_routes(app, {}, lambda function: function, auth, manager,
                         lambda domain: domain, MagicMock(), settings, MagicMock(), CERTIFICATE_FILES)
    response = app.test_client().post('/api/web/certificates/batch', json={
        'domains': ['example.com', 'other.example.com'], 'challenge_type': 'prevalidated'})
    assert response.status_code == (200 if expected else 400)
    if expected:
        assert len(shell.commands_executed) == 2
        for raw in shell.commands_executed:
            command = shlex.split(raw)
            assert command[command.index('--email') + 1] == expected
    else:
        assert not shell.commands_executed
        assert response.get_json()['error'] == 'Email not configured. Set it in Settings first.'
    plan = build_adoption_plan(_rec(), _FakeDNS(), manager.ca_manager, settings=settings.load_settings.return_value)
    assert plan['email_configured'] is bool(expected)
    assert plan['available'] is bool(expected)


@pytest.fixture
def missing_ca(tmp_path):
    settings = MagicMock()
    settings.load_settings.return_value = {'email': 'global@example.com', 'default_ca': 'digicert'}
    shell = MockShellExecutor()
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=MagicMock(), ca_manager=CAManager(settings), shell_executor=shell)
    auth = MagicMock()
    auth.require_role.side_effect = lambda role: lambda function: function
    return settings, manager, auth, shell


@pytest.mark.parametrize('async_', [False, True])
@pytest.mark.parametrize('reissue', [False, True])
def test_unconfigured_ca_is_refused_before_sync_or_async_issuance(missing_ca, tmp_path, async_, reissue):
    from flask_restx import Api

    from modules.api.models import create_api_models
    from modules.api.resources import create_api_resources

    settings, manager, auth, shell = missing_ca
    executor = MagicMock()
    app = Flask(__name__)
    api = Api(app)
    managers = {'auth': auth, 'settings': settings, 'certificates': manager,
                'file_ops': MagicMock(cert_dir=tmp_path), 'cache': MagicMock(),
                'dns': manager.dns_manager, 'ca': manager.ca_manager, 'cert_executor': executor}
    resources = create_api_resources(api, create_api_models(api), managers)
    api.add_resource(resources['CreateCertificate'], '/create')
    api.add_resource(resources['CertificateReissue'], '/<string:domain>/reissue')
    if reissue:
        directory = tmp_path / 'example.com'
        directory.mkdir()
        (directory / 'cert.pem').write_bytes(b'old certificate')
        manager._save_metadata('example.com', {'ca_provider': 'digicert', 'challenge_type': 'http-01'})
    response = app.test_client().post('/example.com/reissue' if reissue else '/create', json={
        'domain': 'example.com', 'ca_provider': 'digicert', 'challenge_type': 'http-01', 'async': async_})
    assert response.status_code == 400, response.get_json()
    assert "CA provider 'digicert' is not configured" in response.get_json()['error']
    executor.submit.assert_not_called()
    assert shell.commands_executed == []


def test_batch_reports_unconfigured_ca_not_missing_email(missing_ca):
    settings, manager, auth, shell = missing_ca
    app = Flask(__name__)
    register_cert_routes(app, {}, lambda function: function, auth, manager,
                         lambda domain: domain, MagicMock(), settings, MagicMock(), CERTIFICATE_FILES)
    response = app.test_client().post('/api/web/certificates/batch', json={
        'domains': ['example.com'], 'ca_provider': 'digicert'})
    assert response.status_code == 400
    assert response.get_json()['error'] == (
        'The selected CA or CA account is not configured on this instance. '
        'Configure it in Settings, or choose one that is configured.')
    assert shell.commands_executed == []


def test_batch_does_not_return_exceptions_from_batch_execution(missing_ca):
    settings, manager, auth, _ = missing_ca
    service = MagicMock()
    service.create_batch.side_effect = ValueError('internal exception details')
    app = Flask(__name__)
    register_cert_routes(app, {'cert_service': service}, lambda function: function, auth, manager,
                         lambda domain: domain, MagicMock(), settings, MagicMock(), CERTIFICATE_FILES)
    response = app.test_client().post('/api/web/certificates/batch', json={'domains': ['example.com']})
    assert response.status_code == 500
    assert response.get_json() == {'error': 'Batch creation failed'}
    service.create_batch.assert_called_once()


def test_adoption_reports_email_and_dns_even_when_ca_is_not_configured(missing_ca):
    settings, manager, _, _ = missing_ca
    plan = build_adoption_plan(_rec(), _FakeDNS(settings=settings.load_settings.return_value), manager.ca_manager)
    assert plan['available'] is False
    assert "CA provider 'digicert' is not configured" in plan['reason']
    assert plan['email_configured'] is True
    assert plan['dns_provider'] == 'cloudflare'
    assert plan['dns_provider_configured'] is True


def test_resolved_ca_account_cannot_inject_a_log_line(missing_ca, caplog):
    settings, manager, _, _ = missing_ca
    account_id = 'work\nforged log line'
    settings.load_settings.return_value['ca_providers'] = {
        'digicert': {'accounts': {account_id: {'email': 'ca@example.com'}}}}
    with caplog.at_level('INFO', logger='modules.core.certificates'):
        manager._resolve_ca(settings, 'digicert', account_id, False)
    message = next(record.getMessage() for record in caplog.records if 'Using CA account:' in record.getMessage())
    assert '\n' not in message
    assert 'work' in message
