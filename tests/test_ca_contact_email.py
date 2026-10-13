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
    plan = build_adoption_plan(_rec(), _FakeDNS(), settings=settings.load_settings.return_value)
    assert plan['email_configured'] is bool(expected)
    assert plan['available'] is bool(expected)
