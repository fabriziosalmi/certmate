"""Create and reissue accept the resolved CA account's contact email."""
from unittest.mock import MagicMock

import pytest

from modules.core.ca_manager import CAManager
from modules.core.cert_service import CertificateService
from modules.core.certificates import CertificateManager
from modules.core.shell import MockShellExecutor

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


@pytest.mark.parametrize('provider', ['letsencrypt', 'letsencrypt_staging'])
def test_unconfigured_letsencrypt_keeps_global_email(tmp_path, provider):
    settings = MagicMock()
    settings.load_settings.return_value = {'email': 'global@example.com'}
    manager = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                                 dns_manager=MagicMock(), ca_manager=CAManager(settings))
    service = CertificateService(manager, settings, MagicMock())
    assert service.prepare_create(domain='example.com', ca_provider=provider,
                                  challenge_type='http-01', user={})['email'] == 'global@example.com'
