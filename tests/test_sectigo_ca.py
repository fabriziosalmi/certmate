"""Sectigo uses the shared CA account, EAB and certbot paths."""

import pytest

from modules.core.ca_manager import CAManager
from modules.core.caa import CA_IDENTIFIERS
from modules.core.certificates import CertificateManager
from modules.core.settings import (
    SECRET_MASK_SENTINEL, _deep_merge_dict, _strip_masked_values,
    mask_secrets_in_settings,
)


pytestmark = pytest.mark.unit


class Settings:
    def __init__(self, accounts):
        self.accounts = accounts

    def load_settings(self):
        return {'ca_providers': {'sectigo': {'accounts': self.accounts}}}


@pytest.fixture
def accounts():
    return {
        'production-ov': {'acme_url': 'https://acme.sectigo.com/v2/OV',
                          'eab_kid': 'ov-kid', 'eab_hmac': 'ov-secret', 'email': 'ov@example.com'},
        'production-dv': {'acme_url': 'https://acme.sectigo.com/v2/DV',
                          'eab_kid': 'dv-kid', 'eab_hmac': 'dv-secret', 'email': 'dv@example.com'},
    }


def test_metadata_and_validation(accounts):
    manager = CAManager(Settings(accounts))
    info = manager.get_supported_cas()['sectigo']
    assert info['name'] == 'Sectigo'
    assert info['requires_eab'] is True
    assert info['supports_wildcard'] is True
    assert info['certificate_types'] == ['DV', 'OV']
    assert 'sectigo.com' in CA_IDENTIFIERS['sectigo']
    assert manager.validate_ca_configuration('sectigo', accounts['production-ov'])[0]
    for missing, expected in [('acme_url', 'ACME Directory URL'),
                              ('eab_kid', 'EAB Key ID'), ('eab_hmac', 'HMAC Key')]:
        config = {k: v for k, v in accounts['production-ov'].items() if k != missing}
        valid, message = manager.validate_ca_configuration('sectigo', config)
        assert not valid and expected in message
    assert not manager.validate_ca_configuration('sectigo', {
        **accounts['production-ov'], 'acme_url': 'not-a-url'})[0]
    valid, message = manager.validate_ca_configuration('sectigo', {
        **accounts['production-ov'], 'acme_url': 'http://acme.sectigo.com/v2/OV'})
    assert not valid and 'HTTPS' in message


def test_account_specific_directory_and_certbot_command(accounts):
    manager = CAManager(Settings(accounts))
    for account_id, expected in accounts.items():
        config, used = manager.get_ca_config('sectigo', account_id)
        assert used == account_id
        assert manager.get_acme_server_url('sectigo', account_config=config) == expected['acme_url']
        command, env = manager.build_certbot_command(
            'example.com', expected['email'], 'sectigo', 'custom-script', {}, config)
        assert env == {}
        for flag, value in [('--server', expected['acme_url']),
                            ('--eab-kid', expected['eab_kid']),
                            ('--eab-hmac-key', expected['eab_hmac'])]:
            assert command[command.index(flag) + 1] == value
        other = accounts['production-dv' if account_id == 'production-ov' else 'production-ov']
        assert other['eab_hmac'] not in command


def test_missing_directory_fails_closed_and_existing_ca_urls_unchanged(accounts):
    manager = CAManager(Settings(accounts))
    with pytest.raises(ValueError, match='Sectigo ACME URL'):
        manager.get_acme_server_url('sectigo', account_config={})
    with pytest.raises(ValueError, match='HTTPS ACME Directory URL'):
        manager.get_acme_server_url('sectigo', account_config={
            **accounts['production-ov'], 'acme_url': 'http://acme.sectigo.com/v2/OV'})
    with pytest.raises(ValueError, match='HTTPS ACME Directory URL'):
        manager.get_acme_server_url('sectigo', staging=True, account_config={
            **accounts['production-ov'], 'staging_url': 'http://acme.sectigo.com/v2/OV'})
    for provider in ('letsencrypt', 'digicert', 'actalis', 'zerossl', 'google'):
        info = manager.ca_providers[provider]
        assert manager.get_acme_server_url(provider, account_config=accounts['production-ov']) == info['production_url']
        assert manager.get_acme_server_url(provider, staging=True, account_config=accounts['production-ov']) == info['staging_url']
    assert manager.get_acme_server_url('private_ca', account_config=accounts['production-ov']) == accounts['production-ov']['acme_url']
    assert not manager.validate_ca_configuration('private_ca', {
        'acme_url': 'http://internal-ca.example.com/directory'})[0]
    assert manager.validate_ca_configuration('private_ca', {
        'acme_url': 'https://internal-ca.example.com/directory'})[0]


def test_unknown_account_never_falls_back_to_lets_encrypt(accounts):
    class Issuer:
        ca_manager = CAManager(Settings(accounts))

    with pytest.raises(ValueError, match='CA account not configured for sectigo'):
        CertificateManager._resolve_ca(Issuer(), {}, 'sectigo', 'unknown', False)


def test_hmac_mask_and_unrelated_update(accounts):
    settings = Settings(accounts).load_settings()
    masked = mask_secrets_in_settings(settings)
    for account_id in accounts:
        assert masked['ca_providers']['sectigo']['accounts'][account_id]['eab_hmac'] == SECRET_MASK_SENTINEL
    cleaned = _strip_masked_values(masked)
    for account_id in accounts:
        assert 'eab_hmac' not in cleaned['ca_providers']['sectigo']['accounts'][account_id]
    cleaned['ca_providers']['sectigo']['accounts']['production-ov']['email'] = 'new@example.com'
    restored = _deep_merge_dict(settings, cleaned)
    for account_id, config in accounts.items():
        assert restored['ca_providers']['sectigo']['accounts'][account_id]['eab_hmac'] == config['eab_hmac']
    assert restored['ca_providers']['sectigo']['accounts']['production-ov']['email'] == 'new@example.com'
