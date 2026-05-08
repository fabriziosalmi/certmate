from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core import dns_alias_hook
from modules.core.shell import MockShellExecutor


CORE_ALIAS_PROVIDERS = [
    'cloudflare', 'route53', 'azure', 'google', 'powerdns', 'digitalocean',
    'linode', 'edgedns', 'gandi', 'ovh', 'namecheap', 'arvancloud',
    'infomaniak', 'acme-dns', 'duckdns',
]


def _provider_config(provider):
    if provider == 'cloudflare':
        return {'api_token': 'cf-token'}
    if provider == 'route53':
        return {'access_key_id': 'aws-key', 'secret_access_key': 'aws-secret'}
    if provider == 'azure':
        return {
            'subscription_id': 'sub',
            'resource_group': 'rg',
            'tenant_id': 'tenant',
            'client_id': 'client',
            'client_secret': 'secret',
        }
    if provider == 'google':
        return {
            'project_id': 'project',
            'service_account_key': '{"client_email":"svc@example.com","private_key":"key"}',
        }
    if provider == 'powerdns':
        return {'api_url': 'https://powerdns.example.com:8081', 'api_key': 'pdns-key'}
    if provider == 'digitalocean':
        return {'api_token': 'do-token'}
    if provider == 'linode':
        return {'api_key': 'linode-key'}
    if provider == 'edgedns':
        return {
            'client_token': 'client-token',
            'client_secret': 'client-secret',
            'access_token': 'access-token',
            'host': 'akab-host',
        }
    if provider == 'gandi':
        return {'api_token': 'gandi-token'}
    if provider == 'ovh':
        return {
            'endpoint': 'ovh-eu',
            'application_key': 'app-key',
            'application_secret': 'app-secret',
            'consumer_key': 'consumer-key',
        }
    if provider == 'namecheap':
        return {'username': 'namecheap-user', 'api_key': 'namecheap-key', 'client_ip': '127.0.0.1'}
    if provider == 'arvancloud':
        return {'api_key': 'arvan-key'}
    if provider == 'infomaniak':
        return {'api_token': 'infomaniak-token'}
    if provider == 'acme-dns':
        return {
            'api_url': 'https://auth.acme-dns.io',
            'username': 'acme-user',
            'password': 'acme-password',
            'subdomain': 'jam--ie.bksslvalidation.ie',
        }
    if provider == 'duckdns':
        return {'api_token': 'duck-token'}
    return {'nameserver': '127.0.0.1', 'tsig_key': 'key', 'tsig_secret': 'secret'}


def _manager(tmp_path, provider='cloudflare'):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_propagation_seconds': {provider: 1},
    }
    settings_mgr.get_domain_dns_provider.return_value = provider

    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (
        _provider_config(provider),
        'production',
    )

    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)

    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=dns_mgr,
        storage_manager=None,
        ca_manager=None,
        shell_executor=shell,
    ), shell


def _d_flags(cmd):
    return [cmd[i + 1] for i in range(len(cmd)) if cmd[i] == '-d']


@pytest.mark.parametrize(
    ('provider', 'plugin_flag', 'credentials_flag'),
    [
        ('cloudflare', '--dns-cloudflare', '--dns-cloudflare-credentials'),
        ('powerdns', '--dns-powerdns', '--dns-powerdns-credentials'),
        ('route53', '--dns-route53', '--dns-route53-credentials'),
    ],
)
def test_domain_alias_uses_manual_hook_not_provider_plugin(tmp_path, provider, plugin_flag, credentials_flag):
    mgr, shell = _manager(tmp_path, provider=provider)

    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        result = mgr.create_certificate(
            domain='jam.ie',
            email='test@example.com',
            dns_provider=provider,
            staging=True,
            domain_alias='jam--ie.bksslvalidation.ie',
        )

    assert result['success'] is True
    cmd = shell.commands_executed[0].split()
    assert _d_flags(cmd) == ['jam.ie']
    assert '--manual' in cmd
    assert '--manual-auth-hook' in cmd
    assert '--manual-cleanup-hook' in cmd
    assert plugin_flag not in cmd
    assert credentials_flag not in cmd
    assert f'{plugin_flag}-propagation-seconds' not in cmd


@pytest.mark.parametrize('provider', CORE_ALIAS_PROVIDERS)
def test_domain_alias_all_core_providers_use_manual_hook(tmp_path, provider):
    mgr, shell = _manager(tmp_path, provider=provider)

    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        result = mgr.create_certificate(
            domain='jam.ie',
            email='test@example.com',
            dns_provider=provider,
            staging=True,
            domain_alias='jam--ie.bksslvalidation.ie',
        )

    assert result['success'] is True
    cmd = shell.commands_executed[0].split()
    assert '--manual' in cmd
    assert '--manual-auth-hook' in cmd
    assert result['domain'] == 'jam.ie'


def test_domain_alias_does_not_require_provider_certbot_plugin(tmp_path):
    mgr, shell = _manager(tmp_path, provider='powerdns')

    with patch('modules.core.certificates.check_certbot_plugin_installed') as plugin_check:
        result = mgr.create_certificate(
            domain='jam.ie',
            email='test@example.com',
            dns_provider='powerdns',
            staging=True,
            domain_alias='jam--ie.bksslvalidation.ie',
        )

    assert result['success'] is True
    plugin_check.assert_not_called()
    assert '--manual' in shell.commands_executed[0].split()


@pytest.mark.parametrize(
    ('provider', 'expected_secret'),
    [
        ('cloudflare', '"api_token": "cf-token"'),
        ('powerdns', '"api_key": "pdns-key"'),
        ('route53', '"access_key_id": "aws-key"'),
    ],
)
def test_domain_alias_hook_config_contains_provider_alias_and_is_cleaned_up(tmp_path, provider, expected_secret):
    mgr, shell = _manager(tmp_path, provider=provider)
    captured = {}
    original = CertificateManager._configure_dns_alias_arguments

    def capture_config(cmd, hook_config):
        captured['path'] = Path(hook_config)
        captured['content'] = captured['path'].read_text()
        original(cmd, hook_config)

    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True), \
         patch.object(CertificateManager, '_configure_dns_alias_arguments', side_effect=capture_config):
        mgr.create_certificate(
            domain='jam.ie',
            email='test@example.com',
            dns_provider=provider,
            staging=True,
            domain_alias='jam--ie.bksslvalidation.ie',
        )

    assert f'"provider": "{provider}"' in captured['content']
    assert '"domain_alias": "jam--ie.bksslvalidation.ie"' in captured['content']
    assert expected_secret in captured['content']
    assert '"config":' in captured['content']
    assert not captured['path'].exists()


def test_domain_alias_rejects_unsupported_provider(tmp_path):
    mgr, _ = _manager(tmp_path, provider='rfc2136')

    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(RuntimeError) as exc_info:
            mgr.create_certificate(
                domain='example.com',
                email='test@example.com',
                dns_provider='rfc2136',
                staging=True,
                domain_alias='validation.example.org',
            )

    assert 'does not support this DNS provider yet' in str(exc_info.value)


def test_domain_alias_missing_provider_credentials_fails_before_certbot(tmp_path):
    mgr, shell = _manager(tmp_path, provider='digitalocean')
    mgr.dns_manager.get_dns_provider_account_config.return_value = ({'api_token': ''}, 'production')

    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(ValueError) as exc_info:
            mgr.create_certificate(
                domain='example.com',
                email='test@example.com',
                dns_provider='digitalocean',
                staging=True,
                domain_alias='validation.example.org',
            )

    assert 'digitalocean DNS alias mode requires: api_token' in str(exc_info.value)
    assert shell.commands_executed == []


def test_acme_dns_alias_mismatch_fails_before_certbot(tmp_path):
    mgr, shell = _manager(tmp_path, provider='acme-dns')

    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True):
        with pytest.raises(ValueError) as exc_info:
            mgr.create_certificate(
                domain='example.com',
                email='test@example.com',
                dns_provider='acme-dns',
                staging=True,
                domain_alias='other.example.org',
            )

    assert "ACME-DNS domain_alias must match configured subdomain" in str(exc_info.value)
    assert shell.commands_executed == []


@pytest.mark.parametrize(
    ('provider', 'expected_lexicon_provider', 'expected_key', 'expected_value'),
    [
        ('cloudflare', 'cloudflare', 'auth_token', 'cf-token'),
        ('route53', 'route53', 'auth_access_key', 'aws-key'),
        ('azure', 'azure', 'auth_subscription_id', 'sub'),
        ('google', 'googleclouddns', 'project_id', 'project'),
        ('powerdns', 'powerdns', 'pdns_server', 'https://powerdns.example.com:8081'),
        ('digitalocean', 'digitalocean', 'auth_token', 'do-token'),
        ('linode', 'linode', 'auth_token', 'linode-key'),
        ('gandi', 'gandi', 'api_protocol', 'rest'),
        ('ovh', 'ovh', 'auth_entrypoint', 'ovh-eu'),
        ('namecheap', 'namecheap', 'auth_client_ip', '127.0.0.1'),
        ('arvancloud', 'arvancloud', 'auth_token', 'arvan-key'),
        ('infomaniak', 'infomaniak', 'auth_token', 'infomaniak-token'),
        ('duckdns', 'duckdns', 'auth_token', 'duck-token'),
    ],
)
def test_lexicon_alias_config_mapping(provider, expected_lexicon_provider, expected_key, expected_value):
    config = dns_alias_hook._lexicon_config(
        provider,
        'jam--ie.bksslvalidation.ie',
        _provider_config(provider),
    )

    assert config['provider_name'] == expected_lexicon_provider
    assert config['domain'] == 'jam--ie.bksslvalidation.ie'
    assert config[expected_key] == expected_value


def test_google_alias_config_encodes_service_account():
    config = dns_alias_hook._lexicon_config(
        'google',
        'jam--ie.bksslvalidation.ie',
        _provider_config('google'),
    )

    assert config['auth_service_account_info'].startswith('base64::')


def test_lexicon_alias_create_and_delete_use_target_record(monkeypatch):
    calls = []

    class FakeOperations:
        def create_record(self, rtype, name, content):
            calls.append(('create', rtype, name, content))

        def delete_record(self, identifier=None, rtype=None, name=None, content=None):
            calls.append(('delete', rtype, name, content))

    class FakeClient:
        def __init__(self, config):
            calls.append(('config', config['provider_name'], config['domain']))

        def __enter__(self):
            return FakeOperations()

        def __exit__(self, exc_type, exc, tb):
            return False

    monkeypatch.setitem(__import__('sys').modules, 'lexicon.client', MagicMock(Client=FakeClient))
    hook_config = {
        'provider': 'cloudflare',
        'domain_alias': 'jam--ie.bksslvalidation.ie',
        'config': _provider_config('cloudflare'),
    }

    dns_alias_hook._lexicon_change(hook_config, 'validation-token', 'create')
    dns_alias_hook._lexicon_change(hook_config, 'validation-token', 'delete')

    assert ('create', 'TXT', '_acme-challenge.jam--ie.bksslvalidation.ie', 'validation-token') in calls
    assert ('delete', 'TXT', '_acme-challenge.jam--ie.bksslvalidation.ie', 'validation-token') in calls


def test_acme_dns_alias_requires_matching_subdomain(monkeypatch):
    calls = []
    monkeypatch.setattr(dns_alias_hook, '_json_request', lambda *args: calls.append(args) or {})

    dns_alias_hook._acme_dns_change(
        {
            'provider': 'acme-dns',
            'domain_alias': 'jam--ie.bksslvalidation.ie',
            'config': _provider_config('acme-dns'),
        },
        'validation-token',
        'create',
    )

    assert calls[0][0] == 'POST'
    assert calls[0][1] == 'https://auth.acme-dns.io/update'
    assert calls[0][3]['txt'] == 'validation-token'


def test_acme_dns_alias_rejects_non_matching_subdomain():
    with pytest.raises(dns_alias_hook.DNSAliasError):
        dns_alias_hook._acme_dns_change(
            {
                'provider': 'acme-dns',
                'domain_alias': 'other.example.org',
                'config': _provider_config('acme-dns'),
            },
            'validation-token',
            'create',
        )
