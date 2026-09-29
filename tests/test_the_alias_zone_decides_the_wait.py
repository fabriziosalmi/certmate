"""With a DNS alias on another provider, the ALIAS provider decides the wait.

The TXT record lands on the alias zone, so its provider's propagation time is
the one that matters. Renewal already used it (strategy, environment and
propagation from alias_dns_provider). Issuance used the PRIMARY provider's:
a Cloudflare domain aliased onto a Route53 zone waited Cloudflare's
configured seconds for a Route53 record. Found by the #666 map (D5).
"""
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from tests.test_create_cert_io import _StagingShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.com'


def _manager(tmp_path, seen):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'cloudflare': 11, 'route53': 97},
        'default_key_type': 'ecdsa', 'default_elliptic_curve': 'secp384r1',
    }
    settings_mgr.get_domain_dns_provider.return_value = 'cloudflare'
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.side_effect = lambda provider, *a, **k: (
        {'api_token': 'cf'} if provider == 'cloudflare'
        else {'access_key_id': 'AKIA', 'secret_access_key': 's', 'region': 'us-east-1'},
        'default')
    manager = CertificateManager(
        cert_dir=tmp_path, settings_manager=settings_mgr, dns_manager=dns_mgr,
        storage_manager=None, ca_manager=None,
        shell_executor=_StagingShellExecutor(tmp_path, DOMAIN))
    manager._write_pfx = lambda domain: None
    real = manager._create_dns_alias_hook_config

    def recording(provider, config, alias, propagation):
        seen.append((provider, propagation))
        return real(provider, config, alias, propagation)

    manager._create_dns_alias_hook_config = recording
    return manager


def test_an_alias_on_another_provider_waits_that_provider_s_time(tmp_path):
    """THE regression."""
    seen = []
    _manager(tmp_path, seen).create_certificate(
        DOMAIN, 'a@example.com', 'cloudflare',
        domain_alias='_acme.alias.example.net', alias_dns_provider='route53')

    assert seen == [('route53', 97)], seen


def test_an_alias_on_the_same_provider_is_unchanged(tmp_path):
    """CONTROL: the everyday alias, one provider for both."""
    seen = []
    _manager(tmp_path, seen).create_certificate(
        DOMAIN, 'a@example.com', 'cloudflare',
        domain_alias='_acme.alias.example.com')

    assert seen == [('cloudflare', 11)], seen


def test_the_alias_provider_s_credentials_reach_certbot_s_environment(tmp_path):
    """Route53 reads its credentials from the environment, as renewal already
    prepared them. The primary provider's environment alone is not enough."""
    seen = []
    manager = _manager(tmp_path, seen)
    manager.create_certificate(
        DOMAIN, 'a@example.com', 'cloudflare',
        domain_alias='_acme.alias.example.net', alias_dns_provider='route53')

    env = manager.shell_executor.envs_executed[-1] or {}
    assert env.get('AWS_ACCESS_KEY_ID') == 'AKIA', sorted(k for k in env if k.startswith('AWS'))
