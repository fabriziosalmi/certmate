"""
Tests for SAN domains support and DNS provider fallback (Issue #56).

Unit tests — no Docker container required.
"""
import pytest
from unittest.mock import MagicMock, patch
from pathlib import Path


class TestBuildCertbotCommandSanDomains:
    """Test that CAManager.build_certbot_command accepts san_domains."""

    def setup_method(self):
        from modules.core.ca_manager import CAManager
        self.ca_manager = CAManager.__new__(CAManager)
        self.ca_manager.settings_manager = MagicMock()
        self.ca_manager.ca_providers = {
            'letsencrypt': {
                'name': "Let's Encrypt",
                'production_url': 'https://acme-v02.api.letsencrypt.org/directory',
                'staging_url': 'https://acme-staging-v02.api.letsencrypt.org/directory',
                'requires_eab': False,
            }
        }

    def test_san_domains_parameter_accepted(self):
        """build_certbot_command must accept san_domains keyword without error."""
        cmd, extra_env = self.ca_manager.build_certbot_command(
            domain='example.com',
            email='test@example.com',
            ca_provider='letsencrypt',
            dns_provider='cloudflare',
            dns_config={'api_token': 'fake'},
            account_config={},
            staging=False,
            cert_dir=Path('/tmp/test-certs'),
            san_domains=['www.example.com', 'mail.example.com'],
        )
        assert isinstance(cmd, list)
        assert isinstance(extra_env, dict)

    def test_san_domains_added_to_command(self):
        """SAN domains should appear as -d flags in the certbot command."""
        cmd, _ = self.ca_manager.build_certbot_command(
            domain='example.com',
            email='test@example.com',
            ca_provider='letsencrypt',
            dns_provider='cloudflare',
            dns_config={'api_token': 'fake'},
            account_config={},
            san_domains=['www.example.com', 'mail.example.com'],
        )
        d_flags = [cmd[i + 1] for i in range(len(cmd)) if cmd[i] == '-d']
        assert 'example.com' in d_flags
        assert 'www.example.com' in d_flags
        assert 'mail.example.com' in d_flags

    def test_no_san_domains(self):
        """Without san_domains, only primary domain should appear."""
        cmd, _ = self.ca_manager.build_certbot_command(
            domain='example.com',
            email='test@example.com',
            ca_provider='letsencrypt',
            dns_provider='cloudflare',
            dns_config={'api_token': 'fake'},
            account_config={},
            san_domains=None,
        )
        d_flags = [cmd[i + 1] for i in range(len(cmd)) if cmd[i] == '-d']
        assert d_flags == ['example.com']

    def test_returns_tuple(self):
        """build_certbot_command must return a (cmd, env) tuple."""
        result = self.ca_manager.build_certbot_command(
            domain='example.com',
            email='test@example.com',
            ca_provider='letsencrypt',
            dns_provider='cloudflare',
            dns_config={'api_token': 'fake'},
            account_config={},
        )
        assert isinstance(result, tuple)
        assert len(result) == 2


class TestDnsProviderFallback:
    """Test that get_domain_dns_provider does NOT hardcode 'cloudflare'."""

    def setup_method(self):
        from modules.core.settings import SettingsManager
        self.mgr = SettingsManager.__new__(SettingsManager)
        self.mgr.settings_file = Path('/tmp/fake-settings.json')

    def test_returns_none_when_no_provider_configured(self):
        """Should return None when no DNS provider is configured anywhere."""
        settings = {'domains': []}
        result = self.mgr.get_domain_dns_provider('unknown.com', settings)
        assert result is None

    def test_returns_configured_default_provider(self):
        """Should return the configured default provider, not hardcoded cloudflare."""
        settings = {'dns_provider': 'route53', 'domains': []}
        result = self.mgr.get_domain_dns_provider('example.com', settings)
        assert result == 'route53'

    def test_returns_domain_specific_provider(self):
        """Should return the domain-specific provider when configured."""
        settings = {
            'dns_provider': 'cloudflare',
            'domains': [
                {'domain': 'example.com', 'dns_provider': 'route53'}
            ],
        }
        result = self.mgr.get_domain_dns_provider('example.com', settings)
        assert result == 'route53'

    def test_legacy_string_domain_uses_default(self):
        """Legacy string domains should use the configured default provider."""
        settings = {
            'dns_provider': 'route53',
            'domains': ['example.com'],
        }
        result = self.mgr.get_domain_dns_provider('example.com', settings)
        assert result == 'route53'

    def test_domain_config_without_provider_uses_default(self):
        """Domain config without dns_provider should fall back to default."""
        settings = {
            'dns_provider': 'route53',
            'domains': [{'domain': 'example.com'}],
        }
        result = self.mgr.get_domain_dns_provider('example.com', settings)
        assert result == 'route53'
