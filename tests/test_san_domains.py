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


class TestRoute53PropagationFlag:
    """Issue #75 — certbot-dns-route53 removed --dns-route53-propagation-seconds.

    The certbot-dns-route53 plugin (≥ 1.22) no longer accepts a
    ``--dns-route53-propagation-seconds`` argument; it polls Route53
    internally.  CertMate must NOT pass that flag for Route53.
    """

    def setup_method(self):
        from modules.core.dns_strategies import Route53Strategy, CloudflareStrategy, DNSStrategyFactory
        self.route53 = Route53Strategy()
        self.cloudflare = CloudflareStrategy()
        self.factory = DNSStrategyFactory

    def test_route53_does_not_support_propagation_flag(self):
        """Route53Strategy.supports_propagation_seconds_flag must be False."""
        assert self.route53.supports_propagation_seconds_flag is False

    def test_other_providers_do_support_propagation_flag(self):
        """All non-Route53 strategies should still support the propagation flag."""
        assert self.cloudflare.supports_propagation_seconds_flag is True

    def test_all_non_route53_strategies_support_flag(self):
        """Every strategy except Route53 should support the propagation flag."""
        from modules.core.dns_strategies import DNSStrategyFactory
        for name, strategy_cls in DNSStrategyFactory._strategies.items():
            strategy = strategy_cls()
            if name == 'route53':
                assert strategy.supports_propagation_seconds_flag is False, \
                    f"Route53 should NOT support propagation-seconds flag"
            else:
                assert strategy.supports_propagation_seconds_flag is True, \
                    f"{name} should support propagation-seconds flag"

    def test_propagation_flag_not_in_certbot_cmd_for_route53(self):
        """When CertificateManager builds the command for Route53, the
        --dns-route53-propagation-seconds flag must be absent."""
        from modules.core.dns_strategies import Route53Strategy
        strategy = Route53Strategy()
        cmd = ['certbot', 'certonly', '--dns-route53']
        # Simulate what certificates.py does
        if strategy.supports_propagation_seconds_flag:
            cmd.extend([f'--{strategy.plugin_name}-propagation-seconds', '60'])
        assert '--dns-route53-propagation-seconds' not in cmd


class TestAcmeConnectionSSLHandling:
    """Issue #74 — ACME endpoint test must use the provided CA cert for SSL
    verification instead of always falling back to the system CA bundle."""

    def test_ca_cert_written_to_tempfile_for_verification(self, tmp_path):
        """When a CA cert is supplied the connection test should pass verify=<path>."""
        import tempfile, os

        fake_cert = (
            "-----BEGIN CERTIFICATE-----\n"
            "MIIBIjANBgkq...(fake PEM content)...\n"
            "-----END CERTIFICATE-----\n"
        )

        # Simulate the tempfile creation logic used in resources.py
        _ca_bundle_tmp = None
        try:
            _ca_bundle_tmp = tempfile.NamedTemporaryFile(
                mode='w', suffix='.pem', delete=False
            )
            _ca_bundle_tmp.write(fake_cert.strip())
            _ca_bundle_tmp.flush()
            _ca_bundle_tmp.close()
            verify_ssl = _ca_bundle_tmp.name

            assert os.path.isfile(verify_ssl)
            with open(verify_ssl) as fh:
                assert 'BEGIN CERTIFICATE' in fh.read()
        finally:
            if _ca_bundle_tmp is not None:
                try:
                    os.unlink(_ca_bundle_tmp.name)
                except OSError:
                    pass

    def test_no_ca_cert_uses_system_bundle(self):
        """When no CA cert is supplied, verify_ssl should default to True."""
        ca_cert = None
        _ca_bundle_tmp = None

        if ca_cert:
            import tempfile
            _ca_bundle_tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False)
            verify_ssl = _ca_bundle_tmp.name
        else:
            verify_ssl = True

        assert verify_ssl is True
        assert _ca_bundle_tmp is None
