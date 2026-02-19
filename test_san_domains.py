"""Tests for SAN domains support (Issue #56).

Verifies that build_certbot_command() accepts san_domains keyword argument
and that the full certificate creation call chain passes SAN domains correctly.
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
                'name': 'Let\'s Encrypt',
                'production_url': 'https://acme-v02.api.letsencrypt.org/directory',
                'staging_url': 'https://acme-staging-v02.api.letsencrypt.org/directory',
                'requires_eab': False
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
            san_domains=['www.example.com', 'mail.example.com']
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
            san_domains=['www.example.com', 'mail.example.com']
        )
        # Primary domain
        assert '-d' in cmd
        idx = cmd.index('-d')
        assert cmd[idx + 1] == 'example.com'
        # SAN domains must also be present
        d_flags = [cmd[i + 1] for i in range(len(cmd)) if cmd[i] == '-d']
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
            san_domains=None
        )
        d_flags = [cmd[i + 1] for i in range(len(cmd)) if cmd[i] == '-d']
        assert d_flags == ['example.com']

    def test_returns_tuple(self):
        """build_certbot_command must return a (cmd, env) tuple, not just a list."""
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


class TestCreateCertificateSanDomains:
    """Test that create_certificate correctly passes san_domains through the call chain."""

    @patch('modules.core.certificates.DNSStrategyFactory')
    def test_san_domains_passed_to_build_certbot_command(self, mock_factory):
        """create_certificate should pass san_domains to ca_manager.build_certbot_command."""
        from modules.core.certificates import CertificateManager

        mock_settings_mgr = MagicMock()
        mock_settings_mgr.load_settings.return_value = {
            'default_ca_provider': 'letsencrypt',
            'dns_propagation_seconds': {}
        }
        mock_settings_mgr.get_domain_dns_provider.return_value = 'cloudflare'

        mock_ca_manager = MagicMock()
        mock_ca_manager.get_ca_config.return_value = ({'acme_url': 'https://acme.test'}, 'default')
        mock_ca_manager.build_certbot_command.return_value = (
            ['certbot', 'certonly', '-d', 'example.com', '-d', 'www.example.com'],
            {}
        )

        mock_strategy = MagicMock()
        mock_strategy.create_config_file.return_value = '/tmp/creds'
        mock_factory.get_strategy.return_value = mock_strategy

        mgr = CertificateManager.__new__(CertificateManager)
        mgr.settings_manager = mock_settings_mgr
        mgr.ca_manager = mock_ca_manager
        mgr.cert_dir = Path('/tmp/test-certs')
        mgr.metrics = None

        # Mock subprocess to prevent actual certbot execution
        with patch('modules.core.certificates.subprocess') as mock_subprocess:
            mock_subprocess.run.return_value = MagicMock(returncode=0, stdout='', stderr='')
            try:
                mgr.create_certificate(
                    domain='example.com',
                    email='test@example.com',
                    dns_provider='cloudflare',
                    dns_config={'api_token': 'fake'},
                    san_domains=['www.example.com']
                )
            except Exception:
                pass  # We only care that build_certbot_command was called correctly

        # Verify san_domains was passed through
        mock_ca_manager.build_certbot_command.assert_called_once()
        call_kwargs = mock_ca_manager.build_certbot_command.call_args
        # san_domains should be passed (either as kwarg or positional)
        assert 'san_domains' in call_kwargs.kwargs or \
               (len(call_kwargs.args) > 8 and call_kwargs.args[8] is not None), \
               "san_domains was not passed to build_certbot_command"
