"""
Unit tests for DuckDNS DNS-01 provider integration.

DuckDNS enables issuance of publicly-trusted certificates for free
*.duckdns.org subdomains — the canonical "I don't own a domain" path.
These tests verify the provider is wired into the strategy factory,
the credential file is written in the exact format certbot-dns-duckdns
expects, and the provider is registered in every validation surface.

No external network access; no Docker required.
"""
import pytest

from modules.core.dns_strategies import (
    DNSStrategyFactory,
    DuckDNSStrategy,
)
from modules.core.utils import (
    _DNS_PROVIDER_CREDENTIALS,
    create_duckdns_config,
    validate_dns_provider_account,
)


class TestDuckDNSStrategy:
    def test_factory_returns_duckdns_strategy(self):
        strategy = DNSStrategyFactory.get_strategy('duckdns')
        assert isinstance(strategy, DuckDNSStrategy)

    def test_plugin_name_matches_certbot_plugin(self):
        # certbot-dns-duckdns registers as 'dns-duckdns'
        assert DuckDNSStrategy().plugin_name == 'dns-duckdns'

    def test_propagation_default_is_60_seconds(self):
        # Plugin default is 30s; we use 60s for a safer margin under load.
        assert DuckDNSStrategy().default_propagation_seconds == 60

    def test_supports_propagation_flag(self):
        # Used by CertificateManager to decide whether to append
        # --{plugin}-propagation-seconds. DuckDNS plugin accepts it.
        assert DuckDNSStrategy().supports_propagation_seconds_flag is True


class TestDuckDNSConfigFile:
    def test_creates_ini_with_expected_key(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_path = create_duckdns_config('a1b2c3d4-e5f6-7890-abcd-ef1234567890')

        assert config_path.exists()
        assert config_path.name == 'duckdns.ini'
        content = config_path.read_text()
        # Exact key required by certbot-dns-duckdns plugin.
        assert 'dns_duckdns_token = a1b2c3d4-e5f6-7890-abcd-ef1234567890' in content

    def test_config_file_permissions_are_0600(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        config_path = create_duckdns_config('token-goes-here')
        # Credentials file must not be world-readable.
        assert (config_path.stat().st_mode & 0o777) == 0o600

    def test_strategy_creates_config_from_dict(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        strategy = DuckDNSStrategy()
        config_path = strategy.create_config_file({'api_token': 'test-token-value'})
        assert config_path is not None
        assert 'dns_duckdns_token = test-token-value' in config_path.read_text()


class TestDuckDNSCertbotArguments:
    def test_configures_authenticator_and_credentials_flags(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        strategy = DuckDNSStrategy()
        credentials_file = strategy.create_config_file({'api_token': 'tok'})

        cmd = []
        strategy.configure_certbot_arguments(cmd, credentials_file)

        # certbot-dns-duckdns exposes multiple --dns-duckdns-* options,
        # which makes the bare --dns-duckdns selector ambiguous to argparse.
        # The plugin must be selected via --authenticator dns-duckdns.
        assert '--authenticator' in cmd, f"expected --authenticator in {cmd}"
        auth_idx = cmd.index('--authenticator')
        assert cmd[auth_idx + 1] == 'dns-duckdns'

        # The bare --dns-duckdns flag must NOT appear — it would crash
        # certbot with "ambiguous option" (reproduced in smoke test).
        assert '--dns-duckdns' not in cmd, (
            f"--dns-duckdns is ambiguous for this plugin; use --authenticator instead: {cmd}"
        )

        assert '--dns-duckdns-credentials' in cmd
        cred_idx = cmd.index('--dns-duckdns-credentials')
        assert cmd[cred_idx + 1] == str(credentials_file)


class TestDuckDNSValidation:
    def test_duckdns_registered_in_required_fields_map(self):
        assert 'duckdns' in _DNS_PROVIDER_CREDENTIALS
        assert _DNS_PROVIDER_CREDENTIALS['duckdns'] == ['api_token']

    def test_validate_dns_provider_account_accepts_valid_config(self):
        ok, msg = validate_dns_provider_account(
            'duckdns', 'default', {'api_token': 'some-uuid-token'}
        )
        assert ok, msg

    def test_validate_dns_provider_account_rejects_missing_token(self):
        ok, msg = validate_dns_provider_account('duckdns', 'default', {})
        assert not ok
        assert 'api_token' in msg

    def test_validate_dns_provider_account_rejects_empty_token(self):
        ok, _ = validate_dns_provider_account(
            'duckdns', 'default', {'api_token': '   '}
        )
        assert not ok


class TestDuckDNSSettingsIntegration:
    def test_duckdns_in_supported_providers_set(self):
        # Settings validator rejects unknown dns_provider values; ensure
        # duckdns survives a save round-trip.
        from modules.core.settings import SettingsManager
        import inspect
        src = inspect.getsource(SettingsManager.save_settings)
        assert "'duckdns'" in src

    def test_duckdns_in_propagation_defaults(self):
        from modules.core.settings import SettingsManager
        import inspect
        # Propagation defaults are applied inside save_settings.
        src = inspect.getsource(SettingsManager.save_settings)
        assert "'duckdns': 60" in src
