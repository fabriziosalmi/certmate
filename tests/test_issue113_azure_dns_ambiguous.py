"""Regression test for issue #113.

certbot-dns-azure exposes several --dns-azure-* options
(--dns-azure-credentials, --dns-azure-config,
--dns-azure-propagation-seconds), which made certbot reject the bare
--dns-azure shorthand with::

    certbot: error: ambiguous option: --dns-azure could match
    --dns-azure-propagation-seconds, --dns-azure-config,
    --dns-azure-credentials

The fix selects the plugin via ``--authenticator <name>`` in the base
``DNSProviderStrategy.configure_certbot_arguments``, which sidesteps
argparse's prefix matching entirely. This test pins that contract for
Azure and also for the generic strategy so the same class of bug cannot
silently regress for any future plugin that grows additional sub-flags.
"""
import pytest

from modules.core.dns_strategies import (
    AzureStrategy,
    CloudflareStrategy,
    GoogleStrategy,
)


pytestmark = [pytest.mark.unit]


class TestAzureStrategyAvoidsAmbiguousFlag:
    def test_azure_uses_authenticator_not_shorthand(self, tmp_path, monkeypatch):
        """The Azure command must use ``--authenticator dns-azure`` and must
        not contain the bare ``--dns-azure`` shorthand."""
        monkeypatch.chdir(tmp_path)
        strategy = AzureStrategy()
        creds = strategy.create_config_file({
            'subscription_id': 'sub',
            'resource_group': 'rg',
            'tenant_id': 'tenant',
            'client_id': 'client',
            'client_secret': 'shhh',
        })

        cmd = []
        strategy.configure_certbot_arguments(cmd, creds)

        assert '--authenticator' in cmd
        auth_idx = cmd.index('--authenticator')
        assert cmd[auth_idx + 1] == 'dns-azure'

        # The bare --dns-azure shorthand is exactly what certbot rejected.
        assert '--dns-azure' not in cmd, (
            f"--dns-azure is ambiguous for this plugin; use --authenticator instead: {cmd}"
        )

        assert '--dns-azure-credentials' in cmd
        cred_idx = cmd.index('--dns-azure-credentials')
        assert cmd[cred_idx + 1] == str(creds)


class TestBaseStrategyAvoidsAmbiguousFlag:
    """Pin the contract on the shared base method so the fix cannot regress
    for any provider that does not override ``configure_certbot_arguments``.
    """

    @pytest.mark.parametrize("strategy_cls,plugin_name,config", [
        (CloudflareStrategy, 'dns-cloudflare', {'api_token': 'tok'}),
        (GoogleStrategy, 'dns-google', {'project_id': 'p', 'service_account_key': '{}'}),
    ])
    def test_authenticator_selector_used(self, strategy_cls, plugin_name, config, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        strategy = strategy_cls()
        creds = strategy.create_config_file(config)

        cmd = []
        strategy.configure_certbot_arguments(cmd, creds)

        assert '--authenticator' in cmd
        auth_idx = cmd.index('--authenticator')
        assert cmd[auth_idx + 1] == plugin_name
        # The shorthand selector must not appear — even when it currently
        # works for these providers, it would silently break the day they
        # grow a second --{plugin}-* option.
        assert f'--{plugin_name}' not in cmd

    def test_domain_alias_logs_cname_hint(self, tmp_path, monkeypatch, caplog):
        """The CNAME hint logged for DNS alias validation must still fire
        after the --authenticator switch."""
        monkeypatch.chdir(tmp_path)
        strategy = AzureStrategy()
        creds = strategy.create_config_file({
            'subscription_id': 'sub',
            'resource_group': 'rg',
            'tenant_id': 'tenant',
            'client_id': 'client',
            'client_secret': 'shhh',
        })

        cmd = []
        with caplog.at_level('INFO'):
            strategy.configure_certbot_arguments(cmd, creds, domain_alias='delegated.example.com')

        assert any('delegated.example.com' in record.message for record in caplog.records)
