"""Azure DNS-01 is answered by CertMate's own manual hook, not by a certbot plugin (#103).

`certbot-dns-azure` has no release for certbot 4 or later. The strategy that used
to write its ini file and select its authenticator now writes the config the hook
reads and hands certbot `--manual` with the hook as auth and cleanup. These tests
pin the seams the hook's own tests (test_azure_dns_hook.py) cannot see:

* what the config file holds, and that it is 0600 and gone when the operation ends;
* the certbot command create and renew build, and that neither names the plugin;
* that the wait reaches the hook, since `--manual` has no propagation flag;
* that a certificate issued by the old plugin renews through the hook with no
  action from the operator (certbot replaces the stored authenticator when the
  command line names `--manual`, measured on certbot 2.10 and 5.8).
"""
import json
import os
import shlex
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core import azure_dns_hook
from modules.core.certificates import CertificateManager
from modules.core.dns_strategies import AzureStrategy, DNSStrategyFactory, manual_hook_arguments
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.com'
ACCOUNT = {
    'subscription_id': 'SUB-123', 'resource_group': 'rg-prod', 'tenant_id': 'TENANT-XYZ',
    'client_id': 'CLIENT-AAA', 'client_secret': 'a-secret-that-must-not-stay-on-disk',
    # Explicit zones: the operator's own list, so no Azure call is made to discover them.
    'zone_domains': ['example.com'],
}


@pytest.fixture(autouse=True)
def in_a_scratch_directory(tmp_path, monkeypatch):
    """Credentials land in letsencrypt/config under the working directory."""
    monkeypatch.chdir(tmp_path)


def _written(strategy_config):
    path = AzureStrategy().create_config_file(strategy_config)
    return path, json.loads(path.read_text(encoding='utf-8'))


def _config(**overrides):
    config = {k: v for k, v in ACCOUNT.items() if k != 'zone_domains'}
    config['_zone_domain'] = 'example.com'
    config.update(overrides)
    return config


# --------------------------------------------------------------------------
# The config file
# --------------------------------------------------------------------------

def test_the_config_carries_what_the_hook_reads():
    path, config = _written(_config())
    assert config == {
        'tenant_id': 'TENANT-XYZ', 'client_id': 'CLIENT-AAA',
        'client_secret': 'a-secret-that-must-not-stay-on-disk',
        'subscription_id': 'SUB-123', 'resource_group': 'rg-prod', 'zones': ['example.com']}
    assert path.suffix == '.json' and path.parent.as_posix().endswith('letsencrypt/config')


def test_the_config_is_readable_by_the_owner_only():
    path, _ = _written(_config())
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_nothing_of_the_plugins_ini_format_is_written():
    path, _ = _written(_config())
    text = path.read_text(encoding='utf-8')
    assert 'dns_azure' not in text and 'AzurePublicCloud' not in text


def test_every_zone_discovery_found_reaches_the_hook_in_order():
    """The hook takes the longest one a challenge falls under, so a SAN certificate
    spanning two hosted zones, or a wildcard under a parent zone, still lands right."""
    _, config = _written(_config(_zone_domains=['sub.example.com', 'example.com', 'other.org']))
    assert config['zones'] == ['sub.example.com', 'example.com', 'other.org']


def test_the_list_of_zones_wins_over_the_legacy_single_zone():
    _, config = _written(_config(_zone_domains=['example.com'], _zone_domain='ignored.example'))
    assert config['zones'] == ['example.com']


@pytest.mark.parametrize('overrides', [
    {'_zone_domains': [], '_zone_domain': ''},
    {'_zone_domains': [' '], '_zone_domain': ''},
    {'_zone_domains': None, '_zone_domain': ''}])
def test_a_config_with_no_zone_is_refused_before_anything_is_written(overrides):
    with pytest.raises(ValueError, match='zone'):
        AzureStrategy().create_config_file(_config(**overrides))
    assert not list(Path('letsencrypt/config').glob('azure-*'))


# --------------------------------------------------------------------------
# The certbot arguments
# --------------------------------------------------------------------------

def test_the_arguments_hand_certbot_the_hook_and_never_name_the_plugin(tmp_path):
    strategy = AzureStrategy()
    path = strategy.create_config_file(_config())
    cmd = []
    strategy.configure_certbot_arguments(cmd, path)

    assert cmd[:3] == ['--manual', '--preferred-challenges', 'dns']
    auth = shlex.split(cmd[cmd.index('--manual-auth-hook') + 1])
    cleanup = shlex.split(cmd[cmd.index('--manual-cleanup-hook') + 1])
    script = str(Path(azure_dns_hook.__file__))
    assert auth[1:] == [script, '--config', str(path), '--action', 'auth']
    assert cleanup[1:] == [script, '--config', str(path), '--action', 'cleanup']
    assert '--authenticator' not in cmd
    assert not any(part.startswith('--dns-azure') for part in cmd)


def test_a_path_with_a_space_survives_the_shell_certbot_runs_the_hook_through():
    flags = manual_hook_arguments(Path('/opt/cert mate/hook.py'), Path('/tmp/a b/azure.json'))
    parsed = shlex.split(flags[flags.index('--manual-auth-hook') + 1])
    assert parsed[1:] == ['/opt/cert mate/hook.py', '--config', '/tmp/a b/azure.json', '--action', 'auth']


def test_the_arguments_need_the_config_the_strategy_writes():
    with pytest.raises(ValueError):
        AzureStrategy().configure_certbot_arguments([], None)


def test_azure_is_a_manual_provider_so_the_plugin_preflight_has_nothing_to_look_for():
    strategy = DNSStrategyFactory.get_strategy('azure')
    assert strategy.plugin_name == 'manual'
    assert strategy.supports_propagation_seconds_flag is False
    assert strategy.propagation_via_environment is True


def test_an_account_level_wait_is_handed_to_the_hook():
    env = {}
    AzureStrategy().prepare_environment(env, {'propagation_seconds': 90})
    assert env['CERTMATE_DNS_PROPAGATION_SECONDS'] == '90'
    env = {}
    AzureStrategy().prepare_environment(env, {})
    assert env == {}


def test_the_cname_hint_for_a_domain_alias_is_still_logged(caplog):
    strategy = AzureStrategy()
    path = strategy.create_config_file(_config())
    with caplog.at_level('INFO'):
        strategy.configure_certbot_arguments([], path, domain_alias='delegated.example.com')
    assert any('delegated.example.com' in record.message for record in caplog.records)


def test_the_alias_hook_builds_its_arguments_the_same_way():
    """One quoting rule for every hook CertMate runs through certbot's shell."""
    from modules.core import dns_alias_hook
    cmd = []
    CertificateManager._configure_dns_alias_arguments(cmd, Path('/tmp/alias.json'))
    assert cmd == manual_hook_arguments(Path(dns_alias_hook.__file__), Path('/tmp/alias.json'))


# --------------------------------------------------------------------------
# Create and renew, through the real manager
# --------------------------------------------------------------------------

def _manager(tmp_path, shell):
    settings = MagicMock()
    settings.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01', 'dns_propagation_seconds': {}}
    settings.get_domain_dns_provider.return_value = 'azure'
    dns = MagicMock()
    dns.get_dns_provider_account_config.return_value = (dict(ACCOUNT), 'default')
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=settings, dns_manager=dns,
        storage_manager=None, ca_manager=None, shell_executor=shell)


class _RecordingShell(MockShellExecutor):
    """Reads the hook config while certbot would be running, before the manager removes it."""

    def __init__(self, tmp_path, domain):
        super().__init__()
        self.tmp_path, self.domain = tmp_path, domain
        self.config_seen = None
        self.mode_seen = None

    def run(self, cmd, **kwargs):
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        if '--manual-auth-hook' in argv:
            hook = shlex.split(argv[argv.index('--manual-auth-hook') + 1])
            config_path = Path(hook[hook.index('--config') + 1])
            self.config_seen = json.loads(config_path.read_text(encoding='utf-8'))
            self.mode_seen = stat.S_IMODE(os.stat(config_path).st_mode)
        live = self.tmp_path / self.domain / 'live' / self.domain
        live.mkdir(parents=True, exist_ok=True)
        for name in ('cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'):
            (live / name).write_bytes(b'pem-bytes\n')
        return super().run(cmd, **kwargs)


def _no_plugin_lookup():
    return patch('modules.core.certificates.check_certbot_plugin_installed',
                 side_effect=AssertionError('the plugin preflight ran for a manual-hook provider'))


def test_create_answers_through_the_hook_and_leaves_no_secret_behind(tmp_path):
    shell = _RecordingShell(tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    with patch.object(CertificateManager, '_write_pfx', return_value=None), _no_plugin_lookup():
        result = _manager(tmp_path, shell).create_certificate(
            domain=DOMAIN, email='a@b.it', dns_provider='azure')

    assert result['success'] is True
    argv = shlex.split(shell.commands_executed[0])
    assert '--manual' in argv and '--manual-auth-hook' in argv and '--manual-cleanup-hook' in argv
    assert '--authenticator' not in argv and not any('propagation-seconds' in a for a in argv)
    assert shell.config_seen['zones'] == ['example.com']
    assert shell.config_seen['client_secret'] == ACCOUNT['client_secret']
    assert shell.mode_seen == 0o600
    assert shell.envs_executed[0]['CERTMATE_DNS_PROPAGATION_SECONDS'] == '180'      # Azure's default wait
    assert not list(Path('letsencrypt/config').glob('azure-*')), 'the credentials outlived the operation'
    metadata = json.loads((tmp_path / DOMAIN / 'metadata.json').read_text())
    assert metadata['dns_provider'] == 'azure'


def test_the_configured_wait_reaches_the_hook(tmp_path):
    shell = _RecordingShell(tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    manager = _manager(tmp_path, shell)
    manager.settings_manager.load_settings.return_value['dns_propagation_seconds'] = {'azure': 240}
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        manager.create_certificate(domain=DOMAIN, email='a@b.it', dns_provider='azure')
    assert shell.envs_executed[0]['CERTMATE_DNS_PROPAGATION_SECONDS'] == '240'


def test_the_credentials_are_removed_when_certbot_fails_too(tmp_path):
    shell = _RecordingShell(tmp_path, DOMAIN)
    shell.set_next_result(returncode=1, stderr='certbot: the challenge failed')
    with patch.object(CertificateManager, '_write_pfx', return_value=None), pytest.raises(RuntimeError):
        _manager(tmp_path, shell).create_certificate(domain=DOMAIN, email='a@b.it', dns_provider='azure')
    assert not list(Path('letsencrypt/config').glob('azure-*'))


def test_a_certificate_the_plugin_issued_renews_through_the_hook(tmp_path):
    """Its renewal config says `authenticator = dns-azure`; the command line replaces that."""
    shell = _RecordingShell(tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    domain_dir = tmp_path / DOMAIN
    (domain_dir / 'renewal').mkdir(parents=True)
    (domain_dir / 'renewal' / f'{DOMAIN}.conf').write_text(
        '[renewalparams]\nauthenticator = dns-azure\ndns_azure_credentials = /gone/azure.ini\n')
    (domain_dir / 'cert.pem').write_text('fake certificate content')
    (domain_dir / 'metadata.json').write_text(json.dumps({'domain': DOMAIN, 'dns_provider': 'azure'}))

    with patch.object(CertificateManager, '_write_pfx', return_value=None), _no_plugin_lookup():
        _manager(tmp_path, shell).renew_certificate(DOMAIN)

    argv = shlex.split(shell.commands_executed[0])
    assert argv[:2] == ['certbot', 'renew']
    assert '--manual' in argv and '--manual-auth-hook' in argv
    assert shell.config_seen['zones'] == ['example.com']
    assert not list(Path('letsencrypt/config').glob('azure-*'))
