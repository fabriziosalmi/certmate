"""PowerDNS DNS-01 is answered by CertMate's own manual hook, not by a certbot plugin.

`certbot-dns-powerdns` 0.2.1 needs `dns-lexicon<=3.5.6`, which no environment
holding CertMate's pins can install, and 0.1.1 stops at the first zone guess on
current PowerDNS. The strategy now writes the config the hook reads and hands
certbot `--manual` with the hook as auth and cleanup. These tests pin the seams
the hook's own tests (test_powerdns_dns_hook.py) cannot see:

* what the config file holds, and that it is 0600 and gone when the operation ends;
* the certbot command create and renew build, and that neither names the plugin;
* that the wait reaches the hook, since `--manual` has no propagation flag;
* that a certificate issued by the plugin renews through the hook with no action
  from the operator;
* that alias mode still goes through the alias hook.
"""
import json
import os
import shlex
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core import dns_alias_hook, powerdns_dns_hook
from modules.core.certificates import CertificateManager
from modules.core.dns_strategies import DNSStrategyFactory, PowerDNSStrategy
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.com'
ACCOUNT = {'api_url': 'https://pdns.example.com:8081', 'api_key': 'a-key-that-must-not-stay-on-disk'}


@pytest.fixture(autouse=True)
def in_a_scratch_directory(tmp_path, monkeypatch):
    """Credentials land in letsencrypt/config under the working directory."""
    monkeypatch.chdir(tmp_path)


def _written(config):
    path = PowerDNSStrategy().create_config_file(config)
    return path, json.loads(path.read_text(encoding='utf-8'))


# --------------------------------------------------------------------------
# The config file
# --------------------------------------------------------------------------

def test_the_config_carries_what_the_hook_reads():
    path, config = _written(dict(ACCOUNT))
    assert config == ACCOUNT
    assert path.suffix == '.json' and path.parent.as_posix().endswith('letsencrypt/config')


def test_a_server_id_is_passed_on_when_set():
    _, config = _written({**ACCOUNT, 'server_id': 'ns1'})
    assert config['server_id'] == 'ns1'
    _, config = _written({**ACCOUNT, 'server_id': '  '})
    assert 'server_id' not in config


def test_the_config_is_readable_by_the_owner_only():
    path, _ = _written(dict(ACCOUNT))
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_nothing_of_the_plugins_ini_format_is_written():
    path, _ = _written(dict(ACCOUNT))
    assert 'dns_powerdns' not in path.read_text(encoding='utf-8')


# --------------------------------------------------------------------------
# The certbot arguments
# --------------------------------------------------------------------------

def test_the_arguments_hand_certbot_the_hook_and_never_name_the_plugin():
    strategy = PowerDNSStrategy()
    path = strategy.create_config_file(dict(ACCOUNT))
    cmd = []
    strategy.configure_certbot_arguments(cmd, path)

    assert cmd[:3] == ['--manual', '--preferred-challenges', 'dns']
    auth = shlex.split(cmd[cmd.index('--manual-auth-hook') + 1])
    cleanup = shlex.split(cmd[cmd.index('--manual-cleanup-hook') + 1])
    script = str(Path(powerdns_dns_hook.__file__))
    assert auth[1:] == [script, '--config', str(path), '--action', 'auth']
    assert cleanup[1:] == [script, '--config', str(path), '--action', 'cleanup']
    assert '--authenticator' not in cmd
    assert not any(part.startswith('--dns-powerdns') for part in cmd)


def test_the_arguments_need_the_config_the_strategy_writes():
    with pytest.raises(ValueError):
        PowerDNSStrategy().configure_certbot_arguments([], None)


def test_powerdns_is_a_manual_provider_so_the_plugin_preflight_has_nothing_to_look_for():
    strategy = DNSStrategyFactory.get_strategy('powerdns')
    assert strategy.plugin_name == 'manual'
    assert strategy.supports_propagation_seconds_flag is False
    assert strategy.propagation_via_environment is True


def test_an_account_level_wait_is_handed_to_the_hook():
    env = {}
    PowerDNSStrategy().prepare_environment(env, {'propagation_seconds': 90})
    assert env['CERTMATE_DNS_PROPAGATION_SECONDS'] == '90'
    env = {}
    PowerDNSStrategy().prepare_environment(env, {})
    assert env == {}


# --------------------------------------------------------------------------
# Create and renew, through the real manager
# --------------------------------------------------------------------------

def _manager(tmp_path, shell, *, dns_provider='powerdns', account=None):
    settings = MagicMock()
    settings.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01', 'dns_propagation_seconds': {}}
    settings.get_domain_dns_provider.return_value = dns_provider
    dns = MagicMock()
    dns.get_dns_provider_account_config.return_value = (dict(account or ACCOUNT), 'default')
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=settings, dns_manager=dns,
        storage_manager=None, ca_manager=None, shell_executor=shell)


class _RecordingShell(MockShellExecutor):
    """Reads the hook config while certbot would be running, before the manager removes it."""

    def __init__(self, tmp_path, domain):
        super().__init__()
        self.tmp_path, self.domain = tmp_path, domain
        self.hook_script = self.config_seen = self.mode_seen = None

    def run(self, cmd, **kwargs):
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        if '--manual-auth-hook' in argv:
            hook = shlex.split(argv[argv.index('--manual-auth-hook') + 1])
            self.hook_script = hook[1]
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
            domain=DOMAIN, email='a@b.it', dns_provider='powerdns')

    assert result['success'] is True
    argv = shlex.split(shell.commands_executed[0])
    assert '--manual' in argv and '--manual-cleanup-hook' in argv
    assert '--authenticator' not in argv and not any('propagation-seconds' in a for a in argv)
    assert shell.hook_script == str(Path(powerdns_dns_hook.__file__))
    assert shell.config_seen == ACCOUNT
    assert shell.mode_seen == 0o600
    assert shell.envs_executed[0]['CERTMATE_DNS_PROPAGATION_SECONDS'] == '60'      # PowerDNS's default wait
    assert not list(Path('letsencrypt/config').glob('powerdns-*')), 'the credentials outlived the operation'


def test_the_configured_wait_reaches_the_hook(tmp_path):
    shell = _RecordingShell(tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    manager = _manager(tmp_path, shell)
    manager.settings_manager.load_settings.return_value['dns_propagation_seconds'] = {'powerdns': 240}
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        manager.create_certificate(domain=DOMAIN, email='a@b.it', dns_provider='powerdns')
    assert shell.envs_executed[0]['CERTMATE_DNS_PROPAGATION_SECONDS'] == '240'


def test_the_credentials_are_removed_when_certbot_fails_too(tmp_path):
    shell = _RecordingShell(tmp_path, DOMAIN)
    shell.set_next_result(returncode=1, stderr='certbot: the challenge failed')
    with patch.object(CertificateManager, '_write_pfx', return_value=None), pytest.raises(RuntimeError):
        _manager(tmp_path, shell).create_certificate(domain=DOMAIN, email='a@b.it', dns_provider='powerdns')
    assert not list(Path('letsencrypt/config').glob('powerdns-*'))


def test_a_certificate_the_plugin_issued_renews_through_the_hook(tmp_path):
    """Its renewal config says `authenticator = dns-powerdns`; the command line replaces that."""
    shell = _RecordingShell(tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    domain_dir = tmp_path / DOMAIN
    (domain_dir / 'renewal').mkdir(parents=True)
    (domain_dir / 'renewal' / f'{DOMAIN}.conf').write_text(
        '[renewalparams]\nauthenticator = dns-powerdns\n'
        'dns_powerdns_credentials = /gone/powerdns.ini\n')
    (domain_dir / 'cert.pem').write_text('fake certificate content')
    (domain_dir / 'metadata.json').write_text(json.dumps({'domain': DOMAIN, 'dns_provider': 'powerdns'}))

    with patch.object(CertificateManager, '_write_pfx', return_value=None), _no_plugin_lookup():
        _manager(tmp_path, shell).renew_certificate(DOMAIN)

    argv = shlex.split(shell.commands_executed[0])
    assert argv[:2] == ['certbot', 'renew']
    assert '--manual' in argv and '--manual-auth-hook' in argv
    assert not any(part.startswith('--dns-powerdns') for part in argv)
    assert shell.hook_script == str(Path(powerdns_dns_hook.__file__))
    assert shell.config_seen == ACCOUNT
    assert not list(Path('letsencrypt/config').glob('powerdns-*'))


def test_alias_mode_still_goes_through_the_alias_hook(tmp_path):
    """The record then lands on the alias zone, which the alias hook writes."""
    shell = _RecordingShell(tmp_path, DOMAIN)
    shell.set_next_result(returncode=0)
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = _manager(tmp_path, shell).create_certificate(
            domain=DOMAIN, email='a@b.it', dns_provider='powerdns',
            domain_alias='validation.example.net')
    assert result['success'] is True
    assert shell.hook_script == str(Path(dns_alias_hook.__file__))
