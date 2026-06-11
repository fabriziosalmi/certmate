"""
Tests for the custom-script DNS provider (#286).

Admin-supplied auth/cleanup hook scripts via certbot --manual cover any
DNS provider without a certbot plugin (OCI — #285 — in-house DNS, ...).
The pins that matter:

- the certbot command carries --manual + the hook paths and never an
  --authenticator/plugin credentials pair or a propagation flag
- hook paths are validated like deploy hooks: absolute, existing,
  executable, not world-writable — failing loudly beats a baffling
  certbot error
- the plugin-installed preflight is skipped ('manual' is certbot core,
  not an installable plugin)
- renewal validates the hooks still exist but adds no arguments:
  certbot replays manual_auth_hook from its own renewal conf
"""
import json
import os
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.dns_providers import DNSManager
from modules.core.dns_strategies import CustomScriptStrategy, DNSStrategyFactory
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]


@pytest.fixture
def auth_hook(tmp_path):
    script = tmp_path / 'certmate-dns-auth.sh'
    script.write_text('#!/bin/sh\nexit 0\n')
    script.chmod(0o755)
    return script


@pytest.fixture
def cleanup_hook(tmp_path):
    script = tmp_path / 'certmate-dns-cleanup.sh'
    script.write_text('#!/bin/sh\nexit 0\n')
    script.chmod(0o755)
    return script


# ---------------------------------------------------------------------------
# Strategy unit tests
# ---------------------------------------------------------------------------

def test_factory_dispatches_custom_script():
    assert isinstance(
        DNSStrategyFactory.get_strategy('custom-script'), CustomScriptStrategy
    )


def test_command_arguments(auth_hook, cleanup_hook):
    strategy = CustomScriptStrategy()
    strategy.create_config_file({
        'auth_hook': str(auth_hook), 'cleanup_hook': str(cleanup_hook),
    })
    cmd = []
    strategy.configure_certbot_arguments(cmd, None)
    assert cmd[cmd.index('--manual-auth-hook') + 1] == str(auth_hook)
    assert cmd[cmd.index('--manual-cleanup-hook') + 1] == str(cleanup_hook)
    assert '--manual' in cmd
    assert cmd[cmd.index('--preferred-challenges') + 1] == 'dns'
    assert '--authenticator' not in cmd


def test_cleanup_hook_is_optional(auth_hook):
    strategy = CustomScriptStrategy()
    strategy.create_config_file({'auth_hook': str(auth_hook)})
    cmd = []
    strategy.configure_certbot_arguments(cmd, None)
    assert '--manual-auth-hook' in cmd
    assert '--manual-cleanup-hook' not in cmd


def test_no_propagation_flag_and_core_plugin():
    strategy = CustomScriptStrategy()
    # --manual has no propagation flag; certbot core 'manual' is never an
    # installable plugin, which is what skips the preflight.
    assert strategy.supports_propagation_seconds_flag is False
    assert strategy.plugin_name == 'manual'


def test_missing_auth_hook_raises():
    with pytest.raises(ValueError, match="requires an 'auth_hook'"):
        CustomScriptStrategy().create_config_file({})


def test_relative_path_rejected():
    with pytest.raises(ValueError, match='absolute path'):
        CustomScriptStrategy().create_config_file({'auth_hook': 'bin/hook.sh'})


def test_nonexistent_script_rejected(tmp_path):
    with pytest.raises(ValueError, match='does not exist'):
        CustomScriptStrategy().create_config_file({
            'auth_hook': str(tmp_path / 'missing.sh'),
        })


def test_non_executable_script_rejected(tmp_path):
    script = tmp_path / 'hook.sh'
    script.write_text('#!/bin/sh\nexit 0\n')
    script.chmod(0o644)
    with pytest.raises(ValueError, match='not executable'):
        CustomScriptStrategy().create_config_file({'auth_hook': str(script)})


def test_world_writable_script_rejected(tmp_path):
    script = tmp_path / 'hook.sh'
    script.write_text('#!/bin/sh\nexit 0\n')
    script.chmod(0o777)
    with pytest.raises(ValueError, match='world-writable'):
        CustomScriptStrategy().create_config_file({'auth_hook': str(script)})


def test_propagation_hint_exported(auth_hook):
    strategy = CustomScriptStrategy()
    env = {}
    strategy.prepare_environment(env, {
        'auth_hook': str(auth_hook), 'propagation_seconds': 90,
    })
    assert env['CERTMATE_DNS_PROPAGATION_SECONDS'] == '90'


# ---------------------------------------------------------------------------
# Create / renew flow
# ---------------------------------------------------------------------------

def _cert_manager(tmp_path, shell, hook_config):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_propagation_seconds': {},
    }
    settings_mgr.get_domain_dns_provider.return_value = 'custom-script'

    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (hook_config, 'default')

    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=dns_mgr,
        storage_manager=None,
        ca_manager=None,
        shell_executor=shell,
    )


def _fake_issuance(shell, tmp_path, domain):
    from modules.core.constants import CERTIFICATE_FILES

    original_run = shell.run

    def run(cmd, **kwargs):
        result = original_run(cmd, **kwargs)
        live_dir = tmp_path / domain / 'live' / domain
        live_dir.mkdir(parents=True, exist_ok=True)
        for cert_file in CERTIFICATE_FILES:
            (live_dir / cert_file).write_bytes(b'pem-bytes\n')
        return result

    shell.run = run
    return shell


def test_create_certificate_uses_manual_hooks(tmp_path, auth_hook, cleanup_hook):
    domain = 'app.example.com'
    shell = _fake_issuance(MockShellExecutor(), tmp_path, domain)
    shell.set_next_result(returncode=0)
    mgr = _cert_manager(tmp_path, shell, {
        'auth_hook': str(auth_hook), 'cleanup_hook': str(cleanup_hook),
    })

    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        result = mgr.create_certificate(
            domain=domain, email='a@b.it', dns_provider='custom-script',
        )

    assert result['success'] is True
    cmd = shell.commands_executed[0].split()
    assert cmd[cmd.index('--manual-auth-hook') + 1] == str(auth_hook)
    assert cmd[cmd.index('--manual-cleanup-hook') + 1] == str(cleanup_hook)
    assert '--authenticator' not in cmd
    # --manual accepts no propagation flag.
    assert not any('propagation-seconds' in part for part in cmd)
    metadata = json.loads((tmp_path / domain / 'metadata.json').read_text())
    assert metadata['dns_provider'] == 'custom-script'


def test_create_fails_loudly_when_script_vanished(tmp_path):
    domain = 'app.example.com'
    shell = MockShellExecutor()
    mgr = _cert_manager(tmp_path, shell, {
        'auth_hook': str(tmp_path / 'gone.sh'),
    })

    with patch.object(CertificateManager, '_write_pfx', return_value=None), \
         pytest.raises(ValueError, match='does not exist'):
        mgr.create_certificate(
            domain=domain, email='a@b.it', dns_provider='custom-script',
        )
    # certbot must never have been invoked with a broken hook.
    assert not shell.commands_executed


def test_renew_validates_hooks_but_adds_no_arguments(tmp_path, auth_hook):
    """certbot renew replays manual_auth_hook from the renewal conf; the
    renew command CertMate builds must stay argument-free for hooks."""
    domain = 'app.example.com'
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)
    mgr = _cert_manager(tmp_path, shell, {'auth_hook': str(auth_hook)})

    domain_dir = tmp_path / domain
    domain_dir.mkdir()
    (domain_dir / 'cert.pem').write_text('fake certificate content')
    (domain_dir / 'metadata.json').write_text(json.dumps({
        'domain': domain,
        'dns_provider': 'custom-script',
    }))

    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        mgr.renew_certificate(domain)

    assert shell.commands_executed, 'renewal never invoked certbot'
    cmd = shell.commands_executed[0].split()
    assert cmd[:2] == ['certbot', 'renew']
    assert '--manual-auth-hook' not in cmd


# ---------------------------------------------------------------------------
# Test endpoint validation
# ---------------------------------------------------------------------------

def _dns_manager():
    return DNSManager(settings_manager=MagicMock())


def test_provider_test_validates_filesystem(auth_hook):
    ok, message = _dns_manager().test_provider('custom-script', {
        'auth_hook': str(auth_hook),
    })
    assert ok, message
    assert 'executable' in message


def test_provider_test_rejects_missing_script(tmp_path):
    ok, message = _dns_manager().test_provider('custom-script', {
        'auth_hook': str(tmp_path / 'missing.sh'),
    })
    assert not ok
    assert 'does not exist' in message


def test_provider_test_requires_auth_hook():
    ok, message = _dns_manager().test_provider('custom-script', {})
    assert not ok
    assert 'auth_hook' in message
