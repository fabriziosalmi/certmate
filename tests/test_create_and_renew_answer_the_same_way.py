"""Create and renew tell certbot the same thing about the challenge (#666, S3).

They used to decide separately. Create chose between the provider's plugin
and CertMate's DNS alias hook on the challenge type, the alias and whether
the hook implements the provider; renew chose on the stored alias alone, and
passed the plugin's options only when a credentials file existed. Three
things followed, each verified before this change:

* **D6.** certbot replays the options of the run that issued a certificate
  unless the renew command line overrides them, and renew never passed the
  wait. Raising a provider's propagation seconds in Settings changed new
  certificates only. Measured against Let's Encrypt staging in
  test_renewal_uses_todays_settings_e2e.py: set 11 s, issue, set 17 s,
  renew -> certbot ran with 11. The HTTP-01 webroot and the custom-script
  hooks were replayed the same way.
* **D11.** Renew chose the alias hook whenever an alias was stored. Create
  never uses the hook for HTTP-01 and stores the alias anyway, so an HTTP-01
  certificate issued with one failed every renewal with "DNS alias provider
  account for http-01 is not configured". (For DNS-01 the same shape is
  unreachable: create refuses an alias the hook does not implement, which
  the last test here pins.)

The test below is the guard: for each way a challenge can be answered, the
challenge part of the renew command is the challenge part of the create
command.
"""
import re
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES
from modules.core.dns_strategies import acme_webroot_dir
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.com'
ALIAS = 'alias.example.net'
WAIT = 42

ACCOUNTS = {
    'cloudflare': {'api_token': 'cf-token-' + 'x' * 32},
    'route53': {'access_key_id': 'AKIAEXAMPLE', 'secret_access_key': 's' * 40},
    'hetzner': {'api_token': 'h' * 32},
}

CHALLENGE_START = ('--authenticator', '--manual', '--webroot')
NOT_CHALLENGE = {'--renew-with-new-domains', '--force-renewal'}


def _manager(tmp_path, captured):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_propagation_seconds': {p: WAIT for p in ACCOUNTS},
    }
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.side_effect = (
        lambda provider, *a, **k: (ACCOUNTS.get(provider), 'default'))

    shell = MockShellExecutor()
    original_run = shell.run

    def run(cmd, **kwargs):
        captured.append(list(cmd))
        result = original_run(cmd, **kwargs)
        live = tmp_path / DOMAIN / 'live' / DOMAIN
        live.mkdir(parents=True, exist_ok=True)
        for name in CERTIFICATE_FILES:
            (live / name).write_bytes(b'pem-bytes\n')
        return result

    shell.run = run
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=settings_mgr, dns_manager=dns_mgr,
        storage_manager=None, ca_manager=None, shell_executor=shell)


def _challenge_part(argv):
    start = next(i for i, token in enumerate(argv) if token in CHALLENGE_START)
    part = [t for t in argv[start:] if t not in NOT_CHALLENGE]
    # Temp files get a fresh name per run; what they are is what matters.
    return [re.sub(r'\S*certmate-dns-alias-\S*?\.json', '<hook-config>',
                   re.sub(r'\S+\.ini$', '<credentials>', t)) for t in part]


CASES = {
    'file-based plugin': dict(dns_provider='cloudflare'),
    'environment-based plugin': dict(dns_provider='route53'),
    'generic plugin': dict(dns_provider='hetzner'),
    'alias hook': dict(dns_provider='cloudflare', domain_alias=ALIAS),
    'http-01': dict(challenge_type='http-01'),
    'http-01 with an alias': dict(challenge_type='http-01', domain_alias=ALIAS),
}


@pytest.mark.parametrize('request_args', CASES.values(), ids=CASES.keys())
def test_renew_answers_the_challenge_the_way_create_did(tmp_path, request_args):
    captured = []
    manager = _manager(tmp_path, captured)
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        manager.create_certificate(domain=DOMAIN, email='a@example.com',
                                   **request_args)
        manager.renew_certificate(DOMAIN, force=True)

    create_argv, renew_argv = captured
    assert renew_argv[:2] == ['certbot', 'renew']
    assert _challenge_part(renew_argv) == _challenge_part(create_argv)


def test_the_wait_renew_passes_is_todays(tmp_path):
    """The guard above would pass if both sides passed the same stale value;
    this pins that it is the one Settings hold now."""
    captured = []
    manager = _manager(tmp_path, captured)
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        manager.create_certificate(domain=DOMAIN, email='a@example.com',
                                   dns_provider='cloudflare')
        manager.settings_manager.load_settings.return_value = {
            **manager.settings_manager.load_settings.return_value,
            'dns_propagation_seconds': {'cloudflare': 97},
        }
        manager.renew_certificate(DOMAIN, force=True)

    renew_argv = captured[-1]
    flag = renew_argv.index('--dns-cloudflare-propagation-seconds')
    assert renew_argv[flag + 1] == '97'


def test_the_webroot_renew_passes_is_todays(tmp_path, monkeypatch):
    captured = []
    manager = _manager(tmp_path, captured)
    monkeypatch.setenv('ACME_CHALLENGES_DIR', str(tmp_path / 'before'))
    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        manager.create_certificate(domain=DOMAIN, email='a@example.com',
                                   challenge_type='http-01')
        monkeypatch.setenv('ACME_CHALLENGES_DIR', str(tmp_path / 'after'))
        manager.renew_certificate(DOMAIN, force=True)

    renew_argv = captured[-1]
    assert renew_argv[renew_argv.index('-w') + 1] == str(acme_webroot_dir())
    assert str(acme_webroot_dir()).endswith('after')


def test_create_refuses_an_alias_the_hook_does_not_implement(tmp_path):
    """Why the guard above has no "DNS-01 alias on a generic provider" case:
    no such certificate can be issued, so there is nothing to renew."""
    manager = _manager(tmp_path, [])
    with pytest.raises(Exception, match='does not support this DNS provider'):
        manager.create_certificate(domain=DOMAIN, email='a@example.com',
                                   dns_provider='hetzner', domain_alias=ALIAS)
