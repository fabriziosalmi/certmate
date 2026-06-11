"""
Pins for #279: Let's Encrypt staging modelled as the letsencrypt_staging
CA entry instead of a per-certificate boolean.

The invariants worth pinning, none of which had coverage before:

1. The staging entry issues against the staging directory — there was no
   test anywhere asserting the *effect* of staging on the certbot
   command.
2. The legacy staging boolean keeps working by mapping onto the entry.
3. A staging request whose CA config cannot be resolved must NOT be
   silently reset to production letsencrypt (the pre-#279 catch did
   exactly that for every provider).
4. Renewal never recomputes the ACME endpoint: certbot replays it from
   its own renewal conf, so the renew command must carry no --server or
   --staging.
"""
import json
from unittest.mock import MagicMock, patch

import pytest

from modules.core.ca_manager import CAManager
from modules.core.certificates import CertificateManager
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

STAGING_DIRECTORY = 'https://acme-staging-v02.api.letsencrypt.org/directory'
PRODUCTION_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory'


def _ca_manager(settings=None):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = settings or {}
    return CAManager(settings_manager=settings_mgr)


def _cert_manager(tmp_path, shell, settings=None, ca_manager=None):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = settings or {
        'default_ca': 'letsencrypt',
        'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'duckdns': 1},
    }
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'

    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (
        {'api_token': 'duck-token'}, 'default'
    )

    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=dns_mgr,
        storage_manager=None,
        ca_manager=ca_manager,
        shell_executor=shell,
    )


# ---------------------------------------------------------------------------
# 1. Directory pins
# ---------------------------------------------------------------------------

def test_staging_ca_pins_staging_directory():
    manager = _ca_manager()
    cmd, _env = manager.build_certbot_command(
        domain='example.com', email='a@b.it',
        ca_provider='letsencrypt_staging',
        dns_provider='cloudflare', dns_config={},
        account_config={'email': 'a@b.it'},
    )
    assert cmd[cmd.index('--server') + 1] == STAGING_DIRECTORY


def test_staging_ca_directory_is_staging_regardless_of_boolean():
    manager = _ca_manager()
    for staging in (False, True):
        cmd, _env = manager.build_certbot_command(
            domain='example.com', email='a@b.it',
            ca_provider='letsencrypt_staging',
            dns_provider='cloudflare', dns_config={},
            account_config={'email': 'a@b.it'}, staging=staging,
        )
        assert cmd[cmd.index('--server') + 1] == STAGING_DIRECTORY


def test_letsencrypt_still_pins_production_directory():
    manager = _ca_manager()
    cmd, _env = manager.build_certbot_command(
        domain='example.com', email='a@b.it',
        ca_provider='letsencrypt',
        dns_provider='cloudflare', dns_config={},
        account_config={'email': 'a@b.it'},
    )
    assert cmd[cmd.index('--server') + 1] == PRODUCTION_DIRECTORY


# ---------------------------------------------------------------------------
# 2. Account aliasing
# ---------------------------------------------------------------------------

def test_get_ca_config_staging_inherits_letsencrypt_account():
    manager = _ca_manager({
        'ca_providers': {'letsencrypt': {'email': 'le@b.it'}},
    })
    config, account_id = manager.get_ca_config('letsencrypt_staging')
    assert config == {'email': 'le@b.it'}
    assert account_id == 'default'


def test_get_ca_config_explicit_staging_entry_wins():
    manager = _ca_manager({
        'ca_providers': {
            'letsencrypt': {'email': 'le@b.it'},
            'letsencrypt_staging': {'email': 'staging@b.it'},
        },
    })
    config, _ = manager.get_ca_config('letsencrypt_staging')
    assert config == {'email': 'staging@b.it'}


def test_get_ca_config_staging_unconfigured_raises():
    # The create path catches this and falls through to the plain-certbot
    # branch, which covers staging via --staging.
    manager = _ca_manager({'ca_providers': {}})
    with pytest.raises(ValueError):
        manager.get_ca_config('letsencrypt_staging')


# ---------------------------------------------------------------------------
# 3. Create-path normalization and no-silent-production-flip
# ---------------------------------------------------------------------------

def _create(mgr, domain, **kwargs):
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        return mgr.create_certificate(
            domain=domain, email='a@b.it', dns_provider='duckdns', **kwargs
        )


def _fake_issuance(shell, tmp_path, domain):
    """Make the mocked certbot run 'succeed' by staging the live files."""
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


def test_legacy_staging_boolean_maps_to_staging_ca(tmp_path):
    domain = 'app.example.duckdns.org'
    shell = _fake_issuance(MockShellExecutor(), tmp_path, domain)
    shell.set_next_result(returncode=0)
    mgr = _cert_manager(tmp_path, shell)  # no ca_manager: plain-certbot branch

    result = _create(mgr, domain, staging=True)

    assert result['success'] is True
    assert result['ca_provider'] == 'letsencrypt_staging'
    cmd = shell.commands_executed[0].split()
    assert '--staging' in cmd
    metadata = json.loads((tmp_path / domain / 'metadata.json').read_text())
    assert metadata['ca_provider'] == 'letsencrypt_staging'
    assert metadata['staging'] is True


def test_unconfigured_staging_ca_is_not_flipped_to_production(tmp_path):
    """Regression pin for the silent fallback: pre-#279 the get_ca_config
    failure path reset any provider to 'letsencrypt', so an unconfigured
    staging request issued an untracked PRODUCTION certificate."""
    domain = 'app.example.duckdns.org'
    shell = _fake_issuance(MockShellExecutor(), tmp_path, domain)
    shell.set_next_result(returncode=0)
    ca_manager = _ca_manager({'ca_providers': {}})  # nothing configured
    mgr = _cert_manager(tmp_path, shell, ca_manager=ca_manager)

    result = _create(mgr, domain, ca_provider='letsencrypt_staging')

    assert result['success'] is True
    assert result['ca_provider'] == 'letsencrypt_staging'
    cmd = shell.commands_executed[0].split()
    # Fallback branch has no --server, so --staging is what keeps the
    # request on the staging directory.
    assert '--staging' in cmd
    assert '--server' not in cmd


def test_fallback_preserves_staging_for_unconfigured_other_ca(tmp_path):
    """Regression (adversarial review): a legacy staging=True request with an
    unconfigured non-LE provider used to be reset to production letsencrypt
    by the fallback — issuing a trusted production cert (and burning real
    rate limits) where a test was intended."""
    domain = 'app.example.duckdns.org'
    shell = _fake_issuance(MockShellExecutor(), tmp_path, domain)
    shell.set_next_result(returncode=0)
    ca_manager = _ca_manager({'ca_providers': {}})
    mgr = _cert_manager(tmp_path, shell, ca_manager=ca_manager)

    result = _create(mgr, domain, ca_provider='zerossl', staging=True)

    assert result['success'] is True
    assert result['ca_provider'] == 'letsencrypt_staging'
    cmd = shell.commands_executed[0].split()
    assert '--staging' in cmd
    assert '--server' not in cmd


def test_configured_staging_ca_issues_against_staging_server(tmp_path):
    domain = 'app.example.duckdns.org'
    shell = _fake_issuance(MockShellExecutor(), tmp_path, domain)
    shell.set_next_result(returncode=0)
    ca_manager = _ca_manager({
        'ca_providers': {'letsencrypt': {'email': 'a@b.it'}},
    })
    mgr = _cert_manager(tmp_path, shell, ca_manager=ca_manager)

    result = _create(mgr, domain, ca_provider='letsencrypt_staging')

    assert result['success'] is True
    cmd = shell.commands_executed[0].split()
    assert cmd[cmd.index('--server') + 1] == STAGING_DIRECTORY


# ---------------------------------------------------------------------------
# 4. Renewal invariant
# ---------------------------------------------------------------------------

def test_renew_never_recomputes_acme_server(tmp_path):
    """certbot replays the ACME endpoint from its own renewal conf; the
    renew command must not inject --server or --staging, or a renewal
    could flip a certificate to a different CA than issued it."""
    domain = 'app.example.duckdns.org'
    shell = MockShellExecutor()
    shell.set_next_result(returncode=0)
    mgr = _cert_manager(tmp_path, shell)

    domain_dir = tmp_path / domain
    domain_dir.mkdir()
    (domain_dir / 'cert.pem').write_text('fake certificate content')
    (domain_dir / 'metadata.json').write_text(json.dumps({
        'domain': domain,
        'dns_provider': 'duckdns',
        'staging': True,
        'ca_provider': 'letsencrypt_staging',
    }))

    with patch.object(CertificateManager, '_write_pfx', return_value=None):
        mgr.renew_certificate(domain)

    assert shell.commands_executed, 'renewal never invoked certbot'
    cmd = shell.commands_executed[0].split()
    assert '--server' not in cmd
    assert '--staging' not in cmd
