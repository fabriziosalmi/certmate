"""Regression tests for issue #466 — acme-dns must never touch certbot plugins.

The published ``certbot-acme-dns`` package registers as an authenticator but
implements no credentials-file option, so the ``--acme-dns-credentials`` flag
CertMate used to emit was rejected by certbot's own argument parser
("unrecognized arguments") and acme-dns issuance could never succeed. acme-dns
is now driven end to end by CertMate's native DNS hook, both on issuance and on
renewal — including for certificates issued before the fix, whose metadata
carries no ``domain_alias``.
"""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.dns_strategies import AcmeDNSStrategy

# Reuse the fixtures the DNS-alias suite already maintains so the acme-dns
# account shape stays defined in exactly one place.
from tests.test_domain_alias import _manager, _provider_config

ACME_DNS_SUBDOMAIN = 'certmate-validation.example.net'


def _cmd(shell):
    return shell.commands_executed[0].split()


def test_acme_dns_issuance_uses_native_hook_not_certbot_plugin(tmp_path):
    """The exact scenario from #466: plain acme-dns issuance, no alias mode."""
    mgr, shell = _manager(tmp_path, provider='acme-dns')

    result = mgr.create_certificate(
        domain='app.certmate.example',
        email='test@example.com',
        dns_provider='acme-dns',
        staging=True,
    )

    assert result['success'] is True
    cmd = _cmd(shell)
    assert '--manual' in cmd
    assert '--manual-auth-hook' in cmd
    assert '--manual-cleanup-hook' in cmd
    # The flags that made certbot bail out with "unrecognized arguments".
    assert '--acme-dns-credentials' not in cmd
    assert '--acme-dns-propagation-seconds' not in cmd
    assert '--authenticator' not in cmd


def test_acme_dns_issuance_does_not_require_a_certbot_plugin(tmp_path):
    """No plugin preflight: there is no acme-dns plugin worth checking for."""
    mgr, _shell = _manager(tmp_path, provider='acme-dns')

    with patch('modules.core.certificates.check_certbot_plugin_installed') as plugin_check:
        result = mgr.create_certificate(
            domain='app.certmate.example',
            email='test@example.com',
            dns_provider='acme-dns',
            staging=True,
        )

    assert result['success'] is True
    plugin_check.assert_not_called()


def test_acme_dns_hook_config_carries_account_and_subdomain(tmp_path):
    """The hook needs the acme-dns credentials, and must clean them up after."""
    mgr, _shell = _manager(tmp_path, provider='acme-dns')
    captured = {}
    original = CertificateManager._configure_dns_alias_arguments

    def capture_config(cmd, hook_config):
        captured['path'] = Path(hook_config)
        captured['content'] = json.loads(captured['path'].read_text())
        original(cmd, hook_config)

    with patch.object(CertificateManager, '_configure_dns_alias_arguments', side_effect=capture_config):
        result = mgr.create_certificate(
            domain='app.certmate.example',
            email='test@example.com',
            dns_provider='acme-dns',
            staging=True,
        )

    assert result['success'] is True
    payload = captured['content']
    assert payload['provider'] == 'acme-dns'
    # The alias target is the configured subdomain even though the caller
    # never passed domain_alias — acme-dns is CNAME delegation by nature.
    assert payload['domain_alias'] == ACME_DNS_SUBDOMAIN
    assert payload['config']['api_url'] == 'https://auth.acme-dns.io'
    assert payload['config']['username'] == 'acme-user'
    assert payload['config']['subdomain'] == ACME_DNS_SUBDOMAIN
    # Credentials must not outlive the certbot run.
    assert not captured['path'].exists()


def test_acme_dns_renewal_without_metadata_alias_uses_native_hook(tmp_path):
    """Certificates issued before the fix have no domain_alias in metadata.

    They must still renew through the hook rather than falling back to the
    broken plugin path, without requiring a metadata migration.
    """
    mgr, shell = _manager(tmp_path, provider='acme-dns')
    domain_dir = tmp_path / 'app.certmate.example'
    domain_dir.mkdir()
    (domain_dir / 'cert.pem').write_text('fake certificate content')
    (domain_dir / 'metadata.json').write_text(json.dumps({
        'domain': 'app.certmate.example',
        'dns_provider': 'acme-dns',
        'account_id': 'production',
        # deliberately no domain_alias / alias_dns_provider
    }))

    captured = {}
    original = CertificateManager._configure_dns_alias_arguments

    def capture_config(cmd, hook_config):
        captured['content'] = json.loads(Path(hook_config).read_text())
        original(cmd, hook_config)

    with patch.object(CertificateManager, '_configure_dns_alias_arguments', side_effect=capture_config):
        result = mgr.renew_certificate('app.certmate.example')

    assert result['success'] is True
    cmd = _cmd(shell)
    assert '--manual' in cmd
    assert '--manual-auth-hook' in cmd
    assert '--acme-dns-credentials' not in cmd
    assert captured['content']['provider'] == 'acme-dns'
    assert captured['content']['domain_alias'] == ACME_DNS_SUBDOMAIN


def test_acme_dns_strategy_refuses_to_build_certbot_arguments():
    """Guard rail: restoring the plugin flags must fail loudly, not silently."""
    with pytest.raises(RuntimeError, match='native DNS hook'):
        AcmeDNSStrategy().configure_certbot_arguments([], Path('/tmp/creds.json'))


def test_acme_dns_native_alias_only_applies_to_acme_dns():
    """The routing switch must not divert any other provider to the hook."""
    assert CertificateManager._acme_dns_native_alias(
        'acme-dns', _provider_config('acme-dns')) == ACME_DNS_SUBDOMAIN
    assert CertificateManager._acme_dns_native_alias(
        'cloudflare', _provider_config('cloudflare')) == ''
    # Trailing dots are normalised.
    assert CertificateManager._acme_dns_native_alias(
        'acme-dns', {'subdomain': 'sub.example.net.'}) == 'sub.example.net'


@pytest.mark.parametrize('config', [{}, None, {'subdomain': '   '}])
def test_acme_dns_without_a_subdomain_reports_a_config_error(config):
    """A blank subdomain is a settings problem, and must say so.

    Returning '' here would drop the request back onto the plugin path, where
    AcmeDNSStrategy raises "this is a bug in the caller" — true of the code
    path, useless to the person who just left a field empty.
    """
    with pytest.raises(ValueError, match='missing its Subdomain'):
        CertificateManager._acme_dns_native_alias('acme-dns', config)


def test_acme_dns_missing_subdomain_surfaces_through_create(tmp_path):
    """Issuance fails with the config error, not with "bug in the caller".

    ValueError is how create_certificate reports every other validation
    problem (bad SAN, unknown provider); the API layer turns it into a 4xx.
    """
    mgr, shell = _manager(tmp_path, provider='acme-dns')
    mgr.dns_manager.get_dns_provider_account_config.return_value = (
        {'api_url': 'https://auth.acme-dns.io', 'username': 'u', 'password': 'p'},
        'production',
    )

    with pytest.raises(ValueError, match='missing its Subdomain'):
        mgr.create_certificate(
            domain='app.certmate.example',
            email='test@example.com',
            dns_provider='acme-dns',
            staging=True,
        )

    # It must fail before certbot is ever invoked.
    assert shell.commands_executed == []
