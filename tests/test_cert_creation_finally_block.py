"""
Regression tests for CertificateManager.create_certificate() finally-block
safety.

The finally block reads ca_extra_env to clean up the REQUESTS_CA_BUNDLE
temp file. If an exception is raised before ca_extra_env is bound (e.g.
plugin-not-installed at the early plugin check), the original
UnboundLocalError would mask the real exception and prevent meaningful
error reporting to API clients. These tests pin the contract: early
failures must surface their actual exception, not UnboundLocalError.
"""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager


def _make_manager(tmp_path):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01'
    }
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (
        {'api_token': 'fake'}, 'default'
    )
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=dns_mgr,
        storage_manager=None,
        ca_manager=None,
    )


def test_plugin_not_installed_surfaces_runtime_error_not_unbound_local(tmp_path):
    """If the certbot plugin is missing, the user must see RuntimeError
    with the install hint, not an UnboundLocalError from the finally block."""
    mgr = _make_manager(tmp_path)
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=False):
        with pytest.raises(RuntimeError) as exc_info:
            mgr.create_certificate(
                domain='example.duckdns.org',
                email='test@example.com',
                dns_provider='duckdns',
                staging=True,
            )
    assert 'is not installed' in str(exc_info.value)
    assert 'UnboundLocalError' not in str(exc_info.value)


def test_invalid_domain_san_surfaces_value_error_not_unbound_local(tmp_path):
    """An invalid SAN raises ValueError before ca_extra_env is bound;
    the finally must not crash."""
    mgr = _make_manager(tmp_path)
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True):
        with pytest.raises(ValueError) as exc_info:
            mgr.create_certificate(
                domain='example.duckdns.org',
                email='test@example.com',
                dns_provider='duckdns',
                staging=True,
                san_domains=['not a valid domain!!!'],
            )
    assert 'Invalid SAN' in str(exc_info.value)
