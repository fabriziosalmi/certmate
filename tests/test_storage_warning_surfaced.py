"""A failed external-storage save must not be silent.

External storage (Azure KV / AWS Secrets / Vault / Infisical) is the
disaster-recovery copy: if the local cert_dir is on ephemeral storage and
is lost, the certificate is only recoverable from the backend. When
store_certificate failed, create_certificate still returned
success=True with only a log line — the operator had no signal the backup
never landed. These tests pin that the failure is surfaced on the create
result, persisted in metadata.json, and visible via get_certificate_info,
while a clean store stays quiet and no raw exception text (which can carry
backend credentials) leaks into the surfaced warning.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]

_LIVE = {f: f"-----BEGIN-----\n{f}\n-----END-----\n".encode() for f in CERTIFICATE_FILES}


class _StagingShell(MockShellExecutor):
    """On a successful certbot run, stage the live/<domain>/ files so
    create_certificate's copy block runs to completion."""

    def __init__(self, cert_dir, domain):
        super().__init__()
        self._cert_dir = Path(cert_dir)
        self._domain = domain
        self.set_next_result(returncode=0)

    def run(self, cmd, **kwargs):
        result = super().run(cmd, **kwargs)
        if result.returncode == 0:
            live = self._cert_dir / self._domain / 'live' / self._domain
            live.mkdir(parents=True, exist_ok=True)
            for f in CERTIFICATE_FILES:
                # No explicit chmod: this test asserts the storage_warning
                # surface, not file modes (that is test_create_cert_io's job).
                # An os.chmod(...0o644) here only tripped CodeQL's
                # overly-permissive-file rule for no behavioural gain.
                (live / f).write_bytes(_LIVE[f])
        return result


def _make_manager(tmp_path, domain, storage_manager):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'duckdns': 1},
    }
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = ({'api_token': 'x'}, 'default')
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=settings_mgr, dns_manager=dns_mgr,
        storage_manager=storage_manager, ca_manager=None,
        shell_executor=_StagingShell(tmp_path, domain),
    )


def _storage_mock(backend_name, *, store_returns=None, store_raises=None):
    storage = MagicMock()
    storage.get_backend_name.return_value = backend_name
    if store_raises is not None:
        storage.store_certificate.side_effect = store_raises
    else:
        storage.store_certificate.return_value = store_returns
    # Make get_certificate_info skip the storage-retrieve path and read the
    # local file, so these tests exercise the local metadata surface.
    storage.retrieve_certificate_info = None
    storage.retrieve_certificate.return_value = None
    return storage


def _issue(mgr, domain):
    with patch('modules.core.certificates.check_certbot_plugin_installed', return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        return mgr.create_certificate(
            domain=domain, email='t@example.com', dns_provider='duckdns', staging=True,
        )


def test_storage_returns_false_surfaces_warning(tmp_path):
    domain = 'a.example.duckdns.org'
    storage = _storage_mock('azure_keyvault', store_returns=False)
    mgr = _make_manager(tmp_path, domain, storage)

    result = _issue(mgr, domain)

    assert result['success'] is True
    assert result.get('storage_warning')
    assert 'azure_keyvault' in result['storage_warning']

    meta = json.loads((tmp_path / domain / 'metadata.json').read_text())
    assert meta.get('storage_warning')

    info = mgr.get_certificate_info(domain)
    assert info.get('storage_warning')


def test_storage_raises_surfaces_generic_warning_without_secret(tmp_path):
    domain = 'b.example.duckdns.org'
    storage = _storage_mock('vault', store_raises=RuntimeError("token=s3cr3t connection refused"))
    mgr = _make_manager(tmp_path, domain, storage)

    result = _issue(mgr, domain)

    assert result['success'] is True
    warn = result.get('storage_warning')
    assert warn and 'vault' in warn
    # Raw exception text can carry backend credentials — it must never reach
    # the surfaced warning, only the server log.
    assert 's3cr3t' not in warn


def test_clean_store_has_no_warning(tmp_path):
    domain = 'c.example.duckdns.org'
    storage = _storage_mock('aws', store_returns=True)
    mgr = _make_manager(tmp_path, domain, storage)

    result = _issue(mgr, domain)

    assert result['success'] is True
    assert result.get('storage_warning') is None
    assert mgr.get_certificate_info(domain).get('storage_warning') is None
