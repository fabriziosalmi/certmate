"""A not-yet-due renewal retries a failed backend store and rebuilds downstream.

_store_in_backend was reached only from create and the renewed=True branch. A
store that failed once (expired Vault token, transient 5xx) was never retried:
the local cert was fresh but the backend stayed on the OLD generation, and
because get_certificate_info reads the backend copy when a backend is
configured, needs_renewal stayed True forever — every run landed in the
not-yet-due branch, which never touched the backend (#1). And when that branch
republished the flat PEMs, the new generation reached /download and the deploy
hooks but not the backend or the PFX (#2).

The not-yet-due branch now pushes to the backend when the external copy is
behind (a prior store failed, or the flats were just republished), clearing the
storage_warning on success.
"""
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.constants import CERTIFICATE_FILES
from modules.core.shell import MockShellExecutor

pytestmark = [pytest.mark.unit]


class _NotYetDueExecutor(MockShellExecutor):
    """certbot exits 0 and prints the not-yet-due sentinel; produces no new
    live files, so renew_certificate concludes renewed=False."""
    def run(self, cmd, **kwargs):
        self.set_next_result(returncode=0,
                             stdout='Certificate not yet due for renewal')
        return super().run(cmd, **kwargs)


def _mgr(tmp_path, storage):
    sm = MagicMock()
    sm.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
        'default_key_type': 'ecdsa', 'default_elliptic_curve': 'secp384r1',
    }
    sm.get_domain_dns_provider.return_value = 'duckdns'
    dns = MagicMock()
    dns.get_dns_provider_account_config.return_value = (
        {'api_token': 'duck-token'}, 'default')
    return CertificateManager(
        cert_dir=tmp_path, settings_manager=sm, dns_manager=dns,
        storage_manager=storage, ca_manager=None,
        shell_executor=_NotYetDueExecutor())   # no-op: prints not-yet-due


def _seed(tmp_path, domain, metadata):
    d = tmp_path / domain
    (d / 'live' / domain).mkdir(parents=True)
    for name in CERTIFICATE_FILES:
        (d / name).write_bytes(b'flat-' + name.encode())
        (d / 'live' / domain / name).write_bytes(b'flat-' + name.encode())
    (d / 'metadata.json').write_text(json.dumps(metadata))
    return d


def _renew(mgr, domain):
    with patch('modules.core.certificates.check_certbot_plugin_installed',
               return_value=True), \
         patch.object(CertificateManager, '_write_pfx', return_value=None):
        return mgr.renew_certificate(domain)


def test_a_persisted_storage_warning_makes_the_not_yet_due_branch_retry(tmp_path):
    domain = 'retry.example.duckdns.org'
    storage = MagicMock()
    storage.get_backend_name.return_value = 'vault'
    storage.store_certificate.return_value = True   # succeeds this time
    mgr = _mgr(tmp_path, storage)
    _seed(tmp_path, domain, {'domain': domain,
                             'storage_warning': 'previous store failed'})

    result = _renew(mgr, domain)

    assert result['renewed'] is False               # not yet due
    storage.store_certificate.assert_called_once()  # but the backend was retried
    # and the warning is cleared on success
    meta = json.loads((tmp_path / domain / 'metadata.json').read_text())
    assert 'storage_warning' not in meta


def test_no_warning_and_no_stale_does_not_touch_the_backend(tmp_path):
    """CONTROL: a healthy not-yet-due run (external copy already current) must
    not push on every daily check."""
    domain = 'healthy.example.duckdns.org'
    storage = MagicMock()
    storage.get_backend_name.return_value = 'vault'
    mgr = _mgr(tmp_path, storage)
    _seed(tmp_path, domain, {'domain': domain})   # no storage_warning

    result = _renew(mgr, domain)

    assert result['renewed'] is False
    storage.store_certificate.assert_not_called()


def test_no_backend_configured_still_returns_not_yet_due(tmp_path):
    """CONTROL: with no storage backend the branch behaves as before."""
    domain = 'nobackend.example.duckdns.org'
    mgr = _mgr(tmp_path, None)
    _seed(tmp_path, domain, {'domain': domain,
                             'storage_warning': 'stale'})
    result = _renew(mgr, domain)
    assert result['renewed'] is False
