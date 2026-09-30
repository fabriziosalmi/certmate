"""A CSR-only certificate's renewal is a renewal (#666, D4), and a renewal
failure says what failed without "Exception: " in front of it (D8).

D4. A CSR-only certificate has no certbot lineage, so it renews by re-running
issuance with the stored CSR (`_renew_from_stored_csr`). That went through
`create_certificate` like a new certificate: every renewal reset `created_at`
to the day of the renewal, never stamped `renewed_at`, and was counted in the
creation metrics — on top of the renewal its caller counts. Measured on the
real manager before the change: `created_at` moved, `renewed_at` None,
creation metric recorded twice for one certificate.

D8. The renewal's catch-all re-wrapped every failure as
`RuntimeError(f"Exception: {msg}")`, including the RuntimeErrors that already
said what went wrong, so the `certificate_failed` event (webhooks,
notifications) and the audit record read "Exception: Certificate renewal
failed: ...".
"""
import json
import time
from unittest.mock import MagicMock, patch

import pytest

from modules.core.certificates import CertificateManager
from modules.core.csr_issuance import CSR_OUTPUT_DIRNAME
from modules.core.shell import MockShellExecutor
from tests.test_csr_only_issuance import _csr, _self_signed

pytestmark = [pytest.mark.unit]

DOMAIN = 'api.example.com'


def _manager(tmp_path, returncode=0):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
        'dns_propagation_seconds': {}}
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = (
        {'api_token': 'x' * 40}, 'default')
    shell = MockShellExecutor()
    original_run = shell.run

    def run(cmd, **kwargs):
        result = original_run(cmd, **kwargs)
        if '--csr' in cmd:
            # certbot --csr writes to the output directory CertMate names. The
            # fake writes to the same place, known here rather than read back
            # out of the command.
            out = tmp_path / DOMAIN / CSR_OUTPUT_DIRNAME
            out.mkdir(parents=True, exist_ok=True)
            pem = _self_signed(DOMAIN)     # a new certificate every run
            for name in ('cert.pem', 'chain.pem', 'fullchain.pem'):
                (out / name).write_bytes(pem)
        return result

    shell.run = run
    manager = CertificateManager(
        cert_dir=tmp_path, settings_manager=settings_mgr, dns_manager=dns_mgr,
        storage_manager=None, ca_manager=None, shell_executor=shell)
    return manager, shell


def _metadata(tmp_path):
    return json.loads((tmp_path / DOMAIN / 'metadata.json').read_text())


@pytest.fixture
def issued(tmp_path):
    manager, shell = _manager(tmp_path)
    creations = []
    with patch.object(CertificateManager, '_write_pfx', return_value=None), \
         patch.object(CertificateManager, '_record_creation_metrics',
                      side_effect=lambda *a, **k: creations.append(a)):
        manager.create_certificate(domain=DOMAIN, email='a@example.com',
                                   dns_provider='cloudflare', csr_pem=_csr())
        yield manager, shell, creations


def test_a_csr_renewal_keeps_the_day_it_was_created(issued, tmp_path):
    manager, _, _ = issued
    created = _metadata(tmp_path)['created_at']
    time.sleep(0.01)

    result = manager.renew_certificate(DOMAIN)

    assert result['renewed'] is True
    metadata = _metadata(tmp_path)
    assert metadata['created_at'] == created
    assert metadata['renewed_at'] and metadata['renewed_at'] > created
    assert metadata['key_management'] == 'external'


def test_a_csr_renewal_is_not_counted_as_a_creation(issued):
    manager, _, creations = issued
    assert len(creations) == 1          # the issuance

    manager.renew_certificate(DOMAIN)

    assert len(creations) == 1, 'the renewal was counted as a creation'


def test_a_new_csr_certificate_is_still_a_creation(issued, tmp_path):
    """CONTROL: the flag must not have silenced the ordinary path."""
    _, _, creations = issued
    assert len(creations) == 1
    assert 'renewed_at' not in _metadata(tmp_path)


def _ordinary(manager, tmp_path):
    """The same certificate, taken down the ordinary `certbot renew` path,
    where the catch-all lives (a CSR renewal returns before it)."""
    meta = _metadata(tmp_path)
    meta.pop('key_management')
    (tmp_path / DOMAIN / 'metadata.json').write_text(json.dumps(meta))
    return patch.object(CertificateManager, '_lineage_lost_its_key',
                        return_value=False)


def test_a_renewal_failure_says_what_failed(issued, tmp_path):
    manager, _, _ = issued
    refusal = RuntimeError('Cannot renew api.example.com: the account is gone')
    with _ordinary(manager, tmp_path), \
         patch.object(CertificateManager, '_prepare_renewal_dns',
                      side_effect=refusal), \
         pytest.raises(RuntimeError) as raised:
        manager.renew_certificate(DOMAIN)
    assert str(raised.value) == str(refusal), str(raised.value)


def test_an_unexpected_fault_is_still_wrapped_and_keeps_its_cause(issued, tmp_path):
    manager, _, _ = issued
    with _ordinary(manager, tmp_path), \
         patch.object(CertificateManager, '_prepare_renewal_dns',
                      side_effect=KeyError('boom')), \
         pytest.raises(RuntimeError) as raised:
        manager.renew_certificate(DOMAIN)
    assert not str(raised.value).startswith('Exception:'), str(raised.value)
    assert isinstance(raised.value.__cause__, KeyError)
