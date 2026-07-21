"""Deleting a certificate must destroy the copy in the storage backend too.

Regression test for #419. `CertificateDetail.delete` removed the local
directory and the settings entry but never called the storage backend's
`delete_certificate` — which was, consequently, dead code. With Vault / AWS
Secrets Manager / Azure Key Vault / Infisical configured as the certificate
store, `DELETE /api/certificates/example.com` returned 200 and the UI showed
the certificate gone while the full PEM bundle — `privkey.pem` included —
stayed in the external secret store indefinitely, and a later storage
migration or restore resurrected it.
"""

from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager


pytestmark = [pytest.mark.unit]


def _manager(tmp_path, storage_manager):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {'domains': []}
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=MagicMock(),
        storage_manager=storage_manager,
        ca_manager=None,
    )


def _seed_local_cert(cert_dir, domain='example.com'):
    d = cert_dir / domain
    d.mkdir(parents=True)
    (d / 'cert.pem').write_text('CERT')
    (d / 'privkey.pem').write_text('KEY')
    return d


def _remote_backend(name='hashicorp_vault', deleted=True):
    sm = MagicMock()
    sm.get_backend_name.return_value = name
    sm.delete_certificate.return_value = deleted
    return sm


def test_delete_removes_the_bundle_from_the_remote_backend(tmp_path):
    storage = _remote_backend()
    mgr = _manager(tmp_path, storage)
    domain_dir = _seed_local_cert(tmp_path)

    assert mgr.delete_certificate('example.com') is True

    assert not domain_dir.exists()
    storage.delete_certificate.assert_called_once_with('example.com')


def test_delete_succeeds_when_only_the_remote_copy_remains(tmp_path):
    """A local dir already gone must not make the remote key undeletable."""
    storage = _remote_backend()
    mgr = _manager(tmp_path, storage)

    assert mgr.delete_certificate('ghost.example.com') is True
    storage.delete_certificate.assert_called_once_with('ghost.example.com')


def test_missing_everywhere_still_reports_not_found(tmp_path):
    storage = _remote_backend(deleted=False)
    mgr = _manager(tmp_path, storage)

    assert mgr.delete_certificate('nowhere.example.com') is False


def test_local_backend_is_not_asked_to_delete_twice(tmp_path):
    """The local backend points at the directory rmtree already removed."""
    storage = _remote_backend(name='local_filesystem')
    mgr = _manager(tmp_path, storage)
    _seed_local_cert(tmp_path)

    assert mgr.delete_certificate('example.com') is True
    storage.delete_certificate.assert_not_called()


def test_a_backend_outage_does_not_fail_the_local_deletion(tmp_path, caplog):
    """But it must be loud: the operator believes the key is destroyed."""
    storage = _remote_backend()
    storage.delete_certificate.side_effect = RuntimeError('vault unreachable')
    mgr = _manager(tmp_path, storage)
    domain_dir = _seed_local_cert(tmp_path)

    with caplog.at_level('ERROR'):
        assert mgr.delete_certificate('example.com') is True

    assert not domain_dir.exists()
    assert any('may still be stored there' in r.getMessage()
               for r in caplog.records), "a silent failure here misleads the operator"


def test_a_backend_reporting_nothing_to_delete_warns(tmp_path, caplog):
    storage = _remote_backend(deleted=False)
    mgr = _manager(tmp_path, storage)
    _seed_local_cert(tmp_path)

    with caplog.at_level('WARNING'):
        assert mgr.delete_certificate('example.com') is True

    assert any('verify by hand' in r.getMessage() for r in caplog.records)


def test_no_storage_manager_configured_is_not_an_error(tmp_path):
    mgr = _manager(tmp_path, None)
    _seed_local_cert(tmp_path)

    assert mgr.delete_certificate('example.com') is True
