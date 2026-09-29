"""The external-copy warning must be set on renewal, and cleared when it recovers.

Regression tests for #423. A storage-backend failure during renewal was only
logged, while the same failure at creation set ``metadata['storage_warning']``
— and nothing ever cleared it. Two symmetric failures:

- A Vault token expires mid-life. Nightly renewals keep succeeding locally
  while the DR copy silently stops updating; the API and the UI show nothing,
  and the operator discovers the stale external copy during a restore.
- One failed store at creation leaves the warning in metadata forever, so the
  dashboard keeps warning long after the backend recovered — and an operator
  who learns to ignore a stale warning will ignore the real one.
"""

from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager


pytestmark = [pytest.mark.unit]


def _manager(tmp_path, storage_manager):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {}
    return CertificateManager(
        cert_dir=tmp_path,
        settings_manager=settings_mgr,
        dns_manager=MagicMock(),
        storage_manager=storage_manager,
        ca_manager=None,
    )


def _backend(name='hashicorp_vault', stored=True, boom=None):
    sm = MagicMock()
    sm.get_backend_name.return_value = name
    if boom is not None:
        sm.store_certificate.side_effect = boom
    else:
        sm.store_certificate.return_value = stored
    return sm


# --- _store_in_backend -----------------------------------------------------

def test_a_successful_store_produces_no_warning(tmp_path):
    mgr = _manager(tmp_path, _backend())
    assert mgr._store_in_backend('example.com', {}, {}) is None


def test_a_refused_store_warns_and_names_the_backend(tmp_path):
    mgr = _manager(tmp_path, _backend(stored=False))
    warning = mgr._store_in_backend('example.com', {}, {})
    assert warning and 'hashicorp_vault' in warning


def test_a_raising_backend_warns_without_leaking_the_exception(tmp_path):
    """Backend errors can embed credentials and URLs."""
    mgr = _manager(tmp_path, _backend(boom=RuntimeError('token s.SECRET at https://vault:8200')))
    warning = mgr._store_in_backend('example.com', {}, {})
    assert warning
    assert 'SECRET' not in warning and 'vault:8200' not in warning


def test_no_backend_configured_is_not_a_warning(tmp_path):
    mgr = _manager(tmp_path, None)
    assert mgr._store_in_backend('example.com', {}, {}) is None


# --- _apply_storage_warning ------------------------------------------------

def test_the_warning_is_recorded_in_metadata(tmp_path):
    mgr = _manager(tmp_path, None)
    md = {}
    mgr._apply_storage_warning(md, 'the external copy is stale')
    assert md['storage_warning'] == 'the external copy is stale'


def test_a_recovered_backend_clears_a_stale_warning(tmp_path):
    """The half nobody implemented: the warning outlived the outage."""
    mgr = _manager(tmp_path, None)
    md = {'storage_warning': 'Certificate issued but NOT saved to vault'}
    mgr._apply_storage_warning(md, None)
    assert 'storage_warning' not in md


def test_clearing_is_a_no_op_when_there_was_no_warning(tmp_path):
    mgr = _manager(tmp_path, None)
    md = {'domain': 'example.com'}
    mgr._apply_storage_warning(md, None)
    assert md == {'domain': 'example.com'}


def test_create_and_renew_share_one_implementation():
    """They drifted precisely because they were two copies of this logic, and
    the drift was a defect: create stored before merging a reissue's metadata.
    Now one method, `_commit_certificate`, does store -> warning -> save ->
    invalidate -> PFX for both. Each path must call it and must not re-inline
    any of its steps: that is how the second copy would grow back.
    """
    import inspect

    for method in (CertificateManager.create_certificate,
                   CertificateManager._publish_renewed_certificate):
        body = inspect.getsource(method)
        assert 'self._commit_certificate(' in body, method.__name__
        for step in ('_store_in_backend(', '_save_metadata(', '_write_pfx(',
                     'storage_manager.store_certificate'):
            assert step not in body, f'{method.__name__} re-inlines {step}'
