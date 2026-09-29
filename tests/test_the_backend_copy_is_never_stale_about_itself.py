"""The external copy must not carry a warning about itself once it has landed.

`_store_in_backend` was handed the metadata as loaded from disk, and on a
renewal after a failed store that record still says "the external copy is
missing or stale". The store succeeded, the local metadata was then cleared,
and the backend kept the stale sentence. With a cloud backend,
get_certificate_info reads the backend's copy of the metadata, so the dashboard
went on warning about a problem that had already fixed itself: #423's symptom,
from the other side. Found by the #666 map; measured before this fix:
backend copy 'previous store to vault failed', local copy None.
"""
import json
from unittest.mock import MagicMock

import pytest

from tests.test_create_cert_io import _LIVE_CONTENTS
from tests.test_reissue_keeps_metadata_with_the_default_backend import DOMAIN, _manager

pytestmark = [pytest.mark.unit]

STALE = 'Certificate issued but NOT saved to the vault storage backend'


def _renewed_domain(tmp_path):
    domain_dir = tmp_path / DOMAIN
    live = domain_dir / 'live' / DOMAIN
    live.mkdir(parents=True)
    for name, content in _LIVE_CONTENTS.items():
        (live / name).write_bytes(content)
    (domain_dir / 'metadata.json').write_text(json.dumps(
        {'domain': DOMAIN, 'storage_warning': STALE}))
    return domain_dir


def _backend(result=True):
    received = []
    storage = MagicMock()
    storage.get_backend_name.return_value = 'vault'
    storage.store_certificate.side_effect = (
        lambda d, files, meta: received.append(dict(meta)) or result)
    return storage, received


def test_a_copy_that_lands_does_not_carry_the_old_warning(tmp_path):
    """THE regression."""
    domain_dir = _renewed_domain(tmp_path)
    storage, received = _backend(True)
    manager, _ = _manager(tmp_path, storage)

    manager._publish_renewed_certificate(
        DOMAIN, domain_dir, json.loads((domain_dir / 'metadata.json').read_text()))

    assert 'storage_warning' not in received[-1], received[-1]
    local = json.loads((domain_dir / 'metadata.json').read_text())
    assert 'storage_warning' not in local


def test_a_copy_that_fails_still_leaves_the_warning_locally(tmp_path):
    """CONTROL: the warning exists for this case, and it lives where the
    operator reads it."""
    domain_dir = _renewed_domain(tmp_path)
    storage, _received = _backend(False)
    manager, _ = _manager(tmp_path, storage)

    manager._publish_renewed_certificate(
        DOMAIN, domain_dir, json.loads((domain_dir / 'metadata.json').read_text()))

    local = json.loads((domain_dir / 'metadata.json').read_text())
    assert 'vault' in local['storage_warning']


def test_the_caller_s_record_is_not_modified(tmp_path):
    """The copy is taken for the backend only: the caller still owns its dict,
    and _commit_certificate decides what the local record says."""
    domain_dir = _renewed_domain(tmp_path)
    storage, _received = _backend(True)
    manager, _ = _manager(tmp_path, storage)
    record = {'domain': DOMAIN, 'storage_warning': STALE}

    manager._store_in_backend(DOMAIN, {}, record)

    assert record['storage_warning'] == STALE
