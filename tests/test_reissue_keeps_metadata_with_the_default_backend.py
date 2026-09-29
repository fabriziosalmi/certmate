"""A reissue keeps the certificate's own metadata, with the backend a default
install actually runs.

#421 made a reissue merge the metadata it owns (CA, DNS, SANs...) into what is
on disk, so keys that belong to the CERTIFICATE (the deployment probe config,
renewed_at, anything a later version adds) survive an Edit & Reissue. Its test
used `storage_manager=None`. A default install always has a StorageManager,
whose local backend writes metadata.json into the same directory, and create
stored BEFORE merging: the store overwrote metadata.json with the
issuance-only dict, and the merge then read back the file it had just
overwritten. Found by the #666 create/renew map; measured here.
"""
import json
from unittest.mock import MagicMock

import pytest

from modules.core.certificates import CertificateManager
from modules.core.storage_backends import StorageManager
from tests.test_create_cert_io import _StagingShellExecutor

pytestmark = [pytest.mark.unit]

DOMAIN = 'app.example.duckdns.org'
CERTIFICATE_OWNED = {
    'deployment_protocol': 'smtp-starttls',
    'deployment_port': 587,
    'deployment_host': 'mail.example.com',
    'renewed_at': '2026-09-01T02:00:00',
}


def _manager(tmp_path, storage_manager):
    settings_mgr = MagicMock()
    settings_mgr.load_settings.return_value = {
        'default_ca': 'letsencrypt', 'challenge_type': 'dns-01',
        'dns_propagation_seconds': {'duckdns': 1}, 'default_key_type': 'ecdsa',
        'default_elliptic_curve': 'secp384r1',
        'certificate_storage': {'backend': 'local_filesystem'},
    }
    settings_mgr.get_domain_dns_provider.return_value = 'duckdns'
    dns_mgr = MagicMock()
    dns_mgr.get_dns_provider_account_config.return_value = ({'api_token': 't'}, 'default')
    manager = CertificateManager(
        cert_dir=tmp_path, settings_manager=settings_mgr, dns_manager=dns_mgr,
        storage_manager=storage_manager, ca_manager=None,
        shell_executor=_StagingShellExecutor(tmp_path, DOMAIN))
    manager._write_pfx = lambda domain: None
    return manager, settings_mgr


def _seed(tmp_path):
    domain_dir = tmp_path / DOMAIN
    domain_dir.mkdir()
    (domain_dir / 'metadata.json').write_text(json.dumps({
        'domain': DOMAIN, 'dns_provider': 'duckdns', 'ca_provider': 'letsencrypt',
        'created_at': '2026-06-01T00:00:00', **CERTIFICATE_OWNED}))
    for name in ('cert.pem', 'privkey.pem'):
        (domain_dir / name).write_text('old')


def _reissue(manager):
    manager.create_certificate(DOMAIN, 'a@example.com', 'duckdns',
                               ca_provider='letsencrypt', replace=True)


def test_a_reissue_keeps_what_belongs_to_the_certificate(tmp_path):
    """THE regression, with the StorageManager a default install builds."""
    _seed(tmp_path)
    storage = StorageManager(MagicMock(), default_cert_dir=tmp_path)
    manager, settings_mgr = _manager(tmp_path, storage)
    storage.settings_manager = settings_mgr

    _reissue(manager)

    on_disk = json.loads((tmp_path / DOMAIN / 'metadata.json').read_text())
    lost = {k: v for k, v in CERTIFICATE_OWNED.items() if on_disk.get(k) != v}
    assert lost == {}, f'the reissue dropped {sorted(lost)}'


def test_the_backend_receives_the_merged_record(tmp_path):
    """A cloud backend's copy must carry the same keys: it is what a DR
    restore brings back, and what get_certificate_info reads when set."""
    _seed(tmp_path)
    received = []
    storage = MagicMock()
    storage.store_certificate.side_effect = lambda d, files, meta: received.append(dict(meta)) or True
    storage.get_backend_name.return_value = 'recording'
    manager, _ = _manager(tmp_path, storage)

    _reissue(manager)

    assert received, 'the backend was never called'
    lost = {k for k, v in CERTIFICATE_OWNED.items() if received[-1].get(k) != v}
    assert lost == set(), f'the backend copy is missing {sorted(lost)}'


def test_without_a_storage_manager_it_already_worked(tmp_path):
    """CONTROL: #421's own configuration. It passed then and must pass now."""
    _seed(tmp_path)
    manager, _ = _manager(tmp_path, None)

    _reissue(manager)

    on_disk = json.loads((tmp_path / DOMAIN / 'metadata.json').read_text())
    assert all(on_disk.get(k) == v for k, v in CERTIFICATE_OWNED.items()), on_disk


def test_create_reissue_and_renew_commit_in_the_same_order(tmp_path):
    """The behavioural half of the guard: the steps after certbot, recorded as
    they run, must be the same sequence for all three, and the record the
    backend receives must be the record that is saved."""
    from tests.test_create_cert_io import _LIVE_CONTENTS

    runs = {}
    for label in ('create', 'reissue', 'renew'):
        root = tmp_path / label
        root.mkdir()
        if label != 'create':
            _seed(root)
        calls, stored, saved = [], [], []
        storage = MagicMock()
        storage.get_backend_name.return_value = 'recording'

        def store(d, files, meta, stored=stored, calls=calls):
            calls.append('store')
            stored.append(dict(meta))
            return True

        storage.store_certificate.side_effect = store
        manager, _ = _manager(root, storage)
        real_save = manager._save_metadata

        def save(d, meta, calls=calls, saved=saved, real_save=real_save):
            calls.append('save')
            saved.append(dict(meta))
            return real_save(d, meta)

        manager._save_metadata = save
        manager._invalidate_certificate_info_cache = lambda d, calls=calls: calls.append('invalidate')
        manager._write_pfx = lambda d, calls=calls: calls.append('pfx')

        if label == 'renew':
            live = root / DOMAIN / 'live' / DOMAIN
            live.mkdir(parents=True)
            for name, content in _LIVE_CONTENTS.items():
                (live / name).write_bytes(content)
            manager._publish_renewed_certificate(
                DOMAIN, root / DOMAIN, json.loads((root / DOMAIN / 'metadata.json').read_text()))
        else:
            manager.create_certificate(DOMAIN, 'a@example.com', 'duckdns',
                                       ca_provider='letsencrypt', replace=(label == 'reissue'))
        runs[label] = (calls, stored, saved)

    sequences = {label: calls for label, (calls, _s, _v) in runs.items()}
    # The same sequence for all three is the property. (save invalidates the
    # cache itself when it writes; the explicit call covers a refused write,
    # so 'invalidate' appears twice, identically everywhere.)
    assert sequences['create'] == sequences['reissue'] == sequences['renew'], sequences
    first = sequences['create']
    assert first.index('store') < first.index('save') < first.index('pfx'), first
    for label, (_calls, stored, saved) in runs.items():
        assert stored[-1] == {k: v for k, v in saved[-1].items() if k != 'storage_warning'}, label
