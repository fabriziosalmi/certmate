"""A share-safe backup must not carry private keys.

``create_unified_backup(include_secrets=False)`` masked the settings tree and
said so in its manifest (``secrets_masked``), its docstring, and the web
route's docstring ("share-safe masked snapshot"). The archive walk never
looked at what it was zipping: every ACME private key, the ACME account key,
the private CA key and any PKCS#12 bundle went in. These tests pin the
predicate, both manifests, the full-archive path, and the file-name
sanitising of ``backup_reason``.
"""
import json
import zipfile
from pathlib import Path

import pytest

from modules.core.file_operations import (
    FileOperations, _is_key_material, _safe_backup_reason,
)

pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    cert_dir, data_dir, backup_dir, logs_dir = (
        tmp_path / 'certs', tmp_path / 'data', tmp_path / 'backups', tmp_path / 'logs')
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    return FileOperations(cert_dir, data_dir, backup_dir, logs_dir)


def _plant_instance(file_ops):
    """The on-disk shape of one issued domain plus the private CA."""
    dom = file_ops.cert_dir / 'example.com'
    for rel, body in {
        'cert.pem': 'CERT', 'chain.pem': 'CHAIN', 'fullchain.pem': 'FULL',
        'privkey.pem': 'KEY', 'metadata.json': '{"domain": "example.com"}',
        'cert.pfx': 'PFX',
        'live/example.com/privkey.pem': 'KEY', 'live/example.com/cert.pem': 'CERT',
        'archive/example.com/privkey1.pem': 'KEY1', 'archive/example.com/cert1.pem': 'CERT1',
        'accounts/acme-v02.api.letsencrypt.org/directory/abc/private_key.json': '{"kty":"RSA"}',
        'accounts/acme-v02.api.letsencrypt.org/directory/abc/regr.json': '{}',
        'renewal/example.com.conf': 'conf',
        'keys/0000_key-certbot.pem': 'KEY0', 'keys/0001_key-certbot.pem': 'KEY1',
        'csr/0000_csr-certbot.pem': 'CSR0',
    }.items():
        path = dom / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body)
    ca = file_ops.data_dir / 'certs' / 'ca'
    ca.mkdir(parents=True)
    (ca / 'ca.key').write_text('CAKEY')
    (ca / 'ca.crt').write_text('CACRT')
    (ca / 'crl.pem').write_text('CRL')
    client = file_ops.data_dir / 'certs' / 'client' / 'alice'
    client.mkdir(parents=True)
    (client / 'alice.crt').write_text('CRT')
    (client / 'alice.key').write_text('KEY')
    (client / 'alice.p12').write_text('P12')


def _names(file_ops, filename):
    with zipfile.ZipFile(file_ops.backup_dir / 'unified' / filename) as zf:
        manifest = json.loads(zf.read('backup_metadata.json'))
        settings_copy = json.loads(zf.read('settings.json'))['metadata']
        return set(zf.namelist()), manifest, settings_copy


KEY_FILES = {
    'certificates/example.com/privkey.pem',
    'certificates/example.com/live/example.com/privkey.pem',
    'certificates/example.com/archive/example.com/privkey1.pem',
    'certificates/example.com/accounts/acme-v02.api.letsencrypt.org/directory/abc/private_key.json',
    'certificates/example.com/cert.pfx',
    'data/certs/ca/ca.key',
    'data/certs/client/alice/alice.key',
    'data/certs/client/alice/alice.p12',
    'certificates/example.com/keys/0000_key-certbot.pem',
    'certificates/example.com/keys/0001_key-certbot.pem',
}
PUBLIC_FILES = {
    'certificates/example.com/csr/0000_csr-certbot.pem',
    'certificates/example.com/cert.pem',
    'certificates/example.com/fullchain.pem',
    'certificates/example.com/metadata.json',
    'certificates/example.com/renewal/example.com.conf',
    'certificates/example.com/accounts/acme-v02.api.letsencrypt.org/directory/abc/regr.json',
    'data/certs/ca/ca.crt',
    'data/certs/ca/crl.pem',
    'data/certs/client/alice/alice.crt',
}


def test_share_safe_backup_carries_no_private_key(file_ops):
    _plant_instance(file_ops)
    filename = file_ops.create_unified_backup({'domains': []}, 'nightly')
    names, manifest, settings_copy = _names(file_ops, filename)

    assert not (names & KEY_FILES), sorted(names & KEY_FILES)
    assert PUBLIC_FILES <= names, sorted(PUBLIC_FILES - names)
    assert manifest['secrets_masked'] is True
    assert manifest['key_material_excluded'] is True
    assert manifest['key_files_excluded'] == len(KEY_FILES)
    # settings.json carries the same manifest, with the final count.
    assert settings_copy['key_files_excluded'] == len(KEY_FILES)


def test_disaster_recovery_backup_carries_every_key(file_ops):
    _plant_instance(file_ops)
    filename = file_ops.create_unified_backup({'domains': []}, 'dr', include_secrets=True)
    names, manifest, _ = _names(file_ops, filename)

    assert KEY_FILES <= names, sorted(KEY_FILES - names)
    assert manifest['secrets_masked'] is False
    assert manifest['key_material_excluded'] is False
    assert manifest['key_files_excluded'] == 0


@pytest.mark.parametrize('name, expected', [
    ('privkey.pem', True), ('privkey1.pem', True), ('PRIVKEY.PEM', True), ('privkey.pem.staging', True),
    ('private_key.json', True), ('ca.key', True), ('alice.key', True),
    ('cert.pfx', True), ('bundle.p12', True), ('0000_key-certbot.pem', True),
    ('cert.pem', False), ('fullchain.pem', False), ('chain.pem', False),
    ('regr.json', False), ('metadata.json', False), ('ca.crt', False),
    ('crl.pem', False), ('private_key.json.bak', False), ('keyring.txt', False),
])
def test_key_material_predicate(name, expected):
    assert _is_key_material(Path('/x') / name) is expected


@pytest.mark.parametrize('reason, expected', [
    ('manual', 'manual'),
    ('pre_restore', 'pre_restore'),
    ('../../etc/cron.d/x', 'etc_cron.d_x'),
    ('a b\n;rm -rf /', 'a_b_rm_-rf'),
    ('', 'manual'), (None, 'manual'),
    ('x' * 100, 'x' * 48),
])
def test_backup_reason_is_a_file_name_token(reason, expected):
    assert _safe_backup_reason(reason) == expected


def test_reason_cannot_steer_the_archive_outside_the_backup_dir(file_ops):
    filename = file_ops.create_unified_backup({'domains': []}, '../../escape')
    assert filename and '/' not in filename and '..' not in filename
    assert (file_ops.backup_dir / 'unified' / filename).exists()


def test_share_safe_archive_is_refused_over_an_instance_with_certificates(file_ops):
    _plant_instance(file_ops)
    filename = file_ops.create_unified_backup({'domains': []}, 'nightly')
    before = (file_ops.cert_dir / 'example.com' / 'privkey.pem').read_text()
    (file_ops.cert_dir / 'example.com' / 'cert.pem').write_text('NEWER-CERT-ON-DISK')

    ok = file_ops.restore_unified_backup(str(file_ops.backup_dir / 'unified' / filename))

    assert ok is False
    assert 'key_material_excluded' in (file_ops.last_restore_error or '')
    assert 'example.com' in file_ops.last_restore_error
    # Nothing written: the on-disk pair is untouched.
    assert (file_ops.cert_dir / 'example.com' / 'cert.pem').read_text() == 'NEWER-CERT-ON-DISK'
    assert (file_ops.cert_dir / 'example.com' / 'privkey.pem').read_text() == before


def test_share_safe_archive_restores_onto_an_empty_instance(file_ops):
    _plant_instance(file_ops)
    filename = file_ops.create_unified_backup({'domains': []}, 'nightly')
    import shutil
    shutil.rmtree(file_ops.cert_dir / 'example.com')

    ok = file_ops.restore_unified_backup(str(file_ops.backup_dir / 'unified' / filename))

    assert ok is True
    assert file_ops.last_restore_error is None
    assert (file_ops.cert_dir / 'example.com' / 'cert.pem').exists()
    assert not (file_ops.cert_dir / 'example.com' / 'privkey.pem').exists()


def test_disaster_recovery_archive_restores_over_certificates(file_ops):
    _plant_instance(file_ops)
    filename = file_ops.create_unified_backup({'domains': []}, 'dr', include_secrets=True)
    (file_ops.cert_dir / 'example.com' / 'privkey.pem').write_text('ROTATED')

    ok = file_ops.restore_unified_backup(str(file_ops.backup_dir / 'unified' / filename))

    assert ok is True and file_ops.last_restore_error is None
    assert (file_ops.cert_dir / 'example.com' / 'privkey.pem').read_text() == 'KEY'
