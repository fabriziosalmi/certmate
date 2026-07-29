"""Tests for the fingerprint-keyed certificate inventory
(``modules/core/cert_inventory.py``), covering #468:

* idempotent upsert keyed by fingerprint,
* one certificate on N hosts -> one record with N endpoints,
* first_seen / last_seen tracking,
* the managed flag + managed-domain link,
* source preservation and the probe-result bridge,
* schema versioning,
* and that the SQLite DB is carried by (and restored from) a unified backup.
"""

import zipfile
from datetime import datetime, timedelta, timezone

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from modules.core.cert_inventory import CertInventory, SCHEMA_VERSION, SOURCES

pytestmark = [pytest.mark.unit]


@pytest.fixture
def inv(tmp_path):
    return CertInventory(tmp_path / 'data')


# --------------------------------------------------------------------------- #
# schema / construction
# --------------------------------------------------------------------------- #

def test_db_created_under_inventory_subdir(tmp_path):
    inventory = CertInventory(tmp_path / 'data')
    assert inventory.db_path.exists()
    assert inventory.db_path.parent.name == 'inventory'


def test_schema_version_set(inv):
    with inv._connect() as conn:
        version = conn.execute('PRAGMA user_version').fetchone()[0]
    assert version == SCHEMA_VERSION


def test_reopen_is_idempotent(tmp_path):
    CertInventory(tmp_path / 'data').record_observation(
        fingerprint='aa', host='h.example.com', port=443)
    # A second open of the same dir must not wipe or re-migrate.
    reopened = CertInventory(tmp_path / 'data')
    assert reopened.count() == 1


# --------------------------------------------------------------------------- #
# idempotency & endpoints
# --------------------------------------------------------------------------- #

def test_record_is_idempotent_by_fingerprint(inv):
    for _ in range(3):
        inv.record_observation(fingerprint='fp1', host='a.example.com', port=443)
    assert inv.count() == 1
    rec = inv.get('fp1')
    assert len(rec['endpoints']) == 1


def test_one_cert_many_endpoints(inv):
    for host in ('a.example.com', 'b.example.com', 'c.example.com'):
        inv.record_observation(fingerprint='shared', host=host, port=443)
    inv.record_observation(fingerprint='shared', host='a.example.com', port=8443)
    assert inv.count() == 1
    rec = inv.get('shared')
    # 3 hosts on :443 + 1 host on :8443 = 4 distinct endpoints, one record.
    assert len(rec['endpoints']) == 4
    hostports = {(e['host'], e['port']) for e in rec['endpoints']}
    assert ('a.example.com', 443) in hostports
    assert ('a.example.com', 8443) in hostports


def test_endpoint_reobservation_updates_last_seen(inv):
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           observed_at='2026-01-01T00:00:00Z')
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           observed_at='2026-02-01T00:00:00Z')
    rec = inv.get('fp')
    ep = rec['endpoints'][0]
    assert ep['first_seen'] == '2026-01-01T00:00:00Z'
    assert ep['last_seen'] == '2026-02-01T00:00:00Z'


def test_first_and_last_seen_tracked(inv):
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           observed_at='2026-01-01T00:00:00Z')
    inv.record_observation(fingerprint='fp', host='other.example.com', port=443,
                           observed_at='2026-03-01T00:00:00Z')
    rec = inv.get('fp')
    assert rec['first_seen'] == '2026-01-01T00:00:00Z'
    assert rec['last_seen'] == '2026-03-01T00:00:00Z'


# --------------------------------------------------------------------------- #
# metadata / managed / source
# --------------------------------------------------------------------------- #

def test_full_metadata_roundtrip(inv):
    inv.record_observation(
        fingerprint='fp',
        host='h.example.com', port=443,
        subject_cn='h.example.com',
        subject='CN=h.example.com',
        issuer_cn='Test CA',
        issuer='CN=Test CA,O=Test',
        serial='12345',
        not_before='2026-01-01T00:00:00Z',
        not_after='2026-04-01T00:00:00Z',
        key={'type': 'ECDSA', 'size': 256, 'curve': 'secp256r1'},
        signature_algorithm='ecdsa-with-SHA256',
        san_dns=['h.example.com', 'www.h.example.com'],
        source='probed',
    )
    rec = inv.get('fp')
    assert rec['issuer'] == 'CN=Test CA,O=Test'
    assert rec['key'] == {'type': 'ECDSA', 'size': 256, 'curve': 'secp256r1'}
    assert rec['san_dns'] == ['h.example.com', 'www.h.example.com']
    assert rec['signature_algorithm'] == 'ecdsa-with-SHA256'


def test_metadata_immutable_on_reobservation(inv):
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           subject_cn='original', source='probed')
    # A re-observation with different metadata must NOT rewrite the immutable
    # fields (a fingerprint uniquely determines the certificate).
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           subject_cn='changed', source='probed')
    assert inv.get('fp')['subject_cn'] == 'original'


def test_managed_flag_and_domain_link(inv):
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           source='issued', managed=True,
                           managed_domain='example.com')
    rec = inv.get('fp')
    assert rec['managed'] is True
    assert rec['managed_domain'] == 'example.com'


def test_managed_is_sticky_true(inv):
    # Discovered as managed, later re-probed as an anonymous observation:
    # it stays managed and keeps its domain link.
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           source='issued', managed=True,
                           managed_domain='example.com')
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           source='probed', managed=False)
    rec = inv.get('fp')
    assert rec['managed'] is True
    assert rec['managed_domain'] == 'example.com'


def test_managed_promotion_fills_domain(inv):
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           source='probed', managed=False)
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           source='probed', managed=True,
                           managed_domain='example.com')
    rec = inv.get('fp')
    assert rec['managed'] is True
    assert rec['managed_domain'] == 'example.com'


def test_source_preserved_from_first_discovery(inv):
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           source='issued')
    inv.record_observation(fingerprint='fp', host='h.example.com', port=443,
                           source='probed')
    assert inv.get('fp')['source'] == 'issued'


def test_unknown_source_rejected(inv):
    with pytest.raises(ValueError):
        inv.record_observation(fingerprint='fp', host='h', port=443,
                               source='bogus')


def test_missing_fingerprint_rejected(inv):
    with pytest.raises(ValueError):
        inv.record_observation(fingerprint='', host='h', port=443)


def test_all_sources_accepted(inv):
    for i, src in enumerate(SOURCES):
        inv.record_observation(fingerprint=f'fp{i}', host='h', port=443, source=src)
    assert inv.count() == len(SOURCES)


# --------------------------------------------------------------------------- #
# queries
# --------------------------------------------------------------------------- #

def test_list_filter_by_managed(inv):
    inv.record_observation(fingerprint='m', host='h', port=443,
                           source='issued', managed=True)
    inv.record_observation(fingerprint='u', host='h2', port=443,
                           source='probed', managed=False)
    managed = inv.list_all(managed=True)
    assert [r['fingerprint'] for r in managed] == ['m']


def test_list_filter_by_source(inv):
    inv.record_observation(fingerprint='a', host='h', port=443, source='probed')
    inv.record_observation(fingerprint='b', host='h2', port=443, source='ct-log')
    ct = inv.list_all(source='ct-log')
    assert [r['fingerprint'] for r in ct] == ['b']


def test_list_pagination(inv):
    for i in range(5):
        inv.record_observation(fingerprint=f'fp{i}', host='h', port=443,
                               observed_at=f'2026-01-0{i + 1}T00:00:00Z')
    page = inv.list_all(limit=2, offset=0)
    assert len(page) == 2
    # newest last_seen first
    assert page[0]['fingerprint'] == 'fp4'


def test_find_by_endpoint(inv):
    inv.record_observation(fingerprint='fp', host='shared.example.com', port=443)
    hits = inv.find_by_endpoint('shared.example.com', 443)
    assert len(hits) == 1
    assert hits[0]['fingerprint'] == 'fp'


def test_get_missing_returns_none(inv):
    assert inv.get('nope') is None


# --------------------------------------------------------------------------- #
# probe-result bridge
# --------------------------------------------------------------------------- #

def _ok_probe_result():
    return {
        'host': 'h.example.com', 'port': 443, 'status': 'ok',
        'certificate': {
            'subject_cn': 'h.example.com',
            'subject': 'CN=h.example.com',
            'issuer_cn': "Let's Encrypt",
            'issuer': "CN=R3,O=Let's Encrypt",
            'serial_number': '999',
            'not_before': '2026-01-01T00:00:00Z',
            'not_after': '2026-04-01T00:00:00Z',
            'fingerprint_sha256': 'deadbeef',
            'key': {'type': 'RSA', 'size': 2048, 'curve': None},
            'signature_algorithm': 'sha256WithRSAEncryption',
            'san_dns': ['h.example.com'],
        },
        'validation': {}, 'chain': [],
    }


def test_record_probe_result_ok(inv):
    fp = inv.record_probe_result(_ok_probe_result())
    assert fp == 'deadbeef'
    rec = inv.get('deadbeef')
    assert rec['subject_cn'] == 'h.example.com'
    assert rec['source'] == 'probed'
    assert rec['endpoints'][0]['host'] == 'h.example.com'


@pytest.mark.parametrize('bad', [
    {'status': 'blocked', 'certificate': None},
    {'status': 'unreachable', 'certificate': None},
    {'status': 'ok', 'certificate': {}},  # no fingerprint
    'not a dict',
])
def test_record_probe_result_skips_non_ok(inv, bad):
    assert inv.record_probe_result(bad) is None
    assert inv.count() == 0


def test_record_probe_result_managed_linkage(inv):
    fp = inv.record_probe_result(_ok_probe_result(), source='issued',
                                 managed=True, managed_domain='example.com')
    rec = inv.get(fp)
    assert rec['managed'] is True
    assert rec['managed_domain'] == 'example.com'


# --------------------------------------------------------------------------- #
# backup carries the inventory DB
# --------------------------------------------------------------------------- #

def _self_signed_pem(cn='example.com'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_backup_includes_inventory_db(tmp_path):
    from modules.core.file_operations import FileOperations

    cert_dir = tmp_path / 'certificates'
    data_dir = tmp_path / 'data'
    backup_dir = tmp_path / 'backups'
    logs_dir = tmp_path / 'logs'
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir()
    # A domain dir so the backup has something to anchor on.
    dom = cert_dir / 'example.com'
    dom.mkdir()
    (dom / 'cert.pem').write_bytes(_self_signed_pem())

    inventory = CertInventory(data_dir)
    inventory.record_observation(fingerprint='fp', host='example.com', port=443,
                                 source='issued', managed=True)

    file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
    filename = file_ops.create_unified_backup({"domains": []}, "test")
    assert filename
    backup_path = backup_dir / "unified" / filename

    with zipfile.ZipFile(backup_path) as zf:
        names = zf.namelist()
    assert any(n.startswith('data/inventory/') and n.endswith('inventory.db')
               for n in names), names


def test_backup_restore_round_trips_inventory(tmp_path):
    from modules.core.file_operations import FileOperations

    src = tmp_path / 'src'
    cert_dir = src / 'certificates'
    data_dir = src / 'data'
    backup_dir = src / 'backups'
    logs_dir = src / 'logs'
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir(parents=True)
    (cert_dir / 'example.com').mkdir()
    (cert_dir / 'example.com' / 'cert.pem').write_bytes(_self_signed_pem())

    CertInventory(data_dir).record_observation(
        fingerprint='fp-restore', host='example.com', port=443,
        source='issued', managed=True, subject_cn='example.com')

    file_ops = FileOperations(cert_dir, data_dir, backup_dir, logs_dir)
    filename = file_ops.create_unified_backup({"domains": []}, "test")
    backup_path = backup_dir / "unified" / filename

    # Restore into a pristine instance and re-open the inventory.
    dest = tmp_path / 'restored'
    r_cert, r_data, r_backup, r_logs = (
        dest / 'certificates', dest / 'data', dest / 'backups', dest / 'logs')
    for d in (r_cert, r_data, r_backup, r_logs):
        d.mkdir(parents=True)
    restored = FileOperations(r_cert, r_data, r_backup, r_logs)
    assert restored.restore_unified_backup(str(backup_path)) is True

    inv = CertInventory(r_data)
    rec = inv.get('fp-restore')
    assert rec is not None
    assert rec['managed'] is True
    assert rec['subject_cn'] == 'example.com'
