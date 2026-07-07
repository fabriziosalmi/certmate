"""Off-site backup copy to an S3-compatible target.

After create_unified_backup writes the local .zip(.enc), it best-effort copies
it to a configured S3 target (settings.backup_storage). The local backup is
authoritative; the S3 copy must never break backup creation.
"""
from unittest.mock import MagicMock, patch

import pytest

from modules.core.file_operations import FileOperations

pytestmark = [pytest.mark.unit]

_S3_CFG = {'backup_storage': {'backend': 's3_compatible', 's3_compatible': {
    'endpoint_url': 'https://s3.eu-central.example',
    'bucket': 'cm-backups', 'access_key_id': 'AK', 'secret_access_key': 'SK',
    'prefix': 'certmate/backups'}}}


def _fo(tmp_path):
    for d in ('certs', 'data', 'backups', 'logs'):
        (tmp_path / d).mkdir(exist_ok=True)
    return FileOperations(
        cert_dir=tmp_path / 'certs', data_dir=tmp_path / 'data',
        backup_dir=tmp_path / 'backups', logs_dir=tmp_path / 'logs')


def _backup(tmp_path):
    p = tmp_path / 'backup_20260614.zip'
    p.write_bytes(b'UNIFIED-BACKUP-ZIP-BYTES')
    return p


def test_uploads_when_configured(tmp_path):
    fo, path = _fo(tmp_path), _backup(tmp_path)
    fake = MagicMock()
    with patch('boto3.client', return_value=fake) as mk:
        fo._upload_backup_offsite(path, path.name, _S3_CFG, encrypted=True)
    assert mk.call_args.kwargs['endpoint_url'] == 'https://s3.eu-central.example'
    fake.put_object.assert_called_once()
    kw = fake.put_object.call_args.kwargs
    assert kw['Bucket'] == 'cm-backups'
    assert kw['Key'] == 'certmate/backups/backup_20260614.zip'
    assert kw['Body'] == b'UNIFIED-BACKUP-ZIP-BYTES'


def test_refuses_upload_when_not_encrypted(tmp_path):
    """The unified backup contains every private key; if it is NOT encrypted
    (no CERTMATE_BACKUP_PASSPHRASE), off-site upload must be refused so cleartext
    keys never reach third-party storage. Regression guard for the decoupled
    encryption/offsite settings."""
    fo, path = _fo(tmp_path), _backup(tmp_path)
    with patch('boto3.client') as mk:
        # encrypted defaults to False — a fully-configured S3 target must still
        # be skipped.
        fo._upload_backup_offsite(path, path.name, _S3_CFG)
        fo._upload_backup_offsite(path, path.name, _S3_CFG, encrypted=False)
    mk.assert_not_called()


def test_no_upload_when_off_or_unconfigured(tmp_path):
    fo, path = _fo(tmp_path), _backup(tmp_path)
    with patch('boto3.client') as mk:
        fo._upload_backup_offsite(path, path.name, {'backup_storage': {'backend': 'none'}})
        fo._upload_backup_offsite(path, path.name, {})            # no backup_storage at all
        fo._upload_backup_offsite(path, path.name, None)          # no settings at all
        # configured backend but missing credentials -> skip
        fo._upload_backup_offsite(path, path.name, {'backup_storage': {
            'backend': 's3_compatible', 's3_compatible': {'endpoint_url': 'https://x', 'bucket': 'b'}}})
    mk.assert_not_called()


def test_upload_failure_is_best_effort(tmp_path):
    """An S3 outage must NOT break backup creation — never raises."""
    fo, path = _fo(tmp_path), _backup(tmp_path)
    fake = MagicMock()
    fake.put_object.side_effect = RuntimeError('s3 unreachable')
    with patch('boto3.client', return_value=fake):
        fo._upload_backup_offsite(path, path.name, _S3_CFG, encrypted=True)  # no exception
