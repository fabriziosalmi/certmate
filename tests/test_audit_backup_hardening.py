"""Regression tests for the backup-hardening fixes surfaced by the
internal security audit (May 2026).

### C1 — backup ZIP wrote plaintext credentials

Before this fix, ``create_unified_backup`` serialised ``settings.json``
verbatim into the ZIP. The archive therefore contained plaintext
``dns_providers.*`` tokens, ``certificate_storage.*.client_secret``,
``vault_token``, ``secret_access_key``, ``api_bearer_token``,
``smtp_password``, OIDC ``client_secret`` and every other credential.
Admin-gated download, but a leaked backup file (errant rsync of
``data/backups/unified/``, accidental Docker image bake, ops bastion
download) became a full credential dump.

The fix: ``create_unified_backup(..., include_secrets=False)`` is now
the default. Every secret-bearing field is replaced with the canonical
``SECRET_MASK_SENTINEL`` (``'********'``) before serialisation, using
the same ``_is_secret_key`` predicate as the masked GET on
``/api/web/settings``. The ZIP file is also ``chmod 0600`` so the
default umask cannot leave it world-readable on POSIX hosts.

``include_secrets=True`` is the opt-in plaintext path for full
disaster-recovery use; the audit-log entry records the opt-in so a
SIEM can flag the resulting file-on-disk credential dump.

### G — restore must re-validate deploy hooks

Before this fix, ``restore_unified_backup`` wrote the restored
``settings.json`` to disk verbatim. A backup created when
``DeployManager._validate_hook`` was more permissive (or a hand-
tampered backup zip) could install a hook command that today's
validator rejects, and the next renewal would execute it via
``sh -c``.

The fix: ``restore_unified_backup`` runs the current validator over
every ``deploy_hooks.global_hooks`` entry and refuses the restore if
any hook fails. ``pre_restore_backup`` (created by the caller) is
the rollback target.

### Restore + masked-backup interaction

Restoring a masked backup onto an existing install must NOT destroy
the existing on-disk credentials. The restore re-uses the
``_strip_masked_values`` + deep-merge pipeline from PR #215: the
sentinel signals "preserve existing on-disk value". On a fresh
restore the sentinel stays as-is and a warning is logged so the
operator knows to re-enter credentials.
"""

import json
import os
import stat
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.file_operations import FileOperations
from modules.core.settings import SECRET_MASK_SENTINEL


pytestmark = [pytest.mark.unit]


@pytest.fixture
def file_ops(tmp_path):
    cert_dir = tmp_path / 'certs'
    data_dir = tmp_path / 'data'
    backup_dir = tmp_path / 'backups'
    logs_dir = tmp_path / 'logs'
    for d in (cert_dir, data_dir, backup_dir, logs_dir):
        d.mkdir(parents=True, exist_ok=True)
    return FileOperations(cert_dir, data_dir, backup_dir, logs_dir)


@pytest.fixture
def sample_settings_with_secrets():
    """A settings dict that hits every credential field name pattern
    the project's mask regex recognises — DNS tokens, storage backend
    creds, API bearer, SMTP password, OIDC client_secret."""
    return {
        'email': 'ops@example.com',
        'dns_provider': 'cloudflare',
        'dns_providers': {
            'cloudflare': {'api_token': 'CF-PLAINTEXT-TOKEN'},
            'route53': {
                'access_key_id': 'AKIA-FAKE-id',
                'secret_access_key': 'AWS-PLAINTEXT-SECRET-KEY',
            },
        },
        'certificate_storage': {
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://x.vault.azure.net/',
                'client_id': 'azure-client-id-uuid',
                'client_secret': 'AZURE-PLAINTEXT-CLIENT-SECRET',
                'tenant_id': 'azure-tenant-uuid',
            },
        },
        'api_bearer_token': 'BEARER-PLAINTEXT-TOKEN',
        'notifications': {
            'smtp': {
                'host': 'smtp.example.com',
                'username': 'noreply@example.com',
                'smtp_password': 'SMTP-PLAINTEXT-PASSWORD',
            },
        },
        'oidc': {
            'enabled': True,
            'client_id': 'oidc-client-id',
            'client_secret': 'OIDC-PLAINTEXT-CLIENT-SECRET',
        },
        'default_key_type': 'rsa',  # NOT a secret — pin the exclusion
        'default_key_size': 4096,    # NOT a secret
    }


def _read_settings_from_zip(zip_path):
    with zipfile.ZipFile(zip_path, 'r') as zf:
        with zf.open('settings.json') as f:
            return json.loads(f.read().decode('utf-8'))


class TestBackupMasksSecretsByDefault:
    """Default ``create_unified_backup`` (no ``include_secrets`` flag)
    must mask every credential before writing the ZIP."""

    def test_default_backup_masks_dns_provider_tokens(self, file_ops, sample_settings_with_secrets):
        filename = file_ops.create_unified_backup(sample_settings_with_secrets, 'test_default')
        assert filename, 'create_unified_backup returned None'
        zip_path = file_ops.backup_dir / 'unified' / filename
        payload = _read_settings_from_zip(zip_path)['settings']

        # Every credential field carries the mask sentinel, NOT the plaintext.
        assert payload['dns_providers']['cloudflare']['api_token'] == SECRET_MASK_SENTINEL
        assert payload['dns_providers']['route53']['secret_access_key'] == SECRET_MASK_SENTINEL
        assert payload['certificate_storage']['azure_keyvault']['client_secret'] == SECRET_MASK_SENTINEL
        assert payload['api_bearer_token'] == SECRET_MASK_SENTINEL
        assert payload['notifications']['smtp']['smtp_password'] == SECRET_MASK_SENTINEL
        assert payload['oidc']['client_secret'] == SECRET_MASK_SENTINEL

    def test_default_backup_preserves_non_secret_fields(self, file_ops, sample_settings_with_secrets):
        """Masking must not affect the operator-facing fields the regex
        excludes (``default_key_type``, ``default_key_size``) or any
        non-secret string like the DNS-provider name itself."""
        filename = file_ops.create_unified_backup(sample_settings_with_secrets, 'test_excl')
        payload = _read_settings_from_zip(file_ops.backup_dir / 'unified' / filename)['settings']

        assert payload['default_key_type'] == 'rsa'
        assert payload['default_key_size'] == 4096
        assert payload['dns_provider'] == 'cloudflare'
        assert payload['email'] == 'ops@example.com'
        # Storage backend name is operator-visible, must survive masking.
        assert payload['certificate_storage']['backend'] == 'azure_keyvault'

    def test_default_backup_metadata_records_masked_mode(self, file_ops, sample_settings_with_secrets):
        filename = file_ops.create_unified_backup(sample_settings_with_secrets, 'test_meta')
        meta = _read_settings_from_zip(file_ops.backup_dir / 'unified' / filename)['metadata']
        assert meta['secrets_masked'] is True

    def test_backup_file_is_mode_0600(self, file_ops, sample_settings_with_secrets):
        """The default umask leaves backup files world-readable on
        many distros. Pin 0600 so the contents (even masked) are not
        broadcast to every user on the host."""
        filename = file_ops.create_unified_backup(sample_settings_with_secrets, 'test_perms')
        zip_path = file_ops.backup_dir / 'unified' / filename
        mode = stat.S_IMODE(zip_path.stat().st_mode)
        assert mode == 0o600, f'expected 0o600, got {oct(mode)}'


class TestBackupOptInPlaintext:
    """``include_secrets=True`` is the audit-logged opt-in for full
    disaster-recovery; the resulting ZIP is a credential dump and the
    metadata records the opt-in so an inspector can tell the modes
    apart."""

    def test_plaintext_backup_includes_secrets(self, file_ops, sample_settings_with_secrets):
        filename = file_ops.create_unified_backup(
            sample_settings_with_secrets, 'test_opt_in', include_secrets=True,
        )
        payload = _read_settings_from_zip(file_ops.backup_dir / 'unified' / filename)['settings']

        assert payload['dns_providers']['cloudflare']['api_token'] == 'CF-PLAINTEXT-TOKEN'
        assert payload['certificate_storage']['azure_keyvault']['client_secret'] == 'AZURE-PLAINTEXT-CLIENT-SECRET'
        assert payload['oidc']['client_secret'] == 'OIDC-PLAINTEXT-CLIENT-SECRET'
        assert payload['api_bearer_token'] == 'BEARER-PLAINTEXT-TOKEN'

    def test_plaintext_backup_metadata_records_opt_in(self, file_ops, sample_settings_with_secrets):
        filename = file_ops.create_unified_backup(
            sample_settings_with_secrets, 'test_opt_in_meta', include_secrets=True,
        )
        meta = _read_settings_from_zip(file_ops.backup_dir / 'unified' / filename)['metadata']
        assert meta['secrets_masked'] is False


class TestRestoreReValidatesDeployHooks:
    """Audit finding G: a restore that would install a hook today's
    validator rejects must be refused, not silently written.

    The repro path is "settings.json saved under a more-permissive
    older validator, or hand-tampered backup zip" — operator never
    intentionally created a malicious hook, but the file survives
    until renewal time when ``sh -c <command>`` runs it."""

    def _make_backup(self, file_ops, settings, name='hook_test', include_secrets=True):
        return file_ops.create_unified_backup(settings, name, include_secrets=include_secrets)

    def test_restore_refuses_unsafe_hook_command(self, file_ops):
        unsafe_settings = {
            'email': 'ops@example.com',
            'deploy_hooks': {
                'global_hooks': [
                    {
                        'id': 'h1',
                        'name': 'malicious',
                        'command': 'echo hi; cat /etc/passwd > /tmp/x',
                        'timeout': 10,
                    },
                ],
            },
        }
        filename = self._make_backup(file_ops, unsafe_settings, 'unsafe_hook')
        zip_path = file_ops.backup_dir / 'unified' / filename

        ok = file_ops.restore_unified_backup(str(zip_path))
        assert ok is False
        # And the on-disk settings.json must NOT have been overwritten
        # — restore aborted before the write.
        settings_file = file_ops.data_dir / 'settings.json'
        assert not settings_file.exists(), 'restore should not have written settings.json'

    def test_restore_accepts_safe_hook_command(self, file_ops):
        safe_settings = {
            'email': 'ops@example.com',
            'deploy_hooks': {
                'global_hooks': [
                    {
                        'id': 'h1',
                        'name': 'cp_nginx',
                        'command': 'cp $CERTMATE_FULLCHAIN_PATH /etc/nginx/ssl/site.crt',
                        'timeout': 10,
                    },
                ],
            },
        }
        filename = self._make_backup(file_ops, safe_settings, 'safe_hook')
        zip_path = file_ops.backup_dir / 'unified' / filename

        ok = file_ops.restore_unified_backup(str(zip_path))
        assert ok is True
        settings_file = file_ops.data_dir / 'settings.json'
        restored = json.loads(settings_file.read_text(encoding='utf-8'))
        assert restored['deploy_hooks']['global_hooks'][0]['name'] == 'cp_nginx'


class TestRestoreMaskedBackupPreservesOnDiskSecrets:
    """Restoring a masked backup on top of an existing install must NOT
    destroy the on-disk credentials. The mask sentinel signals
    "preserve existing", using the same deep-merge pipeline as PR #215
    on the settings POST path."""

    def test_restore_masked_backup_preserves_existing_secrets(self, file_ops, sample_settings_with_secrets):
        # Seed an on-disk settings.json with real secrets.
        settings_file = file_ops.data_dir / 'settings.json'
        on_disk = {
            'certificate_storage': {
                'backend': 'azure_keyvault',
                'azure_keyvault': {
                    'vault_url': 'https://x.vault.azure.net/',
                    'client_id': 'azure-client-id-uuid',
                    'client_secret': 'EXISTING-AZURE-SECRET',  # real on-disk value
                    'tenant_id': 'azure-tenant-uuid',
                },
            },
        }
        settings_file.write_text(json.dumps(on_disk), encoding='utf-8')

        # Create a MASKED backup (default).
        filename = file_ops.create_unified_backup(sample_settings_with_secrets, 'masked_restore')
        zip_path = file_ops.backup_dir / 'unified' / filename
        # Sanity: the zip carries the sentinel, not the plaintext.
        backup_payload = _read_settings_from_zip(zip_path)['settings']
        assert backup_payload['certificate_storage']['azure_keyvault']['client_secret'] == SECRET_MASK_SENTINEL

        # Restore.
        ok = file_ops.restore_unified_backup(str(zip_path))
        assert ok is True

        restored = json.loads(settings_file.read_text(encoding='utf-8'))
        # Key assertion: the existing on-disk secret SURVIVED the
        # masked-backup restore. The sentinel did NOT overwrite it.
        assert restored['certificate_storage']['azure_keyvault']['client_secret'] == 'EXISTING-AZURE-SECRET'

    def test_restore_plaintext_backup_overwrites_existing_secrets(self, file_ops, sample_settings_with_secrets):
        """Conversely, the opt-in plaintext backup MUST overwrite
        on-disk secrets — that is the whole point of a disaster-recovery
        snapshot. Pin the contrast so future refactors do not collapse
        the two modes."""
        settings_file = file_ops.data_dir / 'settings.json'
        on_disk = {
            'certificate_storage': {
                'backend': 'azure_keyvault',
                'azure_keyvault': {
                    'client_secret': 'EXISTING-AZURE-SECRET',
                },
            },
        }
        settings_file.write_text(json.dumps(on_disk), encoding='utf-8')

        filename = file_ops.create_unified_backup(
            sample_settings_with_secrets, 'plaintext_restore', include_secrets=True,
        )
        ok = file_ops.restore_unified_backup(str(file_ops.backup_dir / 'unified' / filename))
        assert ok is True

        restored = json.loads(settings_file.read_text(encoding='utf-8'))
        assert restored['certificate_storage']['azure_keyvault']['client_secret'] == 'AZURE-PLAINTEXT-CLIENT-SECRET'


class TestBackupUtcRealignment:
    """Tests to verify UTC alignment in backups and prune logic."""

    def test_backup_creation_uses_utc_time(self, file_ops, sample_settings_with_secrets):
        fixed_utc_now = datetime(2026, 5, 22, 15, 30, 45, 123456)
        fixed_iso = fixed_utc_now.isoformat()
        
        with patch('modules.core.file_operations.utc_now', return_value=fixed_utc_now), \
             patch('modules.core.file_operations.utc_now_iso', return_value=fixed_iso):
            
            filename = file_ops.create_unified_backup(sample_settings_with_secrets, 'utc_test')
            
            # The filename should use the UTC timestamp format %Y%m%d_%H%M%S_%f
            expected_timestamp = fixed_utc_now.strftime("%Y%m%d_%H%M%S_%f")
            assert filename.startswith(f"backup_{expected_timestamp}_utc_test")
            
            zip_path = file_ops.backup_dir / 'unified' / filename
            meta = _read_settings_from_zip(zip_path)['metadata']
            assert meta['timestamp'] == fixed_iso

    def test_backup_pruning_respects_utc_cutoff(self, file_ops):
        # Setup backup directory
        unified_dir = file_ops.backup_dir / "unified"
        unified_dir.mkdir(parents=True, exist_ok=True)
        
        fixed_utc_now = datetime(2026, 5, 22, 12, 0, 0)
        
        # We will create three backup files:
        # 1. A recent backup (2 days old) - should be kept
        # 2. A backup exactly at the cutoff (30 days old) - should be kept
        # 3. An old backup (31 days old) - should be pruned
        
        recent_time = fixed_utc_now - timedelta(days=2)
        cutoff_time = fixed_utc_now - timedelta(days=30)
        old_time = fixed_utc_now - timedelta(days=31)
        
        # Convert to UNIX timestamps (UTC)
        recent_ts = recent_time.replace(tzinfo=timezone.utc).timestamp()
        cutoff_ts = cutoff_time.replace(tzinfo=timezone.utc).timestamp()
        old_ts = old_time.replace(tzinfo=timezone.utc).timestamp()
        
        recent_file = unified_dir / "backup_recent_reason.zip"
        cutoff_file = unified_dir / "backup_cutoff_reason.zip"
        old_file = unified_dir / "backup_old_reason.zip"
        
        for f in (recent_file, cutoff_file, old_file):
            f.write_text("dummy zip content")
            
        os.utime(recent_file, (recent_ts, recent_ts))
        os.utime(cutoff_file, (cutoff_ts, cutoff_ts))
        os.utime(old_file, (old_ts, old_ts))
        
        with patch('modules.core.file_operations.utc_now', return_value=fixed_utc_now):
            file_ops._prune_unified_backups()
            
        assert recent_file.exists()
        assert cutoff_file.exists()
        assert not old_file.exists()

    def test_backup_pruning_respects_max_count(self, file_ops):
        unified_dir = file_ops.backup_dir / "unified"
        unified_dir.mkdir(parents=True, exist_ok=True)
        
        fixed_utc_now = datetime(2026, 5, 22, 12, 0, 0)
        
        # Create MAX_BACKUPS_PER_TYPE + 5 files, all within retention period.
        # Ensure we set their mtime in order so we can assert the oldest ones are deleted.
        created_files = []
        for i in range(55): # MAX_BACKUPS_PER_TYPE is 50, so 50 + 5 = 55
            f = unified_dir / f"backup_{i:03d}_reason.zip"
            f.write_text("dummy zip content")
            # older file index has older timestamp
            file_time = fixed_utc_now - timedelta(hours=(55 - i))
            file_ts = file_time.replace(tzinfo=timezone.utc).timestamp()
            os.utime(f, (file_ts, file_ts))
            created_files.append(f)
            
        with patch('modules.core.file_operations.utc_now', return_value=fixed_utc_now):
            file_ops._prune_unified_backups()
            
        # The oldest 5 should be unlinked (indices 0 to 4)
        for i in range(5):
            assert not created_files[i].exists(), f"File {created_files[i].name} should have been pruned"
        # The newest 50 should be retained (indices 5 onwards)
        for i in range(5, 55):
            assert created_files[i].exists(), f"File {created_files[i].name} should have been kept"
