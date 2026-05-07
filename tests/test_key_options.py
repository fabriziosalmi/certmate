"""Tests for the configurable certificate key type/size feature.

The validator is a pure function so it covers exhaustively; the certbot
command-builder tests use the same MagicMock pattern as
``tests/test_san_domains.py`` (no Docker, no real certbot needed).
"""
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# validate_key_options
# ---------------------------------------------------------------------------


class TestValidateKeyOptionsAccepts:
    @pytest.mark.parametrize("key_size", [2048, 3072, 4096])
    def test_rsa_with_supported_size(self, key_size):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('rsa', key_size, None)
        assert ok, err
        assert err == ''

    @pytest.mark.parametrize("curve", ['secp256r1', 'secp384r1'])
    def test_ecdsa_with_supported_curve(self, curve):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('ecdsa', None, curve)
        assert ok, err

    def test_all_none_means_use_defaults(self):
        """Treat (None, None, None) as 'caller did not pick anything'."""
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options(None, None, None)
        assert ok and err == ''


class TestValidateKeyOptionsRejects:
    def test_unknown_key_type(self):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('dsa', None, None)
        assert not ok
        assert 'key_type' in err

    def test_rsa_with_unsupported_size(self):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('rsa', 1024, None)
        assert not ok
        assert 'key_size' in err

    def test_rsa_missing_size(self):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('rsa', None, None)
        assert not ok
        assert 'key_size' in err

    def test_rsa_with_curve(self):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('rsa', 2048, 'secp256r1')
        assert not ok
        assert 'elliptic_curve' in err

    def test_ecdsa_with_size(self):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('ecdsa', 2048, None)
        assert not ok
        assert 'key_size' in err

    def test_ecdsa_missing_curve(self):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('ecdsa', None, None)
        assert not ok
        assert 'elliptic_curve' in err

    def test_ecdsa_with_unsupported_curve(self):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options('ecdsa', None, 'secp521r1')
        assert not ok
        assert 'elliptic_curve' in err

    def test_size_or_curve_without_type(self):
        """An incomplete shape (size set, type missing) must be rejected."""
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options(None, 4096, None)
        assert not ok


# ---------------------------------------------------------------------------
# build_certbot_command emits the right flags
# ---------------------------------------------------------------------------


@pytest.fixture
def ca_manager():
    from modules.core.ca_manager import CAManager
    mgr = CAManager.__new__(CAManager)
    mgr.settings_manager = MagicMock()
    mgr.ca_providers = {
        'letsencrypt': {
            'name': "Let's Encrypt",
            'production_url': 'https://acme-v02.api.letsencrypt.org/directory',
            'staging_url': 'https://acme-staging-v02.api.letsencrypt.org/directory',
            'requires_eab': False,
        }
    }
    return mgr


class TestBuildCertbotCommandKeyFlags:
    def _common_kwargs(self):
        return {
            'domain': 'example.com',
            'email': 'test@example.com',
            'ca_provider': 'letsencrypt',
            'dns_provider': 'cloudflare',
            'dns_config': {'api_token': 'fake'},
            'account_config': {},
        }

    def test_rsa_4096_emits_key_type_and_size(self, ca_manager):
        cmd, _ = ca_manager.build_certbot_command(
            **self._common_kwargs(),
            key_type='rsa', key_size=4096,
        )
        assert '--key-type' in cmd
        assert cmd[cmd.index('--key-type') + 1] == 'rsa'
        assert '--rsa-key-size' in cmd
        assert cmd[cmd.index('--rsa-key-size') + 1] == '4096'
        # Cross-pollination guard.
        assert '--elliptic-curve' not in cmd

    def test_ecdsa_secp384r1_emits_key_type_and_curve(self, ca_manager):
        cmd, _ = ca_manager.build_certbot_command(
            **self._common_kwargs(),
            key_type='ecdsa', elliptic_curve='secp384r1',
        )
        assert '--key-type' in cmd
        assert cmd[cmd.index('--key-type') + 1] == 'ecdsa'
        assert '--elliptic-curve' in cmd
        assert cmd[cmd.index('--elliptic-curve') + 1] == 'secp384r1'
        assert '--rsa-key-size' not in cmd

    def test_no_key_kwargs_emits_no_key_flags(self, ca_manager):
        """Backwards compatibility: callers that don't opt in get the same
        certbot command as before this feature existed (certbot picks its
        own RSA-2048 default at run time)."""
        cmd, _ = ca_manager.build_certbot_command(**self._common_kwargs())
        assert '--key-type' not in cmd
        assert '--rsa-key-size' not in cmd
        assert '--elliptic-curve' not in cmd

    def test_rsa_without_size_does_not_emit_partial_flags(self, ca_manager):
        """Defensive: if the caller passes key_type=rsa but forgot key_size,
        the builder should NOT emit a half-flag (which would crash certbot).
        Validation happens upstream — the builder is conservative."""
        cmd, _ = ca_manager.build_certbot_command(
            **self._common_kwargs(),
            key_type='rsa', key_size=None,
        )
        assert '--key-type' not in cmd
        assert '--rsa-key-size' not in cmd


# ---------------------------------------------------------------------------
# Settings: legacy install picks up rsa/2048 defaults silently
# ---------------------------------------------------------------------------


class TestHydrateFromStorage:
    """Restore PEMs+metadata from the storage backend at startup.

    This is the missing half of the Docker/K8s ephemeral-filesystem story:
    when the container starts on a fresh volume, neither the PEMs nor the
    certbot renewal conf are on disk. ``hydrate_from_storage`` puts the
    PEMs and metadata.json back so the dashboard, the API and the
    renew loop see a populated ``certificates/`` again — and the
    metadata-driven rebuild path then handles the still-missing
    renewal/<domain>.conf on the first renew after restart.
    """

    def _make_manager(self, tmp_path, storage_manager):
        from modules.core.certificates import CertificateManager
        mgr = CertificateManager.__new__(CertificateManager)
        mgr.cert_dir = tmp_path / 'certificates'
        mgr.cert_dir.mkdir(parents=True)
        mgr.storage_manager = storage_manager
        mgr.settings_manager = MagicMock()
        return mgr

    def test_restores_missing_cert_from_storage(self, tmp_path):
        storage = MagicMock()
        storage.get_backend_name.return_value = 'azure_keyvault'
        storage.retrieve_certificate.return_value = (
            {
                'cert.pem': b'-----CERT-----',
                'chain.pem': b'-----CHAIN-----',
                'fullchain.pem': b'-----FULLCHAIN-----',
                'privkey.pem': b'-----KEY-----',
            },
            {'domain': 'example.com', 'key_type': 'ecdsa', 'elliptic_curve': 'secp384r1'},
        )
        mgr = self._make_manager(tmp_path, storage)
        mgr.settings_manager.load_settings.return_value = {
            'domains': [{'domain': 'example.com', 'dns_provider': 'cloudflare'}],
        }

        results = mgr.hydrate_from_storage()
        assert results == {'example.com': 'restored'}
        domain_dir = mgr.cert_dir / 'example.com'
        assert (domain_dir / 'cert.pem').read_bytes() == b'-----CERT-----'
        assert (domain_dir / 'privkey.pem').read_bytes() == b'-----KEY-----'
        assert (domain_dir / 'metadata.json').exists()
        meta = json.loads((domain_dir / 'metadata.json').read_text())
        assert meta['key_type'] == 'ecdsa'

    def test_skips_domains_already_present_locally(self, tmp_path):
        storage = MagicMock()
        mgr = self._make_manager(tmp_path, storage)
        domain_dir = mgr.cert_dir / 'example.com'
        domain_dir.mkdir()
        (domain_dir / 'cert.pem').write_text('already here')
        mgr.settings_manager.load_settings.return_value = {
            'domains': [{'domain': 'example.com'}],
        }

        results = mgr.hydrate_from_storage()
        assert results == {'example.com': 'present'}
        # Storage was never queried — local copy wins.
        storage.retrieve_certificate.assert_not_called()
        # Local file untouched.
        assert (domain_dir / 'cert.pem').read_text() == 'already here'

    def test_marks_missing_when_backend_has_no_record(self, tmp_path):
        storage = MagicMock()
        storage.retrieve_certificate.return_value = None
        mgr = self._make_manager(tmp_path, storage)
        mgr.settings_manager.load_settings.return_value = {
            'domains': ['orphan.example.com'],  # legacy string form
        }

        results = mgr.hydrate_from_storage()
        assert results == {'orphan.example.com': 'missing'}
        # Did not write anything for an absent record.
        assert not (mgr.cert_dir / 'orphan.example.com').exists()

    def test_storage_error_does_not_block_other_domains(self, tmp_path):
        storage = MagicMock()
        storage.get_backend_name.return_value = 'azure_keyvault'

        def fake_retrieve(domain):
            if domain == 'broken.example.com':
                raise RuntimeError("Azure unreachable")
            return (
                {'cert.pem': b'-----CERT-----', 'privkey.pem': b'-----KEY-----'},
                {'domain': domain},
            )

        storage.retrieve_certificate.side_effect = fake_retrieve
        mgr = self._make_manager(tmp_path, storage)
        mgr.settings_manager.load_settings.return_value = {
            'domains': [
                {'domain': 'broken.example.com'},
                {'domain': 'good.example.com'},
            ],
        }

        results = mgr.hydrate_from_storage()
        assert results['broken.example.com'] == 'error'
        assert results['good.example.com'] == 'restored'
        # The good cert was still written.
        assert (mgr.cert_dir / 'good.example.com' / 'cert.pem').exists()

    def test_no_storage_manager_returns_empty(self, tmp_path):
        mgr = self._make_manager(tmp_path, storage_manager=None)
        assert mgr.hydrate_from_storage() == {}

    def test_privkey_chmod_0600(self, tmp_path):
        import stat
        storage = MagicMock()
        storage.get_backend_name.return_value = 'azure_keyvault'
        storage.retrieve_certificate.return_value = (
            {'cert.pem': b'-----CERT-----', 'privkey.pem': b'-----KEY-----'},
            {'domain': 'example.com'},
        )
        mgr = self._make_manager(tmp_path, storage)
        mgr.settings_manager.load_settings.return_value = {
            'domains': [{'domain': 'example.com'}],
        }
        mgr.hydrate_from_storage()
        privkey = mgr.cert_dir / 'example.com' / 'privkey.pem'
        # Owner-only read/write; nothing for group/other.
        mode = privkey.stat().st_mode & 0o777
        assert mode == 0o600


class TestRenewalFallbackToMetadata:
    """Renewal path when the certbot renewal/<domain>.conf is missing.

    The Docker/K8s ephemeral-filesystem case: the cert PEMs were
    rehydrated from a remote storage backend on pod startup, but the
    per-cert renewal conf certbot writes alongside them was not. Without
    the fix, ``certbot renew --cert-name`` would fail outright (or worse,
    silently regenerate with the wrong key shape). With the fix,
    ``renew_certificate`` detects the missing conf and rebuilds the cert
    from ``metadata.json`` (also synced to the storage backend), so the
    original key_type / key_size / SAN list / DNS plugin are preserved.
    """

    def _make_manager(self, tmp_path):
        from modules.core.certificates import CertificateManager
        mgr = CertificateManager.__new__(CertificateManager)
        mgr.cert_dir = tmp_path / 'certificates'
        mgr.cert_dir.mkdir(parents=True)
        mgr._domain_locks = {}
        mgr._domain_locks_mutex = MagicMock()
        mgr._domain_locks_mutex.__enter__ = lambda self_: None
        mgr._domain_locks_mutex.__exit__ = lambda self_, *a: None
        mgr.settings_manager = MagicMock()
        return mgr

    def test_missing_renewal_conf_triggers_metadata_rebuild(self, tmp_path):
        from threading import RLock
        from modules.core.certificates import CertificateManager

        mgr = self._make_manager(tmp_path)
        domain = 'example.com'
        domain_dir = mgr.cert_dir / domain
        domain_dir.mkdir()
        # cert.pem exists, renewal/<domain>.conf does NOT — the exact
        # state CertMate sees after restoring from a remote backend.
        (domain_dir / 'cert.pem').write_text('fake')
        (domain_dir / 'metadata.json').write_text(json.dumps({
            'domain': domain,
            'email': 'ops@example.com',
            'san_domains': ['www.example.com'],
            'dns_provider': 'cloudflare',
            'account_id': 'production',
            'ca_provider': 'letsencrypt',
            'staging': False,
            'key_type': 'ecdsa',
            'elliptic_curve': 'secp384r1',
            'key_size': None,
            'challenge_type': 'dns-01',
            'domain_alias': None,
        }))

        mgr.settings_manager.load_settings.return_value = {
            'email': 'ops@example.com',
            'dns_provider': 'cloudflare',
            'default_ca': 'letsencrypt',
            'domains': [{'domain': domain, 'dns_provider': 'cloudflare', 'dns_account_id': 'production'}],
        }
        # Lock so renew_certificate enters the body and we can trace the
        # call to create_certificate without spawning real concurrency.
        mgr._domain_locks[domain] = RLock()

        # create_certificate is the delegation target; replace with a
        # spy so we can assert the args (in particular the key shape and
        # force=True) match the metadata.
        mgr.create_certificate = MagicMock(return_value={'created_at': '2026-05-08T00:00:00'})

        result = mgr.renew_certificate(domain)

        mgr.create_certificate.assert_called_once()
        kwargs = mgr.create_certificate.call_args.kwargs
        assert kwargs['domain'] == domain
        assert kwargs['email'] == 'ops@example.com'
        assert kwargs['dns_provider'] == 'cloudflare'
        assert kwargs['account_id'] == 'production'
        assert kwargs['ca_provider'] == 'letsencrypt'
        assert kwargs['key_type'] == 'ecdsa'
        assert kwargs['elliptic_curve'] == 'secp384r1'
        assert kwargs['san_domains'] == ['www.example.com']
        assert kwargs['force'] is True

        assert result['rebuilt_from_metadata'] is True

    def test_missing_renewal_conf_with_no_metadata_uses_settings_fallback(self, tmp_path):
        """Worst case: filesystem fully wiped, even metadata.json is gone.

        Pull whatever still survives from settings (email, dns provider,
        per-domain entry) and let create_certificate fall back to the
        global default key shape. This keeps renewals from hard-failing
        the very first time after a fresh deploy with empty volume.
        """
        from threading import RLock

        mgr = self._make_manager(tmp_path)
        domain = 'orphan.example.com'
        domain_dir = mgr.cert_dir / domain
        domain_dir.mkdir()
        (domain_dir / 'cert.pem').write_text('fake')
        # Intentionally no metadata.json.

        mgr.settings_manager.load_settings.return_value = {
            'email': 'ops@example.com',
            'dns_provider': 'cloudflare',
            'default_ca': 'letsencrypt',
            'domains': [{
                'domain': domain,
                'dns_provider': 'route53',
                'dns_account_id': 'prod',
                'key_type': 'rsa',
                'key_size': 4096,
            }],
        }
        mgr._domain_locks[domain] = RLock()
        mgr.create_certificate = MagicMock(return_value={})

        mgr.renew_certificate(domain)
        kwargs = mgr.create_certificate.call_args.kwargs
        assert kwargs['dns_provider'] == 'route53'
        assert kwargs['account_id'] == 'prod'
        assert kwargs['key_type'] == 'rsa'
        assert kwargs['key_size'] == 4096
        assert kwargs['force'] is True

    def test_no_metadata_no_email_anywhere_raises(self, tmp_path):
        from threading import RLock

        mgr = self._make_manager(tmp_path)
        domain = 'lost.example.com'
        domain_dir = mgr.cert_dir / domain
        domain_dir.mkdir()
        (domain_dir / 'cert.pem').write_text('fake')

        mgr.settings_manager.load_settings.return_value = {'domains': []}
        mgr._domain_locks[domain] = RLock()

        with pytest.raises(RuntimeError, match='Cannot renew'):
            mgr.renew_certificate(domain)


class TestDomainEntryPersistence:
    """``build_domain_entry`` is the helper the create-cert endpoint uses
    to compose the per-domain settings entry. It exists as a separate
    function so the "persist only explicit overrides" rule can be pinned
    by tests without spinning up Flask.
    """

    def test_inheritor_entry_has_no_key_fields(self):
        from modules.core.utils import build_domain_entry
        entry = build_domain_entry(
            domain='example.com',
            dns_provider='cloudflare',
            dns_account_id='production',
        )
        assert entry == {
            'domain': 'example.com',
            'dns_provider': 'cloudflare',
            'dns_account_id': 'production',
        }
        for k in ('key_type', 'key_size', 'elliptic_curve'):
            assert k not in entry

    def test_rsa_override_persists_only_type_and_size(self):
        from modules.core.utils import build_domain_entry
        entry = build_domain_entry(
            domain='example.com',
            dns_provider='cloudflare',
            dns_account_id='production',
            key_type='rsa', key_size=4096, elliptic_curve=None,
        )
        assert entry['key_type'] == 'rsa'
        assert entry['key_size'] == 4096
        assert 'elliptic_curve' not in entry

    def test_ecdsa_override_persists_only_type_and_curve(self):
        from modules.core.utils import build_domain_entry
        entry = build_domain_entry(
            domain='example.com',
            dns_provider='cloudflare',
            dns_account_id='production',
            key_type='ecdsa', key_size=None, elliptic_curve='secp384r1',
        )
        assert entry['key_type'] == 'ecdsa'
        assert entry['elliptic_curve'] == 'secp384r1'
        assert 'key_size' not in entry


class TestEndpointPayloadValidation:
    """The CreateCertificate endpoint runs ``validate_key_options`` on the
    payload before invoking the certificate manager so the caller gets a
    clean 400 (with the specific reason) instead of a 500 from certbot.
    These tests pin the contract via the validator alone — the endpoint
    is otherwise plumbing — but they document the matrix the API must
    reject end-to-end.
    """

    @pytest.mark.parametrize("payload,reason_keyword", [
        ({'key_type': 'rsa', 'key_size': 1024}, 'key_size'),
        ({'key_type': 'rsa', 'key_size': 2048, 'elliptic_curve': 'secp256r1'}, 'elliptic_curve'),
        ({'key_type': 'ecdsa', 'key_size': 4096}, 'key_size'),
        ({'key_type': 'ecdsa', 'elliptic_curve': 'secp521r1'}, 'elliptic_curve'),
        ({'key_type': 'dsa', 'key_size': 2048}, 'key_type'),
        ({'key_size': 4096}, 'key_type'),  # size without type
    ])
    def test_invalid_payload_rejected_with_specific_reason(self, payload, reason_keyword):
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options(
            payload.get('key_type'),
            payload.get('key_size'),
            payload.get('elliptic_curve'),
        )
        assert not ok
        assert reason_keyword in err

    def test_payload_without_any_key_fields_passes(self):
        """The endpoint only calls validate_key_options when at least one
        of the three fields is present. A completely absent triple must
        not be a 400; the cert gets the global default."""
        from modules.core.utils import validate_key_options
        ok, err = validate_key_options(None, None, None)
        assert ok and err == ''


class TestCorruptMetadataInRebuildPath:
    """``_renew_from_metadata`` must keep working when ``metadata.json``
    is unparseable — falls back to the per-domain settings entry rather
    than letting a json.JSONDecodeError propagate to the caller.
    """

    def test_corrupt_metadata_falls_back_to_settings(self, tmp_path):
        from threading import RLock
        from modules.core.certificates import CertificateManager

        mgr = CertificateManager.__new__(CertificateManager)
        mgr.cert_dir = tmp_path / 'certificates'
        mgr.cert_dir.mkdir(parents=True)
        mgr._domain_locks = {}
        mgr._domain_locks_mutex = MagicMock()
        mgr._domain_locks_mutex.__enter__ = lambda self_: None
        mgr._domain_locks_mutex.__exit__ = lambda self_, *a: None
        mgr.settings_manager = MagicMock()

        domain = 'example.com'
        domain_dir = mgr.cert_dir / domain
        domain_dir.mkdir()
        (domain_dir / 'cert.pem').write_text('fake')
        # Garbage that json.load will choke on.
        (domain_dir / 'metadata.json').write_text('{this is not valid json...')

        mgr.settings_manager.load_settings.return_value = {
            'email': 'ops@example.com',
            'dns_provider': 'cloudflare',
            'default_ca': 'letsencrypt',
            'domains': [{
                'domain': domain,
                'dns_provider': 'cloudflare',
                'dns_account_id': 'production',
                'key_type': 'rsa',
                'key_size': 4096,
            }],
        }
        mgr._domain_locks[domain] = RLock()
        mgr.create_certificate = MagicMock(return_value={})

        # Should not raise even though metadata.json is malformed.
        mgr.renew_certificate(domain)

        kwargs = mgr.create_certificate.call_args.kwargs
        # Settings-fallback supplied the values that metadata couldn't.
        assert kwargs['key_type'] == 'rsa'
        assert kwargs['key_size'] == 4096
        assert kwargs['dns_provider'] == 'cloudflare'
        assert kwargs['account_id'] == 'production'


class TestSettingsKeyDefaultsMigration:
    def test_legacy_settings_get_rsa_2048_defaults(self, tmp_path):
        from modules.core.file_operations import FileOperations
        from modules.core.settings import SettingsManager

        cert_dir = tmp_path / 'certificates'
        data_dir = tmp_path / 'data'
        backup_dir = tmp_path / 'backups'
        logs_dir = tmp_path / 'logs'
        for d in (cert_dir, data_dir, backup_dir, logs_dir):
            d.mkdir()

        # Pre-feature settings.json: no default_key_* keys at all.
        legacy = {
            'domains': [],
            'email': 'ops@example.com',
            'auto_renew': True,
            'renewal_threshold_days': 30,
            'api_bearer_token_hash': 'placeholder',
            'setup_completed': True,
            'dns_provider': 'cloudflare',
            'challenge_type': 'dns-01',
            'dns_providers': {},
        }
        settings_file = data_dir / 'settings.json'
        settings_file.write_text(json.dumps(legacy))

        file_ops = FileOperations(
            cert_dir=cert_dir, data_dir=data_dir,
            backup_dir=backup_dir, logs_dir=logs_dir,
        )
        sm = SettingsManager(file_ops=file_ops, settings_file=settings_file)
        loaded = sm.load_settings()

        assert loaded['default_key_type'] == 'rsa'
        assert loaded['default_key_size'] == 2048
        assert loaded['default_elliptic_curve'] == 'secp256r1'

    def test_save_settings_rejects_inconsistent_global_defaults(self, tmp_path):
        """save_settings must reject ``key_type='rsa'`` paired with an
        elliptic_curve override on the global defaults — otherwise a UI bug
        could silently persist a contradiction the renew loop would later
        choke on."""
        from modules.core.file_operations import FileOperations
        from modules.core.settings import SettingsManager

        cert_dir = tmp_path / 'certificates'
        data_dir = tmp_path / 'data'
        backup_dir = tmp_path / 'backups'
        logs_dir = tmp_path / 'logs'
        for d in (cert_dir, data_dir, backup_dir, logs_dir):
            d.mkdir()

        file_ops = FileOperations(
            cert_dir=cert_dir, data_dir=data_dir,
            backup_dir=backup_dir, logs_dir=logs_dir,
        )
        sm = SettingsManager(file_ops=file_ops, settings_file=data_dir / 'settings.json')

        ok = sm.save_settings({
            'email': 'ops@example.com',
            'dns_provider': 'cloudflare',
            'api_bearer_token_hash': 'placeholder',
            'default_key_type': 'rsa',
            'default_key_size': 1024,  # rejected by validate_key_options
            'default_elliptic_curve': 'secp256r1',
        })
        assert ok is False
