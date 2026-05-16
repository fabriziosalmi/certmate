"""
Coverage-focused unit tests for modules/core/storage_backends.

The module was at ~25% coverage — the LocalFileSystemBackend was partially
exercised by other tests, but the retry machinery, transient-error
heuristic, domain validation, Azure-secret-name sanitisation, and the
StorageManager dispatch logic were all unverified. The cloud backends
themselves (Azure KV, AWS Secrets Manager, Vault, Infisical) wrap SDKs
that need network — exhaustive mocking of each SDK adds maintenance debt
without proving the CertMate-layer logic. We focus instead on:

  - the cross-cutting helpers (_is_transient, _with_retry,
    _validate_storage_domain) where a regression silently breaks every
    backend's failure handling
  - LocalFileSystemBackend's full lifecycle (the only backend that ships
    by default and the fallback every cloud-backend init failure lands on)
  - Azure secret-name sanitisation (collision avoidance is security-
    critical: two distinct domains mapping to the same Azure secret name
    would let one cert overwrite another)
  - StorageManager factory dispatch + the fallback path when
    backend_type is unknown or a cloud backend init raises
"""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from modules.core.storage_backends import (
    _is_transient,
    _with_retry,
    _validate_storage_domain,
    LocalFileSystemBackend,
    AzureKeyVaultBackend,
    AWSSecretsManagerBackend,
    HashiCorpVaultBackend,
    InfisicalBackend,
    StorageManager,
)


pytestmark = [pytest.mark.unit]


# ---------------------------------------------------------------------------
# _is_transient — the heuristic that decides whether _with_retry sleeps and
# retries vs. fails fast. Wrong answer here = either swallowing real errors
# behind retries OR failing fast on a temporary blip.
# ---------------------------------------------------------------------------


class TestIsTransient:
    def test_429_rate_limit_is_transient(self):
        exc = type('Err', (Exception,), {'status_code': 429})()
        assert _is_transient(exc) is True

    @pytest.mark.parametrize("code", [500, 502, 503, 504])
    def test_5xx_is_transient(self, code):
        exc = type('Err', (Exception,), {'status_code': code})()
        assert _is_transient(exc) is True

    def test_401_unauthorized_is_not_transient(self):
        """401 from a backend means stale credentials — retrying won't help
        and just delays the error. Must NOT be marked transient."""
        exc = type('Err', (Exception,), {'status_code': 401})()
        assert _is_transient(exc) is False

    def test_400_bad_request_is_not_transient(self):
        exc = type('Err', (Exception,), {'status_code': 400})()
        assert _is_transient(exc) is False

    def test_boto3_response_metadata_5xx_is_transient(self):
        """boto3 wraps the HTTP code inside response['ResponseMetadata']."""
        exc = Exception("aws err")
        exc.response = {'ResponseMetadata': {'HTTPStatusCode': 503}}
        assert _is_transient(exc) is True

    @pytest.mark.parametrize("msg", [
        "Request timeout",
        "Rate limit exceeded",
        "Connection refused",
        "Throttled by upstream",
        "503 Service Unavailable",
    ])
    def test_message_keyword_match_marks_transient(self, msg):
        """Fallback when the exception carries no status_code: substring
        match on the message."""
        assert _is_transient(Exception(msg)) is True

    def test_plain_error_message_is_not_transient(self):
        assert _is_transient(Exception("Domain not found")) is False


# ---------------------------------------------------------------------------
# _with_retry decorator — the only thing standing between a transient blip
# and a renewal-cycle outage. Tested without sleeping by setting delay=0.
# ---------------------------------------------------------------------------


class TestWithRetry:
    def test_success_on_first_attempt_returns_value(self):
        calls = []

        @_with_retry(max_attempts=3, delay=0)
        def fn():
            calls.append(1)
            return "ok"

        assert fn() == "ok"
        assert len(calls) == 1

    def test_retries_on_transient_error_then_succeeds(self):
        calls = []

        @_with_retry(max_attempts=3, delay=0)
        def fn():
            calls.append(1)
            if len(calls) < 3:
                raise Exception("timeout")  # _is_transient via keyword
            return "recovered"

        assert fn() == "recovered"
        assert len(calls) == 3

    def test_does_not_retry_non_transient_error(self):
        """A non-transient error must bubble up on first attempt — no
        sleep, no retry. Critical for surfacing config errors fast."""
        calls = []

        @_with_retry(max_attempts=3, delay=0)
        def fn():
            calls.append(1)
            raise ValueError("Domain not found")

        with pytest.raises(ValueError, match="Domain not found"):
            fn()
        assert len(calls) == 1, "must NOT retry non-transient errors"

    def test_raises_last_exception_after_max_attempts(self):
        """All N attempts transient — the final exception propagates."""
        @_with_retry(max_attempts=3, delay=0)
        def fn():
            raise Exception("timeout")

        with pytest.raises(Exception, match="timeout"):
            fn()


# ---------------------------------------------------------------------------
# _validate_storage_domain — every cloud backend funnels through this
# before producing storage paths. Path-traversal here = silent overwrite
# of another tenant's cert.
# ---------------------------------------------------------------------------


class TestValidateStorageDomain:
    @pytest.mark.parametrize("good", [
        "example.com",
        "sub.example.com",
        "deep.sub.example.com",
        "host-with-dashes.example.com",
        "x12345.com",
    ])
    def test_valid_domains_pass(self, good):
        assert _validate_storage_domain(good) == good

    @pytest.mark.parametrize("evil", [
        "",
        "../etc/passwd",
        "domain/../other",
        "a/b",
        "a\\b",
        "domain\x00null",
        "not a domain",   # space — disallowed
        "domain.com/extra",  # path injection attempt
    ])
    def test_path_traversal_and_garbage_rejected(self, evil):
        with pytest.raises(ValueError):
            _validate_storage_domain(evil)


# ---------------------------------------------------------------------------
# LocalFileSystemBackend — the default and fallback. Full lifecycle.
# ---------------------------------------------------------------------------


class TestLocalFileSystemBackend:
    @pytest.fixture
    def backend(self, tmp_path):
        return LocalFileSystemBackend(cert_dir=tmp_path / "certs")

    @pytest.fixture
    def sample_cert(self):
        return {
            'cert.pem': b'-----BEGIN CERTIFICATE-----\nfake\n',
            'privkey.pem': b'-----BEGIN PRIVATE KEY-----\nfake\n',
            'fullchain.pem': b'-----BEGIN CERTIFICATE-----\nfake-chain\n',
        }, {'dns_provider': 'cloudflare', 'issued_at': '2026-05-15'}

    def test_store_then_retrieve_round_trip(self, backend, sample_cert):
        files, meta = sample_cert
        assert backend.store_certificate('example.com', files, meta) is True
        result = backend.retrieve_certificate('example.com')
        assert result is not None
        out_files, out_meta = result
        assert out_files['cert.pem'] == files['cert.pem']
        assert out_files['privkey.pem'] == files['privkey.pem']
        assert out_meta == meta

    @pytest.mark.skipif(os.name == "nt", reason="POSIX-only permission check")
    def test_stored_privkey_is_0600(self, backend, sample_cert):
        files, meta = sample_cert
        backend.store_certificate('example.com', files, meta)
        key_path = backend.cert_dir / 'example.com' / 'privkey.pem'
        mode = stat.S_IMODE(os.stat(key_path).st_mode)
        assert mode == 0o600, (
            f"private key file must be 0o600 — group/other read access would "
            f"leak the private key to non-root users on the host. Got {oct(mode)}"
        )

    @pytest.mark.skipif(os.name == "nt", reason="POSIX-only permission check")
    def test_stored_metadata_is_0600(self, backend, sample_cert):
        files, meta = sample_cert
        backend.store_certificate('example.com', files, meta)
        meta_path = backend.cert_dir / 'example.com' / 'metadata.json'
        mode = stat.S_IMODE(os.stat(meta_path).st_mode)
        assert mode == 0o600

    def test_retrieve_missing_returns_none(self, backend):
        assert backend.retrieve_certificate('nonexistent.example.com') is None

    def test_list_returns_only_dirs_with_cert(self, backend, sample_cert, tmp_path):
        files, meta = sample_cert
        backend.store_certificate('a.example.com', files, meta)
        backend.store_certificate('b.example.com', files, meta)
        # And an empty domain dir (no cert.pem inside) — must NOT surface.
        (backend.cert_dir / 'empty.example.com').mkdir()
        result = backend.list_certificates()
        assert result == ['a.example.com', 'b.example.com']

    def test_list_returns_empty_when_no_certs(self, backend):
        assert backend.list_certificates() == []

    def test_delete_removes_domain_tree(self, backend, sample_cert):
        files, meta = sample_cert
        backend.store_certificate('toremove.example.com', files, meta)
        assert backend.certificate_exists('toremove.example.com') is True
        assert backend.delete_certificate('toremove.example.com') is True
        assert backend.certificate_exists('toremove.example.com') is False
        assert not (backend.cert_dir / 'toremove.example.com').exists()

    def test_delete_missing_returns_false(self, backend):
        assert backend.delete_certificate('nope.example.com') is False

    def test_get_backend_name(self, backend):
        assert backend.get_backend_name() == 'local_filesystem'


# ---------------------------------------------------------------------------
# Azure Key Vault secret-name sanitisation — collision avoidance.
# Two distinct domains that sanitize to the same name would let one cert
# silently overwrite another in Key Vault.
# ---------------------------------------------------------------------------


class TestAzureSecretNameSanitisation:
    @pytest.fixture
    def backend(self):
        """Build an Azure backend with stub config so the sanitiser is
        usable without triggering a real Azure connection."""
        return AzureKeyVaultBackend({
            'vault_url': 'https://stub.vault.azure.net/',
            'client_id': 'cid', 'client_secret': 'cs', 'tenant_id': 'tid',
        })

    def test_sanitised_name_uses_only_allowed_chars(self, backend):
        result = backend._sanitize_secret_name('cert-my.app.example.com-cert-pem')
        # Azure secret names: a-z, A-Z, 0-9, dash only.
        import re
        assert re.match(r'^[a-zA-Z0-9-]+$', result), (
            f"sanitised name must contain only Azure-allowed chars; got {result!r}"
        )

    def test_distinct_inputs_produce_distinct_outputs(self, backend):
        """The CRC32 suffix is the load-bearing collision guard. Two
        domain spellings that look the same after dot-to-dash replacement
        MUST still produce distinct sanitised names — otherwise issuing a
        cert for the second one overwrites the first in Key Vault."""
        a = backend._sanitize_secret_name('cert-my-app.example.com')
        b = backend._sanitize_secret_name('cert-my.app-example.com')
        assert a != b, (
            "two domains that differ only in dot-vs-dash placement must "
            f"produce different Azure secret names; got identical: {a}"
        )

    def test_sanitised_name_within_azure_length_limit(self, backend):
        """Azure enforces a 127-character cap."""
        long_name = 'cert-' + ('x' * 200) + '.example.com'
        result = backend._sanitize_secret_name(long_name)
        assert len(result) <= 127

    def test_sanitised_name_is_deterministic(self, backend):
        """Same input → same output. The CRC32 must not include any
        non-deterministic source (e.g. timestamps, random)."""
        a = backend._sanitize_secret_name('cert-domain.com')
        b = backend._sanitize_secret_name('cert-domain.com')
        assert a == b


# ---------------------------------------------------------------------------
# Cloud-backend constructors — config validation. All four cloud backends
# reject empty/missing required fields with ValueError so misconfiguration
# fails fast instead of producing a half-initialised client.
# ---------------------------------------------------------------------------


class TestCloudBackendConstructorValidation:
    @pytest.mark.parametrize("missing", ['vault_url', 'client_id', 'client_secret', 'tenant_id'])
    def test_azure_missing_field_raises(self, missing):
        config = {
            'vault_url': 'https://x.vault.azure.net/',
            'client_id': 'a', 'client_secret': 'b', 'tenant_id': 'c',
        }
        config[missing] = ''
        with pytest.raises(ValueError, match="vault_url|client_id|client_secret|tenant_id"):
            AzureKeyVaultBackend(config)

    def test_aws_missing_credentials_raise(self):
        """AWS requires access_key_id + secret_access_key. Empty region
        is fine (it defaults to us-east-1); empty credentials are not."""
        with pytest.raises(ValueError, match="access_key_id|secret_access_key"):
            AWSSecretsManagerBackend({'region': 'us-east-1',
                                       'access_key_id': '', 'secret_access_key': 'b'})
        with pytest.raises(ValueError, match="access_key_id|secret_access_key"):
            AWSSecretsManagerBackend({'region': 'us-east-1',
                                       'access_key_id': 'a', 'secret_access_key': ''})

    def test_hashicorp_missing_url_or_token_raises(self):
        with pytest.raises(ValueError):
            HashiCorpVaultBackend({'vault_url': '', 'vault_token': 't'})
        with pytest.raises(ValueError):
            HashiCorpVaultBackend({'vault_url': 'https://x', 'vault_token': ''})

    def test_infisical_missing_client_id_raises(self):
        with pytest.raises(ValueError):
            InfisicalBackend({
                'site_url': 'https://x',
                'client_id': '', 'client_secret': 'b', 'project_id': 'p',
                'environment': 'prod',
            })


# ---------------------------------------------------------------------------
# StorageManager factory — picks the right backend by settings.
# ---------------------------------------------------------------------------


class TestStorageManagerDispatch:
    def _settings_mgr(self, storage_config):
        sm = MagicMock()
        sm.load_settings.return_value = {'certificate_storage': storage_config}
        return sm

    def test_dispatches_local_filesystem_default(self, tmp_path):
        sm = self._settings_mgr({'backend': 'local_filesystem',
                                  'cert_dir': str(tmp_path / 'certs')})
        mgr = StorageManager(sm)
        assert isinstance(mgr.get_backend(), LocalFileSystemBackend)
        assert mgr.get_backend_name() == 'local_filesystem'

    def test_dispatches_azure_keyvault(self):
        sm = self._settings_mgr({
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': 'https://x.vault.azure.net/',
                'client_id': 'c', 'client_secret': 's', 'tenant_id': 't',
            },
        })
        mgr = StorageManager(sm)
        assert isinstance(mgr.get_backend(), AzureKeyVaultBackend)

    def test_unknown_backend_falls_back_to_local(self):
        """An unknown backend string must NOT crash — fall back to local
        filesystem and log. Production safety: a typo in settings doesn't
        take the renewal job offline."""
        sm = self._settings_mgr({'backend': 'mongodb_or_something_weird'})
        mgr = StorageManager(sm)
        assert isinstance(mgr.get_backend(), LocalFileSystemBackend)

    def test_failed_cloud_backend_init_falls_back_to_local(self):
        """Misconfigured cloud backend (e.g. empty vault_url) must NOT crash
        — log the error, fall back to local. The renewal job is more
        valuable than the storage choice."""
        sm = self._settings_mgr({
            'backend': 'azure_keyvault',
            'azure_keyvault': {
                'vault_url': '', 'client_id': '', 'client_secret': '', 'tenant_id': '',
            },
        })
        mgr = StorageManager(sm)
        assert isinstance(mgr.get_backend(), LocalFileSystemBackend)

    def test_initialization_is_lazy_and_idempotent(self, tmp_path):
        """get_backend must not hit the disk / cloud on construction —
        only on first call. And subsequent calls must return the same
        instance (no re-init)."""
        sm = self._settings_mgr({'backend': 'local_filesystem',
                                  'cert_dir': str(tmp_path / 'certs')})
        mgr = StorageManager(sm)
        sm.load_settings.assert_not_called()  # not called in __init__
        first = mgr.get_backend()
        sm.load_settings.assert_called_once()  # only on first get_backend
        second = mgr.get_backend()
        assert first is second  # same instance
        sm.load_settings.assert_called_once()  # still only once


if __name__ == "__main__":  # pragma: no cover
    pytest.main([__file__, "-v"])
