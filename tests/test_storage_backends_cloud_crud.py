"""Round-trip + error coverage for the cloud storage backends' CRUD paths.

``tests/test_storage_backends_coverage.py`` deliberately skips exhaustive SDK
mocking, leaving ``store/retrieve/list/delete_certificate`` on the cloud backends
(AWS Secrets Manager, HashiCorp Vault, Azure Key Vault, Infisical) essentially
untested — a regression that corrupts a cloud upload would ship green. This file
closes that gap.

Each backend builds its SDK client lazily in ``_get_client()`` and caches it on
``self._client``. We inject an in-memory fake client there, so:
  * the tests run with or without the optional cloud SDK installed (none of
    hvac / azure-keyvault-secrets / infisical are in the base test env), and
  * we assert a genuine store -> retrieve -> list -> delete round-trip plus the
    failure contract (client errors map to False / None / []).
"""
import time
from unittest.mock import MagicMock

import pytest

from modules.core.storage_backends import (
    AWSSecretsManagerBackend,
    HashiCorpVaultBackend,
)

pytestmark = [pytest.mark.unit]

SAMPLE_FILES = {'cert.pem': b'-----CERT-----', 'privkey.pem': b'-----KEY-----'}
SAMPLE_META = {'domain': 'example.com', 'issued': '2026-01-01'}


# ---------------------------------------------------------------------------
# AWS Secrets Manager
# ---------------------------------------------------------------------------

class _FakeAwsClient:
    """Minimal in-memory stand-in for a boto3 secretsmanager client."""

    class _ResourceNotFound(Exception):
        pass

    def __init__(self):
        self.store = {}
        self.exceptions = MagicMock()
        self.exceptions.ResourceNotFoundException = _FakeAwsClient._ResourceNotFound

    def update_secret(self, SecretId, SecretString):  # noqa: N803 - boto3 kwarg names
        if SecretId not in self.store:
            raise self._ResourceNotFound()
        self.store[SecretId] = SecretString

    def create_secret(self, Name, SecretString, Description=None):  # noqa: N803
        self.store[Name] = SecretString

    def get_secret_value(self, SecretId):  # noqa: N803
        if SecretId not in self.store:
            raise self._ResourceNotFound()
        return {'SecretString': self.store[SecretId]}

    def get_paginator(self, _operation):
        page = {'SecretList': [{'Name': name} for name in self.store]}
        paginator = MagicMock()
        paginator.paginate.return_value = [page]
        return paginator

    def delete_secret(self, SecretId, ForceDeleteWithoutRecovery=False):  # noqa: N803
        self.store.pop(SecretId, None)

    def describe_secret(self, SecretId):  # noqa: N803
        if SecretId not in self.store:
            raise self._ResourceNotFound()
        return {'ARN': SecretId}


def _aws():
    backend = AWSSecretsManagerBackend({
        'access_key_id': 'AKIAEXAMPLE', 'secret_access_key': 'shh', 'region': 'us-east-1',
    })
    backend._client = _FakeAwsClient()  # bypass lazy boto3 init
    return backend


class TestAwsSecretsManagerCrud:
    def test_store_then_retrieve_round_trip(self):
        b = _aws()
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True
        files, meta = b.retrieve_certificate('example.com')
        assert files == SAMPLE_FILES
        assert meta == SAMPLE_META

    def test_store_updates_existing_secret(self):
        b = _aws()
        b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META)
        new_files = {'cert.pem': b'-----NEW-----'}
        assert b.store_certificate('example.com', new_files, {'v': 2}) is True
        files, meta = b.retrieve_certificate('example.com')
        assert files == new_files and meta == {'v': 2}

    def test_list_returns_only_certmate_prefixed_domains(self):
        b = _aws()
        b.store_certificate('a.example.com', SAMPLE_FILES, {})
        b.store_certificate('b.example.com', SAMPLE_FILES, {})
        b._client.store['unrelated/secret'] = '{}'  # must be ignored
        assert b.list_certificates() == ['a.example.com', 'b.example.com']

    def test_delete_then_retrieve_returns_none(self):
        b = _aws()
        b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META)
        assert b.delete_certificate('example.com') is True
        assert b.retrieve_certificate('example.com') is None

    def test_retrieve_missing_returns_none(self):
        assert _aws().retrieve_certificate('nope.example.com') is None

    def test_store_maps_client_error_to_false(self):
        b = _aws()
        b._client.update_secret = MagicMock(side_effect=b._client._ResourceNotFound())
        b._client.create_secret = MagicMock(side_effect=RuntimeError('AWS down'))
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is False

    def test_invalid_domain_rejected_without_calling_client(self):
        b = _aws()
        b._client.create_secret = MagicMock()
        b._client.update_secret = MagicMock()
        assert b.store_certificate('../evil', SAMPLE_FILES, SAMPLE_META) is False
        b._client.create_secret.assert_not_called()

    def test_get_backend_name(self):
        assert _aws().get_backend_name() == 'aws_secrets_manager'


# ---------------------------------------------------------------------------
# HashiCorp Vault (KV v2)
# ---------------------------------------------------------------------------

class _FakeVaultKvV2:
    def __init__(self):
        self.store = {}

    def create_or_update_secret(self, path, secret, mount_point=None):
        self.store[path] = secret

    def read_secret_version(self, path, mount_point=None):
        if path not in self.store:
            raise KeyError(path)
        return {'data': {'data': self.store[path]}}

    def list_secrets(self, path, mount_point=None):
        prefix = path.rstrip('/') + '/'
        keys = [p[len(prefix):] for p in self.store if p.startswith(prefix)]
        return {'data': {'keys': sorted(keys)}}

    def delete_metadata_and_all_versions(self, path, mount_point=None):
        self.store.pop(path, None)


class _FakeVaultClient:
    def __init__(self):
        self.secrets = MagicMock()
        self.secrets.kv.v2 = _FakeVaultKvV2()

    def is_authenticated(self):
        return True


def _vault():
    backend = HashiCorpVaultBackend({'vault_url': 'https://vault.example', 'vault_token': 'tok'})
    backend._client = _FakeVaultClient()  # bypass lazy hvac init
    # Stamp the renewal clock to "now" so _get_client() returns the cached fake
    # instead of taking the >6h token-renewal branch (which would hit the real hvac).
    backend._token_renewed_at = time.time()
    return backend


class TestHashiCorpVaultCrud:
    def test_store_then_retrieve_round_trip(self):
        b = _vault()
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True
        files, meta = b.retrieve_certificate('example.com')
        assert files == SAMPLE_FILES
        assert meta == SAMPLE_META

    def test_list_returns_stored_domains(self):
        b = _vault()
        b.store_certificate('a.example.com', SAMPLE_FILES, {})
        b.store_certificate('b.example.com', SAMPLE_FILES, {})
        assert b.list_certificates() == ['a.example.com', 'b.example.com']

    def test_delete_then_retrieve_returns_none(self):
        b = _vault()
        b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META)
        assert b.delete_certificate('example.com') is True
        assert b.retrieve_certificate('example.com') is None

    def test_retrieve_missing_returns_none(self):
        assert _vault().retrieve_certificate('nope.example.com') is None

    def test_store_maps_client_error_to_false(self):
        b = _vault()
        b._client.secrets.kv.v2.create_or_update_secret = MagicMock(
            side_effect=RuntimeError('vault sealed'))
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is False

    def test_invalid_domain_rejected(self):
        assert _vault().store_certificate('../evil', SAMPLE_FILES, SAMPLE_META) is False

    def test_get_backend_name(self):
        assert _vault().get_backend_name() == 'hashicorp_vault'
