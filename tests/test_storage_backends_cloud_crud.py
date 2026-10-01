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
import types
from unittest.mock import MagicMock

import pytest

from modules.core.storage_backends import (
    AWSSecretsManagerBackend,
    AzureKeyVaultBackend,
    HashiCorpVaultBackend,
    InfisicalBackend,
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


# ---------------------------------------------------------------------------
# Infisical
# ---------------------------------------------------------------------------

from tests.infisical_sdk_stub import FakeInfisicalClient  # noqa: E402


def _infisical(sdk):
    backend = InfisicalBackend({
        'client_id': 'cid', 'client_secret': 'csecret', 'project_id': 'proj',
    })
    backend._client = FakeInfisicalClient(sdk)  # bypass the lazy SDK client; the options come from the stub module
    return backend


class TestInfisicalCrud:
    def test_store_then_retrieve_round_trip(self, infisical_sdk):
        b = _infisical(infisical_sdk)
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True
        files, meta = b.retrieve_certificate('example.com')
        assert files == SAMPLE_FILES
        assert meta == SAMPLE_META

    def test_list_reads_domain_from_metadata(self, infisical_sdk):
        b = _infisical(infisical_sdk)
        b.store_certificate('a.example.com', SAMPLE_FILES, {'domain': 'a.example.com'})
        b.store_certificate('b.example.com', SAMPLE_FILES, {'domain': 'b.example.com'})
        assert b.list_certificates() == ['a.example.com', 'b.example.com']

    def test_delete_then_retrieve_returns_none(self, infisical_sdk):
        b = _infisical(infisical_sdk)
        b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META)
        assert b.delete_certificate('example.com') is True
        assert b.retrieve_certificate('example.com') is None

    def test_retrieve_missing_returns_none(self, infisical_sdk):
        assert _infisical(infisical_sdk).retrieve_certificate('nope.example.com') is None

    def test_store_maps_client_error_to_false(self, infisical_sdk):
        b = _infisical(infisical_sdk)
        b._client.updateSecret = MagicMock(side_effect=Exception("Secret with name 'x' not found."))
        b._client.createSecret = MagicMock(side_effect=RuntimeError('infisical down'))
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is False

    def test_invalid_domain_rejected(self, infisical_sdk):
        assert _infisical(infisical_sdk).store_certificate('../evil', SAMPLE_FILES, SAMPLE_META) is False

    def test_get_backend_name(self, infisical_sdk):
        assert _infisical(infisical_sdk).get_backend_name() == 'infisical'


class _UpdateThatFails(FakeInfisicalClient):
    """A client whose first `fail_times` updates raise `error`, then behave."""

    def __init__(self, sdk, store, fail_times, error):
        super().__init__(sdk)
        self.store = dict(store)
        self.fail_times, self.error, self.update_calls = fail_times, error, 0

    def updateSecret(self, options):
        self.update_calls += 1
        if self.update_calls <= self.fail_times:
            raise self.error
        return super().updateSecret(options)


def _sleeps(monkeypatch):
    """The retry layer waits between attempts; record it instead of waiting."""
    waited = []
    monkeypatch.setattr('time.sleep', waited.append)
    return waited


class TestInfisicalUpsert:
    def test_a_transient_update_failure_on_an_existing_secret_is_retried(self, infisical_sdk, monkeypatch):
        """The update fails for a reason that passes; the create then says 'already exists', which is
        permanent. That must not bury the retryable error: the write is retried and lands."""
        waited = _sleeps(monkeypatch)
        b = _infisical(infisical_sdk)
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True      # the secrets exist now
        b._client = _UpdateThatFails(infisical_sdk, b._client.store, 1, Exception('rate limit exceeded (429)'))

        renewed = dict(SAMPLE_FILES, **{'cert.pem': b'RENEWED'})
        assert b.store_certificate('example.com', renewed, SAMPLE_META) is True
        assert waited, 'the failed attempt was not retried'
        assert b.retrieve_certificate('example.com')[0]['cert.pem'] == b'RENEWED'

    def test_a_domain_whose_name_looks_like_a_rate_limit_still_gets_its_first_write(self, infisical_sdk, monkeypatch):
        """`_is_transient` reads keywords out of the message and a not-found message contains the secret's
        name: for corporate.example.com it looks like a rate limit. Raising on that before trying the
        create would make this domain's first write fail forever."""
        waited = _sleeps(monkeypatch)
        b = _infisical(infisical_sdk)
        assert b.store_certificate('corporate.example.com', SAMPLE_FILES, {'domain': 'corporate.example.com'}) is True
        assert waited == [], 'a plain not-found was treated as transient and retried'
        assert b.retrieve_certificate('corporate.example.com') is not None

    def test_a_permanent_failure_is_not_retried(self, infisical_sdk, monkeypatch):
        waited = _sleeps(monkeypatch)
        b = _infisical(infisical_sdk)
        b._client.updateSecret = MagicMock(side_effect=Exception('forbidden'))
        b._client.createSecret = MagicMock(side_effect=Exception('denied by policy'))
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is False
        assert waited == [] and b._client.createSecret.call_count == 1


@pytest.mark.parametrize('site_url', [
    'https://app.infisical.com',
    'https://infisical.internal:8443',
    'http://localhost:8080',                # nobody stands between a process and itself
    'http://127.0.0.1:18080',
    'http://[::1]:8080',
    None, '',                               # unset: the default, which is https
])
def test_infisical_accepts_an_https_site_or_a_loopback_one(site_url):
    InfisicalBackend({'client_id': 'c', 'client_secret': 's', 'project_id': 'p', 'site_url': site_url})


@pytest.mark.parametrize('site_url', [
    'http://app.infisical.com',             # plain HTTP: anyone on the path can answer, and the SDK follows a redirect with the body
    'http://10.0.0.5:8080',
    'http://localhost.evil.example',        # a name that merely starts like localhost
    'http://127.0.0.1.evil.example',
    'ftp://infisical.internal',
    'app.infisical.com',                    # no scheme
    'https://',                             # no host
])
def test_infisical_refuses_a_site_that_is_not_https_unless_it_is_loopback(site_url):
    with pytest.raises(ValueError, match='https'):
        InfisicalBackend({'client_id': 'c', 'client_secret': 's', 'project_id': 'p', 'site_url': site_url})


# ---------------------------------------------------------------------------
# Azure Key Vault (storage_mode="secrets")
# ---------------------------------------------------------------------------

class _FakeAzureSecretClient:
    """In-memory stand-in for azure.keyvault.secrets.SecretClient."""

    def __init__(self):
        self.store = {}  # sanitized secret name -> value

    def set_secret(self, name, value):
        self.store[name] = value
        return types.SimpleNamespace(name=name, value=value)

    def get_secret(self, name):
        if name not in self.store:
            raise KeyError(name)  # SDK raises ResourceNotFoundError; backend catches Exception
        return types.SimpleNamespace(
            value=self.store[name],
            properties=types.SimpleNamespace(updated_on=None),
        )

    def list_properties_of_secrets(self):
        return [types.SimpleNamespace(name=n) for n in self.store]

    def begin_delete_secret(self, name):
        self.store.pop(name, None)
        return types.SimpleNamespace()  # long-running-op poller; backend ignores it


def _azure():
    backend = AzureKeyVaultBackend({
        'vault_url': 'https://kv.vault.azure.net/',
        'client_id': 'cid', 'client_secret': 'csecret', 'tenant_id': 'tid',
    })  # storage_mode defaults to "secrets"
    backend._client = _FakeAzureSecretClient()  # bypass lazy azure SDK init
    return backend


class TestAzureKeyVaultCrud:
    def test_store_then_retrieve_round_trip(self):
        b = _azure()
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True
        files, meta = b.retrieve_certificate('example.com')
        assert files == SAMPLE_FILES
        assert meta == SAMPLE_META

    def test_list_reads_domain_from_metadata(self):
        b = _azure()
        b.store_certificate('a.example.com', SAMPLE_FILES, {'domain': 'a.example.com'})
        b.store_certificate('b.example.com', SAMPLE_FILES, {'domain': 'b.example.com'})
        assert b.list_certificates() == ['a.example.com', 'b.example.com']

    def test_delete_then_retrieve_returns_none(self):
        b = _azure()
        b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META)
        assert b.delete_certificate('example.com') is True
        assert b.retrieve_certificate('example.com') is None

    def test_retrieve_missing_returns_none(self):
        assert _azure().retrieve_certificate('nope.example.com') is None

    def test_store_maps_client_error_to_false(self):
        b = _azure()
        b._client.set_secret = MagicMock(side_effect=RuntimeError('vault unreachable'))
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is False

    def test_invalid_domain_rejected(self):
        assert _azure().store_certificate('../evil', SAMPLE_FILES, SAMPLE_META) is False

    def test_get_backend_name(self):
        assert _azure().get_backend_name() == 'azure_keyvault'
