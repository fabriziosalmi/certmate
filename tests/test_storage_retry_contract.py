"""Pin the storage-backend retry contract end to end.

Before this suite landed, ``@_with_retry()`` sat on top of methods that
caught ``Exception`` internally and returned False/None/[] — so the
decorator never saw an exception and NEVER retried anything, on any cloud
backend. InfisicalBackend additionally had no retry wiring at all.

The fix moves the catch outside the retry boundary (public wrapper catches;
inner ``_*_attempt`` method is decorated and raises). These tests assert,
through the PUBLIC methods only:

  1. a transient error on attempt N is retried and a later success wins;
  2. exhausted retries still honour the public contract (False/None/[],
     never an exception leaking to the caller);
  3. non-transient errors fail fast — exactly one SDK call.
"""

import json
import time
from unittest.mock import MagicMock

import pytest

from modules.core.storage_backends import (
    AWSSecretsManagerBackend,
    AzureKeyVaultBackend,
    HashiCorpVaultBackend,
    InfisicalBackend,
)

pytestmark = [pytest.mark.unit]

SAMPLE_FILES = {'cert.pem': b'-----CERT-----'}
SAMPLE_META = {'domain': 'example.com'}

# Messages chosen to trip _is_transient's keyword fallback ('timeout',
# 'rate', 'connection', '503').
TRANSIENT = Exception('connection timeout')


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Retry backoff must not slow the suite down."""
    monkeypatch.setattr(time, 'sleep', lambda *_: None)


# ---------------------------------------------------------------------------
# AWS Secrets Manager
# ---------------------------------------------------------------------------


def _aws():
    backend = AWSSecretsManagerBackend({
        'access_key_id': 'AKIAEXAMPLE', 'secret_access_key': 'shh',
        'region': 'us-east-1',
    })
    client = MagicMock()
    client.exceptions.ResourceNotFoundException = type(
        'ResourceNotFoundException', (Exception,), {})
    backend._client = client
    return backend, client


class TestAwsRetryContract:
    def test_store_retries_transient_then_succeeds(self):
        b, client = _aws()
        client.update_secret.side_effect = [TRANSIENT, None]
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True
        assert client.update_secret.call_count == 2

    def test_retrieve_retries_transient_then_succeeds(self):
        b, client = _aws()
        payload = {'SecretString': json.dumps({
            'files': {'cert.pem': '-----CERT-----'}, 'metadata': SAMPLE_META})}
        client.get_secret_value.side_effect = [TRANSIENT, payload]
        files, meta = b.retrieve_certificate('example.com')
        assert files == SAMPLE_FILES
        assert meta == SAMPLE_META
        assert client.get_secret_value.call_count == 2

    def test_retrieve_exhausted_retries_return_none_without_raising(self):
        b, client = _aws()
        client.get_secret_value.side_effect = TRANSIENT
        assert b.retrieve_certificate('example.com') is None
        assert client.get_secret_value.call_count == 3  # default max_attempts

    def test_retrieve_non_transient_fails_fast(self):
        b, client = _aws()
        client.get_secret_value.side_effect = ValueError('AccessDenied')
        assert b.retrieve_certificate('example.com') is None
        assert client.get_secret_value.call_count == 1

    def test_list_retries_transient_then_succeeds(self):
        b, client = _aws()
        page = {'SecretList': [{'Name': 'certmate/certificates/example.com'}]}
        good = MagicMock()
        good.paginate.return_value = [page]
        client.get_paginator.side_effect = [TRANSIENT, good]
        assert b.list_certificates() == ['example.com']
        assert client.get_paginator.call_count == 2


# ---------------------------------------------------------------------------
# HashiCorp Vault
# ---------------------------------------------------------------------------


def _vault():
    backend = HashiCorpVaultBackend({
        'vault_url': 'https://vault.example.com', 'vault_token': 'tok',
    })
    client = MagicMock()
    backend._client = client
    backend._token_renewed_at = time.time()
    return backend, client


class TestVaultRetryContract:
    def test_store_retries_transient_then_succeeds(self):
        b, client = _vault()
        client.secrets.kv.v2.create_or_update_secret.side_effect = [TRANSIENT, None]
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True
        assert client.secrets.kv.v2.create_or_update_secret.call_count == 2

    def test_retrieve_exhausted_retries_return_none(self):
        b, client = _vault()
        client.secrets.kv.v2.read_secret_version.side_effect = TRANSIENT
        assert b.retrieve_certificate('example.com') is None
        assert client.secrets.kv.v2.read_secret_version.call_count == 3

    def test_list_retries_transient_then_succeeds(self):
        b, client = _vault()
        client.secrets.kv.v2.list_secrets.side_effect = [
            TRANSIENT, {'data': {'keys': ['example.com']}}]
        assert b.list_certificates() == ['example.com']
        assert client.secrets.kv.v2.list_secrets.call_count == 2


# ---------------------------------------------------------------------------
# Infisical — previously had NO retry wiring at all (P-02).
# ---------------------------------------------------------------------------


def _infisical():
    backend = InfisicalBackend({
        'client_id': 'cid', 'client_secret': 'cs', 'project_id': 'pid',
    })
    client = MagicMock()
    backend._client = client
    return backend, client


class TestInfisicalRetryContract:
    def test_store_retries_transient_then_succeeds(self):
        b, client = _infisical()
        # The upsert swallows update_secret errors and falls back to
        # create_secret; only a create failure escapes to the retry layer.
        client.update_secret.side_effect = Exception('secret not found')
        # Attempt 1: cert.pem create raises transient -> retry.
        # Attempt 2: cert.pem create ok, metadata create ok.
        client.create_secret.side_effect = [TRANSIENT, None, None]
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True
        assert client.create_secret.call_count == 3

    def test_list_retries_transient_then_succeeds(self):
        b, client = _infisical()
        secret = MagicMock()
        secret.secret_name = 'certmate-example-com-metadata'
        secret.secret_value = json.dumps({'domain': 'example.com'})
        client.get_secret.return_value = secret
        client.list_secrets.side_effect = [TRANSIENT, [secret]]
        assert b.list_certificates() == ['example.com']
        assert client.list_secrets.call_count == 2

    def test_list_exhausted_retries_return_empty_list(self):
        b, client = _infisical()
        client.list_secrets.side_effect = TRANSIENT
        assert b.list_certificates() == []
        assert client.list_secrets.call_count == 3

    def test_retrieve_non_transient_client_failure_returns_none(self):
        b, client = _infisical()
        # _get_client itself blowing up must map to None, not an exception.
        b._client = None
        b._get_client = MagicMock(side_effect=ValueError('bad credentials'))
        assert b.retrieve_certificate('example.com') is None
        assert b._get_client.call_count == 1


# ---------------------------------------------------------------------------
# Azure Key Vault — store retries per surface, reads via _attempt methods.
# ---------------------------------------------------------------------------


def _azure(mode='secrets'):
    return AzureKeyVaultBackend({
        'vault_url': 'https://kv.example.net', 'client_id': 'cid',
        'client_secret': 'cs', 'tenant_id': 'tid', 'storage_mode': mode,
    })


def _flaky_fn(outcomes):
    """Plain function (not a MagicMock — _retry_call applies functools.wraps,
    which needs real string __name__/__qualname__) that raises or returns
    each outcome in order, repeating the last one. Returns (fn, calls)."""
    calls = {'n': 0}

    def fn(*args, **kwargs):
        outcome = outcomes[min(calls['n'], len(outcomes) - 1)]
        calls['n'] += 1
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    return fn, calls


class TestAzureRetryContract:
    def test_store_retries_secrets_surface_then_succeeds(self):
        b = _azure('secrets')
        fn, calls = _flaky_fn([TRANSIENT, True])
        b._store_as_secrets = fn
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is True
        assert calls['n'] == 2

    def test_store_exhausted_retries_return_false(self):
        b = _azure('secrets')
        fn, calls = _flaky_fn([TRANSIENT])
        b._store_as_secrets = fn
        assert b.store_certificate('example.com', SAMPLE_FILES, SAMPLE_META) is False
        assert calls['n'] == 3

    def test_retrieve_retries_transient_then_succeeds(self):
        b = _azure('secrets')
        b._retrieve_from_secrets = MagicMock(side_effect=[
            TRANSIENT, ({'cert.pem': b'PEM'}, SAMPLE_META, None)])
        files, meta = b.retrieve_certificate('example.com')
        assert files == {'cert.pem': b'PEM'}
        assert meta == SAMPLE_META
        assert b._retrieve_from_secrets.call_count == 2

    def test_retrieve_info_exhausted_retries_return_none(self):
        b = _azure('secrets')
        b._retrieve_info_from_secrets = MagicMock(side_effect=TRANSIENT)
        assert b.retrieve_certificate_info('example.com') is None
        assert b._retrieve_info_from_secrets.call_count == 3

    def test_list_retries_transient_then_succeeds(self):
        b = _azure('secrets')
        b._list_secret_domains = MagicMock(side_effect=[TRANSIENT, ['example.com']])
        assert b.list_certificates() == ['example.com']
        assert b._list_secret_domains.call_count == 2
