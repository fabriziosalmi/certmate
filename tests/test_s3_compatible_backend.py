"""S3-compatible object-storage backend.

One backend for every S3-compatible provider via a configurable endpoint_url
(Hetzner, Contabo, OVHcloud, Scaleway, Wasabi, MinIO, ...). boto3 is already a
core dependency, so no new SDK.

These tests inject a faithful in-memory S3 fake (the repo convention is a fake
client, not moto) and exercise a real store -> exists -> list -> retrieve
(byte fidelity) -> delete round-trip, plus wildcard-domain keys and config
validation.
"""
import io

import pytest

from modules.core.storage_backends import S3CompatibleBackend

pytestmark = [pytest.mark.unit]


class _FakeS3:
    """Minimal in-memory S3 — faithful enough for a real round-trip."""

    class _NoSuchKey(Exception):
        pass

    def __init__(self):
        self._store = {}  # (bucket, key) -> bytes
        self.exceptions = type('Exc', (), {'NoSuchKey': self._NoSuchKey})()

    def put_object(self, Bucket, Key, Body, **kw):
        self._store[(Bucket, Key)] = Body if isinstance(Body, bytes) else Body.encode('utf-8')
        return {}

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self._store:
            raise self.exceptions.NoSuchKey()
        return {'Body': io.BytesIO(self._store[(Bucket, Key)])}

    def delete_object(self, Bucket, Key):
        self._store.pop((Bucket, Key), None)
        return {}

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self._store:
            raise self._NoSuchKey()
        return {}

    def get_paginator(self, op):
        store = self._store

        class _Paginator:
            def paginate(self, Bucket, Prefix=''):
                contents = [{'Key': k} for (b, k) in store if b == Bucket and k.startswith(Prefix)]
                yield {'Contents': contents}

        return _Paginator()


def _backend():
    b = S3CompatibleBackend({
        'endpoint_url': 'https://s3.example.eu',
        'bucket': 'certs',
        'access_key_id': 'AK',
        'secret_access_key': 'SK',
    })
    b._client = _FakeS3()
    return b


def test_round_trip_with_byte_fidelity():
    b = _backend()
    files = {
        'cert.pem': b'-----BEGIN CERTIFICATE-----\nA\n-----END CERTIFICATE-----\n',
        'privkey.pem': b'-----BEGIN PRIVATE KEY-----\nB\n-----END PRIVATE KEY-----\n',
        'chain.pem': b'chain', 'fullchain.pem': b'fullchain',
    }
    meta = {'issuer': 'Test CA', 'expiry_date': '2026-09-01'}

    assert b.store_certificate('a.example.com', files, meta) is True
    assert b.certificate_exists('a.example.com') is True
    assert b.list_certificates() == ['a.example.com']

    got = b.retrieve_certificate('a.example.com')
    assert got is not None
    got_files, got_meta = got
    assert got_files == files          # exact bytes back
    assert got_meta == meta

    assert b.delete_certificate('a.example.com') is True
    assert b.certificate_exists('a.example.com') is False
    assert b.retrieve_certificate('a.example.com') is None
    assert b.list_certificates() == []


def test_wildcard_domain_round_trips():
    b = _backend()
    assert b.store_certificate('*.example.com', {'cert.pem': b'W'}, {}) is True
    assert '*.example.com' in b.list_certificates()
    assert b.retrieve_certificate('*.example.com')[0]['cert.pem'] == b'W'


def test_list_isolates_to_prefix():
    b = _backend()
    # an unrelated object in the same bucket must not appear as a domain
    b._client.put_object(Bucket='certs', Key='unrelated/file.json', Body=b'x')
    b.store_certificate('only.example.com', {'cert.pem': b'C'}, {})
    assert b.list_certificates() == ['only.example.com']


def test_get_backend_name():
    assert _backend().get_backend_name() == 's3_compatible'


def test_requires_endpoint_bucket_and_keys():
    with pytest.raises(ValueError):
        S3CompatibleBackend({'bucket': 'x', 'access_key_id': 'a', 'secret_access_key': 'b'})  # no endpoint
    with pytest.raises(ValueError):
        S3CompatibleBackend({'endpoint_url': 'https://x', 'access_key_id': 'a', 'secret_access_key': 'b'})  # no bucket
    with pytest.raises(ValueError):
        S3CompatibleBackend({'endpoint_url': 'https://x', 'bucket': 'b'})  # no keys
