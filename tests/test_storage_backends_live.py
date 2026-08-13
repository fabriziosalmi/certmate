"""Storage backends against real servers, not a fake of one.

`tests/test_s3_compatible_backend.py` is a good test: an in-memory S3 written
to be faithful, a real store → exists → list → retrieve → delete round-trip,
no mocks. What it cannot do is disagree with me. A fake is written from an
understanding of the protocol, so it reproduces that understanding — including
wherever it is wrong.

Two of the five remote backends can be run for real at no meaningful cost:
MinIO speaks S3, and Vault has a dev mode. Between them they exercise boto3's
`endpoint_url` and addressing, hvac's KV v2 pathing, and the error shapes both
libraries raise — the parts a fake tends to get plausibly wrong.

The first live run found two things the fake never asked about, and both are
pinned below.

Every remote backend decoded certificate files with `errors='replace'`, so
anything that is not valid UTF-8 was stored as U+FFFD. Only PEM reaches them
today, so nothing was corrupt in the field; they refuse now rather than mangle.

And S3 and Vault reported a successful delete for a certificate that had never
been stored, where the local filesystem backend reported False for the same
situation — on the path whose caller warns an operator to check for a leftover
private key.

    CERTMATE_TEST_S3_ENDPOINT=http://localhost:19000 \\
    CERTMATE_TEST_VAULT_ADDR=http://localhost:18200 \\
    pytest tests/test_storage_backends_live.py -m live

Skipped when the variables are absent, so a laptop without containers is not
punished. **Failed**, not skipped, when a variable is set and the server does
not answer — CI always sets them, so CI cannot go quietly green on a service
that never started.
"""
import os
import urllib.error
import urllib.request

import pytest

from modules.core.storage_backends import (
    HashiCorpVaultBackend,
    S3CompatibleBackend,
)

pytestmark = [pytest.mark.live]

S3_ENDPOINT = os.getenv("CERTMATE_TEST_S3_ENDPOINT")
VAULT_ADDR = os.getenv("CERTMATE_TEST_VAULT_ADDR")

PEM = {
    "cert.pem": b"-----BEGIN CERTIFICATE-----\nMIIBtest\n-----END CERTIFICATE-----\n",
    "privkey.pem": b"-----BEGIN PRIVATE KEY-----\nMIIEtest\n-----END PRIVATE KEY-----\n",
}
METADATA = {"ca": "letsencrypt", "issued": "2026-08-13"}


def _reachable(url, path):
    """A set variable and a dead server is a failure, never a skip."""
    try:
        urllib.request.urlopen(url.rstrip("/") + path, timeout=10).close()
        return True
    except urllib.error.HTTPError as answered:
        # HTTPError is itself a file-like response; closing it returns the
        # socket rather than leaving it to the garbage collector.
        answered.close()
        return True              # it answered; the status does not matter here
    except Exception as error:
        pytest.fail(
            f"{url} is configured but did not answer ({error}). This test is "
            f"meant to run against a real server; treating that as a skip is "
            f"how a suite reports success on a service that never started."
        )


@pytest.fixture
def s3(tmp_path):
    if not S3_ENDPOINT:
        pytest.skip("CERTMATE_TEST_S3_ENDPOINT not set")
    _reachable(S3_ENDPOINT, "/minio/health/live")
    import boto3

    bucket = "certmate-live-test"
    client = boto3.client(
        "s3", endpoint_url=S3_ENDPOINT,
        aws_access_key_id=os.getenv("CERTMATE_TEST_S3_KEY", "certmate"),
        aws_secret_access_key=os.getenv("CERTMATE_TEST_S3_SECRET", "certmate123"),
        region_name="us-east-1",
    )
    try:
        client.create_bucket(Bucket=bucket)
    except Exception:
        pass                     # already there from an earlier run
    return S3CompatibleBackend({
        "endpoint_url": S3_ENDPOINT,
        "bucket": bucket,
        "access_key_id": os.getenv("CERTMATE_TEST_S3_KEY", "certmate"),
        "secret_access_key": os.getenv("CERTMATE_TEST_S3_SECRET", "certmate123"),
        "region": "us-east-1",
        "prefix": f"live/{tmp_path.name}",
    })


@pytest.fixture
def vault(tmp_path):
    if not VAULT_ADDR:
        pytest.skip("CERTMATE_TEST_VAULT_ADDR not set")
    _reachable(VAULT_ADDR, "/v1/sys/health")
    return HashiCorpVaultBackend({
        "vault_url": VAULT_ADDR,
        "vault_token": os.getenv("CERTMATE_TEST_VAULT_TOKEN", "certmate-root"),
        "mount_point": "secret",
        "engine_version": "v2",
        "path_prefix": f"certmate-live/{tmp_path.name}",
    })


@pytest.fixture(params=["s3", "vault"])
def backend(request):
    """Both backends through the same contract — it is one interface."""
    return request.getfixturevalue(request.param)


def test_a_certificate_survives_a_round_trip(backend):
    domain = "roundtrip.example.com"
    assert backend.store_certificate(domain, PEM, METADATA) is True
    assert backend.certificate_exists(domain) is True

    result = backend.retrieve_certificate(domain)
    assert result is not None, "stored, then not found"
    files, metadata = result
    assert files == PEM, (
        "the bytes that came back are not the bytes that went in — the fake "
        "cannot tell you this, because it is the same code that wrote them"
    )
    assert metadata.get("ca") == "letsencrypt"

    assert domain in backend.list_certificates()
    assert backend.delete_certificate(domain) is True
    assert backend.certificate_exists(domain) is False


def test_a_wildcard_domain_is_a_usable_key(backend):
    """`*` is legal in a domain and illegal in half the world's key schemes."""
    domain = "*.wildcard.example.com"
    assert backend.store_certificate(domain, PEM, METADATA) is True
    assert backend.certificate_exists(domain) is True
    result = backend.retrieve_certificate(domain)
    assert result is not None and result[0] == PEM
    assert backend.delete_certificate(domain) is True


def test_retrieving_something_that_was_never_stored_returns_none(backend):
    """Not an exception, and not an empty dict that reads as a certificate."""
    assert backend.retrieve_certificate("never-stored.example.com") is None
    assert backend.certificate_exists("never-stored.example.com") is False


def test_deleting_something_absent_does_not_claim_success(backend):
    assert backend.delete_certificate("never-stored.example.com") is False


def test_content_that_cannot_round_trip_is_refused_not_mangled(backend):
    """The finding from the first live run, pinned.

    These backends store text. Until this was measured against MinIO they
    decoded with `errors='replace'`, so a PKCS#12 bundle would have been
    written as mojibake and the store would have reported success — the local
    copy correct, every remote copy quietly ruined.

    Nothing sends binary today: both places that build `cert_files` iterate
    CERTIFICATE_FILES, four PEM files. This is here so that the day someone
    adds `cert.pfx` to that tuple, they get a failed store rather than a
    corrupt disaster-recovery copy.
    """
    domain = "binary.example.com"
    pkcs12_header = {"cert.pfx": b"\x30\x82\x0a\x00\xff\xfe"}
    assert backend.store_certificate(domain, pkcs12_header, METADATA) is False
    assert backend.certificate_exists(domain) is False, (
        "the store refused but wrote something anyway"
    )
