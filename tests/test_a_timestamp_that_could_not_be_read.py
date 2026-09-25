"""A read that failed is not a Certificate object that is absent (#671).

Azure Key Vault's `both` mode keeps two copies of a certificate — one in
Secrets, one as a Certificate object — and decides which to serve by comparing
the Certificate object's `updated_on` with the Secrets copy's. That timestamp
came from `get_certificate_update_time()`, which answered **None for any
exception**; and None is also how it says "there is no Certificate object".

So a throttled read, a 403, or a blip took the Secrets-only branch, and the
branch returns that copy *without comparing anything*. After a renewal had
written the Certificate object, the caller got the certificate the renewal had
replaced — and nothing said so.

The handler that did it carried a comment claiming the opposite: *"None means
'cannot tell', and every caller treats that as 'do not skip the work' rather
than as 'nothing is there'."* Both callers did exactly the second thing. That
is what #671 is about now that every broad handler states its reason: the
reasons themselves are the thing to check.

The distinction is the one #844 made in this same file for
`certificate_exists`, and the fix has the same shape — a third value that a
timestamp cannot carry, so it is an exception. What the callers do with it is
retry the read once through the summary, which reaches the same SDK call: the
failures that cannot be told from absence are overwhelmingly transient, so a
second attempt either gets the number or confirms there is none.
"""
import datetime
import json
from unittest.mock import MagicMock

import pytest

from modules.core.storage_backends import (
    AzureKeyVaultBackend, CertificateUpdateTimeUnknown,
    _AzureKeyVaultCertificateImporter,
)

pytestmark = [pytest.mark.unit]

OLDER = datetime.datetime(2026, 1, 1, 12, 0, 0)     # what Secrets holds
NEWER = datetime.datetime(2026, 9, 25, 12, 0, 0)    # what the renewal wrote

STALE = b'CERT-THE-RENEWAL-REPLACED'
FRESH = b'CERT-THE-RENEWAL-WROTE'

CONFIG = {
    'vault_url': 'https://example.vault.azure.net/',
    'client_id': 'id', 'client_secret': 'shhh', 'tenant_id': 'tenant',
    'storage_mode': 'both',
}


def _secrets_holding_the_older_copy():
    """A Secrets surface that answers with the pre-renewal certificate."""
    client = MagicMock()

    def get_secret(name):
        secret = MagicMock()
        secret.properties.updated_on = OLDER
        if 'cert-pem' in name:
            secret.value = STALE.decode()
        elif 'metadata' in name:
            secret.value = json.dumps({'domain': 'test.example.com'})
        else:
            secret.value = 'X'
        return secret

    client.get_secret.side_effect = get_secret
    return client


def _backend(update_time, summary=(FRESH, NEWER)):
    """A `both`-mode backend whose two surfaces disagree.

    *update_time* is what the Certificate object's timestamp read does: a
    datetime, None (absent), or an exception to raise.
    """
    backend = AzureKeyVaultBackend(CONFIG)
    backend._client = _secrets_holding_the_older_copy()

    importer = MagicMock()
    if isinstance(update_time, Exception):
        importer.get_certificate_update_time.side_effect = update_time
    else:
        importer.get_certificate_update_time.return_value = update_time
    importer.get_certificate_summary.return_value = (
        ({'cert.pem': summary[0]}, {'domain': 'test.example.com'}, summary[1])
        if summary else None)
    importer.export_certificate.return_value = (
        ({'cert.pem': summary[0]}, {'domain': 'test.example.com'})
        if summary else None)
    importer.get_metadata_tags.return_value = {'domain': 'test.example.com'}
    backend._cert_importer = importer
    return backend, importer


def _served(result):
    files, _metadata = result
    return files['cert.pem']


# --- the defect, end to end, on both callers ------------------------------

def _backend_with_a_flaky_vault(failures):
    """A `both`-mode backend over a REAL importer whose client fails *failures*
    times before answering.

    Driving the real importer is what makes this a regression test. The first
    draft stubbed the importer's own method to raise, which exercises the
    caller's handling and nothing else — and it passed against the pre-fix
    code, because the defect is in the producer: the swallow that turned every
    error into None. A test that cannot see the line it is about is decoration.
    """
    backend = AzureKeyVaultBackend(CONFIG)
    backend._client = _secrets_holding_the_older_copy()

    cert = MagicMock()
    cert.properties.updated_on = NEWER
    cert.properties.tags = {'domain': 'test.example.com'}
    # `cer` is DER; the summary parses it, so give it a real certificate.
    cert.cer = _a_real_der_certificate()

    calls = {'n': 0}

    def get_certificate(_name):
        calls['n'] += 1
        if calls['n'] <= failures:
            raise RuntimeError('Too many requests (429)')
        return cert

    client = MagicMock()
    client.get_certificate.side_effect = get_certificate

    importer = _AzureKeyVaultCertificateImporter.__new__(
        _AzureKeyVaultCertificateImporter)
    importer._certificate_name = lambda domain: 'cert-name'
    importer._get_cert_client = lambda: client
    importer.export_certificate = lambda domain: (
        {'cert.pem': FRESH}, {'domain': 'test.example.com'})
    backend._cert_importer = importer
    return backend, calls


def _a_real_der_certificate():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'test.example.com')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=90))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


@pytest.mark.parametrize('method', ['retrieve_certificate_info',
                                    'retrieve_certificate'])
def test_a_failed_timestamp_read_does_not_serve_the_replaced_certificate(method):
    """THE regression, driven through the real read.

    One transient failure on the Certificate object, then the vault answers.
    Before the fix that failure became None, which is the "no Certificate
    object" branch, and that branch returns the Secrets copy without comparing
    — the certificate the renewal had replaced.
    """
    backend, calls = _backend_with_a_flaky_vault(failures=1)

    served = _served(getattr(backend, method)('test.example.com'))

    assert served != STALE, 'served the copy the renewal replaced'
    # >= 2, not == 2: the compare branch reads the certificate itself
    # afterwards, so a retry that succeeds makes three calls on the info path.
    # What this pins is that the failure was retried at all.
    assert calls['n'] >= 2, 'the failed read was not retried'


@pytest.mark.parametrize('method', ['retrieve_certificate_info',
                                    'retrieve_certificate'])
def test_a_vault_that_keeps_failing_falls_back_rather_than_erroring(method):
    """The other end of it: two failures leave nothing to compare against, and
    the Secrets copy is still better than no answer for a listing."""
    backend, calls = _backend_with_a_flaky_vault(failures=99)

    assert _served(getattr(backend, method)('test.example.com')) == STALE
    assert calls['n'] == 2, 'a read that keeps failing must be retried once, not looped'


@pytest.mark.parametrize('method', ['retrieve_certificate_info',
                                    'retrieve_certificate'])
def test_an_absent_certificate_object_still_means_the_secrets_copy(method):
    """CONTROL, and the reason absence is not folded into unknown: an install
    that keeps no Certificate object at all would otherwise pay a second round
    trip on every listing, for a question already answered."""
    backend, importer = _backend(None)

    assert _served(getattr(backend, method)('test.example.com')) == STALE
    importer.get_certificate_summary.assert_not_called()


def test_a_readable_timestamp_still_decides_it(_ignored=None):
    """CONTROL for the comparison itself: nothing above is doing the work."""
    backend, importer = _backend(NEWER)

    assert _served(backend.retrieve_certificate_info('test.example.com')) == FRESH
    importer.get_certificate_summary.assert_called_once()


def test_an_older_certificate_object_does_not_displace_the_secrets_copy():
    """The other direction of the comparison, so "always prefer the Certificate
    object" would not satisfy this file."""
    backend, _ = _backend(datetime.datetime(2025, 1, 1, 12, 0, 0))

    assert _served(backend.retrieve_certificate_info('test.example.com')) == STALE


# --- when there is nothing left to compare against ------------------------

def test_the_last_resort_falls_back_but_says_so(caplog):
    """Both reads failing leaves only the Secrets copy — which may be older,
    and the operator gets that sentence rather than a silent answer."""
    backend, _ = _backend(CertificateUpdateTimeUnknown('throttled'), summary=None)

    with caplog.at_level('WARNING'):
        served = _served(backend.retrieve_certificate_info('test.example.com'))

    assert served == STALE
    # getMessage(), not .message: the warning is a format string plus args, and
    # the domain and the error only appear once they are interpolated.
    assert any('without comparing' in record.getMessage()
               for record in caplog.records), 'the fallback is silent again'


# --- the narrowing itself -------------------------------------------------

def _importer_whose_read_raises(error):
    importer = _AzureKeyVaultCertificateImporter.__new__(
        _AzureKeyVaultCertificateImporter)
    importer._certificate_name = lambda domain: 'cert-name'
    client = MagicMock()
    client.get_certificate.side_effect = error
    importer._get_cert_client = lambda: client
    return importer


def test_a_missing_certificate_object_reads_as_absent():
    """Matched by class name, not by importing azure.core — the offline suite
    runs these backends against fakes with the real package absent."""
    error = type('ResourceNotFoundError', (Exception,), {})('no such certificate')

    assert _importer_whose_read_raises(error).get_certificate_update_time('d') is None


@pytest.mark.parametrize('error', [
    RuntimeError('connection reset'),
    TimeoutError('timed out'),
    PermissionError('the role lost certificates/get'),
])
def test_every_other_failure_says_it_could_not_tell(error):
    importer = _importer_whose_read_raises(error)

    with pytest.raises(CertificateUpdateTimeUnknown):
        importer.get_certificate_update_time('d')


def test_a_present_certificate_object_answers_with_its_timestamp():
    """CONTROL for the instrument: a narrowing that raised on everything would
    satisfy the test above and break the normal path."""
    importer = _AzureKeyVaultCertificateImporter.__new__(
        _AzureKeyVaultCertificateImporter)
    importer._certificate_name = lambda domain: 'cert-name'
    cert = MagicMock()
    cert.properties.updated_on = NEWER
    client = MagicMock()
    client.get_certificate.return_value = cert
    importer._get_cert_client = lambda: client

    assert importer.get_certificate_update_time('d') == NEWER

