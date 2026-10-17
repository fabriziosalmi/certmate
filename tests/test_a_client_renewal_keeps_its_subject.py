"""A client certificate renews with the subject it was issued with (#1256).

`create_client_certificate` wrote the common name, email, organisation and
unit to the metadata, but not the country or the state, and a renewal
re-issues from that metadata. So the renewed certificate took the default: an
identity issued as `C=IT, ST=Lazio` renewed as `C=CH, ST=Switzerland` (and,
with #1251, as whatever `CERTMATE_CLIENT_CERT_DEFAULT_*` says at renewal
time). An mTLS rule that matches on the subject stopped matching after a
renewal nobody chose, and the nightly sweep renews unattended.

The metadata now records the C and ST the certificate carries. A certificate
issued before that has neither field, and its renewal reads them off the
certificate itself, which is the identity a relying party matches on.
"""
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

pytestmark = [pytest.mark.unit]

DEFAULTS = ('CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY', 'CERTMATE_CLIENT_CERT_DEFAULT_STATE')


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in DEFAULTS:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def manager(tmp_path):
    from modules.core.client_certificates import ClientCertificateManager
    from modules.core.private_ca import PrivateCAGenerator

    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    return ClientCertificateManager(tmp_path / 'clients', ca)


def _subject(data):
    cert = x509.load_pem_x509_certificate(open(data['paths']['certificate'], 'rb').read())
    return cert.subject.rfc4514_string()


def _create(manager, **kwargs):
    params = {'common_name': 'alice.example.com', 'organization': 'Acme'}
    params.update(kwargs)
    ok, err, data = manager.create_client_certificate(**params)
    assert ok, err
    return data


def _renew(manager, identifier):
    ok, err, data = manager.renew_certificate(identifier)
    assert ok, err
    return data


def test_a_renewal_keeps_the_country_and_state_it_was_issued_with(manager):
    """The case reported in #1256."""
    issued = _create(manager, country='IT', state='Lazio')

    renewed = _renew(manager, issued['identifier'])

    assert _subject(renewed) == _subject(issued) == (
        'CN=alice.example.com,OU=Users,O=Acme,ST=Lazio,C=IT')


def test_the_metadata_records_what_the_certificate_carries(manager):
    issued = _create(manager, country='IT', state='Lazio')
    cert = x509.load_pem_x509_certificate(open(issued['paths']['certificate'], 'rb').read())

    assert issued['metadata']['country'] == cert.subject.get_attributes_for_oid(
        NameOID.COUNTRY_NAME)[0].value == 'IT'
    assert issued['metadata']['state'] == cert.subject.get_attributes_for_oid(
        NameOID.STATE_OR_PROVINCE_NAME)[0].value == 'Lazio'


def test_a_default_changed_after_issuance_does_not_move_a_renewal(manager, monkeypatch):
    """A certificate issued with the defaults keeps them: the deployment's
    default is for new identities, not a way to rename existing ones."""
    issued = _create(manager)
    monkeypatch.setenv('CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY', 'ES')
    monkeypatch.setenv('CERTMATE_CLIENT_CERT_DEFAULT_STATE', 'Madrid')

    renewed = _renew(manager, issued['identifier'])

    assert 'C=CH' in _subject(renewed) and 'ST=Switzerland' in _subject(renewed)


def test_a_certificate_issued_before_the_fields_existed_renews_from_itself(manager):
    """Metadata written before #1256 has no country or state. The renewal
    reads them off the certificate rather than falling back to the default."""
    issued = _create(manager, country='IT', state='Lazio')
    path = issued['paths']['metadata']
    metadata = json.load(open(path))
    del metadata['country'], metadata['state']
    json.dump(metadata, open(path, 'w'))

    renewed = _renew(manager, issued['identifier'])

    assert 'C=IT' in _subject(renewed) and 'ST=Lazio' in _subject(renewed)


def test_a_new_certificate_without_a_country_still_takes_the_default(manager, monkeypatch):
    """CONTROL: the default still applies where nothing else says."""
    monkeypatch.setenv('CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY', 'ES')

    issued = _create(manager)

    assert 'C=ES' in _subject(issued)


def test_a_csr_s_subject_is_what_the_metadata_records(manager):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COUNTRY_NAME, 'DE'),
               x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, 'Bayern'),
               x509.NameAttribute(NameOID.COMMON_NAME, 'device.example.com')]))
           .sign(key, hashes.SHA256()))

    issued = _create(manager, common_name='device.example.com', generate_key=False,
                     csr_pem=csr.public_bytes(serialization.Encoding.PEM))

    assert issued['metadata']['country'] == 'DE'
    assert issued['metadata']['state'] == 'Bayern'
