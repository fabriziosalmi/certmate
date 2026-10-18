"""A client certificate issued from a CSR is recorded as the certificate says.

The CA signs the CSR's subject and SANs, not the fields sent beside it, while
the record (the dashboard, the audit trail, renewals) took the fields. A CSR
for one identity sent with the name of another was listed under the other.
"""
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tests.test_a_client_identity_the_operator_can_describe import manager  # noqa: F401

pytestmark = [pytest.mark.unit]


def _csr():
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'svc-deploy'),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Platform'),
                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Ops')])
    return (x509.CertificateSigningRequestBuilder().subject_name(subject)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('deploy.internal')]), critical=False)
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


def test_the_record_is_the_certificates_subject_and_names(manager):  # noqa: F811
    ok, err, data = manager.create_client_certificate(
        common_name='test-user', organization='Users', organizational_unit='Staff',
        generate_key=False, csr_pem=_csr())
    assert ok, err
    folder = manager._get_cert_subdir('api-mtls') / data['identifier']
    metadata = json.loads((folder / 'metadata.json').read_text())
    issued = x509.load_pem_x509_certificate(next(folder.glob('*.crt')).read_bytes())
    assert issued.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == 'svc-deploy'
    assert (metadata['common_name'], metadata['organization'], metadata['organizational_unit']) == (
        'svc-deploy', 'Platform', 'Ops')
    assert metadata['subject_alt_names'] == ['DNSName:deploy.internal']


def test_a_generated_key_keeps_the_fields_it_was_given(manager):  # noqa: F811
    ok, err, data = manager.create_client_certificate(common_name='alice.example.com', organization='Acme')
    assert ok, err
    metadata = json.loads((manager._get_cert_subdir('api-mtls') / data['identifier'] / 'metadata.json').read_text())
    assert (metadata['common_name'], metadata['organization']) == ('alice.example.com', 'Acme')
