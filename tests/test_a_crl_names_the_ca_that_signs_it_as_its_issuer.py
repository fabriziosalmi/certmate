"""A CRL and a certificate name the CA that signs them as their issuer, also an intermediate (#1537).

RFC 5280 (5.1.2.3): the issuer of a CRL is the subject of the CA that signs it. The CRL was
built with the issuer of the signing CA's certificate instead. For CertMate's own self-signed
roots the two names are the same, so it only showed when ca.crt held an intermediate: the CRL
then named the root while the intermediate's key signed it. Both CRLs are built by
PrivateCAGenerator.generate_crl: the client-certificate CA's and the ACME CA's (AcmeCA.crl_der).
"""
import datetime
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.acme_ca import AcmeCA
from modules.core.ocsp_crl import CRLManager
from modules.core.private_ca import PrivateCAGenerator

pytestmark = [pytest.mark.unit]


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _intermediate_in(ca_dir):
    """Write an intermediate signed by a separate root as ca.crt and ca.key."""
    now = datetime.datetime.now(datetime.UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name('Org Issuing CA')).issuer_name(_name('Org Root'))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, key_cert_sign=True, crl_sign=True,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(root_key, hashes.SHA256()))
    ca_dir.mkdir(parents=True)
    (ca_dir / 'ca.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ca_dir / 'ca.key').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert


def _assert_named_and_signed_by(crl, intermediate):
    assert crl.issuer == intermediate.subject
    assert crl.issuer != intermediate.issuer
    assert crl.is_signature_valid(intermediate.public_key())


def test_the_client_ca_crl_names_its_signing_intermediate_as_issuer(tmp_path):
    intermediate = _intermediate_in(tmp_path / 'ca')
    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    clients = MagicMock()
    clients.list_client_certificates.return_value = [
        {'serial_number': '1234', 'revoked_at': '2026-11-01T00:00:00+00:00', 'reason_revoked': 'keyCompromise'}]
    pem = CRLManager(ca, clients, tmp_path / 'crl').update_crl()
    crl = x509.load_pem_x509_crl(pem)
    assert crl.get_revoked_certificate_by_serial_number(1234) is not None
    _assert_named_and_signed_by(crl, intermediate)


def test_the_acme_ca_crl_names_its_signing_intermediate_as_issuer(tmp_path):
    intermediate = _intermediate_in(tmp_path / 'acme')
    der = AcmeCA(tmp_path / 'acme').crl_der(
        [{'serial_number': 1234, 'revoked_at': '2026-11-01T00:00:00+00:00', 'reason_revoked': 'keyCompromise'}])
    _assert_named_and_signed_by(x509.load_der_x509_crl(der), intermediate)


def test_a_self_signed_root_still_names_itself_as_the_crl_issuer(tmp_path):
    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    root = ca.get_ca_certificate()
    crl = x509.load_pem_x509_crl(ca.generate_crl([]))
    assert crl.issuer == root.subject
    assert crl.is_signature_valid(root.public_key())


def test_a_certificate_the_client_ca_signs_names_its_signing_intermediate_as_issuer(tmp_path):
    """The same mistake in sign_certificate_request: the leaf named the issuer of
    the CA's certificate, so it did not chain to an intermediate that signed it."""
    intermediate = _intermediate_in(tmp_path / 'ca')
    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder().subject_name(_name('device-1'))
           .sign(key, hashes.SHA256()))
    leaf = ca.sign_certificate_request(csr, days_valid=30, extended_key_usage=['clientAuth'])
    assert leaf is not None
    assert leaf.issuer == intermediate.subject
    leaf.verify_directly_issued_by(intermediate)
