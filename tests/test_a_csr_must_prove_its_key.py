"""The private CA signs a CSR only when its signature proves the key.

A CSR is signed with the private key of the public key it carries: that
signature is how whoever sends it proves they hold the key. The client
certificate path checked it with `csr.public_key()`, which only parses the key,
so a CSR with a broken signature was accepted, and the CA issued a certificate
for a public key its requester never had to hold. Measured on 2026-10-18: a
CSR with one byte of its signature flipped, which `cryptography` reports as
not valid, passed `CSRHandler.validate_csr_pem` and `POST /api/client-certs/create`
answered 201.
"""
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

from modules.core.csr_handler import CSRHandler

pytestmark = [pytest.mark.unit]

KEYS = {
    'ec': lambda: ec.generate_private_key(ec.SECP256R1()),
    'rsa': lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
}


def _csr(kind, tamper=False):
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'device.internal')]))
           .sign(KEYS[kind](), hashes.SHA256()))
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    if tamper:
        der[-5] ^= 0xFF  # a byte inside the signature value
    loaded = x509.load_der_x509_csr(bytes(der))
    assert loaded.is_signature_valid is not tamper, 'the CSR is not the one the test means to send'
    return loaded.public_bytes(serialization.Encoding.PEM)


@pytest.mark.parametrize('kind', sorted(KEYS))
def test_a_csr_whose_signature_is_broken_is_refused(kind):
    ok, error, csr = CSRHandler.validate_csr_pem(_csr(kind, tamper=True))
    assert (ok, csr) == (False, None)
    assert 'signature' in error.lower()


@pytest.mark.parametrize('kind', sorted(KEYS))
def test_a_csr_signed_with_its_key_is_accepted(kind):
    ok, error, csr = CSRHandler.validate_csr_pem(_csr(kind))
    assert ok and error is None and csr is not None


@pytest.fixture
def manager(tmp_path):
    from modules.core.client_certificates import ClientCertificateManager
    from modules.core.private_ca import PrivateCAGenerator

    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    return ClientCertificateManager(tmp_path / 'clients', ca)


def test_the_ca_issues_nothing_for_it(manager, tmp_path):
    ok, error, data = manager.create_client_certificate(
        'device.internal', generate_key=False, csr_pem=_csr('ec', tamper=True))
    assert (ok, data) == (False, None)
    assert 'signature' in error.lower()
    assert not list((tmp_path / 'clients').rglob('*.crt'))


def test_the_ca_still_issues_for_a_valid_one(manager):
    ok, error, data = manager.create_client_certificate(
        'device.internal', generate_key=False, csr_pem=_csr('ec'))
    assert ok, error
    assert data


def test_the_api_refuses_it():
    from tests import contract_support as support
    app, token = support.build_app()
    client = app.test_client()
    headers = {'Authorization': f'Bearer {token}'}
    response = client.post('/api/client-certs/create', headers=headers, json={
        'common_name': 'device.internal', 'generate_key': False,
        'csr': _csr('ec', tamper=True).decode()})
    assert response.status_code == 400, response.get_data(as_text=True)
    assert 'signature' in response.get_data(as_text=True).lower()
    listed = client.get('/api/client-certs', headers=headers).get_json()
    assert not [c for c in (listed or {}).get('certificates', listed or []) if isinstance(c, dict)
                and c.get('common_name') == 'device.internal']
