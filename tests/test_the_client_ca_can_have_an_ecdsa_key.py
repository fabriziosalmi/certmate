"""The client CA can be created with an ECDSA key, and an existing CA keeps the key it has (#1421).

The client CA was always RSA 4096. #1421 asked, beside ECDSA client certificates, for a CA of
the same algorithm, so a whole chain is ECDSA P-384 (WPA3-Enterprise 192-bit mode, for one).

The key is chosen the way the subject is, and only when a CA is created: on first start, from
CERTMATE_CLIENT_CA_KEY_ALGORITHM, or on POST /api/client-certs/ca/reset with key_algorithm.
RSA 4096 stays the default, and an existing CA is never converted: initialize() returns early
when the CA exists, so every certificate it signed keeps verifying.

A P-384 CA signs with SHA-384, matching its strength (RFC 5480); every other CA signs with
SHA-256, as before.
"""
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from modules.core.private_ca import PrivateCAGenerator, client_ca_key_algorithm_from_environment

pytestmark = [pytest.mark.unit]


def _ca(tmp_path, **kw):
    ca = PrivateCAGenerator(tmp_path / 'ca', **kw)
    assert ca.initialize()
    return ca


def _metadata(ca):
    return json.loads(ca.ca_metadata_path.read_text())


def test_the_default_is_rsa_4096_as_before(tmp_path):
    ca = _ca(tmp_path)
    cert = ca.get_ca_certificate()

    assert isinstance(cert.public_key(), rsa.RSAPublicKey) and cert.public_key().key_size == 4096
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)
    assert _metadata(ca)['key_algorithm'] == 'rsa-4096'


@pytest.mark.parametrize('algorithm,curve,digest', [
    ('ecdsa-p384', 'secp384r1', hashes.SHA384),
    ('ecdsa-p256', 'secp256r1', hashes.SHA256),
])
def test_an_ecdsa_ca_signs_its_root_its_leaves_and_its_crl(tmp_path, algorithm, curve, digest):
    from cryptography.hazmat.primitives.serialization import Encoding

    from modules.core.csr_handler import CSRHandler
    ca = _ca(tmp_path, key_algorithm=algorithm)
    root = ca.get_ca_certificate()

    assert isinstance(root.public_key(), ec.EllipticCurvePublicKey)
    assert root.public_key().curve.name == curve
    assert isinstance(root.signature_hash_algorithm, digest)
    assert _metadata(ca)['key_algorithm'] == algorithm

    csr_pem, _, error = CSRHandler.create_csr('leaf.example')
    assert error is None
    leaf = ca.sign_certificate_request(x509.load_pem_x509_csr(csr_pem), days_valid=30)
    leaf = leaf if isinstance(leaf, x509.Certificate) else x509.load_pem_x509_certificate(leaf)
    leaf.verify_directly_issued_by(root)
    assert isinstance(leaf.signature_hash_algorithm, digest)

    crl = x509.load_pem_x509_crl(ca.generate_crl([]))
    assert crl.is_signature_valid(root.public_key())
    assert root.public_bytes(Encoding.PEM)


def test_an_unknown_key_algorithm_is_refused_before_a_key_is_written(tmp_path):
    with pytest.raises(ValueError, match='key_algorithm'):
        PrivateCAGenerator(tmp_path / 'ca', key_algorithm='ecdsa-p521')
    assert not (tmp_path / 'ca' / 'ca.key').exists()


def test_an_existing_ca_keeps_its_key_whatever_is_configured_now(tmp_path):
    _ca(tmp_path)   # RSA 4096, as every CA before this change

    later = _ca(tmp_path, key_algorithm='ecdsa-p384')

    assert isinstance(later.get_ca_certificate().public_key(), rsa.RSAPublicKey)


@pytest.mark.parametrize('value,expected', [(None, None), ('', None), ('  ', None),
                                            ('ecdsa-p384', 'ecdsa-p384'), ('rsa-4096', 'rsa-4096')])
def test_the_variable_is_read_when_set(monkeypatch, value, expected):
    if value is None:
        monkeypatch.delenv('CERTMATE_CLIENT_CA_KEY_ALGORITHM', raising=False)
    else:
        monkeypatch.setenv('CERTMATE_CLIENT_CA_KEY_ALGORITHM', value)

    assert client_ca_key_algorithm_from_environment() == expected


def test_a_wrong_variable_names_itself(monkeypatch):
    monkeypatch.setenv('CERTMATE_CLIENT_CA_KEY_ALGORITHM', 'ed25519')

    with pytest.raises(ValueError, match='CERTMATE_CLIENT_CA_KEY_ALGORITHM'):
        client_ca_key_algorithm_from_environment()


# --- the reset ---------------------------------------------------------------

@pytest.fixture
def manager(tmp_path):
    from modules.core.client_certificates import ClientCertificateManager
    return ClientCertificateManager(tmp_path / 'clients', _ca(tmp_path))


def test_a_reset_can_change_the_key_algorithm(manager):
    ok, error, _ = manager.reset_certificate_authority(key_algorithm='ecdsa-p384')

    assert ok, error
    root = manager.private_ca.get_ca_certificate()
    assert isinstance(root.public_key(), ec.EllipticCurvePublicKey)
    assert root.public_key().curve.name == 'secp384r1'


def test_a_reset_with_an_unknown_algorithm_touches_nothing(manager):
    before = manager.private_ca.ca_cert_path.read_bytes()

    ok, error, _ = manager.reset_certificate_authority(key_algorithm='dsa-1024')

    assert not ok and 'key_algorithm' in error
    assert manager.private_ca.ca_cert_path.read_bytes() == before
