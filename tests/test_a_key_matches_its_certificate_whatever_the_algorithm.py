"""A certificate and its private key match when their public keys are the same bytes (T0.3).

The key-state check compared `public_numbers()`, which exists for RSA, EC and DSA keys
only. For an Ed25519 or an ML-DSA pair the call raised, and the check reported the pair
`mismatched`: needs_renewal true, the certificate unusable, for a key that was the right
one. Measured on main: RSA and ECDSA `present`, Ed25519 and ML-DSA-65 `mismatched`.

The check compares the DER SubjectPublicKeyInfo now, as cert_import already did. Every
algorithm has one, and it names the algorithm, so two keys of different types never match.
"""
import datetime as dt

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa, rsa
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]

NOW = dt.datetime.now(dt.UTC)
NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'k.example')])

KEYS = {
    'RSA': (lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), hashes.SHA256()),
    'ECDSA': (lambda: ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()),
    'Ed25519': (ed25519.Ed25519PrivateKey.generate, None),
    'ML-DSA-65': (mldsa.MLDSA65PrivateKey.generate, None),
}


def _key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def _cert_pem(key, algorithm):
    return (x509.CertificateBuilder().subject_name(NAME).issuer_name(NAME)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW).not_valid_after(NOW + dt.timedelta(days=1))
            .sign(key, algorithm).public_bytes(serialization.Encoding.PEM))


def _state(key_pem, cert_pem):
    return CertificateManager._compare_key_to_certificate('k.example', key_pem, cert_pem)


@pytest.mark.parametrize('kind', sorted(KEYS))
def test_a_certificate_and_its_own_key_match(kind):
    make, algorithm = KEYS[kind]
    key = make()

    assert _state(_key_pem(key), _cert_pem(key, algorithm)) == 'present'


@pytest.mark.parametrize('kind', sorted(KEYS))
def test_another_key_of_the_same_type_does_not(kind):
    make, algorithm = KEYS[kind]

    assert _state(_key_pem(make()), _cert_pem(make(), algorithm)) == 'mismatched'


def test_a_key_of_another_type_does_not():
    make, algorithm = KEYS['ECDSA']

    assert _state(_key_pem(ed25519.Ed25519PrivateKey.generate()), _cert_pem(make(), algorithm)) == 'mismatched'
