"""What the pinned cryptography can do with post-quantum algorithms, written down as a test.

The post-quantum roadmap rests on measurements of cryptography 50.0.2: ML-DSA-44/65/87 sign
and verify certificates, CSRs and CRLs (with `sign(key, None)`: a hash is refused), and
ML-KEM-768 encapsulates. A Dependabot bump that changed any of that would otherwise be
noticed only by the sprint that needed it (task T0.4).

Two of the measurements are refusals the roadmap works around: PKCS#12 does not carry an
ML-DSA key, and an ML-DSA key has no traditional (PKCS#1-style) PEM form. Those are
canaries: the day a bump lifts one, its test fails and names the task that can then drop
its refusal.
"""
import datetime as dt
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import mldsa, mlkem
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

pytestmark = [pytest.mark.unit]

NOW = dt.datetime.now(dt.UTC)
NAME = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'pq.example')])

# FIPS 204 parameter sets, the class cryptography names them by, and their OID (RFC 9881).
ML_DSA = [
    ('MLDSA44PrivateKey', '2.16.840.1.101.3.4.3.17'),
    ('MLDSA65PrivateKey', '2.16.840.1.101.3.4.3.18'),
    ('MLDSA87PrivateKey', '2.16.840.1.101.3.4.3.19'),
]


def _certificate(subject_key, issuer_key, ca=False):
    return (x509.CertificateBuilder().subject_name(NAME).issuer_name(NAME)
            .public_key(subject_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW).not_valid_after(NOW + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            .sign(issuer_key, None))


@pytest.mark.parametrize('cls,oid', ML_DSA)
def test_ml_dsa_signs_a_certificate_with_its_oid(cls, oid):
    key = getattr(mldsa, cls).generate()
    cert = _certificate(key, key, ca=True)

    assert cert.signature_algorithm_oid.dotted_string == oid
    assert cert.public_key_algorithm_oid.dotted_string == oid
    assert cert.signature_hash_algorithm is None
    cert.verify_directly_issued_by(cert)


def test_ml_dsa_refuses_a_hash():
    """Signing code must pass None for ML-DSA, not the SHA-256 every other key takes."""
    key = mldsa.MLDSA65PrivateKey.generate()
    with pytest.raises(ValueError, match='Algorithm must be None'):
        x509.CertificateBuilder().subject_name(NAME).issuer_name(NAME).public_key(key.public_key()) \
            .serial_number(1).not_valid_before(NOW).not_valid_after(NOW + dt.timedelta(days=1)) \
            .sign(key, hashes.SHA256())


def test_ml_dsa_signs_a_leaf_a_csr_and_a_crl():
    ca = mldsa.MLDSA65PrivateKey.generate()
    leaf_key = mldsa.MLDSA65PrivateKey.generate()
    root = _certificate(ca, ca, ca=True)

    _certificate(leaf_key, ca).verify_directly_issued_by(root)
    csr = x509.CertificateSigningRequestBuilder().subject_name(NAME).sign(leaf_key, None)
    assert csr.is_signature_valid
    crl = (x509.CertificateRevocationListBuilder().issuer_name(NAME).last_update(NOW)
           .next_update(NOW + dt.timedelta(days=1)).sign(ca, None))
    assert crl.is_signature_valid(ca.public_key())


def test_an_ml_dsa_key_round_trips_as_pkcs8_pem():
    key = mldsa.MLDSA65PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption())

    assert isinstance(serialization.load_pem_private_key(pem, None), mldsa.MLDSA65PrivateKey)


def test_ml_kem_768_encapsulates():
    key = mlkem.MLKEM768PrivateKey.generate()
    shared, ciphertext = key.public_key().encapsulate()

    assert key.decapsulate(ciphertext) == shared
    assert len(ciphertext) == 1088 and len(shared) == 32


# --- canaries: refusals the roadmap works around -----------------------------

def test_canary_pkcs12_does_not_carry_an_ml_dsa_key():
    key = mldsa.MLDSA65PrivateKey.generate()
    with pytest.raises(TypeError):
        pkcs12.serialize_key_and_certificates(b'x', key, _certificate(key, key), None,
                                              serialization.BestAvailableEncryption(b'pw'))
    # If this starts failing: PKCS#12 now carries ML-DSA. Lift the PFX refusal planned in
    # the post-quantum roadmap (tasks T2.4 and T5.2) instead of keeping it.


def test_canary_an_ml_dsa_key_has_no_traditional_pem_form():
    key = mldsa.MLDSA65PrivateKey.generate()
    with pytest.raises(ValueError):
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                          serialization.NoEncryption())
    # If this starts failing, the PKCS#1-style download (key_format=pkcs1) can serve ML-DSA too.


def test_the_image_check_for_hybrid_key_exchange_is_wired():
    """The CI image job runs scripts/check_hybrid_key_exchange.py inside the built image."""
    ci = (Path(__file__).resolve().parent.parent / '.github' / 'workflows' / 'ci.yml').read_text()

    assert 'docker exec "$cid" python /app/scripts/check_hybrid_key_exchange.py' in ci
