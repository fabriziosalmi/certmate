"""Unit tests for PKCS#1 private-key export on download (issue #233).

The download endpoint's ?key_format=pkcs1 converts certbot's PKCS#8 key
("BEGIN PRIVATE KEY") into the legacy PKCS#1/SEC1 form on the fly. These
pin the conversion helper without needing a running container.
"""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from modules.api.resources import _privkey_to_pkcs1


def _pkcs8_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def test_rsa_pkcs8_converts_to_pkcs1_and_round_trips():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    out = _privkey_to_pkcs1(_pkcs8_pem(key))
    # PKCS#1 uses the "RSA PRIVATE KEY" header (vs PKCS#8 "PRIVATE KEY").
    assert b'BEGIN RSA PRIVATE KEY' in out
    reloaded = serialization.load_pem_private_key(out, password=None)
    assert reloaded.private_numbers() == key.private_numbers()


def test_ecdsa_pkcs8_converts_to_sec1():
    key = ec.generate_private_key(ec.SECP256R1())
    out = _privkey_to_pkcs1(_pkcs8_pem(key))
    # TraditionalOpenSSL for EC keys is SEC1 ("EC PRIVATE KEY").
    assert b'BEGIN EC PRIVATE KEY' in out


def test_unsupported_key_type_raises():
    # Ed25519 has no traditional/SEC1 encoding; the route maps this to 422.
    key = ed25519.Ed25519PrivateKey.generate()
    with pytest.raises((ValueError, TypeError)):
        _privkey_to_pkcs1(_pkcs8_pem(key))
