"""Client-certificate PKCS#12 (.pfx) export (#465).

Server certs already produced an on-disk cert.pfx; client certs — where a .pfx
for import into Windows / mobile keystores is most useful — did not. These
tests cover the on-demand builder: it bundles leaf + key (+ the CA as chain),
encrypts with the configured password, and refuses to emit an unencrypted
key-bearing bundle.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12

from modules.core.client_certificates import ClientCertificateManager

pytestmark = [pytest.mark.unit]


def _cert_and_key(cn):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=90))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())
    return cert_pem, key_pem


@pytest.fixture
def manager(tmp_path):
    ca_pem, _ = _cert_and_key('Test Client CA')
    ca_path = tmp_path / 'ca.crt'
    ca_path.write_bytes(ca_pem)
    private_ca = SimpleNamespace(ca_cert_path=ca_path)
    return ClientCertificateManager(
        client_certs_dir=tmp_path / 'client-certs', private_ca=private_ca)


def _place_cert(manager, identifier, usage='api'):
    d = manager.client_certs_dir / usage / identifier
    d.mkdir(parents=True)
    cert_pem, key_pem = _cert_and_key(identifier)
    (d / f'{identifier}.crt').write_bytes(cert_pem)
    (d / f'{identifier}.key').write_bytes(key_pem)
    return cert_pem


def test_build_pfx_is_loadable_with_password(manager):
    _place_cert(manager, 'alice')
    blob = manager.build_pfx('alice', b'pw-123')
    key, cert, chain = pkcs12.load_key_and_certificates(blob, b'pw-123')
    assert key is not None and cert is not None
    # The CA cert rides along as the chain.
    assert chain and any(
        c.subject.rfc4514_string().endswith('Test Client CA') for c in chain)


def test_build_pfx_rejects_wrong_password(manager):
    _place_cert(manager, 'bob')
    blob = manager.build_pfx('bob', b'right')
    with pytest.raises(ValueError):
        pkcs12.load_key_and_certificates(blob, b'wrong')


def test_build_pfx_empty_password_returns_none(manager):
    _place_cert(manager, 'carol')
    assert manager.build_pfx('carol', b'') is None


def test_build_pfx_unknown_identifier_returns_none(manager):
    assert manager.build_pfx('nobody', b'pw') is None


def test_build_pfx_skips_incomplete_candidate(manager):
    # An incomplete dir (crt, no key) under one usage folder must not shadow a
    # complete cert under another — build_pfx keeps looking.
    incomplete = manager.client_certs_dir / 'vpn' / 'dup'
    incomplete.mkdir(parents=True)
    cert_pem, _ = _cert_and_key('dup')
    (incomplete / 'dup.crt').write_bytes(cert_pem)   # crt only, no key
    _place_cert(manager, 'dup', usage='api')          # complete
    assert manager.build_pfx('dup', b'pw') is not None


def test_build_pfx_without_ca_still_works(tmp_path):
    # No CA cert available -> chain is empty but the PFX still builds.
    private_ca = SimpleNamespace(ca_cert_path=None)
    mgr = ClientCertificateManager(
        client_certs_dir=tmp_path / 'cc', private_ca=private_ca)
    _place_cert(mgr, 'dave')
    blob = mgr.build_pfx('dave', b'pw')
    key, cert, chain = pkcs12.load_key_and_certificates(blob, b'pw')
    assert key is not None and cert is not None
    assert not chain
