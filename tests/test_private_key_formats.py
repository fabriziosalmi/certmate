"""The two shapes of private key a receiver may ask for.

An appliance API wants the key as PEM in a JSON body, and which PEM it wants is
not CertMate's choice: PKCS#8 (`BEGIN PRIVATE KEY`) for most, the traditional
form (`BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`) for the older ones. What
is on disk can be either, depending on the key type and on what produced it, so
the target converts rather than forwarding whatever happens to be there.

A key that has no traditional form (Ed25519, Ed448, X25519) is refused with a
message that says so: substituting the PKCS#8 one would send a receiver the
shape it asked not to get, and it would fail there with an error that names
nothing.
"""
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from modules.core import key_formats as kf

pytestmark = [pytest.mark.unit]


def _pem(key, fmt):
    return key.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption())


@pytest.fixture(scope='module')
def keys():
    return {
        'rsa': rsa.generate_private_key(public_exponent=65537, key_size=2048),
        'ec': ec.generate_private_key(ec.SECP256R1()),
        'ed25519': ed25519.Ed25519PrivateKey.generate(),
    }


def _public(pem_text):
    key = serialization.load_pem_private_key(pem_text.encode(), password=None)
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.mark.parametrize('kind', ['rsa', 'ec', 'ed25519'])
@pytest.mark.parametrize('stored_as', [serialization.PrivateFormat.PKCS8,
                                       serialization.PrivateFormat.TraditionalOpenSSL])
def test_pkcs8_is_produced_from_either_stored_shape(keys, kind, stored_as):
    if kind == 'ed25519' and stored_as is serialization.PrivateFormat.TraditionalOpenSSL:
        pytest.skip('Ed25519 has no traditional form to have been stored in')
    out = kf.private_key_pkcs8(_pem(keys[kind], stored_as))
    assert out.startswith('-----BEGIN PRIVATE KEY-----\n') and out.endswith('-----END PRIVATE KEY-----\n')
    assert _public(out) == keys[kind].public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.mark.parametrize('stored_as', [serialization.PrivateFormat.PKCS8,
                                       serialization.PrivateFormat.TraditionalOpenSSL])
def test_rsa_traditional_is_pkcs1(keys, stored_as):
    out = kf.private_key_traditional(_pem(keys['rsa'], stored_as))
    assert out.startswith('-----BEGIN RSA PRIVATE KEY-----\n')
    assert _public(out) == keys['rsa'].public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.mark.parametrize('stored_as', [serialization.PrivateFormat.PKCS8,
                                       serialization.PrivateFormat.TraditionalOpenSSL])
def test_ec_traditional_is_sec1(keys, stored_as):
    out = kf.private_key_traditional(_pem(keys['ec'], stored_as))
    assert out.startswith('-----BEGIN EC PRIVATE KEY-----\n')
    assert _public(out) == keys['ec'].public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_a_key_with_no_traditional_form_is_refused_by_name(keys):
    with pytest.raises(kf.KeyFormatError) as refused:
        kf.private_key_traditional(_pem(keys['ed25519'], serialization.PrivateFormat.PKCS8))
    assert 'traditional' in str(refused.value) and 'privkey_pkcs8' in str(refused.value)


def test_an_encrypted_key_is_refused_rather_than_guessed_at(keys):
    encrypted = keys['rsa'].private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b'passphrase'))
    with pytest.raises(kf.KeyFormatError) as refused:
        kf.private_key_pkcs8(encrypted)
    assert 'passphrase' in str(refused.value).lower() or 'encrypted' in str(refused.value).lower()


@pytest.mark.parametrize('junk', [b'', b'not a key', b'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'])
def test_garbage_is_refused_without_quoting_it(junk):
    with pytest.raises(kf.KeyFormatError) as refused:
        kf.private_key_pkcs8(junk)
    assert 'AAAA' not in str(refused.value)


def test_the_message_never_contains_the_key_material(keys):
    pem = _pem(keys['ed25519'], serialization.PrivateFormat.PKCS8)
    body = ''.join(pem.decode().strip().splitlines()[1:-1])
    with pytest.raises(kf.KeyFormatError) as refused:
        kf.private_key_traditional(pem)
    assert body not in str(refused.value)
