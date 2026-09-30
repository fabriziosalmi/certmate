"""PKCS#8 and traditional PEM forms of a private key.

What is on disk can be either, and a receiver's API may want a particular one
(`BEGIN PRIVATE KEY` or `BEGIN RSA PRIVATE KEY` / `BEGIN EC PRIVATE KEY`), so a
deploy target converts instead of forwarding whatever happens to be there.

Errors name the problem and never the material: they end up in a result that is
recorded in a log nobody can edit.
"""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa


class KeyFormatError(Exception):
    """The key cannot be produced in the requested form."""


def _load(pem):
    try:
        return serialization.load_pem_private_key(pem, password=None)
    except TypeError:
        raise KeyFormatError('the private key is encrypted with a passphrase; a deploy '
                             'target cannot decrypt it')
    except (ValueError, UnsupportedAlgorithmError):
        raise KeyFormatError('the private key file is not a PEM private key CertMate can read')


try:
    from cryptography.exceptions import UnsupportedAlgorithm as UnsupportedAlgorithmError
except ImportError:  # pragma: no cover - present in every supported cryptography
    UnsupportedAlgorithmError = ValueError


def private_key_pkcs8(pem):
    """The key as PKCS#8 PEM text (`BEGIN PRIVATE KEY`)."""
    key = _load(pem)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode('ascii')


def private_key_traditional(pem):
    """The key as traditional PEM text: PKCS#1 for RSA, SEC1 for EC.

    A key type with no such form is refused, not silently given as PKCS#8: the
    receiver asked for the other shape, and would fail on it with no useful error.
    """
    key = _load(pem)
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise KeyFormatError(
            f'{type(key).__name__.replace("PrivateKey", "")} keys have no traditional PEM '
            f'form; use privkey_pkcs8')
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode('ascii')
