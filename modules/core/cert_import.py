"""Validate an uploaded PEM bundle without issuing or writing anything.

Checks the supplied chain, not public trust or revocation: private CAs and
chains that omit the root are supported.
"""
import datetime
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .utils import validate_domain, validate_key_options

MAX_IMPORT_PEM_BYTES = 64 * 1024
INVALID_IMPORT_BUNDLE = ('Invalid certificate bundle. Check PEM format, validity dates, '
                         'chain signatures and private key match (max 64 KiB per file).')
_CERT_BEGIN = b'-----BEGIN CERTIFICATE-----'
_CERT_END = b'-----END CERTIFICATE-----'


class CertificateImportError(ValueError):
    """An operator-facing refusal authored here, never a raw parser exception."""


def _pem(value, label):
    if not isinstance(value, (str, bytes)) or not value:
        raise CertificateImportError(f'{label} is required in PEM format')
    if len(value) > MAX_IMPORT_PEM_BYTES:
        raise CertificateImportError(f'{label} must not exceed {MAX_IMPORT_PEM_BYTES} bytes')
    try:
        data = value.encode('ascii') if isinstance(value, str) else value
    except UnicodeEncodeError:
        raise CertificateImportError(f'{label} must be ASCII PEM text') from None
    return data.strip() + b'\n'


def _certificates(data, label):
    parts = data.split(_CERT_END)
    if len(parts) < 2 or parts[-1].strip():
        raise CertificateImportError(f'{label} must contain only PEM certificates')
    blocks = []
    for part in parts[:-1]:
        part = part.strip()
        if not part.startswith(_CERT_BEGIN) or part.count(_CERT_BEGIN) != 1:
            raise CertificateImportError(f'{label} must contain only PEM certificates')
        blocks.append(part + _CERT_END)
    try:
        return [x509.load_pem_x509_certificate(block) for block in blocks]
    except ValueError:
        raise CertificateImportError(f'{label} contains an invalid certificate') from None


def preview_import_certificate(certificate):
    """Read public identity only; this does not validate a bundle for import."""
    certificates = _certificates(_pem(certificate, 'Certificate'), 'Certificate')
    if len(certificates) != 1:
        raise CertificateImportError('Select one leaf certificate, not a full chain')
    cert = certificates[0]
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        names = [str(name.value) for name in san]
    except x509.ExtensionNotFound:
        names = []
    return {'common_names': [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)],
            'sans': names}


def _check_name_constraints(issuer, subordinates):
    try:
        constraints = issuer.extensions.get_extension_for_class(x509.NameConstraints).value
    except x509.ExtensionNotFound:
        return
    permitted = constraints.permitted_subtrees or []
    excluded = constraints.excluded_subtrees or []
    for subtree in [*permitted, *excluded]:
        if not isinstance(subtree, x509.DNSName):
            raise CertificateImportError('Only DNS name constraints are supported on import')
        value = subtree.value.lower().removeprefix('.')
        if (not value or '*' in value or
                any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label)
                    for label in value.split('.'))):
            raise CertificateImportError('Unsupported DNS name constraint')

    def matches(name, subtree):
        suffix = subtree.value.lower()
        return name.endswith('.' + suffix.lstrip('.')) or name == suffix

    for index, cert in enumerate(subordinates):
        # RFC 5280 exempts self-issued intermediates, but never the leaf.
        if index and cert.subject == cert.issuer:
            continue
        try:
            names = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = ([a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
                     if index == 0 else [])
        for name in names:
            # shortcut: constrained wildcard imports are refused, add set-based matching when needed.
            if '*' in name:
                raise CertificateImportError('Wildcard certificates with name constraints are not supported on import')
            name = name.lower().rstrip('.')
            if (any(matches(name, subtree) for subtree in excluded) or
                    (permitted and not any(matches(name, subtree) for subtree in permitted))):
                raise CertificateImportError('Certificate DNS name violates chain name constraints')


def validate_import_bundle(certificate, chain, private_key):
    """Validate bundle integrity and return parsed objects and normalized files."""
    leaves = _certificates(_pem(certificate, 'Certificate'), 'Certificate')
    if len(leaves) != 1:
        raise CertificateImportError('Certificate must contain exactly one leaf certificate; put issuers in Chain')
    cert = leaves[0]
    issuers = _certificates(_pem(chain, 'Chain'), 'Chain')
    key_pem = _pem(private_key, 'Private key')
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise CertificateImportError('Private key must be a valid, unencrypted PEM key') from None
    public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if key.public_key().public_bytes(*public_format) != cert.public_key().public_bytes(*public_format):
        raise CertificateImportError('Private key does not match the certificate')
    now = datetime.datetime.now(datetime.UTC)
    bundle = [cert, *issuers]
    if len({c.public_bytes(serialization.Encoding.DER) for c in bundle}) != len(bundle):
        raise CertificateImportError('Chain contains duplicate certificates or the leaf certificate')
    for item in bundle:
        if not item.not_valid_before_utc <= now < item.not_valid_after_utc:
            raise CertificateImportError('Certificate or chain is expired or not yet valid')
        supported = (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage,
                     x509.SubjectAlternativeName, x509.SubjectKeyIdentifier,
                     x509.AuthorityKeyIdentifier)
        if item != cert:
            supported += (x509.NameConstraints,)
        for extension in item.extensions:
            # Critical extensions must be understood, not silently ignored.
            if extension.critical and not isinstance(extension.value, supported):
                raise CertificateImportError('Certificate or chain contains an unsupported critical extension')
        try:
            eku = item.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                raise CertificateImportError('Certificate or chain is not valid for TLS server authentication')
        except x509.ExtensionNotFound:
            pass
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise CertificateImportError('Import a server certificate, not a CA certificate')
    except x509.ExtensionNotFound:
        pass
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not (usage.digital_signature or
                (isinstance(key, rsa.RSAPrivateKey) and usage.key_encipherment) or
                (isinstance(key, ec.EllipticCurvePrivateKey) and usage.key_agreement)):
            raise CertificateImportError('Certificate key usage does not permit TLS server authentication')
    except x509.ExtensionNotFound:
        pass
    intermediate_count = 0
    for index, issuer in enumerate(issuers):
        _check_name_constraints(issuer, bundle[:index + 1])
        try:
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not constraints.ca or (constraints.path_length is not None and intermediate_count > constraints.path_length):
                raise CertificateImportError('Chain contains an invalid CA certificate')
            try:
                if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                    raise CertificateImportError('Chain issuer cannot sign certificates')
            except x509.ExtensionNotFound:
                pass
            bundle[index].verify_directly_issued_by(issuer)
        except (x509.ExtensionNotFound, InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
            raise CertificateImportError('Chain must contain valid signing CAs in issuer order (intermediate first)') from None
        intermediate_count += issuer.subject != issuer.issuer
    if issuers[-1].issuer == issuers[-1].subject:
        try:
            issuers[-1].verify_directly_issued_by(issuers[-1])
        except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
            raise CertificateImportError('Chain root signature is invalid') from None

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    chain_pem = b''.join(c.public_bytes(serialization.Encoding.PEM) for c in issuers)
    return {
        'certificate': cert, 'private_key': key,
        'files': {'cert.pem': cert_pem, 'chain.pem': chain_pem,
                  'fullchain.pem': cert_pem + chain_pem,
                  'privkey.pem': key.private_bytes(serialization.Encoding.PEM,
                                                 serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption())},
        'created_at': cert.not_valid_before_utc.isoformat(),
    }


def validate_import_renewability(bundle):
    """Check that CertMate can issue the bundle's names and key shape later."""
    cert, key = bundle['certificate'], bundle['private_key']
    if isinstance(key, rsa.RSAPrivateKey):
        shape = {'key_type': 'rsa', 'key_size': key.key_size}
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        shape = {'key_type': 'ecdsa', 'elliptic_curve': key.curve.name}
    else:
        raise CertificateImportError('Only RSA and ECDSA keys can be renewed by CertMate')
    ok, error = validate_key_options(shape['key_type'], shape.get('key_size'), shape.get('elliptic_curve'))
    if not ok:
        raise CertificateImportError(error)
    names = _dns_names(cert, non_dns='Only DNS names are supported for automatic renewal',
                       unusable='Certificate contains a DNS name CertMate cannot renew')
    return {'names': names, 'key_options': shape}


# The curves an external certificate may use. Wider than what CertMate issues
# (P-521 is here), because the vendor chose the key, and still only the curves
# the key-state check, the PFX writer and Azure Key Vault all handle.
_EXTERNAL_CURVES = frozenset({'secp256r1', 'secp384r1', 'secp521r1'})


def validate_external_identity(bundle):
    """Check that an external certificate can be identified and served.

    No CA renews it, so nothing here asks whether CertMate could issue the same
    shape. What remains is what the rest of CertMate needs to hold it: DNS names
    to file it under and to check scope against, and a key the key-state check,
    the downloads and the storage backends can handle. RSA from 2048 bits, of
    any length a vendor issues, and the three NIST curves.
    """
    key = bundle['private_key']
    if isinstance(key, rsa.RSAPrivateKey):
        if key.key_size < 2048:
            raise CertificateImportError('RSA keys shorter than 2048 bits are not accepted')
        shape = {'key_type': 'rsa', 'key_size': key.key_size}
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        if key.curve.name not in _EXTERNAL_CURVES:
            raise CertificateImportError('Only the P-256, P-384 and P-521 curves are supported')
        shape = {'key_type': 'ecdsa', 'elliptic_curve': key.curve.name}
    else:
        raise CertificateImportError('Only RSA and ECDSA keys are supported')
    names = _dns_names(bundle['certificate'],
                       non_dns='Only DNS names are supported for an external certificate',
                       unusable='Certificate contains a DNS name CertMate cannot use')
    return {'names': names, 'key_options': shape}


def _dns_names(cert, *, non_dns, unusable):
    """The certificate's DNS names, normalised, primary first; refused with the
    caller's wording when a name is not DNS or not usable as a certificate name."""
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if any(not isinstance(name, x509.DNSName) for name in san):
            raise CertificateImportError(non_dns)
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    if not names or len(names) > 100:
        raise CertificateImportError('Certificate must cover between 1 and 100 DNS names')
    normalized = []
    for name in names:
        ok, domain = validate_domain(name)
        if not ok or domain != name.lower().rstrip('.'):
            raise CertificateImportError(unusable)
        if domain not in normalized:
            normalized.append(domain)
    return normalized
