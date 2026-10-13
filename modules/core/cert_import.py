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
_CERT_BLOCK = re.compile(br'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', re.S)


def _pem(value, label):
    if not isinstance(value, (str, bytes)) or not value:
        raise ValueError(f'{label} is required in PEM format')
    if len(value) > MAX_IMPORT_PEM_BYTES:
        raise ValueError(f'{label} must not exceed {MAX_IMPORT_PEM_BYTES} bytes')
    try:
        data = value.encode('ascii') if isinstance(value, str) else value
    except UnicodeEncodeError:
        raise ValueError(f'{label} must be ASCII PEM text') from None
    return data.strip() + b'\n'


def _certificates(data, label):
    blocks = _CERT_BLOCK.findall(data)
    if not blocks or _CERT_BLOCK.sub(b'', data).strip():
        raise ValueError(f'{label} must contain only PEM certificates')
    try:
        return [x509.load_pem_x509_certificate(block) for block in blocks]
    except ValueError:
        raise ValueError(f'{label} contains an invalid certificate') from None


def preview_import_certificate(certificate):
    """Read public identity only; this does not validate a bundle for import."""
    certificates = _certificates(_pem(certificate, 'Certificate'), 'Certificate')
    if len(certificates) != 1:
        raise ValueError('Select one leaf certificate, not a full chain')
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
            raise ValueError('Only DNS name constraints are supported on import')
        value = subtree.value.lower().removeprefix('.')
        if (not value or '*' in value or
                any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]*[a-z0-9])?', label)
                    for label in value.split('.'))):
            raise ValueError('Unsupported DNS name constraint')

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
                raise ValueError('Wildcard certificates with name constraints are not supported on import')
            name = name.lower().rstrip('.')
            if (any(matches(name, subtree) for subtree in excluded) or
                    (permitted and not any(matches(name, subtree) for subtree in permitted))):
                raise ValueError('Certificate DNS name violates chain name constraints')


def validate_import_bundle(certificate, chain, private_key):
    """Return normalized files, DNS names and the key shape for renewal."""
    leaves = _certificates(_pem(certificate, 'Certificate'), 'Certificate')
    if len(leaves) != 1:
        raise ValueError('Certificate must contain exactly one leaf certificate; put issuers in Chain')
    cert = leaves[0]
    issuers = _certificates(_pem(chain, 'Chain'), 'Chain')
    key_pem = _pem(private_key, 'Private key')
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        raise ValueError('Private key must be a valid, unencrypted PEM key') from None
    public_format = (serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if key.public_key().public_bytes(*public_format) != cert.public_key().public_bytes(*public_format):
        raise ValueError('Private key does not match the certificate')
    if isinstance(key, rsa.RSAPrivateKey):
        shape = {'key_type': 'rsa', 'key_size': key.key_size}
    elif isinstance(key, ec.EllipticCurvePrivateKey):
        shape = {'key_type': 'ecdsa', 'elliptic_curve': key.curve.name}
    else:
        raise ValueError('Only RSA and ECDSA keys can be renewed by CertMate')
    ok, error = validate_key_options(shape['key_type'], shape.get('key_size'), shape.get('elliptic_curve'))
    if not ok:
        raise ValueError(error)

    now = datetime.datetime.now(datetime.timezone.utc)
    bundle = [cert, *issuers]
    if len({c.public_bytes(serialization.Encoding.DER) for c in bundle}) != len(bundle):
        raise ValueError('Chain contains duplicate certificates or the leaf certificate')
    for item in bundle:
        if not item.not_valid_before_utc <= now < item.not_valid_after_utc:
            raise ValueError('Certificate or chain is expired or not yet valid')
        supported = (x509.BasicConstraints, x509.KeyUsage, x509.ExtendedKeyUsage,
                     x509.SubjectAlternativeName, x509.SubjectKeyIdentifier,
                     x509.AuthorityKeyIdentifier)
        if item != cert:
            supported += (x509.NameConstraints,)
        for extension in item.extensions:
            # Critical extensions must be understood, not silently ignored.
            if extension.critical and not isinstance(extension.value, supported):
                raise ValueError('Certificate or chain contains an unsupported critical extension')
        try:
            eku = item.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
                raise ValueError('Certificate or chain is not valid for TLS server authentication')
        except x509.ExtensionNotFound:
            pass
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError('Import a server certificate, not a CA certificate')
    except x509.ExtensionNotFound:
        pass
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not (usage.digital_signature or
                (shape['key_type'] == 'rsa' and usage.key_encipherment) or
                (shape['key_type'] == 'ecdsa' and usage.key_agreement)):
            raise ValueError('Certificate key usage does not permit TLS server authentication')
    except x509.ExtensionNotFound:
        pass
    intermediate_count = 0
    for index, issuer in enumerate(issuers):
        _check_name_constraints(issuer, bundle[:index + 1])
        try:
            constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not constraints.ca or (constraints.path_length is not None and intermediate_count > constraints.path_length):
                raise ValueError('Chain contains an invalid CA certificate')
            try:
                if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                    raise ValueError('Chain issuer cannot sign certificates')
            except x509.ExtensionNotFound:
                pass
            bundle[index].verify_directly_issued_by(issuer)
        except (x509.ExtensionNotFound, InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
            raise ValueError('Chain must contain valid signing CAs in issuer order (intermediate first)') from None
        intermediate_count += issuer.subject != issuer.issuer
    if issuers[-1].issuer == issuers[-1].subject:
        try:
            issuers[-1].verify_directly_issued_by(issuers[-1])
        except (InvalidSignature, UnsupportedAlgorithm, TypeError, ValueError):
            raise ValueError('Chain root signature is invalid') from None

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        if any(not isinstance(name, x509.DNSName) for name in san):
            raise ValueError('Only DNS names are supported for automatic renewal')
        names = san.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        names = [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    if not names or len(names) > 100:
        raise ValueError('Certificate must cover between 1 and 100 DNS names')
    normalized = []
    for name in names:
        ok, domain = validate_domain(name)
        if not ok or domain != name.lower().rstrip('.'):
            raise ValueError('Certificate contains a DNS name CertMate cannot renew')
        if domain not in normalized:
            normalized.append(domain)
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    chain_pem = b''.join(c.public_bytes(serialization.Encoding.PEM) for c in issuers)
    return {
        'files': {'cert.pem': cert_pem, 'chain.pem': chain_pem,
                  'fullchain.pem': cert_pem + chain_pem,
                  'privkey.pem': key.private_bytes(serialization.Encoding.PEM,
                                                 serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption())},
        'names': normalized,
        'key_options': shape,
        'created_at': cert.not_valid_before_utc.isoformat(),
    }
