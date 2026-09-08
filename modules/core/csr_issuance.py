"""Issuing a certificate from a CSR CertMate did not generate (#599).

Some appliances generate their private key on the device and cannot export it.
They can hand out a CSR and nothing else. The workflow those users need is:
the key never leaves the device, CertMate submits the CSR to the CA, and
CertMate manages the certificate and chain it gets back.

certbot supports this as ``certonly --csr``, and that mode differs from the
ordinary one in ways that are not cosmetic. Verified against Let's Encrypt
staging rather than read from the documentation:

* it writes **cert.pem, chain.pem and fullchain.pem and no private key** — the
  three paths must be given explicitly;
* it creates **no lineage**: no ``renewal/`` config and no ``live/`` symlink
  tree. certbot says so itself on success — "Certificates created using --csr
  will not be renewed automatically by Certbot. You will need to renew the
  certificate before it expires, by running the same Certbot command again."

That second point is the one that shapes everything else. `certbot renew` will
never touch these, so renewal here means re-running the same command with the
stored CSR, and the "did it renew" question cannot be answered by looking at
``live/``.

The domain list comes from the CSR, not from the request. A CSR is signed over
its own subject and SANs, so a caller asking for different names would get a
certificate for the ones in the CSR regardless; taking them from the CSR is
the only reading that cannot silently disagree with what the CA issues.
"""
import hashlib

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID

# Flags the ordinary command carries that make no sense — or actively mislead —
# in CSR mode, with how many arguments each consumes.
#
# The key-shape flags are the important ones. In CSR mode certbot does not
# generate a key, so `--key-type ecdsa` describes nothing: the key is whatever
# the appliance made, and leaving the flag in the command would let an operator
# read it back from the logs and believe CertMate chose it.
#
# `-d` goes because the names come from the CSR (certbot ignores it there), and
# `--cert-name` because there is no lineage to name.
_DROPPED_FLAGS = {
    '-d': 1,
    '--domain': 1,
    '--domains': 1,
    '--cert-name': 1,
    '--key-type': 1,
    '--rsa-key-size': 1,
    '--elliptic-curve': 1,
    # Lineage concepts. A CSR renewal goes through create_certificate with
    # `replace=True` so it gets past the "already exists" guard, and that adds
    # these two — but there is no lineage here to renew with new domains, and
    # no renewal window to force past: certbot in --csr mode always issues.
    # Dropping them keeps the renewal command byte-identical to the issuance
    # command, which is the one already proven against a real CA.
    '--renew-with-new-domains': 0,
    '--force-renewal': 0,
}

# What certbot writes in CSR mode. Deliberately not privkey.pem: its absence is
# the feature, and the flat publish step skips files that do not exist.
CSR_OUTPUT_FILES = ('cert.pem', 'chain.pem', 'fullchain.pem')

# Where certbot is told to write them, under the domain's own directory. A
# separate directory rather than the flat one so the publish step still stages
# and promotes as one unit instead of certbot writing the served copy directly.
CSR_OUTPUT_DIRNAME = 'csr-out'


class CSRError(ValueError):
    """A CSR that cannot be used to issue a certificate."""


def read_csr(csr_pem):
    """Parse and check a PEM CSR. Returns the object, or raises ``CSRError``.

    The signature check matters here in a way it does not for a CSR we
    generated ourselves: this one arrived over the API from an appliance, and
    a CSR whose signature does not verify is one the CA will reject after we
    have already created a directory, written metadata and reported progress.
    """
    if not csr_pem:
        raise CSRError('CSR is empty')
    if isinstance(csr_pem, str):
        csr_pem = csr_pem.encode()
    try:
        csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    except Exception:
        raise CSRError('Not a valid PEM certificate signing request')

    if not csr.is_signature_valid:
        raise CSRError(
            'The CSR signature does not verify against its own public key')

    if not csr_domains(csr):
        raise CSRError(
            'The CSR names no domains: it has neither a Common Name nor a '
            'subjectAltName extension')
    return csr


def csr_domains(csr):
    """Every DNS name the CSR asks for, primary first, de-duplicated.

    The Common Name comes first when it is present, because that is the name
    the certificate directory is named for and the one an operator will look
    for. A CSR with only SANs — increasingly the normal shape, since CAs have
    deprecated the CN — uses the first SAN instead.
    """
    names = []
    for attribute in csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
        value = str(attribute.value).strip()
        if value:
            names.append(value)
    try:
        san = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        names.extend(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        pass

    seen, ordered = set(), []
    for name in names:
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            ordered.append(name)
    return ordered


def csr_fingerprint(csr_pem):
    """SHA-256 over the DER, so a re-submitted identical CSR is recognisable.

    Over the DER rather than the PEM text: the same request re-exported by the
    appliance can differ in line wrapping and trailing whitespace while being
    byte-identical once decoded, and "is this the same CSR" should not depend
    on how it was pasted.
    """
    if isinstance(csr_pem, str):
        csr_pem = csr_pem.encode()
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())
    return hashlib.sha256(
        csr.public_bytes(serialization.Encoding.DER)).hexdigest()


def to_csr_command(argv, csr_path, output_dir):
    """Rewrite an ordinary certbot argv into CSR mode.

    A transformation rather than a second builder, deliberately. The hard part
    of the command — the CA, the EAB credentials, the DNS plugin and its
    credentials file, the propagation wait, the alias hook — is identical in
    both modes, and a parallel builder would be one more place for those to
    drift. What changes is small and mechanical: drop what describes a key or a
    lineage, add the CSR and the three output paths.

    Returns a new list; *argv* is not modified.
    """
    rewritten, skip = [], 0
    for token in argv:
        if skip:
            skip -= 1
            continue
        consumed = _DROPPED_FLAGS.get(str(token))
        if consumed is not None:
            skip = consumed
            continue
        rewritten.append(token)

    output_dir = str(output_dir).rstrip('/')
    rewritten.extend([
        '--csr', str(csr_path),
        '--cert-path', f'{output_dir}/cert.pem',
        '--chain-path', f'{output_dir}/chain.pem',
        '--fullchain-path', f'{output_dir}/fullchain.pem',
    ])
    return rewritten
