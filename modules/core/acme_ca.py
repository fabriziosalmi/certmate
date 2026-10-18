"""The CA behind CertMate's ACME server (#476).

A root of its own (decision D1), separate from the client certificate CA: a
relying party that trusts it for server TLS does not trust it for mTLS. It is
made by the same generator as that CA (G1: RSA 4096, ten years), in
data/acme/ca/, which backups carry and share-safe backups carry without its
key. It signs leaves directly (G2): an intermediate would protect a root key
kept elsewhere, and this one would sit on the same host.

The leaf is built here, not copied from the CSR. The CSR proves the key and
names the identifiers (the server has checked both against the order); the
certificate carries the order's names, a subject of the first of them, and
the key usage its key type calls for. Its chain is the leaf alone (G3): the
root goes into trust stores from /acme/root, and a TLS server need not send it.
"""
import os
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .private_ca import PrivateCAGenerator

CLOCK_SKEW = timedelta(minutes=5)
# 45 days (decision D3 on #476), measured against the clients' renewal rules
# with tests/interop/run.sh: certbot 5.8.0 and lego 5.5.2 renew with a third
# of the lifetime left, 15 days; acme.sh 3.1.5 renews 29 days after issuance
# unless given --days (measured: issued 2026-10-18, next renewal 2026-11-16),
# which left a 30-day certificate one day to spare and leaves a 45-day one
# sixteen. And it stays inside the 47 days public certificates are heading for.
DEFAULT_VALIDITY_DAYS = 45
MIN_VALIDITY_DAYS = 1
MAX_VALIDITY_DAYS = 365
MIN_RSA_BITS = 2048
MAX_RSA_BITS = 8192
EC_CURVES = frozenset({'secp256r1', 'secp384r1'})


class AcmeCA:
    def __init__(self, ca_dir):
        # Read when the root is created and never again (PrivateCAGenerator).
        # The suffix tells two instances' roots apart in a trust store.
        subject = {'organization': 'CertMate', 'organizational_unit': 'ACME',
                   'common_name': f'CertMate ACME CA {os.urandom(3).hex()}'}
        self.generator = PrivateCAGenerator(Path(ca_dir), subject=subject)
        self._lock = threading.Lock()

    def ready(self):
        """Create the root on first use, or load it; False when it cannot be had."""
        with self._lock:
            if self.generator.is_ca_loaded():
                return True
            return self.generator.initialize()

    def root_pem(self):
        return self.generator.get_ca_cert_pem() if self.ready() else None

    def root(self):
        return self.generator.get_ca_certificate() if self.ready() else None

    def issue(self, csr, names, days):
        """A server certificate for *names* on the CSR's key, valid *days*."""
        if not self.ready():
            raise RuntimeError('The ACME CA could not be created or loaded')
        ca_cert = self.generator.get_ca_certificate()
        ca_key = self.generator.get_ca_private_key()
        public_key = csr.public_key()
        now = datetime.now(UTC)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])]))
            .issuer_name(ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - CLOCK_SKEW)
            .not_valid_after(now + timedelta(days=days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(public_key), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
        )
        return builder.sign(ca_key, hashes.SHA256())

    def crl_der(self, records):
        """The CRL of this CA over *records* (serial_number, revoked_at, reason_revoked), DER."""
        if not self.ready():
            return None
        pem = self.generator.generate_crl(records)
        return x509.load_pem_x509_crl(pem).public_bytes(serialization.Encoding.DER) if pem else None


def csr_key_refusal(public_key):
    """Why a CSR's key cannot be certified, or None."""
    if isinstance(public_key, rsa.RSAPublicKey):
        if not MIN_RSA_BITS <= public_key.key_size <= MAX_RSA_BITS:
            return f'An RSA key must have {MIN_RSA_BITS} to {MAX_RSA_BITS} bits, not {public_key.key_size}'
        return None
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in EC_CURVES:
            return f'An EC key must be on P-256 or P-384, not {public_key.curve.name}'
        return None
    return 'The key must be RSA or EC'


def _key_usage(public_key):
    # keyEncipherment is for RSA key transport; an EC key never does it.
    return x509.KeyUsage(
        digital_signature=True, content_commitment=False,
        key_encipherment=isinstance(public_key, rsa.RSAPublicKey), data_encipherment=False,
        key_agreement=False, key_cert_sign=False, crl_sign=False, encipher_only=False, decipher_only=False)
