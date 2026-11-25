"""A CRL names its CA's key and carries a number that only grows (#1545).

RFC 5280 section 5.2: a conforming CRL carries the Authority Key Identifier (5.2.1) and the
CRL Number (5.2.3), both non-critical. CertMate's CRLs carried no extensions at all, so a
relying party could not tell which key of the issuer signed one, nor whether the CRL it was
handed is newer than the one it holds. Both the client-certificate CA (CRLManager.update_crl)
and the ACME CA (AcmeCA.crl_der) build their CRL with PrivateCAGenerator.generate_crl.

The identifier is the signing CA certificate's own Subject Key Identifier when it has one,
since that is what relying parties index the CA on; otherwise it is derived from the key.
The number is kept beside the CA, so it grows across rebuilds and restarts, and it never
goes back below the number of the CRL already on disk.
"""
import datetime
import threading
import time
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.acme_ca import AcmeCA
from modules.core.ocsp_crl import CRLManager
from modules.core.private_ca import PrivateCAGenerator

pytestmark = [pytest.mark.unit]

# A Subject Key Identifier no key-derivation method yields, so a CRL whose AKI equals it
# can only have copied it from the CA certificate.
_ODD_SKI = bytes(range(1, 21))
_REVOKED = {'serial_number': 1234, 'revoked_at': '2026-11-01T00:00:00+00:00',
            'reason_revoked': 'keyCompromise'}


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


_CA_KEY_USAGE = x509.KeyUsage(digital_signature=True, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=True, crl_sign=True,
                              encipher_only=False, decipher_only=False)


def _write_pair(ca_dir, cert, key):
    ca_dir.mkdir(parents=True)
    (ca_dir / 'ca.crt').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (ca_dir / 'ca.key').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _root_with_ski(ca_dir):
    """A self-signed root whose SKI is not derived from its key: the AKI must copy it."""
    now = datetime.datetime.now(datetime.UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name('Org Root')).issuer_name(_name('Org Root'))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(_CA_KEY_USAGE, critical=True)
            .add_extension(x509.SubjectKeyIdentifier(_ODD_SKI), critical=False)
            .sign(key, hashes.SHA256()))
    _write_pair(ca_dir, cert, key)
    return cert, _ODD_SKI


def _intermediate_without_ski(ca_dir):
    """An intermediate signed by a separate root, with no SKI: the AKI comes from its key."""
    now = datetime.datetime.now(datetime.UTC)
    root_key = ec.generate_private_key(ec.SECP256R1())
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(_name('Org Issuing CA')).issuer_name(_name('Org Root'))
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(_CA_KEY_USAGE, critical=True)
            .sign(root_key, hashes.SHA256()))
    _write_pair(ca_dir, cert, key)
    expected = x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()).key_identifier
    return cert, expected


def _certmate_root(ca_dir):
    """The root CertMate makes itself (ECDSA so the test stays fast)."""
    ca = PrivateCAGenerator(ca_dir, key_algorithm='ecdsa-p256')
    assert ca.initialize()
    cert = ca.get_ca_certificate()
    expected = cert.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    return cert, expected


SIGNERS = {'root-with-its-own-ski': _root_with_ski,
           'intermediate-without-ski': _intermediate_without_ski,
           'certmate-root': _certmate_root}


class _ClientCA:
    """The client-certificate CA's CRL, through CRLManager.update_crl."""

    def __init__(self, tmp_path):
        self.ca_dir = tmp_path / 'ca'
        self.revoked = []
        self._crl_dir = tmp_path / 'crl'

    def build(self):
        ca = PrivateCAGenerator(self.ca_dir)
        assert ca.initialize()
        clients = MagicMock()
        clients.list_client_certificates.return_value = [
            dict(r, serial_number=str(r['serial_number'])) for r in self.revoked]
        pem = CRLManager(ca, clients, self._crl_dir).update_crl()
        assert pem
        return x509.load_pem_x509_crl(pem)


class _AcmeCA:
    """The ACME CA's CRL, through AcmeCA.crl_der."""

    def __init__(self, tmp_path):
        self.ca_dir = tmp_path / 'acme'
        self.revoked = []

    def build(self):
        der = AcmeCA(self.ca_dir).crl_der(list(self.revoked))
        assert der
        return x509.load_der_x509_crl(der)


CAS = {'client-ca': _ClientCA, 'acme-ca': _AcmeCA}


@pytest.fixture(params=sorted(CAS))
def ca_kind(request):
    return CAS[request.param]


@pytest.fixture(params=sorted(SIGNERS))
def signer(request):
    return SIGNERS[request.param]


def _number(crl):
    ext = crl.extensions.get_extension_for_class(x509.CRLNumber)
    assert ext.critical is False, 'RFC 5280 5.2.3: the CRL Number MUST be non-critical'
    assert 0 <= ext.value.crl_number < 2 ** 159, 'RFC 5280 5.2.3: at most 20 octets'
    return ext.value.crl_number


def _only_the_ca_and_its_crl_remain(ca_dir):
    """Lose whatever CertMate keeps beside the CA, as a restore of an older backup or a
    hand-made CA directory would, leaving the CA pair and the CRL it last published."""
    for path in ca_dir.iterdir():
        if path.is_file() and path.name not in ('ca.crt', 'ca.key', 'crl.pem'):
            path.unlink()


def test_the_crl_names_the_key_of_the_ca_that_signs_it(tmp_path, ca_kind, signer):
    built = ca_kind(tmp_path)
    cert, expected = signer(built.ca_dir)
    crl = built.build()
    ext = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier)
    assert ext.critical is False
    assert ext.value.key_identifier == expected
    assert crl.is_signature_valid(cert.public_key())


def test_the_crl_carries_a_non_critical_number(tmp_path, ca_kind, signer):
    built = ca_kind(tmp_path)
    signer(built.ca_dir)
    _number(built.build())


def test_the_number_grows_after_a_revocation_and_after_a_plain_rebuild(tmp_path, ca_kind, signer):
    built = ca_kind(tmp_path)
    signer(built.ca_dir)
    first = _number(built.build())
    built.revoked.append(_REVOKED)
    after_revocation = built.build()
    assert after_revocation.get_revoked_certificate_by_serial_number(1234) is not None
    second = _number(after_revocation)
    third = _number(built.build())
    assert first < second < third


def test_the_number_survives_a_restart(tmp_path, ca_kind):
    """Each build makes new CA objects, as a new process would; the number is read back."""
    built = ca_kind(tmp_path)
    _intermediate_without_ski(built.ca_dir)
    numbers = [_number(built.build()) for _ in range(3)]
    assert numbers == sorted(set(numbers))
    assert numbers[0] >= 1


def test_a_missing_counter_does_not_take_the_number_below_the_published_crl(tmp_path, ca_kind):
    built = ca_kind(tmp_path)
    _intermediate_without_ski(built.ca_dir)
    for _ in range(3):
        published = _number(built.build())
    _only_the_ca_and_its_crl_remain(built.ca_dir)
    assert _number(built.build()) > published


def test_a_crl_on_disk_seeds_the_number_when_nothing_else_is_kept(tmp_path, ca_kind):
    """A CRL with number 41 on disk and nothing beside it: the next CRL is number 42."""
    built = ca_kind(tmp_path)
    _intermediate_without_ski(built.ca_dir)
    built.build()
    key = serialization.load_pem_private_key((built.ca_dir / 'ca.key').read_bytes(), None)
    cert = x509.load_pem_x509_certificate((built.ca_dir / 'ca.crt').read_bytes())
    now = datetime.datetime.now(datetime.UTC)
    planted = (x509.CertificateRevocationListBuilder().issuer_name(cert.subject)
               .last_update(now).next_update(now + datetime.timedelta(days=7))
               .add_extension(x509.CRLNumber(41), critical=False)
               .sign(key, hashes.SHA256()))
    _only_the_ca_and_its_crl_remain(built.ca_dir)
    (built.ca_dir / 'crl.pem').write_bytes(planted.public_bytes(serialization.Encoding.PEM))
    assert _number(built.build()) == 42


def test_a_crl_from_before_numbers_still_lets_the_ca_rebuild(tmp_path, ca_kind):
    """A crl.pem written by an older CertMate has no number: the next one starts the count."""
    built = ca_kind(tmp_path)
    _intermediate_without_ski(built.ca_dir)
    key = serialization.load_pem_private_key((built.ca_dir / 'ca.key').read_bytes(), None)
    cert = x509.load_pem_x509_certificate((built.ca_dir / 'ca.crt').read_bytes())
    now = datetime.datetime.now(datetime.UTC)
    legacy = (x509.CertificateRevocationListBuilder().issuer_name(cert.subject)
              .last_update(now).next_update(now + datetime.timedelta(days=7))
              .sign(key, hashes.SHA256()))
    (built.ca_dir / 'crl.pem').write_bytes(legacy.public_bytes(serialization.Encoding.PEM))
    first = _number(built.build())
    assert first >= 1
    assert _number(built.build()) > first


def test_the_number_kept_beside_the_ca_outlives_a_deleted_crl(tmp_path, ca_kind):
    """Removing crl.pem (to force a rebuild) does not restart the count: the CA keeps it."""
    built = ca_kind(tmp_path)
    _intermediate_without_ski(built.ca_dir)
    for _ in range(3):
        published = _number(built.build())
    (built.ca_dir / 'crl.pem').unlink()
    assert _number(built.build()) > published


def test_concurrent_rebuilds_of_one_ca_never_share_a_number(tmp_path, monkeypatch):
    """The ACME CA rebuilds without the client CA callers' lock around it; generate_crl
    itself must serialise the number. The read is slowed so unserialised threads collide."""
    ca_dir = tmp_path / 'acme'
    _intermediate_without_ski(ca_dir)
    acme = AcmeCA(ca_dir)
    assert acme.ready()
    original = PrivateCAGenerator._read_crl_number_file

    def slow(self):
        value = original(self)
        time.sleep(0.05)
        return value

    monkeypatch.setattr(PrivateCAGenerator, '_read_crl_number_file', slow)
    numbers = []
    threads = [threading.Thread(target=lambda: numbers.append(
        _number(x509.load_der_x509_crl(acme.crl_der([]))))) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)
    assert len(numbers) == 4
    assert len(set(numbers)) == 4
