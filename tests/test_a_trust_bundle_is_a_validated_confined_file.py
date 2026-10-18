"""A private CA trust bundle is validated PEM, written 0600, under the cert tree.

create_ca_trust_bundle wrote account_config['ca_cert'] straight into the shared
/tmp with no check that it was a certificate. It now parses the content as PEM
certificates first (junk is refused with a clear log, not handed to certbot),
and writes the file 0600 inside a confined directory under CERTMATE_CERT_DIR.
"""
import datetime
import stat
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.ca_manager import CAManager

pytestmark = [pytest.mark.unit]


def _a_ca_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Probe CA')])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture
def manager(tmp_path, monkeypatch):
    monkeypatch.setenv('CERTMATE_CERT_DIR', str(tmp_path / 'certs'))

    class _SM:
        def load_settings(self): return {}
    return CAManager(_SM())


def test_a_real_bundle_is_written_confined_and_0600(manager, tmp_path):
    path = manager.create_ca_trust_bundle('private_ca', {'ca_cert': _a_ca_pem()})
    assert path is not None
    p = Path(path)
    assert (tmp_path / 'certs') in p.parents, p
    assert stat.S_IMODE(p.stat().st_mode) == 0o600
    assert x509.load_pem_x509_certificates(p.read_bytes())


def test_content_that_is_not_a_certificate_is_refused(manager):
    assert manager.create_ca_trust_bundle('private_ca', {'ca_cert': 'not a certificate'}) is None
    garbled = '-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----'
    assert manager.create_ca_trust_bundle('private_ca', {'ca_cert': garbled}) is None


def test_a_private_key_is_not_accepted_as_a_trust_bundle(manager):
    key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    assert manager.create_ca_trust_bundle('private_ca', {'ca_cert': key}) is None
