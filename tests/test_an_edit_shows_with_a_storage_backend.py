"""An edit to a certificate shows in the list when a storage backend is active (#1425).

Adding a probe answered 200 and "Configured Probes" stayed empty. The probe is saved as
`deployment_host/port/protocol` in the certificate's metadata, and an edit (a probe, a
note, the tags, auto-renew, the DNS provider) writes the local metadata.json only;
issuance and renewal write that and the backend's copy together. With a backend active,
the certificate's answer was built from the backend's copy, so every edit was missing
from the list until the next renewal. The deployment check and renewal read the local
copy, which is why probing itself went on working.

The answer now takes the local metadata.json whole when there is one, and the backend's
when there is not (an instance restored from the backend alone).
"""
import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]

DOMAIN = 'probed.example.com'


def _cert_pem():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.now(UTC)
    return (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=89))
            .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.PEM))


def _manager(tmp_path, backend_metadata, local_metadata=None):
    backend = MagicMock()
    backend.retrieve_certificate_info.return_value = ({'cert.pem': _cert_pem()}, backend_metadata)
    settings = MagicMock()
    settings.load_settings.return_value = {}
    if local_metadata is not None:
        (tmp_path / DOMAIN).mkdir()
        (tmp_path / DOMAIN / 'metadata.json').write_text(json.dumps(local_metadata))
    return CertificateManager(cert_dir=tmp_path, settings_manager=settings, dns_manager=MagicMock(),
                              storage_manager=backend, ca_manager=None)


ISSUED = {'domain': DOMAIN, 'dns_provider': 'cloudflare', 'notes': 'from issuance'}


def test_a_probe_added_after_issuance_is_in_the_answer(tmp_path):
    local = {**ISSUED, 'deployment_host': '10.0.0.5', 'deployment_port': 8443, 'deployment_protocol': 'https'}

    info = _manager(tmp_path, ISSUED, local).get_certificate_info(DOMAIN, use_cache=False)

    assert info['deployment_host'] == '10.0.0.5'


def test_a_field_the_edit_removed_does_not_come_back_from_the_backend(tmp_path):
    local = {k: v for k, v in ISSUED.items() if k != 'notes'}

    info = _manager(tmp_path, ISSUED, local).get_certificate_info(DOMAIN, use_cache=False)

    assert info['notes'] is None


def test_without_a_local_copy_the_backend_answers(tmp_path):
    info = _manager(tmp_path, {**ISSUED, 'notes': 'only in the backend'}).get_certificate_info(
        DOMAIN, use_cache=False)

    assert info['notes'] == 'only in the backend'
