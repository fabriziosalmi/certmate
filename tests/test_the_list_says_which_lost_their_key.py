"""The certificate list says which certificates lost their private key (#966).

Step 3 of scenario B asks for "reissue all" from the UI as well as the API.
The dashboard never read `private_key_state`, so a certificate restored from
a share-safe backup looked healthy there until its first sweep failed. Each
certificate now carries `reissue_required`: true exactly when renewal would
answer REISSUE_REQUIRED (the same `_lineage_lost_its_key` test), so the
dashboard can say how many need a reissue and offer the one action.

A key that is still anywhere is not this case: a missing served key with the
lineage intact heals by itself (measured on #966, scenario A), and offering a
reissue there would change a key for nothing.
"""
import datetime
from unittest.mock import MagicMock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.certificates import CertificateManager

pytestmark = [pytest.mark.unit]

DOMAIN = 'keyless.example.com'


def _pem_pair():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, DOMAIN)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=80))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM,
                              serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()))


def _lineage(cert_dir, *, flat_key=False, live_key=False, archive_key=False):
    cert, key = _pem_pair()
    d = cert_dir / DOMAIN
    (d / 'archive' / DOMAIN).mkdir(parents=True)
    (d / 'live' / DOMAIN).mkdir(parents=True)
    (d / 'archive' / DOMAIN / 'cert1.pem').write_bytes(cert)
    (d / 'cert.pem').write_bytes(cert)
    (d / 'fullchain.pem').write_bytes(cert)
    (d / 'live' / DOMAIN / 'cert.pem').write_bytes(cert)
    if flat_key:
        (d / 'privkey.pem').write_bytes(key)
    if live_key:
        (d / 'live' / DOMAIN / 'privkey.pem').write_bytes(key)
    if archive_key:
        (d / 'archive' / DOMAIN / 'privkey1.pem').write_bytes(key)
    (d / 'metadata.json').write_text('{"dns_provider": "cloudflare"}')


def _info(tmp_path):
    settings = MagicMock()
    settings.load_settings.return_value = {'renewal_threshold_days': 30, 'domains': []}
    settings.get_domain_dns_provider.return_value = 'cloudflare'
    mgr = CertificateManager(cert_dir=tmp_path, settings_manager=settings,
                             dns_manager=MagicMock())
    return mgr.get_certificate_info(DOMAIN)


def test_a_lineage_with_no_key_anywhere_is_reported(tmp_path):
    _lineage(tmp_path)
    info = _info(tmp_path)
    assert info['private_key_state'] == 'missing'
    assert info['reissue_required'] is True


@pytest.mark.parametrize('where', ['live_key', 'archive_key'])
def test_a_key_still_in_the_lineage_is_not_a_reissue(tmp_path, where):
    """Missing from the served copy only: the ordinary path republishes it."""
    _lineage(tmp_path, **{where: True})
    info = _info(tmp_path)
    assert info['private_key_state'] == 'missing'
    assert info['reissue_required'] is False


def test_a_healthy_certificate_is_not_a_reissue(tmp_path):
    _lineage(tmp_path, flat_key=True, live_key=True, archive_key=True)
    info = _info(tmp_path)
    assert info['private_key_state'] == 'present'
    assert info['reissue_required'] is False


def test_the_field_survives_the_list_model():
    """The list is marshalled: a field the model does not declare is dropped
    without a word, and the dashboard would never see it."""
    from flask import Flask
    from flask_restx import Api, marshal

    from modules.api.models import create_api_models

    with Flask(__name__).app_context():
        models = create_api_models(Api())
        out = marshal({'domain': DOMAIN, 'reissue_required': True},
                      models['certificate_model'])
    assert out['reissue_required'] is True
