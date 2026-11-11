"""A client certificate gets the kind of key it was asked for, and keeps it on renewal (#1421).

Client certificates were always RSA 2048: CSRHandler.create_csr took 2048 or 4096 and nothing
passed either, and a renewal generated a new RSA 2048 key whatever the certificate had. EAP-TLS
in WPA3-Enterprise 192-bit mode needs ECDSA P-384 (or RSA 3072 and up), so the only way to get
one was a CSR, renewed by hand every year.

Now a create takes key_type, key_size and elliptic_curve, the values server certificates take;
a request that names none gets the client_cert_key_* settings, RSA 2048 unless changed; and the
record keeps the shape, so a renewal generates the same kind of key. A record written before
this kept no shape, so its renewal reads it from the certificate it renews.

An ECDSA certificate carries digitalSignature alone: keyEncipherment is an RSA operation, and
the CA put it on every client certificate.
"""
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from werkzeug.exceptions import HTTPException

pytestmark = [pytest.mark.unit]


@pytest.fixture
def manager(tmp_path):
    from modules.core.client_certificates import ClientCertificateManager
    from modules.core.private_ca import PrivateCAGenerator

    ca = PrivateCAGenerator(tmp_path / 'ca')
    assert ca.initialize()
    return ClientCertificateManager(tmp_path / 'clients', ca)


def _create(manager, **key):
    ok, err, data = manager.create_client_certificate(common_name='wifi-user', **key)
    assert ok, err
    return data['identifier']


def _certificate(manager, identifier):
    path = next(manager.client_certs_dir.glob(f'*/{identifier}/{identifier}.crt'))
    return x509.load_pem_x509_certificate(path.read_bytes())


def _metadata(manager, identifier):
    return json.loads(next(manager.client_certs_dir.glob(f'*/{identifier}/metadata.json')).read_text())


def _key_usage(cert):
    return cert.extensions.get_extension_for_class(x509.KeyUsage).value


def test_an_ecdsa_p384_certificate_is_p384_and_signs_only(manager):
    identifier = _create(manager, key_type='ecdsa', elliptic_curve='secp384r1')
    cert = _certificate(manager, identifier)

    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == 'secp384r1'
    assert _key_usage(cert).digital_signature and not _key_usage(cert).key_encipherment
    record = _metadata(manager, identifier)
    assert (record['key_type'], record['elliptic_curve']) == ('ecdsa', 'secp384r1')
    assert record['key_usage'] == ['digitalSignature']


def test_rsa_3072_is_offered_and_keeps_key_encipherment(manager):
    cert = _certificate(manager, _create(manager, key_type='rsa', key_size=3072))

    assert isinstance(cert.public_key(), rsa.RSAPublicKey) and cert.public_key().key_size == 3072
    assert _key_usage(cert).key_encipherment


def test_no_choice_is_rsa_2048_as_before(manager):
    cert = _certificate(manager, _create(manager))

    assert cert.public_key().key_size == 2048


def test_a_renewal_generates_the_same_kind_of_key(manager):
    identifier = _create(manager, key_type='ecdsa', elliptic_curve='secp384r1')

    ok, err, renewed = manager.renew_certificate(identifier)

    assert ok, err
    cert = _certificate(manager, renewed['identifier'])
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == 'secp384r1'


def test_a_record_from_before_reads_the_shape_from_its_certificate(manager):
    identifier = _create(manager, key_type='rsa', key_size=4096)
    metadata_file = next(manager.client_certs_dir.glob(f'*/{identifier}/metadata.json'))
    record = json.loads(metadata_file.read_text())
    for field in ('key_type', 'key_size', 'elliptic_curve'):
        record.pop(field)
    metadata_file.write_text(json.dumps(record))

    ok, err, renewed = manager.renew_certificate(identifier)

    assert ok, err
    assert _certificate(manager, renewed['identifier']).public_key().key_size == 4096


# --- what the API accepts ----------------------------------------------------

def _shape(data, settings=None, generate_key=True):
    from flask import Flask

    from modules.api.client_certificates import _client_cert_key_shape
    with Flask(__name__).test_request_context('/'):
        return _client_cert_key_shape(data, settings or {}, generate_key)


def test_a_request_with_no_key_gets_the_settings_default():
    settings = {'client_cert_key_type': 'ecdsa', 'client_cert_key_size': 2048,
                'client_cert_elliptic_curve': 'secp384r1'}

    assert _shape({}, settings) == {'key_type': 'ecdsa', 'key_size': None, 'elliptic_curve': 'secp384r1'}
    assert _shape({}) == {'key_type': 'rsa', 'key_size': 2048, 'elliptic_curve': None}


@pytest.mark.parametrize('data', [
    {'key_type': 'ecdsa', 'elliptic_curve': 'secp521r1'},
    {'key_type': 'rsa', 'key_size': 1024},
    {'key_type': 'dsa'},
    {'key_type': 'rsa', 'key_size': 'big'},
])
def test_a_key_server_certificates_would_not_take_is_refused(data):
    with pytest.raises(HTTPException) as refused:
        _shape(data)
    assert refused.value.code == 400


def test_key_options_beside_a_csr_are_refused_not_ignored():
    with pytest.raises(HTTPException) as refused:
        _shape({'key_type': 'ecdsa', 'elliptic_curve': 'secp384r1'}, generate_key=False)
    assert refused.value.code == 400
    assert _shape({}, generate_key=False) == {}


# --- the setting -------------------------------------------------------------

def test_an_invalid_default_is_refused_on_save():
    from modules.core.settings import _invalid_key_defaults

    assert _invalid_key_defaults({'client_cert_key_type': 'ecdsa', 'client_cert_key_size': 2048,
                                  'client_cert_elliptic_curve': 'secp384r1'}, 'client_cert_') == ''
    assert _invalid_key_defaults({'client_cert_key_type': 'ecdsa', 'client_cert_key_size': 2048,
                                  'client_cert_elliptic_curve': 'secp521r1'}, 'client_cert_')


def test_the_setting_is_not_masked_as_a_secret():
    from modules.core.settings import mask_secrets_in_settings

    masked = mask_secrets_in_settings({'client_cert_key_type': 'ecdsa', 'client_cert_key_size': 2048,
                                       'client_cert_elliptic_curve': 'secp384r1'})
    assert masked == {'client_cert_key_type': 'ecdsa', 'client_cert_key_size': 2048,
                      'client_cert_elliptic_curve': 'secp384r1'}
