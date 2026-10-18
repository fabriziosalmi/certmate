"""Finalize, issuance from the ACME root, download and revocation (#476).

A ready order is finalized with a CSR that proves its key and names exactly
the order's names; the certificate is built by the server from the order, not
copied from the CSR, signed by a root of its own (D1, G1, G2), and served as
the leaf alone (G3). The account that ordered it, or the certificate's own
key, can revoke it (G4), and the CRL at /acme/crl says so.
"""
import datetime
import ipaddress
import sqlite3
import zipfile

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from josepy import JWKEC, JWKRSA

from tests.acme_support import (
    AcmeTestClient,
    ChallengeServer,
    b64s,
    eab_for,
    problem,
    registered_client,
    served_app,
)
from tests.test_the_acme_server_validates_orders import _order, _serve

pytestmark = [pytest.mark.unit]


@pytest.fixture
def responder():
    server = ChallengeServer()
    yield server
    server.close()


@pytest.fixture
def app(responder):
    return served_app(responder)


@pytest.fixture
def eab(app):
    return eab_for(app)


@pytest.fixture
def client(app, eab):
    return registered_client(app, eab)


def _csr(names, key=None, common_name=None, extra_san=()):
    key = key or ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)] if common_name else [])
    san = [x509.DNSName(n) for n in names] + list(extra_san)
    csr = (x509.CertificateSigningRequestBuilder().subject_name(subject)
           .add_extension(x509.SubjectAlternativeName(san), critical=False).sign(key, hashes.SHA256()))
    return csr, key


def _der(csr):
    return b64s(csr.public_bytes(serialization.Encoding.DER))


def _ready(client, responder, *names):
    order = _order(client, *names)
    for authz_url in order.get_json()['authorizations']:
        challenge = client.post(authz_url, None).get_json()['challenges'][0]
        _serve(client, responder, challenge)
        assert client.post(challenge['url'], {}).get_json()['status'] == 'valid'
    return order.headers['Location']


def _issue(client, responder, names=('web.lab.internal', 'api.lab.internal'), key=None):
    location = _ready(client, responder, *names)
    csr, key = _csr(list(names), key=key)
    finalized = client.post(location + '/finalize', {'csr': _der(csr)})
    assert finalized.status_code == 200, finalized.get_data(as_text=True)
    pem = client.post(finalized.get_json()['certificate'], None)
    return location, finalized, pem, key


def _root(client):
    return x509.load_pem_x509_certificate(client.http.get(client.url('root')).data)


# --- issuance ------------------------------------------------------------------

def test_a_ready_order_becomes_a_certificate_built_from_the_order(client, responder):
    _location, finalized, pem, key = _issue(client, responder)
    assert finalized.get_json()['status'] == 'valid'
    assert pem.mimetype == 'application/pem-certificate-chain'
    chain = x509.load_pem_x509_certificates(pem.data)
    assert len(chain) == 1  # G3: the leaf alone
    cert = chain[0]
    root = _root(client)
    cert.verify_directly_issued_by(root)  # raises unless the root signed it
    assert cert.issuer == root.subject
    assert root.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.startswith('CertMate ACME CA ')
    assert cert.subject == x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'web.lab.internal')])
    assert cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
        x509.DNSName) == ['web.lab.internal', 'api.lab.internal']
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
    assert list(eku.value) == [ExtendedKeyUsageOID.SERVER_AUTH] and eku.critical is False
    ku = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.digital_signature and not ku.key_encipherment  # an EC key
    assert cert.public_key().public_numbers() == key.public_key().public_numbers()
    lifetime = cert.not_valid_after_utc - cert.not_valid_before_utc
    assert datetime.timedelta(days=30) <= lifetime <= datetime.timedelta(days=30, minutes=6)


def test_an_rsa_key_also_gets_key_encipherment(client, responder):
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _location, _finalized, pem, _key = _issue(client, responder, ('web.lab.internal',), key=rsa_key)
    cert = x509.load_pem_x509_certificate(pem.data)
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_encipherment


def test_the_validity_follows_the_option(app, client, responder):
    from tests.acme_support import enable
    server = app.extensions['certmate_container'].managers['acme_server']
    enable(app, eab_keys=server.config()['eab_keys'], validity_days=7)
    _location, _finalized, pem, _key = _issue(client, responder, ('web.lab.internal',))
    cert = x509.load_pem_x509_certificate(pem.data)
    assert cert.not_valid_after_utc - cert.not_valid_before_utc <= datetime.timedelta(days=7, minutes=6)


def test_the_acme_root_is_not_the_client_certificate_ca(app, client, responder):
    _issue(client, responder, ('web.lab.internal',))
    client_ca = app.extensions['certmate_container'].managers['private_ca'].get_ca_certificate()
    assert _root(client).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != \
        client_ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@pytest.mark.parametrize('make,because', [
    (lambda: _csr(['web.lab.internal']), 'must be the same'),
    (lambda: _csr(['web.lab.internal', 'api.lab.internal', 'db.lab.internal']), 'must be the same'),
    (lambda: _csr(['web.lab.internal', 'api.lab.internal'], common_name='other.lab.internal'), 'must be the same'),
    (lambda: _csr(['web.lab.internal', 'api.lab.internal'],
                  extra_san=[x509.IPAddress(ipaddress.ip_address('10.0.0.1'))]), 'DNS names only'),
    (lambda: _csr(['web.lab.internal', 'api.lab.internal'], key=ec.generate_private_key(ec.SECP521R1())),
     'P-256 or P-384'),
])
def test_a_csr_that_does_not_match_its_order_is_refused(client, responder, make, because):
    location = _ready(client, responder, 'web.lab.internal', 'api.lab.internal')
    csr, _key = make()
    response = client.post(location + '/finalize', {'csr': _der(csr)})
    assert problem(response, because) == 'badCSR'
    assert client.post(location, None).get_json()['status'] == 'ready'


def test_a_csr_with_a_broken_signature_is_refused(client, responder):
    location = _ready(client, responder, 'web.lab.internal')
    csr, _key = _csr(['web.lab.internal'])
    der = bytearray(csr.public_bytes(serialization.Encoding.DER))
    der[-5] ^= 0xFF
    response = client.post(location + '/finalize', {'csr': b64s(bytes(der))})
    assert problem(response, 'does not verify') == 'badCSR'


def test_a_csr_that_is_no_csr_is_refused(client, responder):
    location = _ready(client, responder, 'web.lab.internal')
    assert problem(client.post(location + '/finalize', {'csr': 'bm90IGEgY3Ny'}), 'base64url DER') == 'badCSR'


def test_an_order_that_is_not_ready_cannot_be_finalized(client):
    location = _order(client, 'web.lab.internal').headers['Location']
    csr, _key = _csr(['web.lab.internal'])
    response = client.post(location + '/finalize', {'csr': _der(csr)})
    assert response.status_code == 403 and problem(response, 'pending, not ready') == 'orderNotReady'


def test_an_order_is_finalized_once(client, responder):
    location, _finalized, _pem, _key = _issue(client, responder, ('web.lab.internal',))
    csr, _key = _csr(['web.lab.internal'])
    assert problem(client.post(location + '/finalize', {'csr': _der(csr)}), 'valid, not ready') == 'orderNotReady'


def test_of_two_finalizes_only_one_issues(app, client, responder):
    location = _ready(client, responder, 'web.lab.internal')
    store = app.extensions['certmate_container'].managers['acme_server'].store
    order_id = location.rsplit('/', 1)[-1]
    assert store.begin_finalize(order_id) is True
    assert store.begin_finalize(order_id) is False


def test_an_issuance_that_fails_leaves_the_order_ready(app, client, responder, monkeypatch):
    location = _ready(client, responder, 'web.lab.internal')
    server = app.extensions['certmate_container'].managers['acme_server']

    def fails(*args, **kwargs):
        raise RuntimeError('The ACME CA could not be created or loaded')

    monkeypatch.setattr(server.ca, 'issue', fails)
    csr, _key = _csr(['web.lab.internal'])
    response = client.post(location + '/finalize', {'csr': _der(csr)})
    assert response.status_code == 500
    assert client.post(location, None).get_json()['status'] == 'ready'


def test_an_account_downloads_only_its_own_certificates(app, eab, client, responder):
    _location, finalized, _pem, _key = _issue(client, responder, ('web.lab.internal',))
    other = AcmeTestClient(app)
    assert other.new_account(eab).status_code == 201
    assert problem(other.post(finalized.get_json()['certificate'], None), 'No certificate') == 'unauthorized'
    assert problem(client.post(finalized.get_json()['certificate'], {}), 'POST-as-GET') == 'malformed'


# --- revocation ---------------------------------------------------------------

def _revoke(client, pem, **kwargs):
    cert = x509.load_pem_x509_certificate(pem.data)
    payload = {'certificate': b64s(cert.public_bytes(serialization.Encoding.DER))}
    payload.update({k: v for k, v in kwargs.items() if k == 'reason'})
    extra = {k: v for k, v in kwargs.items() if k != 'reason'}
    return client.post('revoke-cert', payload, **extra), cert


def _crl(client):
    return x509.load_der_x509_crl(client.http.get(client.url('crl')).data)


def test_the_ordering_account_revokes_and_the_crl_says_so(client, responder):
    _location, _finalized, pem, _key = _issue(client, responder, ('web.lab.internal',))
    response, cert = _revoke(client, pem, reason=4)
    assert response.status_code == 200
    crl = _crl(client)
    assert crl.is_signature_valid(_root(client).public_key())
    entry = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    assert entry is not None
    assert entry.extensions.get_extension_for_class(x509.CRLReason).value.reason == x509.ReasonFlags.superseded
    again, _cert = _revoke(client, pem)
    assert problem(again, 'revoked already') == 'alreadyRevoked'


def test_the_certificates_own_key_revokes_it(app, client, responder):
    _location, _finalized, pem, key = _issue(client, responder, ('web.lab.internal',))
    holder = AcmeTestClient(app, key=JWKEC(key=key))
    response, cert = _revoke(holder, pem, kid=None)
    assert response.status_code == 200
    assert _crl(client).get_revoked_certificate_by_serial_number(cert.serial_number) is not None


def test_no_one_else_revokes_it(app, eab, client, responder):
    _location, _finalized, pem, _key = _issue(client, responder, ('web.lab.internal',))
    other = AcmeTestClient(app)
    assert other.new_account(eab).status_code == 201
    response, _cert = _revoke(other, pem)
    assert problem(response, 'Only the account that ordered') == 'unauthorized'
    stranger = AcmeTestClient(app, key=JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048)))
    response, _cert = _revoke(stranger, pem, kid=None)
    assert problem(response, 'neither the ordering account nor the key') == 'unauthorized'


@pytest.mark.parametrize('reason', [2, 6, 7, 8, 9, 10, 11, True, '1'])
def test_a_reason_a_client_may_not_give_is_refused(client, responder, reason):
    _location, _finalized, pem, _key = _issue(client, responder, ('web.lab.internal',))
    response, _cert = _revoke(client, pem, reason=reason)
    assert problem(response, 'must be one of') == 'badRevocationReason'


def test_a_certificate_this_server_did_not_issue_is_refused(client, responder):
    _issue(client, responder, ('web.lab.internal',))
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'web.lab.internal')])
    now = datetime.datetime.now(datetime.UTC)
    foreign = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now)
               .not_valid_after(now + datetime.timedelta(days=1)).sign(key, hashes.SHA256()))
    response = client.post('revoke-cert', {'certificate': b64s(foreign.public_bytes(serialization.Encoding.DER))})
    assert problem(response, 'did not issue') == 'malformed'


# --- what survives -------------------------------------------------------------

def test_a_share_safe_backup_carries_the_acme_root_but_not_its_key(app, client, responder, monkeypatch):
    monkeypatch.delenv('CERTMATE_BACKUP_PASSPHRASE', raising=False)
    _issue(client, responder, ('web.lab.internal',))
    managers = app.extensions['certmate_container'].managers
    managers['file_ops'].create_unified_backup(managers['settings'].load_settings(), 'manual', include_secrets=False)
    archive = sorted((managers['file_ops'].backup_dir / 'unified').glob('*.zip'))[-1]
    with zipfile.ZipFile(archive) as zf:
        names = zf.namelist()
    assert 'data/acme/ca/ca.crt' in names and 'data/acme/ca/ca.key' not in names
    assert 'data/acme/acme.db' in names


def test_the_certificate_is_kept_with_its_order(app, client, responder):
    location, _finalized, pem, _key = _issue(client, responder, ('web.lab.internal',))
    store = app.extensions['certmate_container'].managers['acme_server'].store
    with sqlite3.connect(store.path) as con:
        row = con.execute('SELECT order_id, names, pem FROM certificates').fetchone()
    assert row[0] == location.rsplit('/', 1)[-1] and row[1] == '["web.lab.internal"]'
    assert row[2] == pem.get_data(as_text=True)


def test_a_crl_read_before_a_revocation_is_made_again_after_it(client, responder):
    """The CRL is kept for an hour; a revocation must not wait that hour."""
    _location, _finalized, pem, _key = _issue(client, responder, ('web.lab.internal',))
    before = _crl(client)
    response, cert = _revoke(client, pem)
    assert response.status_code == 200
    assert before.get_revoked_certificate_by_serial_number(cert.serial_number) is None
    assert _crl(client).get_revoked_certificate_by_serial_number(cert.serial_number) is not None
