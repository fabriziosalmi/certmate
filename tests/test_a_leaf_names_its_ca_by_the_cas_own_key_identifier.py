"""A leaf names its CA by the identifier the CA certificate carries (#1562).

A relying party finds the CA of a certificate by matching the leaf's
Authority Key Identifier against the Subject Key Identifier of the CA
certificates it holds. Since #1554 a CRL copies the CA's SKI, but a leaf
still derived its AKI from the CA's public key. For a CA that CertMate made
the two are equal; for a CA certificate made elsewhere, with an SKI computed
another way, the leaf named a CA nobody holds.

The ACME server's renewal information (RFC 9773) is keyed by the same value:
a client computes the identifier from the leaf's AKI, so the server must
compare it with what it put there, or it no longer finds its own
certificates. The three CA kinds are the ones #1554 tests the CRL with.
"""
import datetime

import pytest
from acme import client as acme_client
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from modules.core.acme_ca import AcmeCA
from modules.core.private_ca import PrivateCAGenerator
from tests.acme_support import ChallengeServer, eab_for, registered_client, served_app
from tests.test_a_crl_carries_its_authority_key_and_a_number_that_grows import SIGNERS, _root_with_ski
from tests.test_the_acme_server_issues_and_revokes import _issue

pytestmark = [pytest.mark.unit]


def _csr(name='leaf.lab.internal'):
    key = ec.generate_private_key(ec.SECP256R1())
    return (x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
            .sign(key, hashes.SHA256()))


def _aki(cert):
    return cert.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier


@pytest.fixture(params=sorted(SIGNERS))
def signer(request):
    return SIGNERS[request.param]


def test_a_client_certificate_names_its_ca_by_the_cas_identifier(tmp_path, signer):
    ca_dir = tmp_path / 'ca'
    _cert, expected = signer(ca_dir)
    ca = PrivateCAGenerator(ca_dir)
    assert ca.initialize()
    leaf = ca.sign_certificate_request(_csr())
    assert leaf is not None
    assert _aki(leaf) == expected


def test_an_acme_certificate_names_its_ca_by_the_cas_identifier(tmp_path, signer):
    ca_dir = tmp_path / 'acme'
    _cert, expected = signer(ca_dir)
    leaf = AcmeCA(ca_dir).issue(_csr(), [{'type': 'dns', 'value': 'leaf.lab.internal'}], days=7)
    assert _aki(leaf) == expected


def test_the_acme_server_finds_a_certificate_from_a_ca_made_elsewhere_by_its_renewal_id():
    """The whole path, with a root whose SKI no key method yields: issued by the
    ACME server, the identifier computed by certbot's own function from the
    leaf, and the renewal information found under it."""
    responder = ChallengeServer()
    try:
        app = served_app(responder)
        server = app.extensions['certmate_container'].managers['acme_server']
        ca_dir = server.ca.generator.ca_dir
        assert not (ca_dir / 'ca.crt').exists(), 'the test app already made its ACME root'
        _root_cert, odd_ski = _root_with_ski(ca_dir)
        client = registered_client(app, eab_for(app))
        _location, _finalized, pem, _key = _issue(client, responder)
        leaf = x509.load_pem_x509_certificate(pem.data)
        assert _aki(leaf) == odd_ski
        response = client.http.get(client.url('renewal-info/' + acme_client._renewal_info_path_component(leaf)))
        assert response.status_code == 200, response.get_data(as_text=True)
        assert 'suggestedWindow' in response.get_json()
    finally:
        responder.close()


def test_the_identifier_of_a_ca_that_certmate_made_does_not_change(tmp_path):
    """For CertMate's own CAs the SKI is the key-derived value, so leaves, CRLs
    and renewal identifiers stay what they were before this change."""
    ca = PrivateCAGenerator(tmp_path / 'ca', key_algorithm='ecdsa-p256')
    assert ca.initialize()
    derived = x509.AuthorityKeyIdentifier.from_issuer_public_key(
        ca.get_ca_certificate().public_key()).key_identifier
    assert _aki(ca.sign_certificate_request(_csr())) == derived


def test_a_ca_with_its_own_ski_is_what_the_other_tests_are_about(tmp_path):
    """The control: the root these tests use really carries an SKI that the
    key would not produce, so an AKI equal to it can only have been copied."""
    cert, odd_ski = _root_with_ski(tmp_path / 'ca')
    derived = x509.AuthorityKeyIdentifier.from_issuer_public_key(cert.public_key()).key_identifier
    assert odd_ski != derived
    assert datetime.datetime.now(datetime.UTC) < cert.not_valid_after_utc
