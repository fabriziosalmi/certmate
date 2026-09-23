"""Tests for the revocation check (``modules/core/revocation.py``).

No mocks of the cryptography: a throwaway CA issues a leaf whose AIA and CRL
distribution point name a real HTTP server on 127.0.0.1, and that server
answers with OCSP responses and CRLs signed by real keys. Each test decides
what the server says — good, revoked, signed by a stranger, stale, redirected,
oversized — and checks that only a *verified* answer is ever reported as good
or revoked.

The server is on loopback, so the checks run with ``allow_private=True``; one
test runs without it to prove the SSRF guard refuses the same URLs.
"""

import http.server
import threading
from datetime import datetime, timedelta, timezone

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from modules.core import revocation
from modules.core.revocation import (
    STATUS_GOOD,
    STATUS_NOT_APPLICABLE,
    STATUS_REVOKED,
    STATUS_UNAVAILABLE,
    STATUS_UNKNOWN,
    check_revocation,
)

pytestmark = [pytest.mark.unit]

NOW = datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# A tiny PKI
# --------------------------------------------------------------------------- #

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _make_ca(key=None, cn='Test Issuing CA'):
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=30))
        .not_valid_after(NOW + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(ca_key, ca_cert, base_url, *, ocsp_path='/ocsp', crl_path='/crl',
               ca_path='/ca.der', cn='leaf.example.com', key=None):
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn)).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=90))
    )
    access = []
    if ocsp_path:
        access.append(x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.OCSP,
            x509.UniformResourceIdentifier(base_url + ocsp_path)))
    if ca_path:
        access.append(x509.AccessDescription(
            x509.oid.AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(base_url + ca_path)))
    if access:
        builder = builder.add_extension(x509.AuthorityInformationAccess(access), critical=False)
    if crl_path:
        builder = builder.add_extension(x509.CRLDistributionPoints([
            x509.DistributionPoint(
                full_name=[x509.UniformResourceIdentifier(base_url + crl_path)],
                relative_name=None, reasons=None, crl_issuer=None)
        ]), critical=False)
    return builder.sign(ca_key, hashes.SHA256())


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def _ocsp_response(leaf, ca_cert, signer_key, signer_cert, *, status='good',
                   revoked_reason=None, this_update=None, next_update=None,
                   cert_id_hash=None, extra_certs=None):
    status_map = {
        'good': ocsp.OCSPCertStatus.GOOD,
        'revoked': ocsp.OCSPCertStatus.REVOKED,
        'unknown': ocsp.OCSPCertStatus.UNKNOWN,
    }
    builder = ocsp.OCSPResponseBuilder().add_response(
        cert=leaf, issuer=ca_cert, algorithm=cert_id_hash or hashes.SHA1(),
        cert_status=status_map[status],
        this_update=this_update or (NOW - timedelta(minutes=1)),
        next_update=next_update if next_update is not None else (NOW + timedelta(days=3)),
        revocation_time=(NOW - timedelta(days=2)) if status == 'revoked' else None,
        revocation_reason=revoked_reason if status == 'revoked' else None,
    ).responder_id(ocsp.OCSPResponderEncoding.HASH, signer_cert)
    if extra_certs:
        builder = builder.certificates(extra_certs)
    return builder.sign(signer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _crl(ca_key, ca_cert, revoked_serials=(), *, next_update=None, reason=None):
    builder = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(NOW - timedelta(hours=1))
        .next_update(next_update or (NOW + timedelta(days=7)))
    )
    for serial in revoked_serials:
        entry = (x509.RevokedCertificateBuilder()
                 .serial_number(serial)
                 .revocation_date(NOW - timedelta(days=1)))
        if reason is not None:
            entry = entry.add_extension(x509.CRLReason(reason), critical=False)
        builder = builder.add_revoked_certificate(entry.build())
    return builder.sign(ca_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


# --------------------------------------------------------------------------- #
# A scripted HTTP server
# --------------------------------------------------------------------------- #

class _Server:
    """Serves ``routes[path] -> (status, body)`` and records every request."""

    def __init__(self):
        self.routes = {}
        self.requests = []
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _answer(self):
                length = int(self.headers.get('Content-Length') or 0)
                body = self.rfile.read(length) if length else b''
                server.requests.append((self.command, self.path, self.headers.get('Host'), body))
                status, payload = server.routes.get(self.path, (404, b''))
                self.send_response(status)
                if status in (301, 302):
                    self.send_header('Location', 'http://127.0.0.1:1/elsewhere')
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = _answer
            do_POST = _answer

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.base_url = f'http://127.0.0.1:{self.httpd.server_address[1]}'
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def paths(self):
        return [p for _m, p, _h, _b in self.requests]

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    revocation.clear_caches()
    s = _Server()
    yield s
    s.close()
    revocation.clear_caches()


@pytest.fixture
def pki(server):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, server.base_url)
    server.routes['/ca.der'] = (200, _der(ca_cert))
    server.routes['/crl'] = (200, _crl(ca_key, ca_cert))
    return ca_key, ca_cert, leaf


def _check(leaf, **kw):
    kw.setdefault('allow_private', True)
    kw.setdefault('timeout', 5.0)
    return check_revocation(_der(leaf), **kw)


# --------------------------------------------------------------------------- #
# OCSP
# --------------------------------------------------------------------------- #

def test_ocsp_good_with_issuer_from_aia(server, pki):
    ca_key, ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, _ocsp_response(leaf, ca_cert, ca_key, ca_cert))
    result = _check(leaf)
    assert result['status'] == STATUS_GOOD
    assert result['method'] == 'ocsp'
    assert result['url'] == server.base_url + '/ocsp'
    assert '/ca.der' in server.paths()
    # The request was a real OCSP request naming this serial.
    method, _path, host, body = [r for r in server.requests if r[1] == '/ocsp'][0]
    assert method == 'POST'
    assert host == server.base_url.split('//')[1]
    assert ocsp.load_der_ocsp_request(body).serial_number == leaf.serial_number


def test_ocsp_revoked_carries_time_and_reason(server, pki):
    ca_key, ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, ca_key, ca_cert, status='revoked',
        revoked_reason=x509.ReasonFlags.key_compromise))
    result = _check(leaf)
    assert result['status'] == STATUS_REVOKED
    assert result['method'] == 'ocsp'
    assert result['reason'] == 'key_compromise'
    assert result['revoked_at'].endswith('Z')


def test_issuer_from_served_chain_skips_the_aia_fetch(server, pki):
    ca_key, ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, _ocsp_response(leaf, ca_cert, ca_key, ca_cert))
    result = _check(leaf, chain_ders=[_der(leaf), _der(ca_cert)])
    assert result['status'] == STATUS_GOOD
    assert '/ca.der' not in server.paths()


def test_ocsp_signed_by_a_stranger_is_not_believed(server, pki):
    """A 'good' signed by a key the issuer never vouched for must not count;
    the CRL, which does verify, is what answers."""
    ca_key, ca_cert, leaf = pki
    stranger_key, stranger_cert = _make_ca(cn='Stranger')
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, stranger_key, stranger_cert, extra_certs=[stranger_cert]))
    result = _check(leaf)
    assert result['status'] == STATUS_GOOD
    assert result['method'] == 'crl'
    ocsp_attempt = result['attempts'][0]
    assert ocsp_attempt['method'] == 'ocsp' and ocsp_attempt['outcome'] == 'error'


def test_forged_revoked_answer_is_not_believed_either(server, pki):
    ca_key, ca_cert, leaf = pki
    stranger_key, stranger_cert = _make_ca(cn='Stranger')
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, stranger_key, stranger_cert, status='revoked',
        extra_certs=[stranger_cert]))
    result = _check(leaf)
    assert result['status'] == STATUS_GOOD
    assert result['method'] == 'crl'


def test_ocsp_with_a_tampered_signature_is_not_believed(server, pki):
    """The responder ID names the issuer and the signer lookup succeeds; only
    the signature check stands between this and a believed 'revoked'."""
    ca_key, ca_cert, leaf = pki
    genuine = _ocsp_response(leaf, ca_cert, ca_key, ca_cert, status='revoked')
    # With no certificates attached, the signature BIT STRING is the last
    # field of the DER, so flipping the final byte breaks only the signature.
    forged = genuine[:-1] + bytes([genuine[-1] ^ 0x01])
    assert ocsp.load_der_ocsp_response(forged).certificate_status == ocsp.OCSPCertStatus.REVOKED
    server.routes['/ocsp'] = (200, forged)
    result = _check(leaf)
    assert result['status'] == STATUS_GOOD
    assert result['method'] == 'crl'
    assert 'signature does not verify' in result['attempts'][0]['error']


def test_replayed_good_answer_for_another_certificate_is_not_believed(server, pki):
    """A genuine, correctly signed 'good' — for a different certificate of the
    same CA. Only the serial match stops it from vouching for this one."""
    ca_key, ca_cert, leaf = pki
    sibling = _make_leaf(ca_key, ca_cert, server.base_url, cn='sibling.example.com')
    server.routes['/ocsp'] = (200, _ocsp_response(sibling, ca_cert, ca_key, ca_cert))
    server.routes['/crl'] = (200, _crl(ca_key, ca_cert, [leaf.serial_number]))
    result = _check(leaf)
    assert result['status'] == STATUS_REVOKED
    assert result['method'] == 'crl'
    assert 'does not cover this certificate' in result['attempts'][0]['error']


def test_ocsp_error_status_is_not_an_answer(server, pki):
    _ca_key, _ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, ocsp.OCSPResponseBuilder.build_unsuccessful(
        ocsp.OCSPResponseStatus.UNAUTHORIZED).public_bytes(serialization.Encoding.DER))
    result = _check(leaf)
    assert result['method'] == 'crl'
    assert 'UNAUTHORIZED' in result['attempts'][0]['error']


def test_ocsp_dated_in_the_future_is_not_believed(server, pki):
    ca_key, ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, ca_key, ca_cert, this_update=NOW + timedelta(days=1),
        next_update=NOW + timedelta(days=5)))
    result = _check(leaf)
    assert result['method'] == 'crl'
    assert 'future' in result['attempts'][0]['error']


def _delegated_responder(ca_key, ca_cert, *, ocsp_signing):
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name('Delegated OCSP Responder')).issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=30))
    )
    if ocsp_signing:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.OCSP_SIGNING]), critical=False)
    return key, builder.sign(ca_key, hashes.SHA256())


def test_delegated_responder_with_ocsp_signing_is_accepted(server, pki):
    ca_key, ca_cert, leaf = pki
    d_key, d_cert = _delegated_responder(ca_key, ca_cert, ocsp_signing=True)
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, d_key, d_cert, extra_certs=[d_cert]))
    result = _check(leaf)
    assert result['status'] == STATUS_GOOD
    assert result['method'] == 'ocsp'


def test_delegated_responder_without_ocsp_signing_is_refused(server, pki):
    ca_key, ca_cert, leaf = pki
    d_key, d_cert = _delegated_responder(ca_key, ca_cert, ocsp_signing=False)
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, d_key, d_cert, extra_certs=[d_cert]))
    result = _check(leaf)
    assert result['method'] == 'crl'
    assert 'not authorised for OCSP signing' in result['attempts'][0]['error']


def test_stale_ocsp_response_falls_back_to_crl(server, pki):
    ca_key, ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, ca_key, ca_cert,
        this_update=NOW - timedelta(days=10), next_update=NOW - timedelta(days=3)))
    result = _check(leaf)
    assert result['method'] == 'crl'
    assert 'stale' in result['attempts'][0]['error']


def test_sha256_cert_id_is_matched(server, pki):
    """A responder may use SHA-256 for the CertID; the issuer key hash is then
    recomputed from the SPKI bits, which is parsed by hand — worth a real test
    on an RSA-2048 issuer, whose SPKI uses long-form DER lengths."""
    ca_key, ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, ca_key, ca_cert, cert_id_hash=hashes.SHA256()))
    result = _check(leaf)
    assert result['status'] == STATUS_GOOD
    assert result['method'] == 'ocsp'


def test_sha256_cert_id_with_ec_issuer(server):
    ca_key, ca_cert = _make_ca(key=ec.generate_private_key(ec.SECP384R1()))
    leaf = _make_leaf(ca_key, ca_cert, server.base_url)
    server.routes['/ca.der'] = (200, _der(ca_cert))
    server.routes['/ocsp'] = (200, _ocsp_response(
        leaf, ca_cert, ca_key, ca_cert, cert_id_hash=hashes.SHA256()))
    assert _check(leaf)['status'] == STATUS_GOOD


def test_ocsp_unknown_without_a_crl_is_unknown(server):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, server.base_url, crl_path=None)
    server.routes['/ca.der'] = (200, _der(ca_cert))
    server.routes['/ocsp'] = (200, _ocsp_response(leaf, ca_cert, ca_key, ca_cert, status='unknown'))
    result = _check(leaf)
    assert result['status'] == STATUS_UNKNOWN


def test_ocsp_unknown_is_settled_by_the_crl(server, pki):
    ca_key, ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, _ocsp_response(leaf, ca_cert, ca_key, ca_cert, status='unknown'))
    server.routes['/crl'] = (200, _crl(ca_key, ca_cert, [leaf.serial_number]))
    result = _check(leaf)
    assert result['status'] == STATUS_REVOKED
    assert result['method'] == 'crl'


# --------------------------------------------------------------------------- #
# CRL
# --------------------------------------------------------------------------- #

def test_crl_only_certificate_revoked(server):
    """Let's Encrypt stopped OCSP in 2025: a CRL-only certificate is the
    common case now, not an edge case."""
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, server.base_url, ocsp_path=None)
    server.routes['/ca.der'] = (200, _der(ca_cert))
    server.routes['/crl'] = (200, _crl(ca_key, ca_cert, [leaf.serial_number],
                                       reason=x509.ReasonFlags.superseded))
    result = _check(leaf)
    assert result['status'] == STATUS_REVOKED
    assert result['method'] == 'crl'
    assert result['reason'] == 'superseded'


def test_crl_signed_by_another_key_is_unavailable(server):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, server.base_url, ocsp_path=None)
    impostor_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server.routes['/ca.der'] = (200, _der(ca_cert))
    # Same issuer name, wrong key.
    server.routes['/crl'] = (200, _crl(impostor_key, ca_cert))
    result = _check(leaf)
    assert result['status'] == STATUS_UNAVAILABLE
    assert 'does not verify' in result['error']


def test_crl_from_another_issuer_is_unavailable(server):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, server.base_url, ocsp_path=None)
    other_key, other_cert = _make_ca(cn='Some Other CA')
    server.routes['/ca.der'] = (200, _der(ca_cert))
    server.routes['/crl'] = (200, _crl(other_key, other_cert, [leaf.serial_number]))
    result = _check(leaf)
    assert result['status'] == STATUS_UNAVAILABLE
    assert 'not issued by this certificate' in result['error']


def test_stale_crl_is_unavailable(server):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, server.base_url, ocsp_path=None)
    server.routes['/ca.der'] = (200, _der(ca_cert))
    stale = (x509.CertificateRevocationListBuilder()
             .issuer_name(ca_cert.subject)
             .last_update(NOW - timedelta(days=10))
             .next_update(NOW - timedelta(days=3))
             .sign(ca_key, hashes.SHA256()))
    server.routes['/crl'] = (200, stale.public_bytes(serialization.Encoding.DER))
    result = _check(leaf)
    assert result['status'] == STATUS_UNAVAILABLE
    assert 'stale' in result['error']


def test_crl_is_fetched_once_for_many_certificates(server):
    ca_key, ca_cert = _make_ca()
    leaves = [_make_leaf(ca_key, ca_cert, server.base_url, ocsp_path=None, cn=f'h{i}.example.com')
              for i in range(3)]
    server.routes['/ca.der'] = (200, _der(ca_cert))
    server.routes['/crl'] = (200, _crl(ca_key, ca_cert))
    for leaf in leaves:
        assert _check(leaf)['status'] == STATUS_GOOD
    assert server.paths().count('/crl') == 1
    assert server.paths().count('/ca.der') == 1


def test_oversized_crl_is_refused(server, monkeypatch):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, server.base_url, ocsp_path=None)
    server.routes['/ca.der'] = (200, _der(ca_cert))
    server.routes['/crl'] = (200, _crl(ca_key, ca_cert))
    monkeypatch.setattr(revocation, 'MAX_CRL_BYTES', 100)
    result = _check(leaf)
    assert result['status'] == STATUS_UNAVAILABLE
    assert 'more than 100 bytes' in result['error']


# --------------------------------------------------------------------------- #
# What is never reported as good
# --------------------------------------------------------------------------- #

def test_self_signed_is_not_applicable(server):
    _key, cert = _make_ca()
    assert _check(cert)['status'] == STATUS_NOT_APPLICABLE
    assert server.requests == []


def test_no_ocsp_and_no_crl_is_unavailable(server):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, server.base_url, ocsp_path=None, crl_path=None)
    result = _check(leaf)
    assert result['status'] == STATUS_UNAVAILABLE
    assert 'neither an OCSP responder nor a CRL' in result['error']


def test_issuer_that_did_not_sign_the_leaf_is_unavailable(server, pki):
    _ca_key, _ca_cert, leaf = pki
    _other_key, other = _make_ca(cn='Test Issuing CA')  # same name, other key
    server.routes['/ca.der'] = (200, _der(other))
    result = _check(leaf)
    assert result['status'] == STATUS_UNAVAILABLE
    assert 'issuer not available' in result['error']


def test_every_source_down_is_unavailable_not_good(server, pki):
    _ca_key, _ca_cert, leaf = pki
    server.routes['/ocsp'] = (503, b'')
    server.routes['/crl'] = (500, b'')
    result = _check(leaf)
    assert result['status'] == STATUS_UNAVAILABLE
    assert [a['method'] for a in result['attempts']] == ['ocsp', 'crl']


def test_redirects_are_not_followed(server, pki):
    _ca_key, _ca_cert, leaf = pki
    server.routes['/ocsp'] = (302, b'')
    server.routes['/crl'] = (301, b'')
    result = _check(leaf)
    assert result['status'] == STATUS_UNAVAILABLE
    assert 'HTTP 301' in result['error']
    assert '/elsewhere' not in server.paths()


def test_ssrf_guard_refuses_loopback_urls(server, pki):
    """The URLs come from a certificate someone else wrote: without the
    operator's opt-in, a loopback responder is never contacted."""
    ca_key, ca_cert, leaf = pki
    server.routes['/ocsp'] = (200, _ocsp_response(leaf, ca_cert, ca_key, ca_cert))
    result = _check(leaf, allow_private=False)
    assert result['status'] == STATUS_UNAVAILABLE
    assert 'SSRF guard' in result['error']
    assert server.requests == []


def test_https_urls_are_not_fetched(server):
    ca_key, ca_cert = _make_ca()
    leaf = _make_leaf(ca_key, ca_cert, 'https://127.0.0.1:1', ca_path=None)
    result = _check(leaf, chain_ders=[_der(ca_cert)])
    assert result['status'] == STATUS_UNAVAILABLE
    assert "unsupported URL scheme 'https'" in result['error']


def test_garbage_input_never_raises():
    result = check_revocation(b'not a certificate', allow_private=True)
    assert result['status'] == STATUS_UNAVAILABLE


# --------------------------------------------------------------------------- #
# Through the probe
# --------------------------------------------------------------------------- #

def test_probe_reports_revocation_only_when_asked(server, tmp_path):
    """End to end: a TLS server serves a leaf that its CA has put on the CRL.
    The probe describes it as before and, when asked, says it is revoked."""
    from modules.core.cert_probe import probe_certificate
    from tests.test_cert_probe import _TLSServer, _write_pemfile

    ca_key, ca_cert = _make_ca()
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = _make_leaf(ca_key, ca_cert, server.base_url, ocsp_path=None,
                      cn='localhost', key=leaf_key)
    server.routes['/ca.der'] = (200, _der(ca_cert))
    server.routes['/crl'] = (200, _crl(ca_key, ca_cert, [leaf.serial_number]))

    tls = _TLSServer(_write_pemfile(tmp_path / 'chain.pem', leaf),
                     _write_pemfile(tmp_path / 'key.pem', key=leaf_key))
    try:
        plain = probe_certificate('127.0.0.1', port=tls.port, allow_private=True,
                                  server_name='localhost')
        assert plain['status'] == 'ok'
        assert plain['revocation'] is None
        assert server.requests == []

        checked = probe_certificate('127.0.0.1', port=tls.port, allow_private=True,
                                    server_name='localhost', check_revocation=True)
    finally:
        tls.close()
    assert checked['status'] == 'ok'
    assert checked['revocation']['status'] == STATUS_REVOKED
    assert checked['revocation']['method'] == 'crl'
