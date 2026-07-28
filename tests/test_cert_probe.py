"""Tests for the deep TLS certificate probe (``modules/core/cert_probe.py``).

Covers the three surfaces of #467:

* :func:`parse_certificate` — offline parsing of RSA / ECDSA / Ed25519 certs,
  with and without SAN, self-signed, CA-signed, expired and not-yet-valid, plus
  hostname matching (exact / wildcard / IP / mismatch).
* :func:`ip_is_blocked` and the SSRF guard — private/loopback/link-local/
  reserved targets are refused by default.
* :func:`probe_certificate` — end-to-end against a throwaway in-process TLS
  server, plus the blocked / unreachable / DNS-failure status paths.
"""

import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from modules.core import cert_probe
from modules.core.cert_probe import (
    ip_is_blocked,
    parse_certificate,
    probe_certificate,
    STATUS_BLOCKED,
    STATUS_OK,
    STATUS_UNREACHABLE,
    ERR_DNS,
)

pytestmark = [pytest.mark.unit]


# --------------------------------------------------------------------------- #
# Certificate fixtures
# --------------------------------------------------------------------------- #

def _build_cert(
    *,
    subject_cn='example.com',
    issuer_cn=None,
    san_dns=None,
    san_ip=None,
    key=None,
    issuer_key=None,
    not_before=None,
    not_after=None,
):
    """Build a throwaway certificate. Self-signed unless *issuer_cn*/key given."""
    now = datetime.now(timezone.utc)
    not_before = not_before or (now - timedelta(days=1))
    not_after = not_after or (now + timedelta(days=90))
    key = key or rsa.generate_private_key(public_exponent=65537, key_size=2048)
    issuer_cn = issuer_cn or subject_cn
    issuer_key = issuer_key or key  # self-signed by default

    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)])

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    san_entries = []
    for name in (san_dns or []):
        san_entries.append(x509.DNSName(name))
    for ip in (san_ip or []):
        import ipaddress
        san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if san_entries:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries), critical=False
        )

    # Ed25519 signs without a hash algorithm; RSA/EC need one.
    if isinstance(issuer_key, ed25519.Ed25519PrivateKey):
        cert = builder.sign(issuer_key, None)
    else:
        cert = builder.sign(issuer_key, hashes.SHA256())
    return cert, key


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def _write_pemfile(path, *certs, key=None):
    """Write a cert-chain (+ optional key) PEM file, return its path."""
    data = b''.join(_pem(c) for c in certs)
    if key is not None:
        data += key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    path.write_bytes(data)
    return str(path)


# --------------------------------------------------------------------------- #
# parse_certificate — key types
# --------------------------------------------------------------------------- #

def test_parse_rsa_with_san():
    cert, _ = _build_cert(
        subject_cn='rsa.example.com',
        san_dns=['rsa.example.com', 'www.rsa.example.com'],
    )
    out = parse_certificate(_der(cert))
    c = out['certificate']
    assert c['subject_cn'] == 'rsa.example.com'
    assert c['key']['type'] == 'RSA'
    assert c['key']['size'] == 2048
    assert c['san_dns'] == ['rsa.example.com', 'www.rsa.example.com']
    assert c['fingerprint_sha256'] == cert.fingerprint(hashes.SHA256()).hex()
    assert c['serial_number'] == str(cert.serial_number)
    assert 'rsa' in c['signature_algorithm'].lower()
    assert out['validation']['is_self_signed'] is True


def test_parse_ecdsa_reports_curve():
    key = ec.generate_private_key(ec.SECP256R1())
    cert, _ = _build_cert(subject_cn='ec.example.com', key=key)
    c = parse_certificate(_der(cert))['certificate']
    assert c['key']['type'] == 'ECDSA'
    assert c['key']['curve'] == 'secp256r1'
    assert c['key']['size'] == 256


def test_parse_ed25519():
    key = ed25519.Ed25519PrivateKey.generate()
    cert, _ = _build_cert(subject_cn='ed.example.com', key=key)
    c = parse_certificate(_der(cert))['certificate']
    assert c['key']['type'] == 'Ed25519'


def test_parse_pem_and_der_equivalent():
    cert, _ = _build_cert()
    from_der = parse_certificate(_der(cert))['certificate']
    from_pem = parse_certificate(_pem(cert))['certificate']
    assert from_der['fingerprint_sha256'] == from_pem['fingerprint_sha256']


def test_parse_no_san_list_is_empty():
    cert, _ = _build_cert(subject_cn='nosan.example.com')
    c = parse_certificate(_der(cert))['certificate']
    assert c['san_dns'] == []
    assert c['san_ip'] == []


def test_parse_full_issuer_dn():
    cert, _ = _build_cert(subject_cn='leaf.example.com', issuer_cn='My Issuing CA',
                          issuer_key=rsa.generate_private_key(
                              public_exponent=65537, key_size=2048))
    c = parse_certificate(_der(cert))['certificate']
    assert c['issuer_cn'] == 'My Issuing CA'
    assert 'My Issuing CA' in c['issuer']


def test_parse_invalid_bytes_raises():
    with pytest.raises(ValueError):
        parse_certificate(b'not a certificate')


# --------------------------------------------------------------------------- #
# parse_certificate — validity
# --------------------------------------------------------------------------- #

def test_expired_certificate():
    now = datetime.now(timezone.utc)
    cert, _ = _build_cert(
        not_before=now - timedelta(days=400),
        not_after=now - timedelta(days=10),
    )
    v = parse_certificate(_der(cert))['validation']
    c = parse_certificate(_der(cert))['certificate']
    assert v['is_expired'] is True
    assert v['not_yet_valid'] is False
    assert c['days_until_expiry'] < 0


def test_not_yet_valid_certificate():
    now = datetime.now(timezone.utc)
    cert, _ = _build_cert(
        not_before=now + timedelta(days=5),
        not_after=now + timedelta(days=90),
    )
    v = parse_certificate(_der(cert))['validation']
    assert v['not_yet_valid'] is True
    assert v['is_expired'] is False


def test_ca_signed_is_not_self_signed():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert, _ = _build_cert(subject_cn='leaf.example.com', issuer_cn='Real CA',
                          issuer_key=ca_key)
    v = parse_certificate(_der(cert))['validation']
    assert v['is_self_signed'] is False


def test_days_until_expiry_positive():
    now = datetime.now(timezone.utc)
    cert, _ = _build_cert(not_after=now + timedelta(days=30))
    c = parse_certificate(_der(cert))['certificate']
    assert 28 <= c['days_until_expiry'] <= 30


# --------------------------------------------------------------------------- #
# parse_certificate — hostname matching
# --------------------------------------------------------------------------- #

def test_hostname_match_exact():
    cert, _ = _build_cert(san_dns=['host.example.com'])
    v = parse_certificate(_der(cert), server_name='host.example.com')['validation']
    assert v['hostname_match'] is True


def test_hostname_match_wildcard():
    cert, _ = _build_cert(san_dns=['*.example.com'])
    v = parse_certificate(_der(cert), server_name='api.example.com')['validation']
    assert v['hostname_match'] is True


def test_hostname_wildcard_does_not_span_labels():
    cert, _ = _build_cert(san_dns=['*.example.com'])
    v = parse_certificate(_der(cert), server_name='a.b.example.com')['validation']
    assert v['hostname_match'] is False


def test_hostname_wildcard_does_not_match_apex():
    cert, _ = _build_cert(san_dns=['*.example.com'])
    v = parse_certificate(_der(cert), server_name='example.com')['validation']
    assert v['hostname_match'] is False


def test_hostname_mismatch():
    cert, _ = _build_cert(san_dns=['host.example.com'])
    v = parse_certificate(_der(cert), server_name='other.example.com')['validation']
    assert v['hostname_match'] is False


def test_hostname_falls_back_to_cn_without_san():
    cert, _ = _build_cert(subject_cn='cn-only.example.com')
    v = parse_certificate(_der(cert), server_name='cn-only.example.com')['validation']
    assert v['hostname_match'] is True


def test_hostname_ip_san_match():
    cert, _ = _build_cert(subject_cn='ip.example.com', san_ip=['203.0.113.10'])
    v = parse_certificate(_der(cert), server_name='203.0.113.10')['validation']
    assert v['hostname_match'] is True


def test_hostname_none_when_not_requested():
    cert, _ = _build_cert(san_dns=['host.example.com'])
    v = parse_certificate(_der(cert))['validation']
    assert v['hostname_match'] is None


# --------------------------------------------------------------------------- #
# SSRF guard
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize('addr', [
    '127.0.0.1', '::1',                 # loopback
    '10.0.0.1', '192.168.1.1', '172.16.5.5',  # RFC 1918
    'fc00::1', 'fd12:3456::1',          # ULA
    '169.254.1.1', 'fe80::1',           # link-local
    '0.0.0.0', '::',                    # unspecified
    '::ffff:10.0.0.1',                  # IPv4-mapped private
    '224.0.0.1',                        # multicast
])
def test_ip_is_blocked_rejects_sensitive(addr):
    assert ip_is_blocked(addr) is not None


@pytest.mark.parametrize('addr', [
    '1.1.1.1', '8.8.8.8', '9.9.9.9', '2606:4700:4700::1111',
])
def test_ip_is_blocked_allows_public(addr):
    assert ip_is_blocked(addr) is None


def test_probe_blocks_loopback_by_default():
    result = probe_certificate('127.0.0.1', port=443)
    assert result['status'] == STATUS_BLOCKED
    assert result['certificate'] is None
    assert 'SSRF' in result['error'] or 'loopback' in result['error']


def test_probe_dns_failure_is_unreachable():
    # `.invalid` is reserved by RFC 6761 to never resolve.
    result = probe_certificate('nonexistent-host.invalid')
    assert result['status'] == STATUS_UNREACHABLE
    assert result['error_class'] == ERR_DNS


# --------------------------------------------------------------------------- #
# probe_certificate — live in-process TLS server
# --------------------------------------------------------------------------- #

class _TLSServer:
    """A single-shot TLS server on 127.0.0.1, serving a given cert chain."""

    def __init__(self, certfile, keyfile):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(('127.0.0.1', 0))
        self._sock.listen(5)
        self.port = self._sock.getsockname()[1]
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(certfile, keyfile)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._running = True
        self._thread.start()

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            try:
                with self._ctx.wrap_socket(conn, server_side=True) as s:
                    s.recv(16)
            except (OSError, ssl.SSLError):
                pass

    def close(self):
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass


@pytest.fixture
def tls_server(tmp_path):
    servers = []

    def _start(*certs, key):
        certfile = _write_pemfile(tmp_path / 'chain.pem', *certs)
        keyfile = _write_pemfile(tmp_path / 'key.pem', key=key)
        srv = _TLSServer(certfile, keyfile)
        servers.append(srv)
        return srv

    yield _start
    for srv in servers:
        srv.close()


def test_probe_live_server_ok(tls_server):
    cert, key = _build_cert(subject_cn='localhost', san_dns=['localhost'])
    srv = tls_server(cert, key=key)

    result = probe_certificate('127.0.0.1', port=srv.port,
                               allow_private=True, server_name='localhost')
    assert result['status'] == STATUS_OK
    c = result['certificate']
    assert c['subject_cn'] == 'localhost'
    assert c['key']['type'] == 'RSA'
    assert c['fingerprint_sha256'] == cert.fingerprint(hashes.SHA256()).hex()
    assert result['validation']['hostname_match'] is True
    assert result['validation']['is_self_signed'] is True
    assert len(result['chain']) >= 1
    assert result['connect_ip'] == '127.0.0.1'
    assert result['probed_at']


def test_probe_live_server_serves_chain(tls_server):
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert, _ = _build_cert(subject_cn='Test CA', key=ca_key)
    leaf_cert, leaf_key = _build_cert(
        subject_cn='localhost', san_dns=['localhost'],
        issuer_cn='Test CA', issuer_key=ca_key,
    )
    srv = tls_server(leaf_cert, ca_cert, key=leaf_key)

    result = probe_certificate('127.0.0.1', port=srv.port,
                               allow_private=True, server_name='localhost')
    assert result['status'] == STATUS_OK
    assert result['chain'][0]['subject_cn'] == 'localhost'
    assert result['validation']['is_self_signed'] is False
    # Full served chain (leaf + intermediate) is only exposed by the stdlib on
    # Python 3.13+; older interpreters report the leaf alone.
    if hasattr(ssl.SSLSocket, 'get_unverified_chain'):
        assert len(result['chain']) == 2
    else:
        assert len(result['chain']) == 1


def test_probe_expired_cert_still_described(tls_server):
    now = datetime.now(timezone.utc)
    cert, key = _build_cert(
        subject_cn='localhost', san_dns=['localhost'],
        not_before=now - timedelta(days=400), not_after=now - timedelta(days=1),
    )
    srv = tls_server(cert, key=key)

    result = probe_certificate('127.0.0.1', port=srv.port,
                               allow_private=True, server_name='localhost')
    assert result['status'] == STATUS_OK
    assert result['validation']['is_expired'] is True


def test_probe_connection_refused_is_unreachable():
    # Bind then close to obtain a definitely-closed local port.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()

    result = probe_certificate('127.0.0.1', port=port, allow_private=True,
                               timeout=2)
    assert result['status'] == STATUS_UNREACHABLE
    assert result['error_class'] in ('connection_error', 'timeout')


def test_probe_plaintext_port_is_tls_error(tls_server):
    # A plain (non-TLS) listener → handshake fails cleanly, not a crash.
    plain = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    plain.bind(('127.0.0.1', 0))
    plain.listen(1)
    port = plain.getsockname()[1]

    def _accept():
        try:
            conn, _ = plain.accept()
            conn.recv(16)
            conn.close()
        except OSError:
            pass

    threading.Thread(target=_accept, daemon=True).start()
    try:
        result = probe_certificate('127.0.0.1', port=port, allow_private=True,
                                   timeout=3)
        assert result['status'] == STATUS_UNREACHABLE
        assert result['error_class'] in ('tls_error', 'timeout', 'connection_error')
    finally:
        plain.close()


# --------------------------------------------------------------------------- #
# timeout resolution
# --------------------------------------------------------------------------- #

def test_timeout_clamped(monkeypatch):
    monkeypatch.delenv('CERTMATE_PROBE_TIMEOUT_SECONDS', raising=False)
    assert cert_probe._probe_timeout_seconds(0.1) == cert_probe._TIMEOUT_MIN
    assert cert_probe._probe_timeout_seconds(999) == cert_probe._TIMEOUT_MAX
    assert cert_probe._probe_timeout_seconds(None) == \
        cert_probe.DEFAULT_PROBE_TIMEOUT_SECONDS


def test_timeout_from_env(monkeypatch):
    monkeypatch.setenv('CERTMATE_PROBE_TIMEOUT_SECONDS', '7')
    assert cert_probe._probe_timeout_seconds(None) == 7.0


def test_allow_private_from_env(monkeypatch):
    monkeypatch.setenv('CERTMATE_PROBE_ALLOW_PRIVATE', 'true')
    assert cert_probe._env_allow_private() is True
    monkeypatch.setenv('CERTMATE_PROBE_ALLOW_PRIVATE', 'no')
    assert cert_probe._env_allow_private() is False
