#!/usr/bin/env python3
"""Does this Python's default TLS client offer hybrid post-quantum key exchange?

CertMate reaches CAs, DNS providers and webhooks through Python's `ssl` with its default
context. In the image that is OpenSSL 3.5, whose default groups include X25519MLKEM768
(RFC 10024): the key exchange Let's Encrypt asks operators to support now. Nothing pinned
that, so a base-image bump that lost it would have shipped without a word (the post-quantum
roadmap, task T0.5).

Python 3.12 can neither choose nor read the TLS group, so the server decides: an
`openssl s_server` that accepts X25519MLKEM768 and nothing else. A handshake from
`ssl.create_default_context()` succeeds only if the client offered it. The certificate is
generated here for localhost and trusted explicitly, so the client verifies it as it would
any server.

The control is what makes the answer mean something: a server limited to a group the default
client does not offer (brainpoolP512r1tls13) must REFUSE the same client. If it does not, the
server is not enforcing the group, and a success above proved nothing.

Exit 0 when the hybrid group is offered and the control is refused; 1 otherwise.
Run inside the built image by ci.yml's image job.
"""
import datetime
import shutil
import socket
import ssl
import subprocess  # nosec B404: runs the openssl binary with fixed arguments
import sys
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

HYBRID = 'X25519MLKEM768'
NOT_OFFERED = 'brainpoolP512r1tls13'


def _certificate(directory: Path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')])
    now = datetime.datetime.now(datetime.UTC)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]), critical=False)
            .sign(key, hashes.SHA256()))
    (directory / 'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / 'key.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _free_port():
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def _handshake(openssl, directory: Path, group: str):
    """True if the default client completes a verified TLS 1.3 handshake with a server
    that accepts only *group*."""
    port = _free_port()
    server = subprocess.Popen(  # noqa: S603  # nosec B603: the openssl binary and fixed arguments, no shell
        [openssl, 's_server', '-accept', str(port), '-cert', str(directory / 'cert.pem'),
         '-key', str(directory / 'key.pem'), '-groups', group, '-tls1_3', '-www', '-quiet'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        context = ssl.create_default_context(cafile=str(directory / 'cert.pem'))
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname='localhost') as tls:
                        return tls.version() == 'TLSv1.3'
            except ConnectionRefusedError:
                if time.monotonic() > deadline or server.poll() is not None:
                    raise RuntimeError(f'openssl s_server did not start for {group}') from None
                time.sleep(0.2)
            except ssl.SSLError:
                return False
    finally:
        server.terminate()
        server.wait(timeout=10)


def main():
    openssl = shutil.which('openssl')
    if not openssl:
        print('no openssl binary on PATH: cannot run the check', file=sys.stderr)
        return 1
    print(f'{ssl.OPENSSL_VERSION}; server: {openssl}')
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        _certificate(directory)
        offered = _handshake(openssl, directory, HYBRID)
        control = _handshake(openssl, directory, NOT_OFFERED)
    print(f'server accepting only {HYBRID}: handshake {"OK" if offered else "FAILED"}')
    print(f'server accepting only {NOT_OFFERED} (control): handshake {"OK" if control else "refused"}')
    if control:
        print('the control handshake succeeded: the server is not enforcing the group, '
              'so this check proves nothing', file=sys.stderr)
        return 1
    if not offered:
        print(f"Python's default TLS client does not offer {HYBRID}: the image lost hybrid "
              'post-quantum key exchange (OpenSSL 3.5 or later is needed)', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
