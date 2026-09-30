"""Real TLS for tests: a CA, certificates it signs, and an HTTPS server that records what it is sent.

Shared by the tests of the pinned client and of the deploy target that uses it,
because both need an actual handshake: a mocked connection would pass whether or
not anything was verified.
"""
import datetime
import hashlib
import http.server
import ipaddress
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


# --------------------------------------------------------------------------

def make_cert(common_name, san_dns=None, san_ip=None, issuer=None, issuer_key=None, is_ca=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject)
               .issuer_name(issuer.subject if issuer is not None else subject)
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=30)))
    alt = [x509.DNSName(n) for n in (san_dns or [])] + [
        x509.IPAddress(ipaddress.ip_address(i)) for i in (san_ip or [])]
    if alt:
        builder = builder.add_extension(x509.SubjectAlternativeName(alt), False)
    if is_ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    cert = builder.sign(issuer_key or key, hashes.SHA256())
    return cert, key


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def build_pki(d):
    """Write a CA, a leaf signed by it, a self-signed leaf and a 'system CA' leaf under *d*."""
    ca, ca_key = make_cert('Test CA', is_ca=True)
    leaf, leaf_key = make_cert('appliance.internal', san_dns=['appliance.internal'],
                                issuer=ca, issuer_key=ca_key)
    selfsigned, selfsigned_key = make_cert('appliance.internal', san_dns=['appliance.internal'])
    files = {}
    for name, (cert, key) in {'leaf': (leaf, leaf_key), 'self': (selfsigned, selfsigned_key)}.items():
        files[name] = (d / f'{name}.crt', d / f'{name}.key')
        files[name][0].write_bytes(pem(cert))
        files[name][1].write_bytes(key_pem(key))
    # A second CA, standing in for one the SYSTEM store trusts.
    system_ca, system_ca_key = make_cert('System CA', is_ca=True)
    system_leaf, system_leaf_key = make_cert('appliance.internal', san_dns=['appliance.internal'],
                                              issuer=system_ca, issuer_key=system_ca_key)
    files['system'] = (d / 'system.crt', d / 'system.key')
    files['system'][0].write_bytes(pem(system_leaf))
    files['system'][1].write_bytes(key_pem(system_leaf_key))
    (d / 'system-ca.pem').write_bytes(pem(system_ca))
    return {'system_ca_file': str(d / 'system-ca.pem'),
            'ca_pem': pem(ca).decode(), 'files': files,
            'leaf_sha256': hashlib.sha256(leaf.public_bytes(serialization.Encoding.DER)).hexdigest(),
            'self_sha256': hashlib.sha256(selfsigned.public_bytes(serialization.Encoding.DER)).hexdigest()}


class TLSServer:
    def __init__(self, certfile, keyfile, handler):
        self.httpd = http.server.HTTPServer(('127.0.0.1', 0), handler)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def handler(status=200, body=b'ok', location=None, record=None):
    class H(http.server.BaseHTTPRequestHandler):
        def _do(self):
            n = int(self.headers.get('Content-Length') or 0)
            data = self.rfile.read(n) if n else b''
            if record is not None:
                record.append({'method': self.command, 'path': self.path, 'body': data,
                               'headers': {k.lower(): v for k, v in self.headers.items()}})
            self.send_response(status)
            if location:
                self.send_header('Location', location)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        do_POST = do_PUT = do_PATCH = do_GET = _do

        def log_message(self, *a):
            pass
    return H


