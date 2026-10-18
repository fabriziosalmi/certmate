"""A small ACME client for the tests of CertMate's ACME server (#476).

It signs requests the way RFC 8555 says, from the protected header up, so a
test can break exactly one rule: a nonce used twice, a url for another
resource, an unprotected header, `alg: none`. The well-formed path goes
through the `acme` package where it can (the EAB is built by
acme.messages.ExternalAccountBinding, the code certbot uses), so the server is
held to what a real client sends, not to what these tests think one sends.
"""
import http.server
import json
import os
import threading
import time

import josepy
from acme import messages
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from josepy import b64

from modules.core import pinned_https

BASE = 'https://localhost'


def ec_key(curve=None):
    return josepy.JWKEC(key=ec.generate_private_key(curve or ec.SECP256R1()))


def rsa_key():
    return josepy.JWKRSA(key=rsa.generate_private_key(public_exponent=65537, key_size=2048))


# The public half of a 1024-bit RSA key, generated once outside the
# repository: the server refuses it by its size, before it would check a
# signature, so the test needs only the public key and never makes a weak one.
WEAK_RSA_PUBLIC_JWK = {
    'kty': 'RSA',
    'e': 'AQAB',
    'n': ('va6B3ar_ekmTdwBJYcePq38eHDWix4cmouNAHQXOb46w8BRrtyksGJtFcXfRrCaSebRwR88c1QOTcC7qjELS'
          'VkXP4U8IC8bYk4GwpUgyH6vghZ-I1YJ4PlaRFRwA0A31YnscgO0ni1szVwZXIVn3ysv2sTJB1opNsPzrPwIJy30'),
}


def b64s(data):
    return b64.b64encode(data).decode('ascii')


def enable(app, **overrides):
    """Turn the ACME server on with one EAB key; returns that key's entry."""
    entry = {'kid': 'team-a', 'hmac_key': b64s(os.urandom(32)), 'allowed_identifiers': ['*.lab.internal']}
    config = {'enabled': True, 'allow_http': False, 'eab_required': True, 'eab_keys': [entry]}
    config.update(overrides)
    settings = app.extensions['certmate_container'].managers['settings']
    settings.update(lambda s: s.__setitem__('acme_server', config))
    return entry


def default_alg(key):
    return josepy.ES256 if isinstance(key, josepy.JWKEC) else josepy.RS256


def raw_jws(protected, payload, key, alg=None):
    """A flattened JWS with exactly this protected header."""
    alg = alg or default_alg(key)
    protected_b64 = b64s(json.dumps(protected).encode())
    payload_b64 = b64s(payload)
    signature = alg.sign(key.key, f'{protected_b64}.{payload_b64}'.encode())
    return {'protected': protected_b64, 'payload': payload_b64, 'signature': b64s(signature)}


class AcmeTestClient:
    def __init__(self, app, key=None, base=BASE):
        self.http = app.test_client()
        self.key = key or ec_key()
        self.base = base
        self.account_url = None

    def url(self, path):
        return f'{self.base}/acme/{path}'

    def nonce(self):
        return self.http.head(self.url('new-nonce')).headers['Replay-Nonce']

    def protected(self, url, *, key=None, nonce=..., kid=..., alg=None):
        key = key or self.key
        header = {'alg': (alg or default_alg(key)).name, 'url': url}
        nonce = self.nonce() if nonce is ... else nonce
        if nonce is not None:
            header['nonce'] = nonce
        kid = self.account_url if kid is ... else kid
        if kid is not None:
            header['kid'] = kid
        else:
            header['jwk'] = key.public_key().to_partial_json()
        return header

    def post(self, path_or_url, payload, *, key=None, protected=None, body=None,
             content_type='application/jose+json', **header_args):
        url = path_or_url if path_or_url.startswith('http') else self.url(path_or_url)
        key = key or self.key
        if body is None:
            header = protected or self.protected(url, key=key, **header_args)
            data = b'' if payload is None else json.dumps(payload).encode()
            body = raw_jws(header, data, key)
        return self.http.post(url, data=json.dumps(body) if isinstance(body, dict) else body,
                              content_type=content_type)

    def eab(self, entry, url=None, key=None):
        directory = {'newAccount': url or self.url('new-account')}
        return messages.ExternalAccountBinding.from_data(
            (key or self.key).public_key(), entry['kid'], entry['hmac_key'], directory)

    def new_account(self, entry=None, contact=('mailto:ops@lab.internal',), **extra):
        payload = {'termsOfServiceAgreed': True,
                   'contact': list(contact) if isinstance(contact, tuple) else contact}
        if entry is not None:
            payload['externalAccountBinding'] = self.eab(entry)
        payload.update(extra)
        response = self.post('new-account', payload, kid=None)
        if response.status_code in (200, 201):
            self.account_url = response.headers['Location']
        return response


def problem(response, because=None):
    """The problem type of a refusal, without its namespace.

    Several checks answer with the same type (malformed, unauthorized), so a
    test that names `because`, a fragment of the reason, cannot pass on a
    refusal that some other check made.
    """
    assert response.mimetype == 'application/problem+json', (response.status_code, response.get_data(as_text=True))
    body = response.get_json()
    if because is not None:
        assert because in body['detail'], (because, body['detail'])
    return body['type'].rsplit(':', 1)[-1]


class ChallengeServer:
    """An http-01 responder whose answer each test sets per token."""

    def __init__(self):
        self.answers = {}
        self.hosts = []
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                owner.hosts.append(self.headers.get('Host'))
                token = self.path.rsplit('/', 1)[-1]
                kind, value = owner.answers.get(token, ('status', 404))
                if kind == 'sleep':
                    time.sleep(value)
                    kind, value = 'status', 200
                if kind == 'redirect':
                    self.send_response(302)
                    self.send_header('Location', value)
                    self.end_headers()
                    return
                body = value if kind == 'body' else b''
                self.send_response(200 if kind == 'body' else value)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.httpd = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.port = self.httpd.server_port
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()


def resolve_for_tests(host, port, allow_internal):
    """Test names point at the local challenge server; anything else meets the real guard."""
    if host.endswith('.lab.internal') or host == 'nas.office.internal':
        return '127.0.0.1'
    if host.startswith('nx.'):
        raise pinned_https.UnsafeDestination(f'{host} does not resolve: no such name')
    return pinned_https.resolve(host, port, allow_internal)


PATTERNS = ['*.lab.internal', 'nas.office.internal']


def served_app(responder):
    """An app whose ACME server checks http-01 against *responder*."""
    from tests import contract_support
    application, token = contract_support.build_app()
    application.extensions['certmate_test_token'] = token
    server = application.extensions['certmate_container'].managers['acme_server']
    server.http01_port = responder.port
    server.resolve = resolve_for_tests
    return application


def eab_for(app, patterns=PATTERNS):
    entry = enable(app)
    entry['allowed_identifiers'] = list(patterns)
    enable(app, eab_keys=[entry])
    return entry


def registered_client(app, entry):
    client = AcmeTestClient(app)
    assert client.new_account(entry).status_code == 201
    return client


class DnsResponder:
    """A DNS server on 127.0.0.1 for dns-01: TXT records and CNAMEs a test sets.

    Real UDP, built with dnspython, so the server's resolver is the one the
    instance builds from its settings (decision I1), not a stand-in for it.
    A name with a CNAME is answered with the chain, the way a recursive
    resolver hands it over.
    """

    def __init__(self):
        import socket

        self.txt = {}
        self.cname = {}
        self.asked = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        self.running = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        import dns.message
        import dns.rcode
        import dns.rrset

        while self.running:
            try:
                wire, peer = self.sock.recvfrom(4096)
            except OSError:
                return
            query = dns.message.from_wire(wire)
            name = query.question[0].name.to_text().rstrip('.').lower()
            self.asked.append(name)
            reply = dns.message.make_response(query)
            seen = name
            while seen in self.cname:
                target = self.cname[seen]
                reply.answer.append(dns.rrset.from_text(seen + '.', 60, 'IN', 'CNAME', target + '.'))
                seen = target
            if seen in self.txt:
                reply.answer.append(dns.rrset.from_text_list(
                    seen + '.', 60, 'IN', 'TXT', [f'"{value}"' for value in self.txt[seen]]))
            elif not reply.answer:
                reply.set_rcode(dns.rcode.NXDOMAIN)
            self.sock.sendto(reply.to_wire(), peer)

    def close(self):
        self.running = False
        self.sock.close()


def point_dns_at(app, responder):
    """Configure the instance's resolver (dns_resolver.nameservers) at *responder*."""
    settings = app.extensions['certmate_container'].managers['settings']
    settings.update(lambda s: s.__setitem__('dns_resolver', {'nameservers': [f'127.0.0.1:{responder.port}']}))
