"""A small ACME client for the tests of CertMate's ACME server (#476).

It signs requests the way RFC 8555 says, from the protected header up, so a
test can break exactly one rule: a nonce used twice, a url for another
resource, an unprotected header, `alg: none`. The well-formed path goes
through the `acme` package where it can (the EAB is built by
acme.messages.ExternalAccountBinding, the code certbot uses), so the server is
held to what a real client sends, not to what these tests think one sends.
"""
import json
import os

import josepy
from acme import messages
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from josepy import b64

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
