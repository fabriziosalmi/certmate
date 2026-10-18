"""ACME problem documents (RFC 8555 section 6.7, on RFC 7807).

An ACME client reads why it was refused from the `type` of the problem, not
from the status code: `badNonce` makes it retry with the nonce the answer
carries, `externalAccountRequired` tells it to send an EAB, and so on. Every
refusal of the ACME server is an AcmeProblem, so each one has a type.
"""

ACME_ERROR_PREFIX = 'urn:ietf:params:acme:error:'

# The types this server sends, from the registry in RFC 8555 section 6.7.
KINDS = frozenset({
    'accountDoesNotExist',
    'badNonce',
    'badPublicKey',
    'badSignatureAlgorithm',
    'connection',
    'dns',
    'externalAccountRequired',
    'incorrectResponse',
    'invalidContact',
    'malformed',
    'rejectedIdentifier',
    'unauthorized',
    'unsupportedContact',
    'unsupportedIdentifier',
})


# 403 for a request the server understood and will not authorize, which is
# what 403 means in HTTP; 400 for every other refusal.
_STATUS = {'unauthorized': 403}


class AcmeProblem(Exception):
    """A refusal, sent as application/problem+json."""

    def __init__(self, kind, detail, status=None, headers=None, **fields):
        if kind not in KINDS:
            raise ValueError(f'not an ACME error type this server sends: {kind}')
        super().__init__(detail)
        self.kind = kind
        self.detail = detail
        self.status = status or _STATUS.get(kind, 400)
        self.headers = dict(headers or {})
        self.fields = fields

    def to_json(self):
        body = {'type': ACME_ERROR_PREFIX + self.kind, 'detail': self.detail, 'status': self.status}
        body.update(self.fields)
        return body
