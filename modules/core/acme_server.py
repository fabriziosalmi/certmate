"""CertMate's ACME server (RFC 8555), in front of a CA of its own (#476).

This is the account half: directory, nonces, accounts bound to an External
Account Binding key, account updates and key rollover. Orders, challenges and
issuance follow in their own changes, and the directory lists a resource only
once it answers.

Configuration lives in settings under `acme_server`, which a bulk settings
POST cannot write (settings.SETTINGS_REJECT_KEYS): an EAB key is the right to
enrol, so it is granted through its own admin endpoint, not as a side effect
of saving the settings page. The `hmac_key` of each EAB key is masked by the
settings machinery wherever settings are shown or exported share-safe.

    acme_server:
      enabled: false          # every /acme/ route answers 404 while false
      allow_http: false       # RFC 8555 section 6.1 wants HTTPS; true is for labs and tests
      eab_required: true      # an account needs an EAB key (section 7.3.4)
      eab_keys:
        - kid: team-a         # what the client sends as the EAB key identifier
          hmac_key: <base64url>
          allowed_identifiers: ['*.lab.internal']   # enforced on orders
          disabled: false
"""
import hmac as _hmac
import json
from pathlib import Path

import josepy
from josepy import b64

from .acme_jws import (
    MAC_ALGORITHMS,
    check_public_key,
    parse_flattened,
    thumbprint,
    verify_signature,
)
from .acme_nonces import NonceStore
from .acme_problems import AcmeProblem
from .acme_store import AcmeStore, KeyInUse

DEFAULTS = {
    'enabled': False,
    'allow_http': False,
    'eab_required': True,
    'eab_keys': [],
}

MAX_CONTACTS = 10
MAX_CONTACT_LENGTH = 320


class AcmeServer:
    def __init__(self, settings_manager, data_dir, nonces=None):
        self._settings = settings_manager
        self.db_path = Path(data_dir) / 'acme' / 'acme.db'
        self.nonces = nonces or NonceStore()
        self._store = None

    # -- configuration ---------------------------------------------------

    def config(self):
        stored = (self._settings.load_settings() or {}).get('acme_server')
        merged = dict(DEFAULTS)
        if isinstance(stored, dict):
            merged.update(stored)
        return merged

    @property
    def store(self):
        if self._store is None:
            self._store = AcmeStore(self.db_path)
        return self._store

    def eab_key(self, kid):
        """The enabled EAB key with this identifier, or None."""
        if not isinstance(kid, str):
            return None
        for entry in self.config().get('eab_keys') or []:
            if isinstance(entry, dict) and entry.get('kid') == kid and not entry.get('disabled'):
                return entry
        return None

    # -- accounts --------------------------------------------------------

    def account_json(self, account, urls):
        return {
            'status': account['status'],
            'contact': account['contact'],
            'orders': urls.orders(account['id']),
        }

    def new_account(self, req, urls):
        """Section 7.3. Returns (account, created)."""
        payload = req.json()
        existing = self.store.account_by_thumbprint(thumbprint(req.jwk))
        if existing is not None:
            if existing['status'] != 'valid':
                raise AcmeProblem('unauthorized', f'The account with this key is {existing["status"]}')
            return existing, False
        if payload.get('onlyReturnExisting') is True:
            raise AcmeProblem('accountDoesNotExist', 'No account has this key')

        contact = _contacts(payload.get('contact', []))
        eab = payload.get('externalAccountBinding')
        if eab is None and self.config().get('eab_required', True):
            raise AcmeProblem('externalAccountRequired',
                              'This server requires an External Account Binding: ask its '
                              'administrator for an EAB key identifier and HMAC key')
        eab_kid = self._verify_eab(eab, req.jwk, urls.new_account()) if eab is not None else None

        try:
            account = self.store.create_account(json.dumps(req.jwk.to_partial_json()),
                                                thumbprint(req.jwk), contact, eab_kid)
        except KeyInUse as clash:
            # Two requests with the same new key: the second one finds the first's account.
            return self.store.account(clash.account_id), False
        return account, True

    def _verify_eab(self, eab, account_jwk, new_account_url):
        """Section 7.3.4: an HMAC over the account key, by a key this server issued."""
        parsed = parse_flattened(eab, what='externalAccountBinding', algorithms=MAC_ALGORITHMS)
        header = parsed.signature.combined
        if header.nonce is not None or header.jwk is not None:
            raise AcmeProblem('malformed', 'The externalAccountBinding header carries neither a nonce nor a jwk')
        if header.url != new_account_url:
            raise AcmeProblem('unauthorized', 'The externalAccountBinding was made for another URL')
        entry = self.eab_key(header.kid)
        if entry is None:
            raise AcmeProblem('unauthorized', 'The EAB key identifier is unknown or disabled')
        try:
            bound = josepy.JWK.from_json(json.loads(parsed.payload))
        except (ValueError, josepy.errors.Error):
            raise AcmeProblem('malformed', 'The externalAccountBinding payload is not a JWK') from None
        if not _hmac.compare_digest(thumbprint(bound), thumbprint(account_jwk)):
            raise AcmeProblem('unauthorized', 'The externalAccountBinding binds another account key')
        try:
            mac_key = josepy.JWKOct(key=b64.b64decode(entry['hmac_key']))
            valid = parsed.signature.verify(parsed.payload, mac_key)
        except (ValueError, TypeError, KeyError, josepy.errors.Error):
            valid = False
        if not valid:
            raise AcmeProblem('unauthorized', 'The externalAccountBinding MAC does not verify')
        return header.kid

    def update_account(self, req, account):
        """Section 7.3.2 and 7.3.6: read, change the contacts, or deactivate."""
        if req.is_post_as_get:
            return account
        payload = req.json()
        # Section 7.3.2: the server MUST ignore updates to status other than
        # deactivation, and to fields it does not know. certbot's client sends
        # the whole account back, "status": "valid" included, to change a
        # contact; refusing that broke it.
        if payload.get('status') == 'deactivated':
            return self.store.deactivate(account['id'])
        if 'contact' in payload:
            return self.store.update_contact(account['id'], _contacts(payload['contact']))
        return account

    def change_key(self, req, account, urls):
        """Section 7.3.5: an inner JWS signed by the new key, inside one signed by the old."""
        inner = parse_flattened(req.payload, what='key change')
        header = inner.signature.combined
        if header.jwk is None or header.kid is not None or header.nonce is not None:
            raise AcmeProblem('malformed', 'The inner JWS of a key change carries the new key as jwk, '
                              'and neither kid nor nonce')
        if header.url != urls.key_change():
            raise AcmeProblem('unauthorized', 'The inner JWS was made for another URL')
        check_public_key(header.jwk)
        verify_signature(inner, header.jwk, 'key change')
        try:
            body = json.loads(inner.payload)
            old_key = josepy.JWK.from_json(body['oldKey'])
        except (ValueError, TypeError, KeyError, josepy.errors.Error):
            raise AcmeProblem('malformed', 'The key change payload must carry account and oldKey') from None
        if body.get('account') != urls.account(account['id']):
            raise AcmeProblem('unauthorized', 'The key change names another account')
        if thumbprint(old_key) != account['thumbprint']:
            raise AcmeProblem('unauthorized', 'oldKey is not the key of this account')
        try:
            return self.store.change_key(account['id'], json.dumps(header.jwk.to_partial_json()),
                                         thumbprint(header.jwk))
        except KeyInUse as clash:
            raise AcmeProblem('malformed', 'Another account already has this key', status=409,
                              headers={'Location': urls.account(clash.account_id)}) from None


def _contacts(value):
    """Section 7.3: mailto: URLs only, one address each."""
    if not isinstance(value, list) or len(value) > MAX_CONTACTS:
        raise AcmeProblem('malformed', f'contact must be a list of at most {MAX_CONTACTS} URLs')
    for item in value:
        if not isinstance(item, str) or len(item) > MAX_CONTACT_LENGTH:
            raise AcmeProblem('invalidContact', 'Each contact must be a URL of reasonable length')
        if not item.startswith('mailto:'):
            raise AcmeProblem('unsupportedContact', f'Only mailto: contacts are supported, not {item!r}')
        address = item[len('mailto:'):]
        if address.count('@') != 1 or ',' in address or '?' in address or not address.split('@')[1]:
            raise AcmeProblem('invalidContact', f'{item!r} is not one email address')
    return value
