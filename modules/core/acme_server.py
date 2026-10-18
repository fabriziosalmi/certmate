"""CertMate's ACME server (RFC 8555), in front of a CA of its own (#476).

This is the account half: directory, nonces, accounts bound to an External
Account Binding key, account updates and key rollover. Orders, challenges and
issuance follow in their own changes, and the directory lists a resource only
once it answers.

Configuration lives in settings under `acme_server`, which a bulk settings
POST cannot write (settings.SETTINGS_REJECT_KEYS): an EAB key is the right to
enrol, so it is granted through its own admin endpoint (/api/acme, in
modules/api/resources_acme.py), not as a side effect of saving the settings
page. GET /api/settings does not show `acme_server`, and a share-safe backup
masks each `hmac_key`.

    acme_server:
      enabled: false          # every /acme/ route answers 404 while false
      allow_http: false       # RFC 8555 section 6.1 wants HTTPS; true is for labs and tests
      eab_required: true      # an account needs an EAB key (section 7.3.4)
      eab_keys:
        - kid: team-a         # what the client sends as the EAB key identifier
          hmac_key: <base64url>
          allowed_identifiers: ['*.lab.internal']   # enforced on orders
          note: lab cluster
          created_at: <ISO 8601>
          disabled: false     # disabled, never deleted: its accounts stay attributable
"""
import hmac as _hmac
import json
import os
import re
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
from .utils import utc_now

DEFAULTS = {
    'enabled': False,
    'allow_http': False,
    'eab_required': True,
    'eab_keys': [],
}

MAX_CONTACTS = 10
MAX_CONTACT_LENGTH = 320

# What an admin may set through PATCH /api/acme/server. The EAB keys have
# endpoints of their own: a key is created with a secret shown once, and is
# disabled, never edited or deleted, so the accounts it enrolled stay
# attributable to it.
OPTIONS = ('enabled', 'allow_http', 'eab_required')

KID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_LABEL_RE = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')
MAX_PATTERNS = 50
MAX_NOTE_LENGTH = 200


class AcmeAdminError(Exception):
    """A refusal of the admin API, with the HTTP status it answers with."""

    def __init__(self, message, status=400, code='ACME_ADMIN_INVALID'):
        super().__init__(message)
        self.message = message
        self.status = status
        self.code = code


def name_pattern(value):
    """The normalised form of an allowed-identifier pattern, or AcmeAdminError.

    A pattern is a DNS name (`nas.lab.internal`: that name only) or a DNS
    name under `*.` (`*.lab.internal`: every name below it, at any depth, and
    not the name itself). Orders are checked against them (#476, the next
    change); a pattern that matches anything at all is not one of them.
    """
    if not isinstance(value, str) or not value.strip():
        raise AcmeAdminError('An allowed identifier must be a non-empty string')
    pattern = value.strip().lower().rstrip('.')
    name = pattern[2:] if pattern.startswith('*.') else pattern
    if not name or len(name) > 253 or not all(_LABEL_RE.match(label) for label in name.split('.')):
        raise AcmeAdminError(f'{value!r} is not a DNS name, or a DNS name under "*."')
    return pattern


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

    # -- administration (the /api/acme endpoints) -------------------------

    def admin_view(self):
        config = self.config()
        counts = self._accounts_per_eab_key()
        return {
            'enabled': bool(config.get('enabled')),
            'allow_http': bool(config.get('allow_http')),
            'eab_required': bool(config.get('eab_required', True)),
            'eab_keys': [self._public_eab(entry, counts) for entry in config.get('eab_keys') or []
                         if isinstance(entry, dict)],
        }

    def set_options(self, changes):
        """Change the options named in *changes*; each must be a boolean."""
        unknown = sorted(set(changes) - set(OPTIONS))
        if unknown:
            raise AcmeAdminError(f'Unknown options: {unknown}. The options are {list(OPTIONS)}')
        for name, value in changes.items():
            if not isinstance(value, bool):
                raise AcmeAdminError(f'{name} must be true or false')
        self._write(lambda config: config.update(changes))
        return self.admin_view()

    def create_eab_key(self, kid=None, allowed_identifiers=None, note=''):
        """A new EAB key. The returned entry carries hmac_key, which is never shown again."""
        kid = kid or f'eab-{b64.b64encode(os.urandom(9)).decode()}'
        if not isinstance(kid, str) or not KID_RE.match(kid):
            raise AcmeAdminError('kid must be 1 to 64 letters, digits, "-" or "_"')
        if not isinstance(allowed_identifiers, list) or not allowed_identifiers:
            raise AcmeAdminError('allowed_identifiers must list the names this key may order '
                                 'certificates for, such as "*.lab.internal"')
        if len(allowed_identifiers) > MAX_PATTERNS:
            raise AcmeAdminError(f'At most {MAX_PATTERNS} allowed identifiers per key')
        patterns = list(dict.fromkeys(name_pattern(value) for value in allowed_identifiers))
        if not isinstance(note, str) or len(note) > MAX_NOTE_LENGTH:
            raise AcmeAdminError(f'note must be text of at most {MAX_NOTE_LENGTH} characters')
        entry = {
            'kid': kid,
            'hmac_key': b64.b64encode(os.urandom(32)).decode('ascii'),
            'allowed_identifiers': patterns,
            'note': note,
            'created_at': utc_now().isoformat(),
            'disabled': False,
        }

        def add(config):
            if any(isinstance(e, dict) and e.get('kid') == kid for e in config['eab_keys']):
                raise AcmeAdminError(f'An EAB key called {kid!r} exists already; keys are never reused, '
                                     'so the accounts each one enrolled stay attributable', 409, 'ACME_EAB_KEY_EXISTS')
            config['eab_keys'].append(entry)
        self._write(add)
        return dict(self._public_eab(entry, {}), hmac_key=entry['hmac_key'])

    def disable_eab_key(self, kid):
        """Stop a key from enrolling; the accounts it enrolled keep working."""
        def disable(config):
            for entry in config['eab_keys']:
                if isinstance(entry, dict) and entry.get('kid') == kid:
                    entry['disabled'] = True
                    return
            raise AcmeAdminError(f'No EAB key called {kid!r}', 404, 'ACME_EAB_KEY_NOT_FOUND')
        self._write(disable)
        return next(e for e in self.admin_view()['eab_keys'] if e['kid'] == kid)

    def _write(self, mutate):
        refusal = []

        def mutator(settings):
            config = dict(DEFAULTS)
            if isinstance(settings.get('acme_server'), dict):
                config.update(settings['acme_server'])
            config['eab_keys'] = [dict(e) for e in config.get('eab_keys') or [] if isinstance(e, dict)]
            try:
                mutate(config)
            except AcmeAdminError as error:
                refusal.append(error)
                return
            settings['acme_server'] = config

        saved = self._settings.update(mutator, reason='acme_server')
        if refusal:
            raise refusal[0]
        if not saved:
            raise AcmeAdminError('The settings could not be written', 500, 'SETTINGS_WRITE_FAILED')

    def _accounts_per_eab_key(self):
        # Read only when the database exists: looking at the admin page must
        # not create an ACME database on an instance that never enabled ACME.
        if not self.db_path.exists():
            return {}
        return self.store.accounts_per_eab_key()

    @staticmethod
    def _public_eab(entry, counts):
        return {
            'kid': entry.get('kid'),
            'allowed_identifiers': list(entry.get('allowed_identifiers') or []),
            'note': entry.get('note', ''),
            'created_at': entry.get('created_at'),
            'disabled': bool(entry.get('disabled')),
            'accounts': counts.get(entry.get('kid'), 0),
        }

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
