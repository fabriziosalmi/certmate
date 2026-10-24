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
          allowed_identifiers: ['*.lab.internal', '10.20.0.0/16']   # enforced on orders
          note: lab cluster
          created_at: <ISO 8601>
          disabled: false     # disabled, never deleted: its accounts stay attributable
"""
import hmac as _hmac
import ipaddress
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import josepy
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from josepy import b64

from . import acme_ca, acme_validation, dns_resolver, pinned_https
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

logger = logging.getLogger(__name__)

DEFAULTS = {
    'enabled': False,
    'allow_http': False,
    'eab_required': True,
    'eab_keys': [],
    # The names an account enrolled without an EAB key may order (decision
    # F1 on #476): with eab_required off, an empty list means such accounts
    # order nothing, rather than anything.
    'allowed_identifiers': [],
    # How long a certificate from the ACME CA is valid (decision D3 on #476).
    'validity_days': acme_ca.DEFAULT_VALIDITY_DAYS,
}

# Section 7.6: the RFC 5280 reasons a client may give. The others are about a
# CA or an attribute authority, or put a certificate on hold, which this CA
# does not do.
REVOCATION_REASONS = {0: 'unspecified', 1: 'keyCompromise', 3: 'affiliationChanged',
                      4: 'superseded', 5: 'cessationOfOperation'}
CRL_CACHE_SECONDS = 3600

# ACME Renewal Information (RFC 9773, decision I3 on #476): renew between two
# thirds and five sixths of the lifetime, which for the 45-day default is days
# 30 to 37.5, with a week or more still left; a revoked certificate, now.
#
# "Now" is a window that ended when the certificate was revoked. A client picks
# a random moment inside the window and renews when that moment has passed, so
# a window still open picks a moment in the future: acme.sh 3.1.5, run by cron
# a second after a revocation, picked one 23 seconds ahead and skipped until
# its next run, and lego 5.5.2 skipped too. A window wholly in the past leaves
# no moment to wait for.
ARI_WINDOW = (2 / 3, 5 / 6)
ARI_REVOKED_WINDOW = timedelta(minutes=1)
ARI_RETRY_AFTER_SECONDS = 6 * 3600

ORDER_LIFETIME = timedelta(days=7)
MAX_IDENTIFIERS = 100

MAX_CONTACTS = 10
MAX_CONTACT_LENGTH = 320

# What an admin may set through PATCH /api/acme/server: three booleans and
# the names for accounts without an EAB key. The EAB keys have endpoints of
# their own: a key is created with a secret shown once, and is disabled,
# never edited or deleted, so the accounts it enrolled stay attributable to it.
OPTIONS = ('enabled', 'allow_http', 'eab_required')
LIST_OPTIONS = ('allowed_identifiers',)
INT_OPTIONS = {'validity_days': (acme_ca.MIN_VALIDITY_DAYS, acme_ca.MAX_VALIDITY_DAYS)}

KID_RE = re.compile(r'^[A-Za-z0-9_-]{1,64}$')
_LABEL_RE = re.compile(r'^(?!-)[a-z0-9-]{1,63}(?<!-)$')
MAX_PATTERNS = 50
MAX_NOTE_LENGTH = 200

# create_eab_key makes 32 random bytes. A stored value holding fewer than 16
# is no key: josepy decodes base64url leniently, dropping what is not in the
# alphabet, so the mask a share-safe backup writes ("********") decoded to an
# empty key. Restored onto another instance, where no real value was there to
# put back, every EAB key then took a binding made with that empty key, from
# anyone who knew its kid.
MIN_EAB_KEY_BYTES = 16


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


def identifier_pattern(value):
    """The normalised form of an allowed-identifier pattern: a name, an address or a network.

    A DNS name pattern is name_pattern's. An address pattern (#1338) is an IPv4
    address (`192.168.1.20`: that address only) or an IPv4 network in CIDR
    form (`10.20.0.0/16`: every address in it), and allows "ip" identifiers
    only, as a name pattern allows "dns" identifiers only. A name whose last
    label is all digits is neither: no top-level domain is (RFC 3696), and
    such a pattern could only ever have matched an address taken for a name.
    """
    if not isinstance(value, str) or not value.strip():
        raise AcmeAdminError('An allowed identifier must be a non-empty string')
    text = value.strip()
    network = _written_network(text, refuse=True)
    if network is not None:
        return str(network.network_address) if network.prefixlen == network.max_prefixlen else str(network)
    pattern = name_pattern(text)
    if pattern.rsplit('.', 1)[-1].isdigit():
        raise AcmeAdminError(f'{value!r} is not a DNS name (no top-level domain is all digits), '
                             'nor an IPv4 address or an IPv4 network such as "10.20.0.0/16"')
    return pattern


def _written_network(text, refuse=False):
    """The network an address pattern allows, or None when *text* is not written as one.

    With *refuse*, a pattern written as an address that cannot be one is an
    AcmeAdminError; without, as when reading what is stored, it is None.
    """
    try:
        if '/' in text:
            network = ipaddress.ip_network(text, strict=True)
        else:
            network = ipaddress.ip_network(ipaddress.ip_address(text))
    except ValueError as error:
        if refuse and '/' in text:
            raise AcmeAdminError(f'{text!r} is not an IPv4 network in CIDR form, such as '
                                 f'"10.20.0.0/16": {error}') from None
        return None
    if not refuse:
        # Read from settings, which can be edited by hand: an IPv6 pattern, or
        # one that allows every address, allows nothing.
        return network if network.version == 4 and network.prefixlen else None
    if network.version != 4:
        raise AcmeAdminError(f'{text!r} is an IPv6 address or network; this server certifies '
                             'IPv4 addresses only, for now')
    if network.prefixlen == 0:
        raise AcmeAdminError(f'{text!r} allows every address, which no pattern may do')
    return network


class AcmeServer:
    def __init__(self, settings_manager, data_dir, nonces=None, http01_port=80, https_port=443, resolve=None):
        self._settings = settings_manager
        self.db_path = Path(data_dir) / 'acme' / 'acme.db'
        self.nonces = nonces or NonceStore()
        self._store = None
        # Fixed in production: http-01 is port 80, a redirect may go to 443,
        # and every address goes through pinned_https.resolve. The tests serve
        # on ports of their own and point their names at them, as Pebble lets them.
        self.http01_port = http01_port
        self.https_port = https_port
        self.resolve = resolve or pinned_https.resolve
        # Created on first use: an instance that never issues has no ACME root.
        self.ca = acme_ca.AcmeCA(Path(data_dir) / 'acme' / 'ca')
        self._crl = {'der': None, 'at': 0.0}
        self._crl_lock = threading.Lock()

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
            'allowed_identifiers': list(config.get('allowed_identifiers') or []),
            'validity_days': self.validity_days(),
            'eab_keys': [self._public_eab(entry, counts) for entry in config.get('eab_keys') or []
                         if isinstance(entry, dict)],
        }

    def set_options(self, changes):
        """Change the options named in *changes*: booleans, and allowed_identifiers as a list of patterns."""
        known = OPTIONS + LIST_OPTIONS + tuple(INT_OPTIONS)
        unknown = sorted(set(changes) - set(known))
        if unknown:
            raise AcmeAdminError(f'Unknown options: {unknown}. The options are {list(known)}')
        changes = dict(changes)
        for name, value in changes.items():
            if name in INT_OPTIONS:
                low, high = INT_OPTIONS[name]
                if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
                    raise AcmeAdminError(f'{name} must be a whole number from {low} to {high}')
            elif name in LIST_OPTIONS:
                if not isinstance(value, list) or len(value) > MAX_PATTERNS:
                    raise AcmeAdminError(f'{name} must be a list of at most {MAX_PATTERNS} names or addresses')
                changes[name] = list(dict.fromkeys(identifier_pattern(item) for item in value))
            elif not isinstance(value, bool):
                raise AcmeAdminError(f'{name} must be true or false')
        self._write(lambda config: config.update(changes))
        return self.admin_view()

    def create_eab_key(self, kid=None, allowed_identifiers=None, note=''):
        """A new EAB key. The returned entry carries hmac_key, which is never shown again."""
        kid = kid or f'eab-{b64.b64encode(os.urandom(9)).decode()}'
        if not isinstance(kid, str) or not KID_RE.match(kid):
            raise AcmeAdminError('kid must be 1 to 64 letters, digits, "-" or "_"')
        if not isinstance(allowed_identifiers, list) or not allowed_identifiers:
            raise AcmeAdminError('allowed_identifiers must list the names and addresses this key may order '
                                 'certificates for, such as "*.lab.internal" or "10.20.0.0/16"')
        if len(allowed_identifiers) > MAX_PATTERNS:
            raise AcmeAdminError(f'At most {MAX_PATTERNS} allowed identifiers per key')
        patterns = list(dict.fromkeys(identifier_pattern(value) for value in allowed_identifiers))
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

    # -- the control plane: what was issued, to whom, and the admin's actions --

    def certificates_view(self):
        if not self.db_path.exists():
            return []
        now = utc_now()
        listed = []
        for c in self.store.certificates_listed():
            if c['revoked_at']:
                status = 'revoked'
            elif datetime.fromisoformat(c['not_after']) <= now:
                status = 'expired'
            else:
                status = 'valid'
            listed.append({
                'id': c['id'], 'names': c['names'], 'serial': c['serial'], 'status': status,
                'not_after': c['not_after'], 'created_at': c['created_at'],
                'revoked_at': c['revoked_at'],
                'revocation_reason': REVOCATION_REASONS.get(c['reason']) if c['revoked_at'] else None,
                'account_id': c['account_id'], 'eab_kid': c['eab_kid'],
            })
        return listed

    def accounts_view(self):
        if not self.db_path.exists():
            return []
        return [{'id': a['id'], 'status': a['status'], 'contact': a['contact'], 'eab_kid': a['eab_kid'],
                 'created_at': a['created_at'], 'orders': a['orders'], 'certificates': a['certificates']}
                for a in self.store.accounts_listed()]

    def admin_revoke(self, certificate_id, reason=0):
        """An admin revokes a certificate from the control plane, as section 7.6 lets its owner."""
        if isinstance(reason, bool) or reason not in REVOCATION_REASONS:
            raise AcmeAdminError(f'reason must be one of {sorted(REVOCATION_REASONS)}')
        record = self.store.certificate(certificate_id) if self.db_path.exists() else None
        if record is None:
            raise AcmeAdminError(f'No ACME certificate with id {certificate_id!r}', 404, 'ACME_CERTIFICATE_NOT_FOUND')
        if not self.store.revoke(record['id'], reason):
            raise AcmeAdminError('The certificate is revoked already', 409, 'ACME_CERTIFICATE_ALREADY_REVOKED')
        with self._crl_lock:
            self._crl['der'] = None
        return next(c for c in self.certificates_view() if c['id'] == certificate_id)

    def admin_deactivate(self, account_id):
        """Stop an account for good: it orders nothing again, which disabling its EAB key does not do."""
        account = self.store.account(account_id) if self.db_path.exists() else None
        if account is None:
            raise AcmeAdminError(f'No ACME account with id {account_id!r}', 404, 'ACME_ACCOUNT_NOT_FOUND')
        if account['status'] != 'valid':
            raise AcmeAdminError(f'The account is {account["status"]} already', 409, 'ACME_ACCOUNT_NOT_VALID')
        self.store.deactivate(account_id)
        return next(a for a in self.accounts_view() if a['id'] == account_id)

    # -- orders (section 7.4), authorizations and challenges --------------

    def validity_days(self):
        value = self.config().get('validity_days')
        low, high = INT_OPTIONS['validity_days']
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            return acme_ca.DEFAULT_VALIDITY_DAYS
        return value

    def dns_resolver(self):
        """The resolver dns-01 asks (decision I1): the configured nameservers, else the system's."""
        nameservers = dns_resolver.configured_nameservers(self._settings.load_settings())
        return dns_resolver.build(timeout=acme_validation.BUDGET_SECONDS, nameservers=nameservers)

    def names_for(self, account):
        """The patterns an account's orders are held to (decision F1 on #476).

        The EAB key that enrolled it, disabled or not: disabling a key stops
        it enrolling, and the accounts it enrolled keep their names.
        Accounts enrolled without one get the server-wide list.
        """
        config = self.config()
        if account.get('eab_kid'):
            for entry in config.get('eab_keys') or []:
                if isinstance(entry, dict) and entry.get('kid') == account['eab_kid']:
                    return list(entry.get('allowed_identifiers') or [])
            return []
        return list(config.get('allowed_identifiers') or [])

    def new_order(self, req):
        payload = req.json()
        replaced = self._replaced_by(payload.get('replaces'), req.account) if 'replaces' in payload else None
        if 'notBefore' in payload or 'notAfter' in payload:
            raise AcmeProblem('malformed', 'This server sets the validity of its certificates; '
                              'send neither notBefore nor notAfter')
        identifiers = payload.get('identifiers')
        if not isinstance(identifiers, list) or not identifiers:
            raise AcmeProblem('malformed', 'identifiers must be a non-empty list')
        if len(identifiers) > MAX_IDENTIFIERS:
            raise AcmeProblem('rejectedIdentifier', f'At most {MAX_IDENTIFIERS} identifiers per order')
        wanted = list({(i['type'], i['value']): i for i in map(_order_identifier, identifiers)}.values())
        patterns = self.names_for(req.account)
        refused = [i for i in wanted if not identifier_allowed(i, patterns)]
        if refused:
            raise AcmeProblem('rejectedIdentifier',
                              f'This account may not order {", ".join(i["value"] for i in refused)}',
                              subproblems=[{'type': 'urn:ietf:params:acme:error:rejectedIdentifier',
                                            'detail': f'{i["value"]} is outside the names of this account',
                                            'identifier': i} for i in refused])
        expires = (utc_now() + ORDER_LIFETIME).isoformat()
        return self.store.create_order(req.account['id'], wanted, expires,
                                       replaces=replaced['id'] if replaced else None)

    def _replaced_by(self, cert_id, account):
        """RFC 9773 section 5: the certificate a new order replaces, the account's own and not replaced yet."""
        record = self.certificate_for_ari(cert_id)
        if record is None:
            raise AcmeProblem('malformed', 'replaces names no certificate this server issued')
        if record['account_id'] != account['id']:
            raise AcmeProblem('unauthorized', 'replaces names a certificate of another account')
        if self.store.order_replacing(record['id']) is not None:
            raise AcmeProblem('alreadyReplaced', 'An order replaces that certificate already')
        return record

    # -- ACME Renewal Information (RFC 9773) ------------------------------

    def certificate_for_ari(self, cert_id):
        """The certificate a renewalInfo identifier names: base64url(AKI) "." base64url(serial).

        None when the identifier is well formed and names nothing of this
        server's; malformed when it is not an identifier at all.
        """
        try:
            akid_part, serial_part = cert_id.split('.')
            key_identifier = b64.b64decode(akid_part)
            serial = int.from_bytes(b64.b64decode(serial_part), 'big', signed=True)
        except (ValueError, TypeError, AttributeError):
            raise AcmeProblem('malformed', 'A certificate identifier is base64url(AKI) "." base64url(serial)') from None
        # The serial first, the root second: a lookup must not create the ACME
        # root on a server that never issued, and one that issued has it.
        record = self.store.certificate_by_serial(format(serial, 'x')) if self.db_path.exists() else None
        if record is None:
            return None
        ours = x509.AuthorityKeyIdentifier.from_issuer_public_key(self.ca.root().public_key()).key_identifier
        return record if _hmac.compare_digest(key_identifier, ours) else None

    def renewal_info(self, cert_id):
        """The suggested window (RFC 9773 section 4.2), or None for an identifier that names nothing here."""
        record = self.certificate_for_ari(cert_id)
        if record is None:
            return None
        if record['revoked_at']:
            end = datetime.fromisoformat(record['revoked_at'])
            start = end - ARI_REVOKED_WINDOW
        else:
            leaf = x509.load_pem_x509_certificate(record['pem'].encode())
            born = leaf.not_valid_before_utc.replace(tzinfo=None)
            lifetime = leaf.not_valid_after_utc.replace(tzinfo=None) - born
            start, end = (born + lifetime * share for share in ARI_WINDOW)
        return {'suggestedWindow': {'start': _rfc3339(start.isoformat()), 'end': _rfc3339(end.isoformat())}}

    def owned(self, item, account, what):
        if item is None or item['account_id'] != account['id']:
            raise AcmeProblem('unauthorized', f'No {what} of this account has that URL')
        return item

    def order_json(self, order, urls):
        authorizations = self.store.authorizations_of(order['id'])
        status = order['status']
        if status in ('pending', 'ready') and _expired(order['expires']):
            status = 'invalid'
        body = {
            'status': status,
            'expires': _rfc3339(order['expires']),
            'identifiers': order['identifiers'],
            'authorizations': [urls.authz(a['id']) for a in authorizations],
            'finalize': urls.finalize(order['id']),
        }
        if order.get('error'):
            body['error'] = order['error']
        if order.get('replaces'):
            replaced = self.store.certificate(order['replaces'])
            if replaced:
                body['replaces'] = _ari_id(replaced, self.ca.root())
        if status == 'valid':
            certificate = self.store.certificate_of_order(order['id'])
            if certificate:
                body['certificate'] = urls.certificate(certificate['id'])
        return body

    # -- finalize, certificates and revocation (sections 7.4, 7.4.2, 7.6) -----

    def finalize(self, req, order, urls):
        status = self.order_json(order, urls)['status']
        if status != 'ready':
            raise AcmeProblem('orderNotReady', f'The order is {status}, not ready')
        csr = _csr_for(req.json().get('csr'), order['identifiers'])
        if not self.store.begin_finalize(order['id']):
            raise AcmeProblem('orderNotReady', 'The order is being finalized already')
        issued = None
        try:
            names = [i['value'] for i in order['identifiers']]
            certificate = self.ca.issue(csr, order['identifiers'], self.validity_days())
            issued = self.store.finish_finalize(
                order['id'], order['account_id'], format(certificate.serial_number, 'x'), names,
                certificate.not_valid_after_utc.replace(tzinfo=None).isoformat(),
                certificate.public_bytes(serialization.Encoding.PEM).decode('ascii'))
        finally:
            if issued is None:
                # Back to ready, so the client can finalize again once the
                # cause (the CA could not be made, say) is gone.
                self.store.abort_finalize(order['id'])
        return self.store.order(order['id'])

    def revoke(self, req):
        """Section 7.6: by the account that ordered it, or by the certificate's own key (decision G4)."""
        payload = req.json()
        try:
            presented = x509.load_der_x509_certificate(b64.b64decode(payload.get('certificate', '')))
        except (ValueError, TypeError):
            raise AcmeProblem('malformed', 'certificate must be the base64url DER of a certificate') from None
        record = self.store.certificate_by_serial(format(presented.serial_number, 'x'))
        stored_der = (x509.load_pem_x509_certificate(record['pem'].encode()).public_bytes(serialization.Encoding.DER)
                      if record else None)
        if stored_der != presented.public_bytes(serialization.Encoding.DER):
            raise AcmeProblem('malformed', 'This server did not issue that certificate')
        if req.account is not None:
            if req.account['id'] != record['account_id']:
                raise AcmeProblem('unauthorized', 'Only the account that ordered a certificate, or its own '
                                  'key, may revoke it')
        elif _spki(req.jwk.key) != _spki(presented.public_key()):
            raise AcmeProblem('unauthorized', 'The request is signed by neither the ordering account '
                              'nor the key of the certificate')
        reason = payload.get('reason', 0)
        if isinstance(reason, bool) or reason not in REVOCATION_REASONS:
            raise AcmeProblem('badRevocationReason', f'The reason must be one of {sorted(REVOCATION_REASONS)}')
        if not self.store.revoke(record['id'], reason):
            raise AcmeProblem('alreadyRevoked', 'The certificate is revoked already')
        with self._crl_lock:
            self._crl['der'] = None

    def crl_der(self):
        """The CRL of the ACME CA, made again after a revocation and at least hourly."""
        with self._crl_lock:
            if self._crl['der'] is None or time.monotonic() - self._crl['at'] > CRL_CACHE_SECONDS:
                records = [{'serial_number': int(r['serial'], 16), 'revoked_at': r['revoked_at'],
                            'reason_revoked': REVOCATION_REASONS.get(r['reason'], 'unspecified')}
                           for r in self.store.revoked()]
                self._crl = {'der': self.ca.crl_der(records), 'at': time.monotonic()}
            return self._crl['der']

    def authz_json(self, authz, urls):
        status = authz['status']
        if status == 'pending' and _expired(authz['expires']):
            status = 'expired'
        identifier = {'type': authz['identifier']['type'], 'value': authz['identifier']['value']}
        body = {
            'status': status,
            'expires': _rfc3339(authz['expires']),
            'identifier': identifier,
            'challenges': [self.challenge_json(c, urls) for c in self.store.challenges_of(authz['id'])],
        }
        if authz['identifier'].get('wildcard'):
            body['wildcard'] = True
        return body

    @staticmethod
    def challenge_json(challenge, urls):
        body = {'type': challenge['type'], 'url': urls.challenge(challenge['id']),
                'status': challenge['status'], 'token': challenge['token']}
        if challenge.get('validated'):
            body['validated'] = _rfc3339(challenge['validated'])
        if challenge.get('error'):
            body['error'] = challenge['error']
        return body

    def update_authz(self, req, authz):
        """Section 7.5.2: a client may deactivate its own authorization."""
        if req.is_post_as_get:
            return authz
        if req.json().get('status') == 'deactivated':
            if authz['status'] not in ('pending', 'valid'):
                raise AcmeProblem('malformed', f'An authorization that is {authz["status"]} cannot be deactivated')
            return self.store.deactivate_authorization(authz['id'])
        return authz

    def respond_to_challenge(self, req, challenge, authz):
        """Section 7.5.1: the client says it is ready; the check runs now (decision F3)."""
        if req.is_post_as_get or challenge['status'] != 'pending':
            return challenge
        if authz['status'] != 'pending' or _expired(authz['expires']):
            raise AcmeProblem('malformed', 'The authorization of this challenge is no longer pending')
        key_authorization = f'{challenge["token"]}.{thumbprint(req.jwk)}'
        name = authz['identifier']['value']
        try:
            if challenge['type'] == 'dns-01':
                acme_validation.dns01(name, key_authorization, resolver=self.dns_resolver())
            else:
                acme_validation.http01(name, challenge['token'], key_authorization,
                                       port=self.http01_port, https_port=self.https_port, resolve=self.resolve)
        except acme_validation.ValidationFailed as failed:
            self.store.record_challenge(challenge['id'], False, AcmeProblem(failed.kind, failed.detail).to_json())
        else:
            self.store.record_challenge(challenge['id'], True)
        return self.store.challenge(challenge['id'])

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
        mac_key = _eab_mac_key(entry.get('hmac_key'))
        if mac_key is None:
            logger.warning('EAB key %r holds no usable HMAC key, as a share-safe backup restored onto '
                           'another instance leaves it; it enrols no one, so create a new key', header.kid)
            valid = False
        else:
            try:
                valid = parsed.signature.verify(parsed.payload, josepy.JWKOct(key=mac_key))
            except (ValueError, TypeError, josepy.errors.Error):
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


def name_allowed(name, patterns):
    """Is *name* one of *patterns*: the name itself, or below a "*." pattern?

    The same rule decides a wildcard (decision I2 on #476): *.B ends in ".P"
    exactly when B is P or below it, so a "*.P" pattern allows it, and an exact
    name never does, since no exact name starts with "*.".
    """
    for pattern in patterns:
        if pattern.startswith('*.'):
            if name.endswith(pattern[1:]):
                return True
        elif name == pattern:
            return True
    return False


def identifier_allowed(identifier, patterns):
    """Is *identifier* one of *patterns*? An address by the address patterns, a name by the name ones.

    A stored pattern is read as an address pattern when it is written as one,
    whenever it was stored: before #1338 an address was kept as a name. A name
    can never equal an address pattern, since _order_name refuses an all-digit
    last label, so name_allowed needs no filter.
    """
    if identifier['type'] == 'ip':
        address = ipaddress.ip_address(identifier['value'])
        return any(network is not None and address in network
                   for network in (_written_network(p) for p in patterns))
    return name_allowed(identifier['value'], patterns)


def _order_identifier(item):
    """The identifier an order asks for, normalised, or a refusal: a DNS name, or an IPv4 address."""
    if not isinstance(item, dict) or not isinstance(item.get('value'), str):
        raise AcmeProblem('malformed', 'Each identifier is an object with a type and a value')
    if item.get('type') == 'ip':
        return {'type': 'ip', 'value': _order_address(item['value'])}
    if item.get('type') != 'dns':
        raise AcmeProblem('unsupportedIdentifier',
                          f'Only dns and ip identifiers are supported, not {item.get("type")!r}')
    return {'type': 'dns', 'value': _order_name(item)}


def _order_address(value):
    """The address an "ip" identifier asks for (RFC 8738), or a refusal.

    Its textual form only (section 3): "10.0.0.5", not "010.0.0.5" or with
    spaces, which ipaddress refuses for IPv4. An address http-01 never reaches
    is refused here, by the rule the check itself applies
    (pinned_https.classify): loopback, link-local, multicast, reserved and the
    metadata addresses. Private networks pass, which is what an internal CA is for.
    """
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise AcmeProblem('rejectedIdentifier', f'{value!r} is not an IP address in its textual form') from None
    if address.version == 6:
        raise AcmeProblem('unsupportedIdentifier', f'{value} is an IPv6 address; this server certifies '
                          'IPv4 addresses only, for now')
    if pinned_https.classify(value) == 'refused':
        raise AcmeProblem('rejectedIdentifier', f'{value} is a loopback, link-local, multicast, reserved or '
                          'metadata address, which http-01 can never reach')
    return value


def _order_name(item):
    """The DNS name a dns identifier asks for, normalised, or a refusal."""
    value = item['value'].strip().lower().rstrip('.')
    # A wildcard is "*." and a DNS name, the form name_pattern reads; it is
    # authorized on its base with dns-01 (section 7.1.3, acme_store.create_order).
    try:
        name = name_pattern(value)
    except AcmeAdminError:
        raise AcmeProblem('rejectedIdentifier', f'{item["value"]!r} is not a DNS name') from None
    # No top-level domain is all digits (RFC 3696 section 2), so a name that
    # ends in one is not a DNS name, and an address in particular is an "ip"
    # identifier (RFC 8738 section 3). Taken as a DNS name, "10.0.0.5" passed
    # every check here, was validated over http-01 at that address, and was
    # issued as a dNSName no client accepts as one.
    if name.rsplit('.', 1)[-1].isdigit():
        raise AcmeProblem('rejectedIdentifier', f'{item["value"]!r} is not a DNS name: no top-level domain '
                          'is all digits, and an address is ordered as an "ip" identifier (RFC 8738)')
    return name


def _csr_for(value, identifiers):
    """The CSR of a finalize, checked against the order's identifiers (section 7.4), or badCSR."""
    try:
        csr = x509.load_der_x509_csr(b64.b64decode(value or ''))
    except (ValueError, TypeError):
        raise AcmeProblem('badCSR', 'csr must be the base64url DER of a certificate signing request') from None
    if not csr.is_signature_valid:
        raise AcmeProblem('badCSR', 'The CSR signature does not verify with its own key')
    refusal = acme_ca.csr_key_refusal(csr.public_key())
    if refusal:
        raise AcmeProblem('badCSR', refusal)
    try:
        san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        san = x509.SubjectAlternativeName([])
    if any(not isinstance(general, (x509.DNSName, x509.IPAddress)) for general in san):
        raise AcmeProblem('badCSR', 'The CSR may name DNS names and IP addresses only')
    asked = {('dns', name.lower().rstrip('.')) for name in san.get_values_for_type(x509.DNSName)}
    asked.update(('ip', str(address)) for address in san.get_values_for_type(x509.IPAddress))
    for common in csr.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME):
        # A client may repeat an address in the Common Name, as text.
        try:
            asked.add(('ip', str(ipaddress.ip_address(str(common.value)))))
        except ValueError:
            asked.add(('dns', str(common.value).lower().rstrip('.')))
    wanted = {(i['type'], i['value']) for i in identifiers}
    if asked != wanted:
        raise AcmeProblem('badCSR', f'The CSR names {sorted(v for _, v in asked)}, and the order '
                          f'{sorted(v for _, v in wanted)}: they must be the same')
    return csr


def _ari_id(record, root):
    """The RFC 9773 identifier of a stored certificate, as a client computes it."""
    key_identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(root.public_key()).key_identifier
    serial = int(record['serial'], 16)
    serial_bytes = serial.to_bytes((serial.bit_length() + 8) // 8, 'big', signed=True)
    return f'{b64.b64encode(key_identifier).decode()}.{b64.b64encode(serial_bytes).decode()}'


def _spki(public_key):
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _expired(stamp):
    return datetime.fromisoformat(stamp) <= utc_now()


def _rfc3339(stamp):
    return datetime.fromisoformat(stamp).replace(microsecond=0).isoformat() + 'Z'


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


def _eab_mac_key(value):
    """The HMAC key an EAB entry holds, or None when it holds none worth the name."""
    try:
        key = b64.b64decode(value) if isinstance(value, str) else b''
    except ValueError:
        return None
    return key if len(key) >= MIN_EAB_KEY_BYTES else None
