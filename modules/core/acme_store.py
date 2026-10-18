"""Where the ACME server keeps its state: SQLite under the data directory.

Accounts, orders, authorizations and challenges (#476). SQLite rather than
JSON files because an order moves through
states that several requests touch, and a transaction is the cheap way to make
each move all or nothing. One connection per operation, as the inventory does
(cert_inventory.py), so no connection is shared between threads.

The file is data/acme/acme.db. Backups copy it with SQLite's online backup
(file_operations.py), never as raw bytes in the middle of a write.
"""
import json
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from .utils import utc_now

SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    id          TEXT PRIMARY KEY,
    thumbprint  TEXT NOT NULL UNIQUE,
    jwk         TEXT NOT NULL,
    status      TEXT NOT NULL,
    contact     TEXT NOT NULL,
    eab_kid     TEXT,
    created_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orders (
    id           TEXT PRIMARY KEY,
    account_id   TEXT NOT NULL,
    status       TEXT NOT NULL,
    expires      TEXT NOT NULL,
    identifiers  TEXT NOT NULL,
    error        TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS orders_by_account ON orders (account_id);
CREATE TABLE IF NOT EXISTS authorizations (
    id          TEXT PRIMARY KEY,
    order_id    TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    identifier  TEXT NOT NULL,
    status      TEXT NOT NULL,
    expires     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS authorizations_by_order ON authorizations (order_id);
CREATE TABLE IF NOT EXISTS challenges (
    id         TEXT PRIMARY KEY,
    authz_id   TEXT NOT NULL,
    type       TEXT NOT NULL,
    token      TEXT NOT NULL,
    status     TEXT NOT NULL,
    validated  TEXT,
    error      TEXT
);
CREATE INDEX IF NOT EXISTS challenges_by_authz ON challenges (authz_id);
CREATE TABLE IF NOT EXISTS certificates (
    id          TEXT PRIMARY KEY,
    order_id    TEXT NOT NULL UNIQUE,
    account_id  TEXT NOT NULL,
    serial      TEXT NOT NULL UNIQUE,
    names       TEXT NOT NULL,
    not_after   TEXT NOT NULL,
    pem         TEXT NOT NULL,
    revoked_at  TEXT,
    reason      INTEGER,
    created_at  TEXT NOT NULL
);
"""


# Columns added after a table first shipped, added to a database that lacks
# them: CREATE TABLE IF NOT EXISTS leaves an existing table as it was.
_ADDED_COLUMNS = (
    ('orders', 'replaces', "ALTER TABLE orders ADD COLUMN replaces TEXT"),
)


class KeyInUse(Exception):
    """Another account already has this key."""

    def __init__(self, account_id):
        super().__init__(account_id)
        self.account_id = account_id


def _account(row):
    if row is None:
        return None
    account = dict(row)
    account['contact'] = json.loads(account['contact'])
    return account


def _decoded(row, *json_fields):
    if row is None:
        return None
    item = dict(row)
    for name in json_fields:
        if item.get(name) is not None:
            item[name] = json.loads(item[name])
    return item


def _new_id():
    return secrets.token_urlsafe(12)


class AcmeStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as con, con:
            con.executescript(SCHEMA)
            for table, column, statement in _ADDED_COLUMNS:
                if column not in {row[1] for row in con.execute(f'PRAGMA table_info({table})')}:
                    con.execute(statement)

    def _connect(self):
        con = sqlite3.connect(self.path, timeout=10)
        con.row_factory = sqlite3.Row
        return con

    def account(self, account_id):
        with closing(self._connect()) as con:
            return _account(con.execute('SELECT * FROM accounts WHERE id = ?', (account_id,)).fetchone())

    def account_by_thumbprint(self, thumbprint):
        with closing(self._connect()) as con:
            return _account(con.execute('SELECT * FROM accounts WHERE thumbprint = ?', (thumbprint,)).fetchone())

    def create_account(self, jwk_json, thumbprint, contact, eab_kid):
        """A new valid account; KeyInUse when another request registered the key first."""
        account_id = secrets.token_urlsafe(12)
        try:
            with closing(self._connect()) as con, con:
                con.execute(
                    'INSERT INTO accounts (id, thumbprint, jwk, status, contact, eab_kid, created_at) '
                    'VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (account_id, thumbprint, jwk_json, 'valid', json.dumps(contact), eab_kid,
                     utc_now().isoformat()))
        except sqlite3.IntegrityError:
            existing = self.account_by_thumbprint(thumbprint)
            raise KeyInUse(existing['id'] if existing else None) from None
        return self.account(account_id)

    def accounts_per_eab_key(self):
        """{eab_kid: number of accounts it enrolled}."""
        with closing(self._connect()) as con:
            rows = con.execute('SELECT eab_kid, count(*) FROM accounts WHERE eab_kid IS NOT NULL '
                               'GROUP BY eab_kid').fetchall()
        return dict(rows)

    # -- orders (section 7.4), their authorizations and challenges ---------

    def create_order(self, account_id, identifiers, expires, replaces=None):
        """An order with one pending authorization per identifier, written in one transaction.

        A name gets an http-01 and a dns-01 challenge, each with a token of its
        own, and the client answers the one it can. A wildcard is authorized
        on its base name with dns-01 alone (RFC 8555 section 7.1.3), and the
        authorization's identifier carries `wildcard` so that it can say so.
        """
        order_id = _new_id()
        now = utc_now().isoformat()
        with closing(self._connect()) as con, con:
            con.execute('INSERT INTO orders (id, account_id, status, expires, identifiers, created_at, replaces) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?)',
                        (order_id, account_id, 'pending', expires, json.dumps(identifiers), now, replaces))
            for identifier in identifiers:
                authz_id = _new_id()
                wildcard = identifier['value'].startswith('*.')
                authorized = ({'type': 'dns', 'value': identifier['value'][2:], 'wildcard': True}
                              if wildcard else identifier)
                con.execute('INSERT INTO authorizations (id, order_id, account_id, identifier, status, expires) '
                            'VALUES (?, ?, ?, ?, ?, ?)',
                            (authz_id, order_id, account_id, json.dumps(authorized), 'pending', expires))
                for kind in (('dns-01',) if wildcard else ('http-01', 'dns-01')):
                    con.execute('INSERT INTO challenges (id, authz_id, type, token, status) VALUES (?, ?, ?, ?, ?)',
                                (_new_id(), authz_id, kind, secrets.token_urlsafe(32), 'pending'))
        return self.order(order_id)

    def order(self, order_id):
        with closing(self._connect()) as con:
            return _decoded(con.execute('SELECT * FROM orders WHERE id = ?', (order_id,)).fetchone(),
                            'identifiers', 'error')

    def order_ids_of(self, account_id):
        with closing(self._connect()) as con:
            return [row[0] for row in con.execute(
                'SELECT id FROM orders WHERE account_id = ? ORDER BY created_at', (account_id,))]

    def authorizations_of(self, order_id):
        with closing(self._connect()) as con:
            return [_decoded(row, 'identifier') for row in con.execute(
                'SELECT * FROM authorizations WHERE order_id = ? ORDER BY rowid', (order_id,))]

    def authorization(self, authz_id):
        with closing(self._connect()) as con:
            return _decoded(con.execute('SELECT * FROM authorizations WHERE id = ?', (authz_id,)).fetchone(),
                            'identifier')

    def challenges_of(self, authz_id):
        with closing(self._connect()) as con:
            return [_decoded(row, 'error') for row in con.execute(
                'SELECT * FROM challenges WHERE authz_id = ? ORDER BY rowid', (authz_id,))]

    def challenge(self, challenge_id):
        with closing(self._connect()) as con:
            return _decoded(con.execute('SELECT * FROM challenges WHERE id = ?', (challenge_id,)).fetchone(),
                            'error')

    def record_challenge(self, challenge_id, valid, error=None):
        """The outcome of a check, carried to the challenge, its authorization
        and its order in one transaction (section 7.1.6)."""
        status = 'valid' if valid else 'invalid'
        with closing(self._connect()) as con, con:
            row = con.execute('SELECT authz_id FROM challenges WHERE id = ?', (challenge_id,)).fetchone()
            authz_id = row[0]
            con.execute('UPDATE challenges SET status = ?, validated = ?, error = ? WHERE id = ?',
                        (status, utc_now().isoformat() if valid else None,
                         json.dumps(error) if error else None, challenge_id))
            con.execute('UPDATE authorizations SET status = ? WHERE id = ?', (status, authz_id))
            order_id = con.execute('SELECT order_id FROM authorizations WHERE id = ?', (authz_id,)).fetchone()[0]
            self._settle_order(con, order_id)

    def deactivate_authorization(self, authz_id):
        with closing(self._connect()) as con, con:
            con.execute("UPDATE authorizations SET status = 'deactivated' WHERE id = ?", (authz_id,))
            order_id = con.execute('SELECT order_id FROM authorizations WHERE id = ?', (authz_id,)).fetchone()[0]
            self._settle_order(con, order_id)
        return self.authorization(authz_id)

    @staticmethod
    def _settle_order(con, order_id):
        """pending until every authorization is valid, then ready; invalid
        as soon as one is not going to be."""
        statuses = [row[0] for row in con.execute(
            'SELECT status FROM authorizations WHERE order_id = ?', (order_id,))]
        if any(s in ('invalid', 'deactivated', 'revoked') for s in statuses):
            status = 'invalid'
        elif statuses and all(s == 'valid' for s in statuses):
            status = 'ready'
        else:
            status = 'pending'
        con.execute("UPDATE orders SET status = ? WHERE id = ? AND status IN ('pending', 'ready')",
                    (status, order_id))

    # -- finalize (section 7.4) and the certificates it makes -------------

    def begin_finalize(self, order_id):
        """Move a ready order to processing; False when it was not ready.

        One UPDATE, so of two finalize requests for the same order only one
        goes on to issue."""
        with closing(self._connect()) as con, con:
            moved = con.execute("UPDATE orders SET status = 'processing' WHERE id = ? AND status = 'ready'",
                                (order_id,)).rowcount
        return moved == 1

    def abort_finalize(self, order_id):
        with closing(self._connect()) as con, con:
            con.execute("UPDATE orders SET status = 'ready' WHERE id = ? AND status = 'processing'", (order_id,))

    def finish_finalize(self, order_id, account_id, serial, names, not_after, pem):
        certificate_id = _new_id()
        with closing(self._connect()) as con, con:
            con.execute('INSERT INTO certificates (id, order_id, account_id, serial, names, not_after, pem, created_at) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                        (certificate_id, order_id, account_id, serial, json.dumps(names), not_after, pem,
                         utc_now().isoformat()))
            con.execute("UPDATE orders SET status = 'valid' WHERE id = ?", (order_id,))
        return self.certificate(certificate_id)

    def certificate(self, certificate_id):
        with closing(self._connect()) as con:
            return _decoded(con.execute('SELECT * FROM certificates WHERE id = ?', (certificate_id,)).fetchone(),
                            'names')

    def certificate_of_order(self, order_id):
        with closing(self._connect()) as con:
            return _decoded(con.execute('SELECT * FROM certificates WHERE order_id = ?', (order_id,)).fetchone(),
                            'names')

    def certificate_by_serial(self, serial):
        with closing(self._connect()) as con:
            return _decoded(con.execute('SELECT * FROM certificates WHERE serial = ?', (serial,)).fetchone(),
                            'names')

    def revoke(self, certificate_id, reason):
        """Record a revocation once; False when it was revoked already."""
        with closing(self._connect()) as con, con:
            changed = con.execute('UPDATE certificates SET revoked_at = ?, reason = ? '
                                  'WHERE id = ? AND revoked_at IS NULL',
                                  (utc_now().isoformat(), reason, certificate_id)).rowcount
        return changed == 1

    def revoked(self):
        with closing(self._connect()) as con:
            return [dict(row) for row in con.execute(
                'SELECT serial, revoked_at, reason FROM certificates WHERE revoked_at IS NOT NULL')]

    # -- what the admin API lists ------------------------------------------

    def certificates_listed(self):
        """Every certificate, newest first, with the account and EAB key behind it."""
        with closing(self._connect()) as con:
            return [_decoded(row, 'names') for row in con.execute(
                'SELECT c.id, c.order_id, c.account_id, c.serial, c.names, c.not_after, c.revoked_at, '
                'c.reason, c.created_at, a.eab_kid FROM certificates c '
                'LEFT JOIN accounts a ON a.id = c.account_id ORDER BY c.created_at DESC')]

    def accounts_listed(self):
        """Every account, oldest first, with how many orders and certificates it has."""
        with closing(self._connect()) as con:
            return [_account(row) for row in con.execute(
                'SELECT a.id, a.status, a.contact, a.eab_kid, a.created_at, '
                '(SELECT count(*) FROM orders o WHERE o.account_id = a.id) AS orders, '
                '(SELECT count(*) FROM certificates c WHERE c.account_id = a.id) AS certificates '
                'FROM accounts a ORDER BY a.created_at')]

    def order_replacing(self, certificate_id):
        """The order that replaces this certificate and has not failed, or None (RFC 9773 section 5)."""
        with closing(self._connect()) as con:
            return _decoded(con.execute(
                "SELECT * FROM orders WHERE replaces = ? AND status != 'invalid'", (certificate_id,)).fetchone(),
                'identifiers', 'error')

    def update_contact(self, account_id, contact):
        with closing(self._connect()) as con, con:
            con.execute('UPDATE accounts SET contact = ? WHERE id = ?', (json.dumps(contact), account_id))
        return self.account(account_id)

    def deactivate(self, account_id):
        with closing(self._connect()) as con, con:
            con.execute("UPDATE accounts SET status = 'deactivated' WHERE id = ?", (account_id,))
        return self.account(account_id)

    def change_key(self, account_id, jwk_json, thumbprint):
        """Replace the account's key; KeyInUse names the account that has the new one."""
        try:
            with closing(self._connect()) as con, con:
                con.execute('UPDATE accounts SET jwk = ?, thumbprint = ? WHERE id = ?',
                            (jwk_json, thumbprint, account_id))
        except sqlite3.IntegrityError:
            existing = self.account_by_thumbprint(thumbprint)
            raise KeyInUse(existing['id'] if existing else None) from None
        return self.account(account_id)
