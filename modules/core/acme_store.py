"""Where the ACME server keeps its state: SQLite under the data directory.

Accounts now; orders, authorizations and challenges join them as the server
grows (#476). SQLite rather than JSON files because an order moves through
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
"""


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


class AcmeStore:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as con, con:
            con.executescript(SCHEMA)

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
