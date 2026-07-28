"""Certificate inventory — a persistent, fingerprint-keyed record of every
certificate CertMate has seen, whether it issued it or merely observed it.

CertMate historically only knew about the certificates it issued
(``settings.json`` + ``certificates/<domain>/``). This store adds a durable
inventory keyed by the certificate's **SHA-256 fingerprint**, so that one
certificate serving many hostnames collapses to a single record with many
observed endpoints, and re-observing a certificate is idempotent.

Storage is a single SQLite database at ``<data_dir>/inventory/inventory.db``
(sqlite3 is stdlib — no new dependency). It deliberately uses the default
rollback-journal mode, not WAL: the at-rest ``.db`` file is consistent between
transactions, so the unified backup (which carries the ``data/inventory``
subtree, see ``file_operations._BACKUP_DATA_SUBTREES``) captures a coherent
snapshot without extra ``-wal``/``-shm`` sidecar files to reconcile on restore.

Schema (versioned via ``PRAGMA user_version``):

* ``certificates`` — one row per unique fingerprint: the cert's immutable
  metadata (subject, issuer, serial, validity, key, signature algorithm, SAN),
  its discovery ``source``, whether CertMate ``managed`` it (and which managed
  domain it maps to), and ``first_seen`` / ``last_seen``.
* ``endpoints`` — every ``(host, port)`` a fingerprint was observed at, each
  with its own ``first_seen`` / ``last_seen`` (cascade-deleted with the cert).

The store is thread-safe by opening a short-lived connection per operation:
SQLite serialises writers at the file level, and each public method runs in a
single committed transaction, so concurrent Flask worker threads are safe.
"""

import json
import logging
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .utils import utc_now_iso

logger = logging.getLogger(__name__)

# Bump when the schema changes and add a migration branch in ``_migrate``.
SCHEMA_VERSION = 1

# Recognised discovery sources. ``issued`` = CertMate minted it; ``probed`` =
# seen live via the TLS probe; ``ct-log`` = discovered in Certificate
# Transparency; ``imported`` = loaded from an external source.
SOURCES = ('issued', 'probed', 'ct-log', 'imported')

_SCHEMA = """
CREATE TABLE IF NOT EXISTS certificates (
    fingerprint          TEXT PRIMARY KEY,
    subject_cn           TEXT,
    subject              TEXT,
    issuer_cn            TEXT,
    issuer               TEXT,
    serial               TEXT,
    not_before           TEXT,
    not_after            TEXT,
    key_type             TEXT,
    key_size             INTEGER,
    key_curve            TEXT,
    signature_algorithm  TEXT,
    san_dns              TEXT,   -- JSON array of dNSName SANs
    source               TEXT NOT NULL,
    managed              INTEGER NOT NULL DEFAULT 0,
    managed_domain       TEXT,
    first_seen           TEXT NOT NULL,
    last_seen            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS endpoints (
    fingerprint  TEXT NOT NULL,
    host         TEXT NOT NULL,
    port         INTEGER NOT NULL,
    first_seen   TEXT NOT NULL,
    last_seen    TEXT NOT NULL,
    PRIMARY KEY (fingerprint, host, port),
    FOREIGN KEY (fingerprint) REFERENCES certificates(fingerprint) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_endpoints_hostport ON endpoints(host, port);
CREATE INDEX IF NOT EXISTS idx_certificates_managed ON certificates(managed);
CREATE INDEX IF NOT EXISTS idx_certificates_not_after ON certificates(not_after);
"""


class CertInventory:
    """A SQLite-backed, fingerprint-keyed certificate inventory."""

    DB_FILENAME = 'inventory.db'

    def __init__(self, data_dir, busy_timeout=5.0):
        """Open (creating if needed) the inventory under ``data_dir/inventory``.

        ``busy_timeout`` is how long a connection waits for a competing writer's
        lock before raising ``sqlite3.OperationalError`` — keeps concurrent
        worker threads from failing fast under brief contention.
        """
        self.inventory_dir = Path(data_dir) / 'inventory'
        self.inventory_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.inventory_dir / self.DB_FILENAME
        self._busy_timeout = busy_timeout
        self._migrate()

    # --- connection / schema ------------------------------------------------ #

    def _connect(self):
        conn = sqlite3.connect(str(self.db_path), timeout=self._busy_timeout)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        return conn

    @contextmanager
    def _read_conn(self):
        """A short-lived connection for reads, always closed on exit.

        ``sqlite3``'s own ``with conn`` context manages the transaction but does
        NOT close the connection; wrapping it here honours the "short-lived
        connection per operation" contract on every interpreter (not just
        CPython's prompt refcounting).
        """
        conn = self._connect()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def _write_conn(self):
        """A short-lived connection for writes: one committed transaction,
        always closed on exit (rolled back if the body raises)."""
        conn = self._connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _migrate(self):
        """Create/upgrade the schema, tracked by ``PRAGMA user_version``."""
        with self._write_conn() as conn:
            version = conn.execute('PRAGMA user_version').fetchone()[0]
            if version >= SCHEMA_VERSION:
                return
            # v0 -> v1: initial schema.
            conn.executescript(_SCHEMA)
            conn.execute(f'PRAGMA user_version = {SCHEMA_VERSION}')
            logger.info(
                "Certificate inventory schema initialised at %s (v%d)",
                self.db_path, SCHEMA_VERSION,
            )

    # --- writes ------------------------------------------------------------- #

    def record_observation(
        self,
        *,
        fingerprint,
        host,
        port,
        subject_cn=None,
        subject=None,
        issuer_cn=None,
        issuer=None,
        serial=None,
        not_before=None,
        not_after=None,
        key=None,
        signature_algorithm=None,
        san_dns=None,
        source='probed',
        managed=False,
        managed_domain=None,
        observed_at=None,
    ):
        """Idempotently record that *fingerprint* was observed at *host*:*port*.

        Keyed by fingerprint: a new fingerprint inserts a certificate row; a
        known one only refreshes ``last_seen`` (and can be promoted to
        ``managed``). The endpoint is upserted independently, so one certificate
        seen on N hosts yields one certificate row with N endpoint rows.

        ``host``/``port`` may both be omitted for an endpoint-less observation
        (e.g. a certificate discovered in a CT log, which has no served
        ``host:port``); the certificate row is still created/updated. Supplying
        only one of the two is an error.

        The certificate's cryptographic metadata is immutable for a given
        fingerprint (the fingerprint *is* the hash of the whole cert), so it is
        written only on first insert and never rewritten. ``source`` is likewise
        preserved from first discovery; ``managed`` is sticky-true and
        ``managed_domain`` is filled in if a later observation supplies it.

        Returns the fingerprint.
        """
        if not fingerprint:
            raise ValueError("fingerprint is required")
        if source not in SOURCES:
            raise ValueError(f"unknown source {source!r}; use one of {SOURCES}")
        if (host is None) != (port is None):
            raise ValueError("host and port must be provided together")

        now = observed_at or utc_now_iso()
        key = key or {}
        san_json = json.dumps(list(san_dns or []))
        managed_int = 1 if managed else 0

        with self._write_conn() as conn:
            conn.execute(
                """
                INSERT INTO certificates (
                    fingerprint, subject_cn, subject, issuer_cn, issuer, serial,
                    not_before, not_after, key_type, key_size, key_curve,
                    signature_algorithm, san_dns, source, managed,
                    managed_domain, first_seen, last_seen
                ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    -- managed is sticky-true; a later 'managed' observation
                    -- promotes a previously-unmanaged record.
                    managed = MAX(certificates.managed, excluded.managed),
                    -- fill the managed domain link if we did not have one yet.
                    managed_domain = COALESCE(
                        certificates.managed_domain, excluded.managed_domain
                    )
                """,
                (
                    fingerprint, subject_cn, subject, issuer_cn, issuer, serial,
                    not_before, not_after, key.get('type'), key.get('size'),
                    key.get('curve'), signature_algorithm, san_json, source,
                    managed_int, managed_domain, now, now,
                ),
            )
            if host is not None:
                conn.execute(
                    """
                    INSERT INTO endpoints (fingerprint, host, port, first_seen, last_seen)
                    VALUES (?,?,?,?,?)
                    ON CONFLICT(fingerprint, host, port) DO UPDATE SET
                        last_seen = excluded.last_seen
                    """,
                    (fingerprint, host, int(port), now, now),
                )
        return fingerprint

    def record_certificate(self, certificate, *, source, managed=False,
                           managed_domain=None, observed_at=None,
                           host=None, port=None):
        """Record a parsed certificate metadata dict (see
        :func:`cert_probe.parse_certificate`'s ``certificate`` block).

        The bridge used by every source: pass the parsed metadata plus a
        ``source``, and optionally a ``host``/``port`` for a served observation.
        Returns the fingerprint, or ``None`` if the metadata has none.
        """
        if not isinstance(certificate, dict):
            return None
        fingerprint = certificate.get('fingerprint_sha256')
        if not fingerprint:
            return None
        return self.record_observation(
            fingerprint=fingerprint,
            host=host,
            port=port,
            subject_cn=certificate.get('subject_cn'),
            subject=certificate.get('subject'),
            issuer_cn=certificate.get('issuer_cn'),
            issuer=certificate.get('issuer'),
            serial=certificate.get('serial_number'),
            not_before=certificate.get('not_before'),
            not_after=certificate.get('not_after'),
            key=certificate.get('key'),
            signature_algorithm=certificate.get('signature_algorithm'),
            san_dns=certificate.get('san_dns'),
            source=source,
            managed=managed,
            managed_domain=managed_domain,
            observed_at=observed_at,
        )

    def record_probe_result(self, probe_result, *, source='probed',
                            managed=False, managed_domain=None, observed_at=None):
        """Ingest a :func:`cert_probe.probe_certificate` result into the inventory.

        Only an ``ok`` result carries a certificate; anything else (blocked /
        unreachable) is skipped and returns ``None``, so a caller can feed a raw
        sweep result without pre-filtering. Returns the recorded fingerprint on
        success.
        """
        if not isinstance(probe_result, dict) or probe_result.get('status') != 'ok':
            return None
        return self.record_certificate(
            probe_result.get('certificate') or {},
            host=probe_result.get('host'),
            port=probe_result.get('port'),
            source=source,
            managed=managed,
            managed_domain=managed_domain,
            observed_at=observed_at,
        )

    # --- reads -------------------------------------------------------------- #

    def get(self, fingerprint):
        """Return the full record for *fingerprint* (cert + endpoints), or None."""
        with self._read_conn() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            if row is None:
                return None
            endpoints = conn.execute(
                "SELECT host, port, first_seen, last_seen FROM endpoints "
                "WHERE fingerprint = ? ORDER BY host, port",
                (fingerprint,),
            ).fetchall()
        return _row_to_record(row, endpoints)

    def list_all(self, *, managed=None, source=None, limit=None, offset=0):
        """List inventory records, newest observation first.

        Optional filters: ``managed`` (bool) and ``source``. ``limit``/``offset``
        paginate. Each record includes its full endpoint list.
        """
        clauses, params = [], []
        if managed is not None:
            clauses.append("managed = ?")
            params.append(1 if managed else 0)
        if source is not None:
            clauses.append("source = ?")
            params.append(source)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM certificates {where} ORDER BY last_seen DESC, fingerprint"
        if limit is not None:
            sql += " LIMIT ? OFFSET ?"
            params.extend([int(limit), int(offset)])

        with self._read_conn() as conn:
            cert_rows = conn.execute(sql, params).fetchall()
            records = []
            for row in cert_rows:
                endpoints = conn.execute(
                    "SELECT host, port, first_seen, last_seen FROM endpoints "
                    "WHERE fingerprint = ? ORDER BY host, port",
                    (row['fingerprint'],),
                ).fetchall()
                records.append(_row_to_record(row, endpoints))
        return records

    def find_by_endpoint(self, host, port):
        """Return every record observed at *host*:*port* (usually one)."""
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT fingerprint FROM endpoints WHERE host = ? AND port = ?",
                (host, int(port)),
            ).fetchall()
        return [self.get(r['fingerprint']) for r in rows]

    def find_by_serial(self, serial):
        """Return every record whose certificate serial equals *serial*.

        Used to dedup a CT-log entry (which carries an issuer+serial but not the
        SHA-256 fingerprint) against already-known certificates before spending
        a request to fetch its DER: a real certificate's serial is effectively
        unique, so a serial hit means we already have this cert.
        """
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT fingerprint FROM certificates WHERE serial = ?",
                (str(serial),),
            ).fetchall()
        return [self.get(r['fingerprint']) for r in rows]

    def mark_managed(self, fingerprint, managed_domain):
        """Flag a record managed and link it to *managed_domain* (adoption, #472).

        Returns True if the record existed and was updated.
        """
        with self._write_conn() as conn:
            cur = conn.execute(
                "UPDATE certificates SET managed = 1, managed_domain = ? "
                "WHERE fingerprint = ?",
                (managed_domain, fingerprint),
            )
            return cur.rowcount > 0

    def count(self):
        """Return the number of distinct certificates in the inventory."""
        with self._read_conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM certificates").fetchone()[0]


def _row_to_record(cert_row, endpoint_rows):
    """Assemble a certificate row + its endpoint rows into a JSON-safe dict."""
    try:
        san_dns = json.loads(cert_row['san_dns']) if cert_row['san_dns'] else []
    except (ValueError, TypeError):
        san_dns = []
    return {
        'fingerprint': cert_row['fingerprint'],
        'subject_cn': cert_row['subject_cn'],
        'subject': cert_row['subject'],
        'issuer_cn': cert_row['issuer_cn'],
        'issuer': cert_row['issuer'],
        'serial': cert_row['serial'],
        'not_before': cert_row['not_before'],
        'not_after': cert_row['not_after'],
        'key': {
            'type': cert_row['key_type'],
            'size': cert_row['key_size'],
            'curve': cert_row['key_curve'],
        },
        'signature_algorithm': cert_row['signature_algorithm'],
        'san_dns': san_dns,
        'source': cert_row['source'],
        'managed': bool(cert_row['managed']),
        'managed_domain': cert_row['managed_domain'],
        'first_seen': cert_row['first_seen'],
        'last_seen': cert_row['last_seen'],
        'endpoints': [
            {
                'host': e['host'],
                'port': e['port'],
                'first_seen': e['first_seen'],
                'last_seen': e['last_seen'],
            }
            for e in endpoint_rows
        ],
    }
