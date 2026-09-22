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

v5 adds ``domain_health``: the last answer to the checks that are about the
name rather than the certificate — SPF, DMARC, MX, blocklists and HSTS (see
``domain_health.py``). One row per name, holding whichever checks apply to it.

v4 adds ``expiry_notices``: what has already been said about which expiry
date, so a warning speaks once per threshold instead of every night (see
``expiry_watch.py``).

v3 adds ``domain_registrations``: one row per registrable domain CertMate
tracks, with when its registration expires and where that answer came from
(see ``domain_registration.py``). It is keyed by domain, not by certificate,
because one registration covers every certificate issued under it.

v2 adds the certificate's last revocation answer (``revocation_*`` columns).
Unlike the rest of the row it is mutable — a certificate can be revoked after
it was first seen — so it is rewritten on every checked observation, with one
exception: ``revoked`` is final. Revocation cannot be undone, so a later
``unavailable`` (a responder that did not answer) never replaces it.

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
SCHEMA_VERSION = 5

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

# v2 -> v3: registration expiry per registrable domain.
_REGISTRATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS domain_registrations (
    domain           TEXT PRIMARY KEY,   -- registrable domain, lower case
    status           TEXT NOT NULL,      -- ok / not_published / not_registered / unavailable
    expires_at       TEXT,
    registrar        TEXT,
    registry_status  TEXT,               -- JSON array
    source           TEXT,               -- rdap / whois
    error            TEXT,
    checked_at       TEXT NOT NULL,
    first_seen       TEXT NOT NULL
);
"""

# v3 -> v4: one row per (kind, name, expiry, threshold) already announced.
_EXPIRY_NOTICE_SCHEMA = """
CREATE TABLE IF NOT EXISTS expiry_notices (
    kind        TEXT NOT NULL,      -- certificate / domain
    name        TEXT NOT NULL,
    expires_at  TEXT NOT NULL,      -- the expiry this was said about
    threshold   INTEGER NOT NULL,   -- days-left mark that was announced
    noticed_at  TEXT NOT NULL,
    PRIMARY KEY (kind, name, expires_at, threshold)
);
"""

# v4 -> v5: the last answer to the name-level checks (SPF/DMARC/MX/RBL/HSTS).
_DOMAIN_HEALTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS domain_health (
    name        TEXT PRIMARY KEY,   -- registrable domain or managed host, lower case
    status      TEXT NOT NULL,      -- worst status across the checks that ran
    checks      TEXT NOT NULL,      -- JSON object, one entry per check
    checked_at  TEXT NOT NULL,
    first_seen  TEXT NOT NULL
);
"""

# v1 -> v2: the last revocation answer for each certificate.
_REVOCATION_COLUMNS = (
    ('revocation_status', 'TEXT'),      # good/revoked/unknown/unavailable/not_applicable
    ('revocation_method', 'TEXT'),      # ocsp / crl
    ('revocation_reason', 'TEXT'),      # CRLReason name, when revoked
    ('revoked_at', 'TEXT'),
    ('revocation_error', 'TEXT'),       # why it is unavailable/unknown
    ('revocation_checked_at', 'TEXT'),
)


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
            if version < 1:
                # v0 -> v1: initial schema.
                conn.executescript(_SCHEMA)
            if version < 2:
                existing = {r['name'] for r in conn.execute('PRAGMA table_info(certificates)')}
                for name, sql_type in _REVOCATION_COLUMNS:
                    if name not in existing:
                        # Both parts are module constants above, never input.
                        conn.execute(f'ALTER TABLE certificates ADD COLUMN {name} {sql_type}')
            if version < 3:
                conn.executescript(_REGISTRATION_SCHEMA)
            if version < 4:
                conn.executescript(_EXPIRY_NOTICE_SCHEMA)
            if version < 5:
                conn.executescript(_DOMAIN_HEALTH_SCHEMA)
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
        fingerprint = self.record_certificate(
            probe_result.get('certificate') or {},
            host=probe_result.get('host'),
            port=probe_result.get('port'),
            source=source,
            managed=managed,
            managed_domain=managed_domain,
            observed_at=observed_at,
        )
        if fingerprint and isinstance(probe_result.get('revocation'), dict):
            self.record_revocation(fingerprint, probe_result['revocation'])
        return fingerprint

    def record_revocation(self, fingerprint, revocation):
        """Store the latest revocation answer for *fingerprint*.

        ``revoked`` is final: once a verified answer said revoked, a later
        answer of any other kind is ignored (a CA cannot un-revoke, and a
        responder being down tomorrow says nothing new). Returns True if the
        row was updated.
        """
        status = revocation.get('status')
        if not status:
            return False
        with self._write_conn() as conn:
            cur = conn.execute(
                """
                UPDATE certificates SET
                    revocation_status = ?, revocation_method = ?,
                    revocation_reason = ?, revoked_at = ?,
                    revocation_error = ?, revocation_checked_at = ?
                WHERE fingerprint = ?
                  AND (revocation_status IS NULL OR revocation_status != 'revoked')
                """,
                (
                    status, revocation.get('method'), revocation.get('reason'),
                    revocation.get('revoked_at'), revocation.get('error'),
                    revocation.get('checked_at') or utc_now_iso(), fingerprint,
                ),
            )
            return cur.rowcount > 0

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
        # The WHERE clause is assembled only from fixed literal fragments
        # ("managed = ?" / "source = ?") — every user-supplied value travels as a
        # bound "?" parameter in `params`, never interpolated. So the f-string
        # carries no untrusted data and is injection-safe (bandit B608 false
        # positive on the interpolated-but-constant fragment).
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM certificates {where} ORDER BY last_seen DESC, fingerprint"  # nosec B608
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

    def delete(self, fingerprint):
        """Forget a certificate and every endpoint observed for it (#634).

        Returns True if a record existed and was removed, so the caller can
        answer 404 rather than reporting a deletion that did not happen.

        The endpoint rows go with it via ``ON DELETE CASCADE``, which SQLite
        applies only because ``_connect`` enables ``PRAGMA foreign_keys``.

        This forgets an observation; it is not a blocklist. A certificate whose
        domain is still in the discovery configuration will be recorded again
        on the next scan, which is why the configuration is the thing to edit
        when the intent is "stop looking at this".
        """
        with self._write_conn() as conn:
            cur = conn.execute(
                "DELETE FROM certificates WHERE fingerprint = ?", (fingerprint,)
            )
            return cur.rowcount > 0

    # --- domain registrations (v3) ------------------------------------------ #

    def record_registration(self, result):
        """Store a :meth:`RegistrationClient.lookup` result, keyed by domain.

        An ``unavailable`` answer does not erase a known expiry: a registry
        that timed out today has not changed the date it published yesterday,
        so the previous expiry and registrar are kept and only the status,
        error and ``checked_at`` move. Returns the domain.
        """
        domain = (result.get('domain') or '').strip().lower()
        if not domain:
            raise ValueError('domain is required')
        now = result.get('checked_at') or utc_now_iso()
        status_json = json.dumps(list(result.get('registry_status') or []))
        keep_known = result.get('status') == 'unavailable'
        with self._write_conn() as conn:
            conn.execute(
                """
                INSERT INTO domain_registrations (
                    domain, status, expires_at, registrar, registry_status,
                    source, error, checked_at, first_seen
                ) VALUES (?,?,?,?,?,?,?,?,?)
                ON CONFLICT(domain) DO UPDATE SET
                    status = excluded.status,
                    error = excluded.error,
                    checked_at = excluded.checked_at,
                    expires_at = CASE WHEN ? THEN domain_registrations.expires_at
                                      ELSE excluded.expires_at END,
                    registrar = CASE WHEN ? THEN domain_registrations.registrar
                                     ELSE excluded.registrar END,
                    registry_status = CASE WHEN ? THEN domain_registrations.registry_status
                                           ELSE excluded.registry_status END,
                    source = CASE WHEN ? THEN domain_registrations.source
                                  ELSE excluded.source END
                """,
                (
                    domain, result.get('status'), result.get('expires_at'),
                    result.get('registrar'), status_json, result.get('source'),
                    result.get('error'), now, now,
                    keep_known, keep_known, keep_known, keep_known,
                ),
            )
        return domain

    def get_registration(self, domain):
        """The stored registration for *domain*, or None."""
        with self._read_conn() as conn:
            row = conn.execute(
                "SELECT * FROM domain_registrations WHERE domain = ?",
                (domain.strip().lower(),),
            ).fetchone()
        return _registration_view(row) if row else None

    def list_registrations(self):
        """Every stored registration, soonest expiry first, unknown last."""
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_registrations "
                "ORDER BY expires_at IS NULL, expires_at, domain"
            ).fetchall()
        return [_registration_view(r) for r in rows]

    def prune_registrations(self, keep):
        """Forget registrations for domains no longer tracked. Returns how many.

        The tracked set is recomputed on every sweep from what CertMate
        manages and has discovered; a domain that left it is not something
        the operator is asking about any more.
        """
        keep = {d.strip().lower() for d in keep}
        with self._write_conn() as conn:
            existing = [r['domain'] for r in conn.execute(
                "SELECT domain FROM domain_registrations")]
            stale = [d for d in existing if d not in keep]
            conn.executemany("DELETE FROM domain_registrations WHERE domain = ?",
                             [(d,) for d in stale])
        return len(stale)

    # --- expiry notices (v4) ------------------------------------------------ #

    def record_expiry_notice(self, *, kind, name, expires_at, threshold, noticed_at):
        """Claim a warning. True the first time, False if it was already said.

        Keyed by the expiry date as well as the threshold, so a renewed
        certificate — a new expiry — starts again from the first threshold,
        while a repeated run says nothing.
        """
        if not (kind and name and expires_at):
            return False
        with self._write_conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO expiry_notices (kind, name, expires_at, threshold, noticed_at)
                VALUES (?,?,?,?,?)
                ON CONFLICT(kind, name, expires_at, threshold) DO NOTHING
                """,
                (kind, str(name).lower(), str(expires_at), int(threshold), noticed_at),
            )
            return cur.rowcount > 0

    def expiry_notices(self):
        """Every warning already announced, newest first. For tests and support."""
        with self._read_conn() as conn:
            rows = conn.execute(
                "SELECT kind, name, expires_at, threshold, noticed_at "
                "FROM expiry_notices ORDER BY noticed_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def prune_expiry_notices(self, before):
        """Forget notices about expiry dates older than *before* (a datetime).

        The rows exist to stop a warning repeating; once the date they are
        about is well past, they are only taking up space.
        """
        cutoff = before.isoformat()
        with self._write_conn() as conn:
            cur = conn.execute("DELETE FROM expiry_notices WHERE expires_at < ?", (cutoff,))
            return cur.rowcount

    # --- domain health (v5) -------------------------------------------------- #

    def record_domain_health(self, name, status, checks, checked_at=None):
        """Store the latest name-level checks for *name*. Returns the name.

        The whole result is replaced: unlike a registration expiry, none of
        these answers stays true once a re-check disagrees with it, and a check
        that could not run already says ``unknown`` in *checks* rather than
        going missing.
        """
        name = (name or '').strip().lower()
        if not name:
            raise ValueError('name is required')
        now = checked_at or utc_now_iso()
        with self._write_conn() as conn:
            conn.execute(
                """
                INSERT INTO domain_health (name, status, checks, checked_at, first_seen)
                VALUES (?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET
                    status = excluded.status,
                    checks = excluded.checks,
                    checked_at = excluded.checked_at
                """,
                (name, status, json.dumps(checks or {}), now, now),
            )
        return name

    def get_domain_health(self, name):
        """The stored checks for *name*, or None."""
        with self._read_conn() as conn:
            row = conn.execute(
                "SELECT * FROM domain_health WHERE name = ?",
                ((name or '').strip().lower(),),
            ).fetchone()
        return _domain_health_view(row) if row else None

    def list_domain_health(self):
        """Every stored result, worst first, so the page opens on what is wrong."""
        with self._read_conn() as conn:
            rows = conn.execute(
                """
                SELECT * FROM domain_health
                ORDER BY CASE status
                    WHEN 'failing' THEN 0 WHEN 'warning' THEN 1
                    WHEN 'unknown' THEN 2 ELSE 3 END, name
                """
            ).fetchall()
        return [_domain_health_view(r) for r in rows]

    def prune_domain_health(self, keep):
        """Forget names no longer tracked. Returns how many were forgotten."""
        keep = {n.strip().lower() for n in keep}
        with self._write_conn() as conn:
            existing = [r['name'] for r in conn.execute("SELECT name FROM domain_health")]
            stale = [n for n in existing if n not in keep]
            conn.executemany("DELETE FROM domain_health WHERE name = ?",
                             [(n,) for n in stale])
        return len(stale)

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
        'revocation': _revocation_view(cert_row),
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


def _revocation_view(cert_row):
    """The stored revocation answer, or None when it was never checked."""
    status = cert_row['revocation_status']
    if not status:
        return None
    return {
        'status': status,
        'method': cert_row['revocation_method'],
        'reason': cert_row['revocation_reason'],
        'revoked_at': cert_row['revoked_at'],
        'error': cert_row['revocation_error'],
        'checked_at': cert_row['revocation_checked_at'],
    }


def _domain_health_view(row):
    """A stored domain-health row as a JSON-safe dict."""
    try:
        checks = json.loads(row['checks']) if row['checks'] else {}
    except (ValueError, TypeError):
        checks = {}
    return {
        'name': row['name'],
        'status': row['status'],
        'checks': checks,
        'checked_at': row['checked_at'],
        'first_seen': row['first_seen'],
    }


def _registration_view(row):
    """A stored domain registration as a JSON-safe dict."""
    try:
        registry_status = json.loads(row['registry_status']) if row['registry_status'] else []
    except (ValueError, TypeError):
        registry_status = []
    return {
        'domain': row['domain'],
        'status': row['status'],
        'expires_at': row['expires_at'],
        'registrar': row['registrar'],
        'registry_status': registry_status,
        'source': row['source'],
        'error': row['error'],
        'checked_at': row['checked_at'],
        'first_seen': row['first_seen'],
    }
