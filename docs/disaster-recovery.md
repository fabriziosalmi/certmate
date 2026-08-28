# Disaster Recovery (single node)

This runbook covers backing up a CertMate instance and recovering it after data
loss — a corrupted `settings.json`, an accidentally deleted certificate, a lost
disk, or a destroyed host — and bringing service back on a fresh machine.

> **Scope.** CertMate (this open-source build) is **single-instance by design**.
> This runbook gets one node back to health. It does **not** cover multi-region
> failover, active/active replicas, automated DR drills, or online
> key-encryption-key rotation.

A workable single-node DR posture rests on two independent legs. You need
**both**:

1. **Persistent volumes** — so recreating the container (upgrade, reboot, host
   restart) does not lose state.
2. **Off-node backups** — so losing the disk or the host is still recoverable.

---

## 1. What state CertMate holds

All durable state lives in four directories inside the container. In Docker they
must be bind-mounts or named volumes; on a bare-metal/systemd install they are
the corresponding paths under the install root.

| Path (container) | Contents | Lose it and… |
| --- | --- | --- |
| `/app/certificates` | Issued certificates, **private keys**, and certbot renewal lineage (`accounts/`, `archive/`, `renewal/`). | You lose the certs and the ability to renew in place — you must re-issue. The crown jewels. |
| `/app/data` | `settings.json` (all configuration), `.secret_key` (Flask session key **and** webhook HMAC key), `scheduler_jobs.sqlite` (renewal schedule), `certs/ca/` (the private CA's key and certificate). | You lose configuration, every active login session, the renewal schedule, and the private CA. |
| `/app/backups` | Unified backup archives (`backups/unified/*.zip`). | You lose local backup history (not the live service). |
| `/app/logs` | Application and audit logs. | You lose the audit trail (service keeps running). |

> **If you see `PERSISTENCE CHECK: This appears to be the first boot…` on every
> restart, your volumes are NOT persistent.** Every restart is starting from an
> empty data directory and discarding all configuration. Fix the mounts before
> doing anything else:
>
> ```bash
> docker run -d --name certmate \
>   -v "$PWD/data:/app/data" \
>   -v "$PWD/certificates:/app/certificates" \
>   -v "$PWD/backups:/app/backups" \
>   -v "$PWD/logs:/app/logs" \
>   -p 8000:8000 --env-file .env certmate:latest
> ```
>
> The related log line `CRITICAL: settings.json has no users` is the same root
> cause seen from the settings layer.

---

## 2. The default backup cannot restore a working node

This is the single most important thing to understand before a restore, and the
most common way a DR plan fails in practice.

A unified backup is **masked by default**, and masking removes two different
classes of material:

- **Credentials** — DNS provider tokens, storage backend credentials, the OIDC
  `client_secret`, the SMTP password, the `api_bearer_token`, user password
  hashes — are replaced in the archive by the sentinel `********`.
- **Private key material** — every `privkey*.pem`, certbot's
  `archive/<domain>/privkeyN.pem`, its `keys/` subtree, the ACME account key
  (`accounts/.../private_key.json`), the private CA key
  (`data/certs/ca/ca.key`), and any `.pfx`/PKCS#12 bundle — is **excluded from
  the archive entirely**.

The archive's `backup_metadata.json` states both facts: `secrets_masked: true`,
`key_material_excluded: true`, and `key_files_excluded: <n>`.

This is deliberate — a leaked backup should not leak every CertMate credential
and every private key — but it has a consequence you must plan for:

| From a **masked** backup you get back | From a **masked** backup you do NOT get back |
| --- | --- |
| `settings.json` (domains, providers, hooks, users — secrets masked) | Any certificate's private key: the restored certs **cannot serve TLS** |
| The public certificate material: `cert.pem`, `chain.pem`, `fullchain.pem` | The ACME account key and renewal lineage: certbot **cannot renew in place** |
| `data/certs/ca/ca.crt` | `data/certs/ca/ca.key`: the private CA **can no longer sign** |
| The audit log and the rest of the `data/` subtree | Every credential (see above) |

**A masked backup restores your configuration, not your service.** Recovering a
node from one means re-issuing every certificate through ACME. Size your DR plan
accordingly (§7), and pick a strategy below with that in mind.

### Strategy A — masked backup + secrets managed out of band

Keep backups share-safe (masked) and store the secrets separately in your own
secrets manager / vault:

- **`SECRET_KEY`** — set `SECRET_KEY_FILE=/run/secrets/certmate_secret_key` (or
  `SECRET_KEY=…`). If you set neither, CertMate generates one and persists it to
  `/app/data/.secret_key`; persisting `/app/data` is then enough to keep sessions
  and webhook HMAC stable across restarts. For a fresh-host restore, provide the
  same key, otherwise all sessions are invalidated and webhook signatures change.
- **`API_BEARER_TOKEN`** — set `API_BEARER_TOKEN_FILE=/run/secrets/certmate_api_token`
  (or `API_BEARER_TOKEN=…`). It is stored only as a hash in `settings.json`, so it
  is never recoverable from a backup — provide it via the file/env on restore.
- **DNS provider tokens, storage creds, SMTP password, OIDC `client_secret`** —
  re-enter them in Settings after restoring a masked backup. CertMate logs a
  warning on a fresh-host restore reminding you the masked fields are still blank.

Choose this only if you accept re-issuing certificates as part of recovery, or if
you also keep an independent copy of `/app/certificates` (a volume snapshot, a
filesystem-level backup) alongside the masked archive. **The masked archive alone
is not a recovery plan for the certificates themselves.**

On restore, the masked sentinels are deep-merged with whatever secrets already
exist on disk (so re-restoring on an existing node preserves live secrets); only
a fresh host with no prior `settings.json` ends up with blanks to fill in.

### Strategy B — full backup for one-file restore (recommended for DR)

If you want a single archive that actually restores a working node, create a
backup with secrets and key material included:

```bash
curl -X POST https://certmate.example.com/api/backups/create \
  -H "Authorization: Bearer $API_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "dr_full", "include_secrets": true}'
```

This is the only archive that restores certificates in a usable state, keeps the
renewal lineage, and preserves the private CA. It is also a **plaintext
credential and private-key dump**: it is written `0600` (readable only by the
CertMate process user) and the opt-in is audit-logged, but once it leaves the
host it is as sensitive as your `.env` plus every key you hold.

**Do not carry that risk manually — turn on backup encryption.** Set
`CERTMATE_BACKUP_PASSPHRASE` in the environment and every archive CertMate
writes is encrypted at rest: Fernet (AES-128-CBC + HMAC-SHA256) with a key
derived by PBKDF2-SHA256 at 600,000 iterations, saved as `.zip.enc`. Restore
decrypts transparently when the same passphrase is present.

```bash
# docker-compose.yml, or the .env you already pass to the container
CERTMATE_BACKUP_PASSPHRASE=<from your vault>
```

Three properties matter for DR:

- The passphrase comes **from the environment only, never from `settings.json`** —
  storing it in settings would put it inside the very backups it protects.
- The archive keeps a **cleartext header** carrying non-secret metadata (backup
  id, timestamp, domain names), so you can list and identify archives without
  the passphrase. Only the payload is encrypted.
- **Lose the passphrase and the backup is gone.** Restoring with the wrong one
  fails cleanly — `wrong passphrase or corrupted backup`, nothing is written —
  but there is no recovery path. Keep it in the same vault as `SECRET_KEY`, and
  treat losing it as losing the backup.

Note also that CertMate's automatic `settings.json` self-recovery skips
encrypted archives when no passphrase is present in the environment: an instance
that lost its passphrase cannot even fall back to its own local backups.

Use masked archives for sharing, inspection and configuration history; use a
full archive, encrypted, for actual disaster recovery.

---

## 3. Creating backups

CertMate creates backups automatically on configuration changes (settings saves,
DNS-account changes, migrations) and on demand.

**Manual backup (API):**

```bash
# Masked (share-safe) — the default
curl -X POST https://certmate.example.com/api/backups/create \
  -H "Authorization: Bearer $API_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason": "pre_upgrade"}'

# List backups
curl -H "Authorization: Bearer $API_BEARER_TOKEN" \
  https://certmate.example.com/api/backups

# Download one off-node
curl -H "Authorization: Bearer $API_BEARER_TOKEN" \
  -o backup.zip \
  https://certmate.example.com/api/backups/download/unified/<filename>
```

You can also create, download, and restore from **Settings → Backup Management**
in the web UI.

**What an archive contains:** `settings.json` (masked or plaintext per the mode),
`backup_metadata.json`, and the `certificates/` subtree plus the PKI parts of
`data/`. Certbot's ephemeral `logs/` and `work/` directories are always excluded.
The `accounts/` and `archive/` directories are kept as directories, but in a
masked archive every private key inside them is stripped (§2) — so the lineage
they preserve is only complete in a full (`include_secrets: true`) archive.

Check `backup_metadata.json` before trusting an archive for recovery:

```bash
# a cleartext .zip archive
unzip -p backup.zip backup_metadata.json | jq '{secrets_masked, key_material_excluded, key_files_excluded}'
# an encrypted .zip.enc archive — the header is readable without the passphrase
sed -n 2p backup.zip.enc | jq '.metadata | {secrets_masked, key_material_excluded, key_files_excluded}'
# a DR-capable archive reads: {"secrets_masked": false, "key_material_excluded": false, "key_files_excluded": 0}
```

**Ordering:** `GET /api/backups` returns `{"unified": [...]}` sorted by file
name — that is, **oldest first**. Scripts that want the most recent archive must
take the last element, not the first.

**Retention:** the local store keeps at most **50** archives and prunes anything
older than **30 days**. Local backups are a convenience, not an offsite copy —
see §4.

---

## 4. Getting backups off the node

Local backups die with the disk. Copy them somewhere else on a schedule.

A **full** archive contains private keys and plaintext credentials. Encrypt it —
preferably with `CERTMATE_BACKUP_PASSPHRASE` (§2), so it is already `.zip.enc`
before it ever leaves the host — and restrict who can read it. A **masked** archive holds no
keys and no credentials, but it still lists your domains, hostnames, contact
addresses and hook commands — treat it as internal, not public.

A minimal nightly offsite copy of a DR-capable archive:

```bash
#!/usr/bin/env bash
set -euo pipefail
curl -fsS -X POST "$CERTMATE_URL/api/backups/create" \
  -H "Authorization: Bearer $API_BEARER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"reason":"nightly","include_secrets":true}' >/dev/null
# NOTE: /api/backups returns archives OLDEST first (they are sorted by
# file name, which begins with the timestamp). Do not take .unified[0] —
# that is the oldest archive you have, and the one retention deletes next.
latest=$(curl -fsS -H "Authorization: Bearer $API_BEARER_TOKEN" \
  "$CERTMATE_URL/api/backups" | jq -r '.unified | max_by(.metadata.timestamp) | .filename')
curl -fsS -H "Authorization: Bearer $API_BEARER_TOKEN" \
  -o "/tmp/$latest" "$CERTMATE_URL/api/backups/download/unified/$latest"
# Ship encrypted, e.g. with restic:
restic backup "/tmp/$latest"
rm -f "/tmp/$latest"
```

---

## 5. Recovery procedures

### 5.1 Restore on the same host (corrupted settings, bad change, bad upgrade)

This is the case a masked backup handles well: the machine still holds its
certificates and keys, and you only need the configuration back.

1. Identify a good backup: `GET /api/backups` (or Settings → Backup).
2. Restore it. The restore **automatically takes a pre-restore backup first**, so
   the operation is reversible:

   ```bash
   curl -X POST https://certmate.example.com/api/backups/restore/unified \
     -H "Authorization: Bearer $API_BEARER_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"filename": "<filename>", "create_backup_before_restore": true}'
   ```
3. Verify (§6).

> **Restore can refuse for a good reason.** If the backup contains a deploy hook
> whose command fails the *current* hook validator (an old, more-permissive hook,
> or a tampered archive), the restore is **aborted and your on-disk settings are
> left untouched**. Fix or remove the offending hook, then retry.

### 5.2 Full recovery on a fresh host (lost disk or host)

1. **Provision** a new host with Docker. Recreate the four volume mounts (§1).
2. **Provide secrets** per your chosen strategy (§2): the `.env` /
   `SECRET_KEY_FILE` / `API_BEARER_TOKEN_FILE`, or rely on a full backup.
3. **Start CertMate** and wait for `/health` to report healthy.
4. **Restore** your most recent off-node backup (UI or the API call in §5.1).
5. Then, depending on which kind of archive you restored:

   **From a full archive** — certificates, keys, renewal lineage and the private
   CA are back. Re-check that the hooks and providers point at the new host, then
   verify (§6).

   **From a masked archive** — your configuration is back but your service is
   not. You must additionally:
   - re-enter the provider/storage/SMTP/OIDC secrets in Settings (CertMate warns
     you which are blank);
   - **re-issue every certificate** — they were restored without private keys and
     cannot serve TLS. Re-issuance is idempotent (§5.3); do it before pointing
     traffic at the node, and mind the CA's rate limits if you hold many domains;
   - restore the private CA's `data/certs/ca/ca.key` from wherever you keep it,
     or accept that the private CA must be re-created and its issued client
     certificates re-issued.
6. Verify (§6).

### 5.3 Accidentally deleted or missing certificate

You do not strictly need a backup — issuance is idempotent. Either restore a
backup (§5.1), or simply re-create the certificate (the per-domain lock and the
existing-domain check make a re-run safe):

```bash
curl -X POST https://certmate.example.com/api/certificates/create \
  -H "Authorization: Bearer $API_BEARER_TOKEN" -H "Content-Type: application/json" \
  -d '{"domain":"example.com","dns_provider":"cloudflare"}'
```

Use the **zombie certificate scanner** (`POST /api/certificates/zombies/scan`) to
find on-disk certs no longer tracked in settings after a partial loss.

---

## 6. Verifying a recovery

Do not declare the incident over until all of these pass.

**Start with the key check.** `GET /api/certificates` reports `exists: true` for
any domain whose `cert.pem` parses — it does not look at the private key. After
restoring a masked backup, every certificate is listed as present, with a valid
expiry and `needs_renewal: false`, while none of them can serve TLS. The API
alone cannot tell you whether you have recovered:

```bash
docker exec certmate sh -c '
for d in /app/certificates/*/; do
  n=$(basename "$d"); [ -f "$d/cert.pem" ] || continue
  if [ ! -f "$d/privkey.pem" ]; then echo "$n: NO PRIVATE KEY - cannot serve TLS"; continue; fi
  c=$(openssl x509 -noout -pubkey -in "$d/cert.pem" | openssl sha256)
  k=$(openssl pkey -pubout -in "$d/privkey.pem" | openssl sha256)
  [ "$c" = "$k" ] && echo "$n: ok" || echo "$n: KEY DOES NOT MATCH CERT"
done'
```

Every domain must print `ok`. Then:

- `GET /health` returns `healthy` (and shows the scheduler running — renewals
  fire from it).
- `GET /api/certificates` lists the certificates you expect, with sane expiries.
- A download works: `GET /api/certificates/<domain>/download` returns a valid ZIP.
- The service actually serves the restored certificate:
  `echo | openssl s_client -connect <host>:443 -servername <domain> 2>/dev/null | openssl x509 -noout -dates -subject`
- A renewal path works end to end. The safest live check is an **async** issuance
  against a throwaway subdomain so it cannot disturb production and you can poll
  the result:

  ```bash
  curl -X POST "$CERTMATE_URL/api/certificates/create?async=true" \
    -H "Authorization: Bearer $API_BEARER_TOKEN" -H "Content-Type: application/json" \
    -d '{"domain":"dr-check.example.com","dns_provider":"cloudflare"}'
  # -> 202 {"job_id": "...", "status_url": "/api/certificates/jobs/<id>"}
  # then poll status_url until "succeeded"
  ```
- Logins work and stay logged in (confirms the `SECRET_KEY` was restored, not
  regenerated).

---

## 7. RPO / RTO and drills

- **RPO** (how much you can lose) is bounded by your backup frequency. Automatic
  backups fire on config changes; schedule an additional periodic backup +
  offsite copy (§4) to bound certificate/state drift.
- **RTO** (how long to recover) depends entirely on which archive you hold. From
  a **full** archive it is dominated by provisioning and re-providing secrets:
  the restore itself is fast and the archive is small. From a **masked** archive
  it is dominated by **re-issuing every certificate through the CA** — that means
  DNS-01 propagation per domain and, above a few dozen domains, the CA's rate
  limits (Let's Encrypt allows a limited number of certificates per registered
  domain per week). Measure this before you need it.
- **Test your restore.** A backup you have never restored is a hope, not a plan.
  Periodically (quarterly is a reasonable default for a single node) restore your
  latest backup onto a scratch host and run §6 — including the key check, which
  is the step that distinguishes a real recovery from a node that merely looks
  healthy. If you need this continuously and automatically, that is a signal you
  have outgrown the single-node model.
