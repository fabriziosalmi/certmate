# Backups and recovery

What CertMate backs up, when, what an archive can and cannot restore, and how to
get an instance back.

## Two kinds of archive

Every backup is one archive holding the settings and the certificates together,
so the two cannot come back out of step. There are two kinds:

- **Share-safe:** the settings with every credential masked, and **no private
  keys**: no ACME `privkey.pem`, no ACME account key, no private-CA key, no
  `.pfx`. Certificates, chains, metadata, the audit chain and the inventory are
  all there. The manifest says so (`secrets_masked`, `key_material_excluded`).
  Such an archive cannot restore an instance on its own: `GET /api/backups`
  reports it with `can_restore: false`, and Settings disables its Restore
  button. The restore API does not read `can_restore`: it refuses a share-safe
  archive when this instance already holds certificates; otherwise it restores
  it, keeping the credentials already in this instance's `settings.json`, or,
  on an instance with no `settings.json`, leaving every credential masked, to be
  re-entered before the next renewal.
- **Disaster recovery:** plaintext settings and every key, encrypted at rest when
  `CERTMATE_BACKUP_PASSPHRASE` is set. This is the archive to keep off the host.

**Which one CertMate takes on its own depends on one thing: whether a backup
passphrase is set.** With `CERTMATE_BACKUP_PASSPHRASE`, automatic backups are
disaster-recovery archives, encrypted at rest. Without it they stay share-safe,
because a complete archive that cannot be encrypted would be a plaintext
credential dump written to disk on every settings change; the instance logs a
notice once per process, at the first automatic backup it takes.

CertMate never generates or stores that passphrase: kept beside the archives it
protects, it would protect nothing. It is yours to set and to keep. The
Linux installer, the cloud-init file and the Docker Quick Start's setup command
each generate one.

## When backups are taken

- **Automatically**, whenever DNS providers, domains, certificates or settings
  change. Logging in does not take one.
- **On demand**, from Settings > Backup (**Create Unified Backup**) or through
  the API. `POST /api/backups/create` with `"include_secrets": true` takes a
  disaster-recovery archive whether a passphrase is set or not, as a deliberate
  opt-in that is audited.
- **Before a restore**, if the restore asks for it
  (`create_backup_before_restore`). That archive always includes every secret,
  because a rollback that cannot bring the credentials back is not a rollback.
  Without a passphrase it is plaintext, mode `0600`, and never leaves the host.

**Retention** applies two rules, whichever comes first: the 50 most recent
archives are kept, **and any archive older than 30 days is deleted however few
there are**. Both are constants, not settings, and pruning runs after every
backup. An archive left in `backups/unified/` is therefore deleted after 30 days
like any other: a disaster-recovery archive has to be copied off the host.

## Copying backups off the host

**To S3-compatible storage, automatically.** With `backup_storage` set in the
settings, every backup CertMate takes is also uploaded to an S3 bucket (Hetzner,
Contabo, OVHcloud, Scaleway, Wasabi, MinIO, AWS):

```json
{
 "backup_storage": {
   "backend": "s3_compatible",
   "s3_compatible": {
     "endpoint_url": "https://fsn1.your-objectstorage.com",
     "bucket": "certmate-backups",
     "access_key_id": "your_access_key_id",
     "secret_access_key": "your_secret_access_key",
     "region": "us-east-1",
     "prefix": "certmate/backups"
   }
 }
}
```

- The upload is **refused unless the archive is encrypted**, that is, unless
  `CERTMATE_BACKUP_PASSPHRASE` is set: an archive can hold every private key,
  and the two settings are otherwise independent. The refusal is logged.
- `endpoint_url`, `bucket` and both keys are required. `region` defaults to
  `us-east-1` and `prefix` to `certmate/backups`.
- It is a copy: a failed upload is logged and the local archive stays. Retention
  does not reach the bucket, so expire old objects with the bucket's own
  lifecycle rules.
- This is separate from the [S3-compatible certificate storage
  backend](./storage.md#s3-compatible-object-storage), which has settings of its
  own.

There is no form for it in Settings yet: set it in `settings.json`, or with
`POST /api/settings`, which keeps the stored secret when it receives the
`********` mask.

**By downloading them.** `GET /api/backups/download/unified/<filename>` (admin),
or the download button in Settings > Backup. Download a disaster-recovery
archive; a share-safe one cannot restore the instance.

## Through the API

All of these need admin, except the list, which a viewer can read.

```bash
# Take a backup; "type" is required
curl -X POST "http://localhost:8000/api/backups/create" \
 -H "Authorization: Bearer your_token" \
 -H "Content-Type: application/json" \
 -d '{"type": "unified", "reason": "manual_backup"}'

# List them, with can_restore for each
curl -H "Authorization: Bearer your_token" "http://localhost:8000/api/backups"

# Download one
curl -H "Authorization: Bearer your_token" \
 "http://localhost:8000/api/backups/download/unified/backup_20261017_120000_123456_manual_backup.zip" \
 -o backup.zip
```

Archives are named `backup_<YYYYmmdd_HHMMSS_ffffff>_<reason>.zip` (UTC), or
`.zip.enc` when `CERTMATE_BACKUP_PASSPHRASE` is set. The list comes back oldest
first. The answers and the other routes (restore, upload, delete) are in the
[API reference](./api.md#backups).

## What is in an archive

<!-- illustration: the layout of a disaster-recovery archive -->
```
backup_20261017_120000_000000_manual.zip
  backup_metadata.json   # manifest: secrets_masked, key_material_excluded, key_files_excluded, encrypted
  settings.json          # credentials masked in a share-safe archive, plaintext in a disaster-recovery one
  certificates/
    example.com/
      cert.pem
      chain.pem
      fullchain.pem
      privkey.pem        # disaster recovery only
      metadata.json
      live/ archive/ renewal/ accounts/   # certbot's lineage (keys under accounts/ and live/: disaster recovery only)
  data/
    certs/ca/ca.crt      # ca.key: disaster recovery only
    certs/client/...     # client certificates (.key and .pfx: disaster recovery only)
    audit/ inventory/
```

A share-safe archive also leaves out certbot's `keys/` directory under each
domain.

## Restoring

**First, find an archive that can restore.** Unless `CERTMATE_BACKUP_PASSPHRASE`
was set when it was taken, an automatic backup is share-safe and **cannot
restore this instance**. On an instance that has never had a passphrase, the
newest archive is almost certainly one of those, so "the latest" is the wrong
choice. Ask the API: it reports `can_restore` for each archive, and
`restore_blocked_reason` when it is false.

```bash
# Which archives can restore, newest first
curl -s -H "Authorization: Bearer $API_TOKEN" http://localhost:8000/api/backups \
  | jq -r '.unified | reverse | .[] | "\(.filename)  can_restore=\(.can_restore)  \(.restore_blocked_reason // "")"'

# Restore one whose can_restore is true, taking a backup of the current state first
curl -X POST http://localhost:8000/api/backups/restore/unified \
  -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename": "backup_YYYYmmdd_HHMMSS_ffffff_<reason>.zip.enc", "create_backup_before_restore": true}'
```

In the web interface: Settings > Backup, the archive's **Restore** button. The
settings and the certificates come back together, and the page reloads the
restored settings; nothing restarts.

If nothing reports `can_restore: true`, this instance has no restore point. Set
`CERTMATE_BACKUP_PASSPHRASE`, take a backup at once, and copy it off the host.

**Onto a new instance:** upload the archive with **Restore From Elsewhere** in
Settings > Backup, or `POST /api/backups/upload` (admin, `multipart/form-data`,
field `file`, at most 40 MB). Uploading only stores it, under a name CertMate
generates; restoring it is a separate step, so an upload never changes anything
on its own. An encrypted archive needs the same `CERTMATE_BACKUP_PASSPHRASE` on
the new instance.

## After a downgrade

Running a version older than the one that wrote `settings.json` is not
supported, and can leave the configuration broken or accounts missing. CertMate
logs `DOWNGRADE DETECTED` at startup when it finds this. Run the newer version
again, or restore an archive that can restore, as above.

## Lost admin password

`scripts/reset_admin_password.py` sets a new password for the `admin` user,
creating it if it is missing. It asks for the password twice and needs a shell
where CertMate runs.

```bash
# Docker
docker exec -it certmate python scripts/reset_admin_password.py

# Linux, installed with deploy/install.sh
sudo -u certmate CERTMATE_SETTINGS_PATH=/opt/certmate/data/settings.json \
  /opt/certmate/venv/bin/python /opt/certmate/scripts/reset_admin_password.py
```
