# Certificate storage

Where CertMate keeps the certificates it issues and their private keys, and how
to keep a copy in a secrets manager or in object storage.

## How it works

Every certificate is written to the local certificate directory first: certbot
works there, and backups read it. When another backend is configured, each
issued or renewed certificate is then copied to it, with its chain, its private
key and its metadata. If that copy fails, the certificate is still issued, and
its metadata carries a warning that the external copy is missing or stale.

- **The local directory** is `/app/certificates` in the Docker image.
  `CERTMATE_CERT_DIR` moves it, for certbot, for backups and for the local
  backend at once. The local backend's own `cert_dir` setting moves only that
  backend's copy.
- **Backups contain the local directory only.** A certificate that exists only
  in an external backend is not in a backup. Automatic backups also leave
  private keys out unless `CERTMATE_BACKUP_PASSPHRASE` is set; see
  [Backups and recovery](./backup.md).
- **Nothing encrypts the local directory at rest.** Private keys are written
  readable by their owner only (`0600`).

## Backends

| Backend | `backend` value | SDK in the Docker image | Requirements file |
| --- | --- | --- | --- |
| Local filesystem (default) | `local_filesystem` | nothing to install | none |
| Azure Key Vault | `azure_keyvault` | no | `requirements-azure-storage.txt` |
| AWS Secrets Manager | `aws_secrets_manager` | yes (`boto3`) | `requirements-aws-storage.txt` |
| HashiCorp Vault | `hashicorp_vault` | no | `requirements-vault-storage.txt` |
| Infisical | `infisical` | no | `requirements-infisical-storage.txt` |
| S3-compatible object storage | `s3_compatible` | yes (`boto3`) | none: `boto3` is in `requirements.txt` |

`requirements-storage-all.txt` installs every backend's SDK.
`requirements-minimal.txt` installs none of them, not even `boto3`, so AWS
Secrets Manager and S3-compatible storage need it too.

### Adding a backend's SDK

**From source:** install the requirements file into CertMate's environment, for
example `pip install -r requirements-vault-storage.txt`.

**Docker:** the image ships no pip, so the SDK goes into an image of your own.
Either build CertMate with `--build-arg EXTRA_REQUIREMENTS=requirements-vault-storage.txt`
(several files are separated by spaces), or derive an image from the published
one:

```dockerfile
FROM fabriziosalmi/certmate:latest
USER root
RUN /opt/venv/bin/python -m ensurepip && \
    /opt/venv/bin/python -m pip install --no-cache-dir -c requirements.constraints \
        -r requirements-vault-storage.txt && \
    /opt/venv/bin/python -m pip uninstall -y pip
USER certmate
```

`-c requirements.constraints` keeps every package the image already has at
the version it has; the Docker build uses the same file for
`EXTRA_REQUIREMENTS`. Neither way checks the extra packages against hashes,
as the image's own dependencies are.

## Configuring a backend

In the web interface: Settings > Storage, under **Certificate Storage
Backend**. Pick the backend, fill in its settings, use **Test Connection**,
then save. Saving does not move existing certificates; see
[Migrating between backends](#migrating-between-backends).

The examples below show the same settings as they are stored in
`settings.json`.

### Local filesystem

The default, with nothing to configure. Each domain has a directory under the
certificate directory with `cert.pem`, `chain.pem`, `fullchain.pem`,
`privkey.pem` and `metadata.json`. The same directory also holds certbot's own
working files for that domain.

### Azure Key Vault

```json
{
 "certificate_storage": {
   "backend": "azure_keyvault",
   "azure_keyvault": {
     "vault_url": "https://yourvault.vault.azure.net/",
     "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
     "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
     "client_secret": "your_client_secret",
     "storage_mode": "secrets"
   }
 }
}
```

- `vault_url`, `tenant_id`, `client_id` and `client_secret` are required.
  CertMate authenticates as a service principal with a client secret; managed
  identity is not supported.
- `storage_mode` is `secrets` (the default: each PEM and the metadata as
  separate Key Vault secrets), `certificate` (one Key Vault certificate object,
  which App Service, Application Gateway, Front Door, API Management or an AKS
  ingress can bind directly) or `both`. With `both`, reads use the secrets.

### AWS Secrets Manager

```json
{
 "certificate_storage": {
   "backend": "aws_secrets_manager",
   "aws_secrets_manager": {
     "region": "eu-west-1",
     "access_key_id": "AKIAIOSFODNN7EXAMPLE",
     "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
   }
 }
}
```

- `region` defaults to `us-east-1`.
- To use the AWS credential chain instead of keys (an EC2 instance profile, an
  ECS task role, EKS pod identity), choose **AWS credentials / IAM role (no
  keys)** in Settings, or set `"auth_mode": "iam_role"` and leave the keys out.
  Without `auth_mode`, the keys are required.
- `assume_role_arn` (optional) makes CertMate call `sts:AssumeRole` and refresh
  the temporary credentials on its own. The identity then needs
  `sts:AssumeRole`, and the target role must trust it.
- Each certificate is one secret named `certmate/certificates/<domain>`. The
  identity needs `secretsmanager:ListSecrets` (account-wide, resource `*`) and
  `GetSecretValue`, `DescribeSecret`, `CreateSecret`, `UpdateSecret` and
  `DeleteSecret` on `certmate/certificates/*`.
- Deleting a certificate deletes its secret at once, without the recovery
  window Secrets Manager otherwise applies.
- **Test Connection** reports a permission error as an error, not as an empty
  store.

### HashiCorp Vault

```json
{
 "certificate_storage": {
   "backend": "hashicorp_vault",
   "hashicorp_vault": {
     "vault_url": "https://vault.example.com:8200",
     "vault_token": "hvs.xxxxxxxxxxxxxxxxxxxx",
     "mount_point": "secret",
     "engine_version": "v2"
   }
 }
}
```

- Authentication is by token only. CertMate renews the token every 6 hours.
- `mount_point` defaults to `secret`. `engine_version` defaults to `v2`, and
  any other value means the KV version 1 engine.

### Infisical

```json
{
 "certificate_storage": {
   "backend": "infisical",
   "infisical": {
     "site_url": "https://app.infisical.com",
     "client_id": "your_client_id",
     "client_secret": "your_client_secret",
     "project_id": "your_project_id",
     "environment": "prod"
   }
 }
}
```

- `site_url` defaults to `https://app.infisical.com`, and `environment` to
  `prod`.
- **`site_url` must be `https://`.** Plain `http://` is accepted only for
  `localhost` or a loopback address. The Infisical SDK follows a redirect and
  sends the request body on, and the body here is the certificate and its
  private key. Its HTTP client cannot be configured from CertMate, so CertMate
  refuses the one position where anyone on the path could answer with a
  redirect.
- This backend did not work in v2.44.0 or earlier.

### S3-compatible object storage

One backend for any S3 endpoint: Hetzner, Contabo, OVHcloud, Scaleway,
Exoscale, Wasabi, self-hosted MinIO, or AWS S3 itself.

```json
{
 "certificate_storage": {
   "backend": "s3_compatible",
   "s3_compatible": {
     "endpoint_url": "https://fsn1.your-objectstorage.com",
     "bucket": "certmate",
     "access_key_id": "your_access_key_id",
     "secret_access_key": "your_secret_access_key",
     "region": "us-east-1",
     "prefix": "certmate/certificates"
   }
 }
}
```

- `bucket` is required. `region` defaults to `us-east-1`, and `prefix` to
  `certmate/certificates`.
- Each domain is one object, `<prefix>/<domain>.json`, holding the
  certificate files and their metadata.
- The keys need `s3:ListBucket` on the bucket and `s3:GetObject`,
  `s3:PutObject` and `s3:DeleteObject` on `<prefix>/*`.
- **AWS S3 with an IAM role:** choose **AWS credentials / IAM role (no keys)**
  in Settings, or set `"auth_mode": "iam_role"`, and leave `endpoint_url` and
  the keys empty. An optional `assume_role_arn` works as it does for AWS
  Secrets Manager. Both need an empty `endpoint_url`, so they work with AWS S3
  only.
- The off-site S3 backup storage has settings of its own; this backend stores
  certificates only.

## Migrating between backends

Migration copies every certificate from a source backend to a target backend,
one domain at a time, metadata included. It never deletes the source and never
changes the active backend. When no source is given, the source is the backend
saved in settings, so migrate **before** switching:

1. Test the new backend (`POST /api/storage/test`, or **Test Connection**).
2. Migrate (`POST /api/storage/migrate`, or **Migrate Certificates** in
   Settings).
3. Read the answer: `migrated_count`, `failed_count`, `total`, and
   `migration_results`, one `true` or `false` per domain.
4. Switch the active backend (`POST /api/storage/config`, or save in Settings).
5. Clean up the old storage yourself if you want to: CertMate never deletes it.

If you already saved the new backend, choose **Local filesystem** (or the
previous backend) as **Source backend** in the migration dialog. The dialog
always asks for the source: to move from bucket A to bucket B, choose the
saved S3 backend as the source, even though S3 is also the target. Through the
API, pass `"source_backend": "local_filesystem"`.

A domain whose copy failed is `false` in `migration_results`, and the source
is untouched, so running the migration again, or staying on the old backend,
is safe. A result with no domains means none were found in the source: check
the source and the certificate directory before assuming anything was copied.
From the local filesystem, migration copies the four PEM files and
`metadata.json`.

### Through the API

All four need an admin credential, except `GET /api/storage/info`, which a
viewer can call. The full reference is in [api.md](./api.md#storage-backends).

```bash
# Test a backend before switching to it: its settings go under "config"
curl -X POST "http://localhost:8000/api/storage/test" \
 -H "Authorization: Bearer your_token" \
 -H "Content-Type: application/json" \
 -d '{"backend": "hashicorp_vault",
      "config": {"vault_url": "https://vault.example.com:8200",
                 "vault_token": "hvs.xxxxxxxxxxxxxxxxxxxx"}}'

# Copy every certificate from the saved backend to the new one
curl -X POST "http://localhost:8000/api/storage/migrate" \
 -H "Authorization: Bearer your_token" \
 -H "Content-Type: application/json" \
 -d '{"target_backend": "hashicorp_vault",
      "target_config": {"vault_url": "https://vault.example.com:8200",
                        "vault_token": "hvs.xxxxxxxxxxxxxxxxxxxx"}}'

# Switch the active backend. Here the settings go under a key named after the
# backend, not under "config": a "config" key is ignored, and the backend would
# be saved with no credentials.
curl -X POST "http://localhost:8000/api/storage/config" \
 -H "Authorization: Bearer your_token" \
 -H "Content-Type: application/json" \
 -d '{"backend": "hashicorp_vault",
      "hashicorp_vault": {"vault_url": "https://vault.example.com:8200",
                          "vault_token": "hvs.xxxxxxxxxxxxxxxxxxxx"}}'

# Which backend is active
curl "http://localhost:8000/api/storage/info" \
 -H "Authorization: Bearer your_token"
```
