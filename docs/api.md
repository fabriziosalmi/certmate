# CertMate Client Certificates - API Reference

## Overview

The CertMate Client Certificates API provides REST endpoints for complete certificate management with authentication, rate limiting, and audit logging.

**Base URL**: `http://localhost:8000`

> Every path below is absolute and starts with `/api`. It used to be a
> mix: thirteen paths written relative to a base ending in `/api`, and
> eight written with the prefix — so against the stated base one set
> resolved to `/api/api/...`. The four translations had lost the base-URL
> line entirely, which left their relative paths with nothing to resolve
> against at all.
**Authentication**: Bearer Token (required on all endpoints)
**Content-Type**: `application/json`

---

## Booleans are booleans

A field documented as a boolean is read as written: `true` or `false`, without
quotes. A string, a number or `null` is refused with `400 INVALID_REQUEST` and
a message naming the field, rather than interpreted.

That refusal replaces a silent misreading. Python's `bool("false")` is `True`,
so a client that sent a boolean as a string — easy from a shell, an Ansible or
Terraform template, or an agent filling a tool schema — used to get the
opposite of what it asked for, with a 200. For `include_secrets` on a backup,
the opposite was a plaintext dump of every private key instead of the masked
archive that was requested.

An absent field still falls back to its documented default; only a value that
is present and not a boolean is an error.

## Authentication

All API endpoints require Bearer token authentication.

### Header Format

```
Authorization: Bearer YOUR_TOKEN
```

### Example Request

```bash
curl -X GET http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json"
```

---

## Rate Limiting

API endpoints have rate limits to prevent abuse:

| Endpoint           | Limit | Per    |
| ------------------ | ----- | ------ |
| General            | 100   | minute |
| Create Certificate | 30    | minute |
| Batch Operations   | 10    | minute |
| OCSP Status        | 200   | minute |
| CRL Download       | 60    | minute |
| Per-IP ceiling     | 600   | minute |

The working bucket is per API key (requests authenticated with the same bearer key share one limit) and per IP for session/anonymous requests, so several clients behind one NAT or proxy do not share — and abuse — a single bucket.

Every `/api/` request is **also** counted against a coarse per-IP ceiling, checked first. It sits far above the working limits, so a normal client never meets it; it exists because a bucket keyed only on the caller-supplied bearer token can be reset at will by changing the token, which previously made the per-key limits — and the protection on the unauthenticated OCSP and CRL endpoints — bypassable.

### Configuring rate limits

The limits are configurable per instance (admin only), so a trusted automation fleet behind a single address can raise them instead of tripping the default. Settings → API Keys → **API Rate Limits** exposes a value-per-endpoint form and an on/off toggle; changes apply immediately, with no restart.

The same configuration is available over the API:

```
GET /api/settings/rate-limits
  -> { "enabled": true,
       "limits": { "default": 100, "certificate_create": 30, ... },
       "defaults": { ... } }

PUT /api/settings/rate-limits
  { "enabled": true, "limits": { "certificate_create": 500 } }
```

Each limit is requests per minute (1–100000). Only the endpoint keys returned by `GET` are accepted; omitted keys keep their default. Setting `"enabled": false` turns API rate limiting off entirely (the login endpoint keeps its own separate limiter regardless).

### Rate Limit Response

When rate limited, you'll receive:

```
HTTP 429 Too Many Requests

{
 "error": "Rate limit exceeded",
 "message": "Too many requests. Please try again later.",
 "retry_after": 60
}
```

---

## Endpoints

### Managed certificates

The certificates CertMate issues and renews for your domains. (The section
below this one covers *client* certificates, which are a different feature.)

Every field named here is generated from `modules/api/models.py` into
`/api/swagger.json`, and `tests/test_the_swagger_contract_describes_the_real_response.py`
fails if the code returns a field the contract does not declare.

#### List certificates

**Endpoint**: `GET /api/certificates`

Returns an array of the objects described below, one per managed domain.

#### Get one certificate

**Endpoint**: `GET /api/certificates/<domain>`

**Response** (200 OK). This example is the real shape, taken from the code
rather than written by hand:

```json
{
  "domain": "app.example.com",
  "exists": true,
  "expiry_date": "2026-11-30 09:17:11",
  "days_left": 74,
  "days_until_expiry": 74,
  "seconds_left": 6479999,
  "expired": false,
  "needs_renewal": false,
  "private_key_present": true,
  "private_key_state": "present",
  "usable": true,
  "dns_provider": "cloudflare",
  "domain_alias": null,
  "alias_dns_provider": null,
  "san_domains": ["www.example.com"],
  "ca_provider": "letsencrypt",
  "challenge_type": "dns-01",
  "account_id": "default",
  "storage_warning": null,
  "deployment_port": null,
  "deployment_protocol": null,
  "created_at": "2026-09-01T10:14:02Z",
  "renewed_at": "2026-09-14T02:31:55Z"
}
```

##### Is it still valid?

Read `expired`. Do not compute it from a day count.

`days_left` and `days_until_expiry` are a whole number of days and round down,
so a certificate with 23 hours of life left reports `0`. `days_until_expiry <= 0`
therefore calls a perfectly valid certificate expired, and CertMate's own
dashboard did exactly that until 2.32.2. It is not a corner case: step-ca
issues 24-hour certificates by default, so on a private CA it was every
certificate from the moment it was issued.

| field | meaning |
| :--- | :--- |
| `expired` | Whether it has expired. `null` when the certificate could not be parsed, which is neither expired nor fine. |
| `seconds_left` | Remaining life in seconds, negative once expired. Use it for ordering: `days_left` cannot separate a certificate with hours left from one that lapsed hours ago. |
| `days_left`, `days_until_expiry` | Whole days remaining, rounded down. The same number under two names, kept for compatibility. |

`expired` and `seconds_left` arrived in API contract **2.2**; read the
`X-CertMate-API-Version` response header if you need to support older servers.

##### Can it actually serve TLS?

A certificate with no private key beside it cannot complete a handshake, and
`exists: true` does not tell you whether it has one.

| field | meaning |
| :--- | :--- |
| `private_key_state` | `present`, `missing`, `mismatched`, `unknown`, or `external`. |
| `private_key_present` | Whether a key was found. `null` when it was not looked for. |
| `usable` | `exists` AND a matching key. `null` when the storage backend does not fetch key material on this path and says so, which today means Azure Key Vault. |

`mismatched` is a certificate from one issuance sitting beside a key from
another: the two are compared, not assumed to match. `external` is a CSR-only
certificate, where the key was generated on the device that will serve it and
was never sent here, so its absence is the design rather than a fault, and it
does not force renewal.

`missing` and `mismatched` force `needs_renewal`, because a certificate that
cannot serve TLS has nothing to wait for. Restoring a share-safe backup
produces certificates with no key, which is the case this exists for.

#### Turn automatic renewal on or off

**Endpoint**: `PUT /api/certificates/<domain>/auto-renew` — operator

```json
{ "enabled": false }
```

`enabled` is a JSON boolean. Answers `{"message", "domain", "auto_renew"}`.
A missing `enabled` is `400 AUTO_RENEW_FLAG_REQUIRED`; a domain that is not
tracked in settings is `404 DOMAIN_NOT_IN_SETTINGS`, because only those have a
renewal flag to toggle. The change is audited and published on the event
stream as `certificate_auto_renew_changed`.

#### Check DNS-01 alias records

**Endpoints**:
`POST /api/certificates/check-dns-alias` — viewer, before a certificate exists;
`GET /api/certificates/<domain>/dns-alias-check` — viewer, for one that does.

With DNS alias mode the `_acme-challenge` record of each name is a CNAME into a
zone CertMate can write. These check that every CNAME is in place, before the
order rather than after the CA fails to find the TXT record.

```json
{
  "domain": "example.com",
  "domain_alias": "validation.example.org",
  "san_domains": ["www.example.com"],
  "wildcard": false
}
```

`domain` and `domain_alias` are required for the `POST`; `wildcard: true` adds
`*.<domain>` to the names. The `GET` reads both from the certificate and answers
`400` when it does not use alias mode. Every name is checked against the
caller's scope.

```json
{
  "domain": "example.com",
  "domain_alias": "validation.example.org",
  "ok": false,
  "checks": [
    {
      "source": "_acme-challenge.example.com",
      "expected_target": "_acme-challenge.validation.example.org",
      "found_targets": [],
      "status": "missing",
      "ok": false,
      "error": null
    }
  ]
}
```

`status` per check is `ok`, `missing` (no CNAME), `mismatch` (a CNAME to
somewhere else) or `error` (the lookup failed, with `error` saying why). The
top-level `ok` is true only when there is at least one check and every one is
`ok`.

#### Check CAA before issuing

**Endpoint**: `POST /api/certificates/check-caa` — viewer, since API contract **2.5**

What the CAA records (RFC 8659) say about issuing a set of names from a given
CA. A CAA record names the CAs allowed to issue for a domain, and a CA must
refuse when it is not named — so a record that names a different CA turns
into a failed order, or a failed renewal weeks later.

```json
{
  "domain": "example.com",
  "san_domains": ["www.example.com"],
  "ca_provider": "letsencrypt",
  "challenge_type": "dns-01"
}
```

`ca_provider` and `challenge_type` default to the ones in settings. At most
100 names per request. A scoped key gets `403 DOMAIN_OUT_OF_SCOPE` for any name
outside its scope, as the DNS-alias check does.

**Response** (200 OK):

```json
{
  "status": "forbidden",
  "ca_provider": "letsencrypt",
  "identifiers": ["letsencrypt.org"],
  "domains": [
    {
      "domain": "example.com",
      "status": "forbidden",
      "relevant_name": "example.com",
      "records": ["0 issue \"pki.goog\""],
      "reason": "example.com issue allows only pki.goog"
    }
  ],
  "message": "CAA: example.com issue allows only pki.goog, so Let's Encrypt (letsencrypt.org) will refuse example.com. Add a record such as example.com. CAA 0 issue \"letsencrypt.org\" or choose a CA the record names.",
  "suggested_record": "example.com. CAA 0 issue \"letsencrypt.org\""
}
```

| `status` | meaning |
| :--- | :--- |
| `allowed` | a record names this CA, or the records restrict nothing relevant |
| `no_policy` | no CAA records anywhere up the tree: any CA may issue |
| `forbidden` | records exist and none authorises this CA (for this challenge type, when `validationmethods` is set) |
| `unknown` | the lookup failed; a CA that gets the same answer refuses too |
| `not_applicable` | a private CA: whether it checks CAA is its operator's choice |

The top-level `status` is the most severe across all names. Wildcard names are
judged by `issuewild` when the record set has any. The lookup climbs from each
name towards the TLD and uses the first name that has records, as a CA does.

**This advises, it never gates.** CertMate's resolver is not the CA's —
split-horizon DNS, a record changed a minute ago — and the create endpoint does
not consult it. When an issuance or a renewal does fail and a CAA record
refuses the CA, the same sentence as `message` is appended to the error.

### Client certificates

#### Rebuild the client certificate authority

**Endpoint**: `POST /api/client-certs/ca/reset` (admin), since API contract **2.3**

The private CA that signs client certificates is generated once, on first
start, and its subject comes from `client_ca_subject` in settings:

```json
{
  "client_ca_subject": {
    "country": "IT",
    "state": "Liguria",
    "organization": "Acme SpA",
    "organizational_unit": "IT Security",
    "common_name": "Acme Client CA"
  }
}
```

Send it with `POST /api/settings` like any other settings key.

`country` is an ISO 3166-1 alpha-2 code and anything else is refused before a
key is written. A field left empty is omitted from the subject rather than
written as an empty attribute; `common_name` falls back to `CertMate CA`. An
instance that configures nothing keeps the subject it has always had.

That setting is read **when the CA is created and never again**, because
re-reading it would mean an edit in Settings silently replacing the CA, after
which every client certificate ever issued would stop verifying. Changing it
afterwards is this endpoint.

**Request**:

```json
{
  "confirm": "reset-client-ca",
  "subject": { "country": "IT", "organization": "Acme SpA", "common_name": "Acme Client CA" }
}
```

`confirm` is a typed phrase rather than a boolean, because `{"confirm": true}`
is what a mis-sent form or a retried request produces and neither means
"discard every certificate we have issued". `subject` is optional; omit it to
rebuild with the same subject.

**What it does.** Backs up the existing CA, generates a new one, and removes
every client certificate the old CA signed, because nothing can verify them
any more. It republishes the CRL, which was signed by the old key and is
therefore unverifiable the moment that key changes. It writes an audit record.

**What it does not touch.** Server certificates, settings and DNS accounts.

**Afterwards**, distribute the new CA certificate to everything that trusted
the old one, and reissue the client certificates you still need. Any CRL or
OCSP response published for the previous CA can no longer be verified.


#### 1. Create Certificate

**Endpoint**: `POST /api/client-certs/create`

Create a new client certificate.

**Request**:
```json
{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true,
 "notes": "Production certificate"
}
```

**Parameters**:
- `common_name` (required) - Certificate subject
- `email` (optional) - Email address
- `organization` (optional) - Organization name
- `organizational_unit` (optional) - Department name
- `cert_usage` (optional) - Usage type: `api-mtls`, `vpn`, or custom
- `days_valid` (optional) - Validity in days (default: 365)
- `generate_key` (optional) - Generate private key (default: true)
- `notes` (optional) - Additional notes

**Response** (201 Created):
```json
{
 "identifier": "cert-abc123",
 "common_name": "user@example.com",
 "serial_number": "12345678901234567890",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "cert_usage": "api-mtls",
 "status": "active"
}
```

**Example**:
```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365
 }'
```

---

#### 2. List Certificates

**Endpoint**: `GET /api/client-certs`

List all client certificates with optional filtering.

**Query Parameters**:
- `usage` (optional) - Filter by usage type (e.g., `api-mtls`)
- `revoked` (optional) - Filter by status (`true` or `false`)
- `search` (optional) - Search in common name

**Response** (200 OK):
```json
{
 "certificates": [{
 "identifier": "cert-001",
 "common_name": "user1@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "revoked": false,
 "status": "active"
 },
 {
 "identifier": "cert-002",
 "common_name": "user2@example.com",
 "organization": "ACME Corp",
 "cert_usage": "vpn",
 "created_at": "2024-10-29T18:00:00Z",
 "expires_at": "2025-10-29T18:00:00Z",
 "revoked": true,
 "status": "revoked"
 }
 ],
 "total": 2
}
```

**Examples**:
```bash
# List all certificates
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filter by usage type
curl "http://localhost:8000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# List only revoked
curl "http://localhost:8000/api/client-certs?revoked=true" \
 -H "Authorization: Bearer TOKEN"

# Search by common name
curl "http://localhost:8000/api/client-certs?search=user1" \
 -H "Authorization: Bearer TOKEN"
```

---

#### 3. Get Certificate Details

**Endpoint**: `GET /api/client-certs/<identifier>`

Get complete metadata for a certificate.

**Response** (200 OK):
```json
{
 "type": "client_certificate",
 "identifier": "cert-001",
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "serial_number": "12345678901234567890",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "cert_usage": "api-mtls",
 "notes": "Production certificate",
 "revocation": {
 "revoked": false,
 "revoked_at": null,
 "reason_revoked": null
 },
 "renewal": {
 "renewal_enabled": true,
 "renewal_threshold_days": 30
 }
}
```

**Example**:
```bash
curl http://localhost:8000/api/client-certs/cert-001 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 4. Download Certificate Files

**Endpoint**: `GET /api/client-certs/<identifier>/download/<type>`

Download certificate, private key, or CSR file.

**Parameters**:
- `identifier` - Certificate ID
- `type` - File type: `crt`, `key`, `csr`, or `pfx` (encrypted PKCS#12; requires a PFX password set in Settings, operator role)

**Response** (200 OK):
- Content-Type: `application/octet-stream`
- File attachment with proper naming

**Examples**:
```bash
# Download certificate
curl http://localhost:8000/api/client-certs/cert-001/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o certificate.crt

# Download private key
curl http://localhost:8000/api/client-certs/cert-001/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o private.key

# Download CSR
curl http://localhost:8000/api/client-certs/cert-001/download/csr \
 -H "Authorization: Bearer TOKEN" \
 -o request.csr
```

---

#### 5. Revoke Certificate

**Endpoint**: `POST /api/client-certs/<identifier>/revoke`

Revoke a certificate with optional reason.

**Request** (optional):
```json
{
 "reason": "compromised"
}
```

**Response** (200 OK):
```json
{
 "message": "Certificate revoked: cert-001",
 "revoked_at": "2024-10-30T18:15:00Z",
 "reason": "compromised"
}
```

**Example**:
```bash
curl -X POST http://localhost:8000/api/client-certs/cert-001/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "reason": "compromised"
 }'
```

---

#### 6. Renew Certificate

**Endpoint**: `POST /api/client-certs/<identifier>/renew`

Renew a certificate (same CN, new serial).

**Response** (201 Created):
```json
{
 "identifier": "cert-001-renewed",
 "common_name": "user@example.com",
 "serial_number": "98765432109876543210",
 "created_at": "2024-10-30T18:20:00Z",
 "expires_at": "2025-10-30T18:20:00Z",
 "status": "active"
}
```

**Example**:
```bash
curl -X POST http://localhost:8000/api/client-certs/cert-001/renew \
 -H "Authorization: Bearer TOKEN"
```

---

#### 7. Get Statistics

**Endpoint**: `GET /api/client-certs/stats`

Get certificate usage statistics.

**Response** (200 OK):
```json
{
 "total": 100,
 "active": 85,
 "revoked": 15,
 "expiring_soon": 8,
 "by_usage": {
 "api-mtls": 60,
 "vpn": 35,
 "other": 5
 },
 "created_count": 100,
 "renewal_enabled": 92
}
```

**Example**:
```bash
curl http://localhost:8000/api/client-certs/stats \
 -H "Authorization: Bearer TOKEN"
```

---

#### 8. Batch Import Certificates

**Endpoint**: `POST /api/client-certs/batch`

Create multiple certificates from CSV data in single request.

**Request**:
```json
{
 "headers": ["common_name", "email", "organization", "cert_usage", "days_valid"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp", "api-mtls", "365"],
 ["user2@example.com", "user2@example.com", "ACME Corp", "vpn", "365"],
 ["user3@example.com", "user3@example.com", "ACME Corp", "api-mtls", "365"]
 ]
}
```

**Response** (201 Created):
```json
{
 "total": 3,
 "successful": 3,
 "failed": 0,
 "errors": [],
 "certificates": [{
 "identifier": "cert-batch-001",
 "common_name": "user1@example.com"
 },
 {
 "identifier": "cert-batch-002",
 "common_name": "user2@example.com"
 },
 {
 "identifier": "cert-batch-003",
 "common_name": "user3@example.com"
 }
 ]
}
```

**Example**:
```bash
curl -X POST http://localhost:8000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "headers": ["common_name", "email", "organization"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
 ["user2@example.com", "user2@example.com", "ACME Corp"]
 ]
 }'
```

---

### OCSP & CRL

#### 9. OCSP Status Query

**Endpoint**: `GET /api/ocsp/status/<serial_number>`

Query certificate status via OCSP.

**Response** (200 OK):
```json
{
 "response_status": "successful",
 "certificate_status": "good|revoked|unknown",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z",
 "next_update": null,
 "responder_name": "CertMate OCSP Responder"
}
```

**Example**:
```bash
curl http://localhost:8000/api/ocsp/status/12345678 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 10. CA Certificate

**Endpoint**: `GET /api/client-certs/ca`, since API contract **2.16**

Download the CA certificate that signs this instance's client certificates —
the one a relying party has to trust in order to verify them.

Public, like the CRL below: the servers that need it have no account here,
and it is a public certificate. The CA's private key is served by nothing.

Before 2.16 there was no way to fetch it. `POST /api/client-certs/ca/reset`
was the only `/ca` route, and the only copy of the CA an operator could
obtain came inside the PKCS#12 bundle — which needs operator rights, a
configured `pfx_password`, and ships a private key alongside it.

**Response**: `ca.crt` as a PEM attachment, or `404` when no CA has been
generated yet.

**Example**:
```bash
curl http://localhost:8000/api/client-certs/ca -o ca.crt

# and, on the server that verifies the client certificates:
#   ssl_client_certificate /etc/nginx/ca.crt;   # nginx
#   SSLCACertificateFile   /etc/apache2/ca.crt; # apache
```

---

#### 11. CRL Distribution

**Endpoint**: `GET /api/crl/download/<format_type>`

Download Certificate Revocation List.

**Parameters**:
- `format_type` - `pem`, `der`, or `info`

**Response**:
- For `pem` and `der`: File attachment
- For `info`: JSON with CRL metadata

**Examples**:
```bash
# Download CRL in PEM format
curl http://localhost:8000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Download CRL in DER format
curl http://localhost:8000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Get CRL info
curl http://localhost:8000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

**CRL Info Response**:
```json
{
 "status": "available",
 "issuer": "CN=CertMate CA, O=CertMate",
 "last_update": "2024-10-30T18:00:00Z",
 "next_update": "2024-10-31T18:00:00Z",
 "revoked_count": 5,
 "revoked_serials": [12345678,
 87654321
 ]
}
```

---

#### 12. Download Domain Certificate Files

**Endpoint**: `GET /api/certificates/<domain>/download`

Download certificate files for a specific domain. By default, this endpoint returns a ZIP archive containing all certificate components. A specific file can be requested using the `file` query parameter. JSON mode is also available for automation that wants all PEMs in one response.

**Parameters**:
- `domain` (Path) - The domain name associated with the certificate.
- `file` (Query, Optional) - Specify a single file to download. 
  - Supported values: `fullchain.pem`, `privkey.pem`, `combined.pem`
- `format` (Query, Optional) - Set to `json` to return all certificate files in a JSON object.
- `key_format` (Query, Optional) - `pkcs1` or `pkcs8`. Certbot writes PKCS#8 (`BEGIN PRIVATE KEY`); some older stacks require the legacy traditional form. Valid with `file=privkey.pem` (serves the converted key) or with `format=json` (adds a converted copy to the response).

**Response** (200 OK):
- **Default**: `application/zip` (A ZIP file containing all PEM files)
- **With `file` param**: `application/x-pem-file` (The raw content of the requested file)
- **With `format=json`**: `application/json` with `domain`, `cert_pem`, `chain_pem`, `fullchain_pem`, and `private_key_pem`
- **With `format=json&key_format=pkcs1`**: the above plus `private_key_pkcs1_pem`

The JSON form is the preferred automation shape for Ansible, Salt, or any other client that wants to write PEM files directly.

`key_format=pkcs1` on the JSON form **adds** `private_key_pkcs1_pem` and leaves `private_key_pem` untouched, so an existing consumer is unaffected and a client needing the legacy key no longer has to make a second call and stage it through a file. The field is named for the encoding rather than for RSA: the traditional form of an ECDSA key is SEC1 (`BEGIN EC PRIVATE KEY`), and CertMate issues ECDSA by default. Key types with no traditional encoding (Ed25519) return **422**.

**Examples**:

```bash
# Download all files as a ZIP archive
curl http://localhost:8000/api/certificates/example.com/download \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.zip

# Download only the fullchain.pem file
curl "http://localhost:8000/api/certificates/example.com/download?file=fullchain.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o fullchain.pem

# Download only the private key
curl "http://localhost:8000/api/certificates/example.com/download?file=privkey.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o privkey.pem

# Download the full certificate bundle as JSON
curl "http://localhost:8000/api/certificates/example.com/download?format=json" \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.json

```

---

#### 13. Reissue Domain Certificate (edit configuration)

**Endpoint**: `POST /api/certificates/<domain>/reissue`

Edit a certificate's configuration and reissue it in place — extend or drop
SAN entries without delete + recreate. Omitted fields keep the values the
certificate was issued with (read from its metadata), so DNS/alias/CA
configuration never needs re-entering. The current certificate keeps being
served until the reissue succeeds. The key shape is preserved unless
explicitly changed (no key flags are sent and certbot keeps the lineage key).

**Request Body** (all fields optional):
```json
{
  "san_domains": ["www.example.com", "api.example.com"],
  "domain_alias": "",
  "async": true
}
```

- `san_domains`: replacement SAN set — omit to keep, `[]` to drop every SAN
- `domain_alias`: omit to keep, `""` to clear
- `dns_provider`, `account_id`, `ca_provider`, `challenge_type`: omit to keep
- `key_type`/`key_size`/`elliptic_curve`: omit to keep the existing key shape
- `async`: defer issuance to a background job (202 + job id, poll `GET /api/certificates/jobs/<job_id>`)

**Response** (200 OK, or 202 Accepted with `async`): message, domain, dns_provider, ca_provider, duration.

**Errors**: 404 when no certificate exists for the domain (use create), 403 scope, 400 validation, 409 operation in progress, 422 certbot failure (the previous certificate is still in place).

**Example**:
```bash
curl -X POST http://localhost:8000/api/certificates/example.com/reissue \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"san_domains": ["www.example.com", "api.example.com"]}'
```

---

### Log stream (admin, debugging)

```
GET /api/web/logs/stream
```

Server-Sent Events tail of the application log file, for watching an issuance
or a deployment live from a terminal.

**Requires file logging to be on.** By default CertMate logs to stdout only —
what `docker logs` and every log shipper expect — so this endpoint reports
"Log file not found" until you set `CERTMATE_LOG_FILE`
(e.g. `CERTMATE_LOG_FILE=/app/logs/certmate.log`). The file is rotated
automatically; see the environment table in the README.

```bash
curl -N -H "Authorization: Bearer TOKEN" \
 https://certmate.example.com/api/web/logs/stream
```

Admin-only, because application logs can contain credentials. Only lines
written *after* the connection opens are sent — this is a tail, not a history
download. The stream emits a `: keepalive` comment while idle and closes after
30 idle minutes; an `EventSource` client reconnects on its own, a `curl`
session has to be restarted.

---

### Health

#### Health check

**Endpoint**: `GET /api/health`

**No credential required**, deliberately: this is what a load balancer or an
orchestrator polls, and a probe that needs a secret is a probe that stops
working during the incident it exists to report.

It answers `200` when the instance is healthy or degraded, and `500` when it is
unhealthy, so a liveness check can read the status line alone. The body names
each subsystem:

```json
{
 "status": "degraded",
 "checks": {
   "settings": "ok",
   "scheduler": "not_running",
   "storage": "fallback_to_local (configured backend: azure_keyvault)"
 }
}
```

`checks` carries only subsystems that have something to report. An instance
with no remote storage backend has no `storage` key at all, rather than a green
tick for a subsystem it does not have. The `storage` check is worth watching
even when everything else is green: it is how you learn that the configured
cloud backend failed to initialise and certificates are on local disk. It reads
`unknown` when the backend could not be read at all, which is not the same as
`ok`.

`status` is `healthy`, `degraded` or `unhealthy`, and the worst of the checks
wins. A stopped scheduler is `degraded`, not `unhealthy`: renewals have stopped
firing, which monitoring must see, but the instance still serves and failing
liveness on it would take a working install out of rotation.

Every response carries `X-CertMate-API-Version`; `/api/health` also reports it
as `api_contract_version` for anything that already polls here.

### Authentication and session

These are the endpoints the login flow uses. They are listed because they are
part of the public surface, not because an API client normally needs them: a
machine client authenticates with a bearer token on every request (see
[Authentication](#authentication)) and needs none of this.

#### Log in

**Endpoint**: `POST /api/auth/login` — no credential required, by necessity.

Exchanges a username and password for a session cookie. Rate-limited on two
buckets: per IP and per username.

#### Log out

**Endpoint**: `POST /api/auth/logout` — no credential required.

Invalidates the session server-side, not only the cookie.

#### Who am I

**Endpoint**: `GET /api/auth/me`

Returns the caller's username and role, which is how the dashboard decides
which controls to render. This endpoint has its own answer shape and does not
use the error envelope: it replies `{"user": null}` with `401` when there is no
session, because a UI deciding whether to draw a login form wants that as data
rather than as an error. During first-run setup, before any credential exists,
it answers `200` with `{"auth_mode": "bypass"}`.

#### SSO descriptor

**Endpoint**: `GET /api/auth/oidc/config` — no credential required.

Tells the login page whether to render an SSO button. It returns affordances
only; no client secret and no issuer internals.

#### Start the SSO flow

**Endpoint**: `GET /api/auth/oidc/login` — no credential required,
rate-limited.

Begins the Authorization Code + PKCE flow. The next-URL is validated to be a
path on this site, so it cannot be used as an open redirect.

### Probing a host

#### Read the certificate a host is serving

**Endpoint**: `POST /api/probe` — viewer, since API contract **2.8**

```json
{ "host": "shop.example.com", "port": 443, "server_name": "shop.example.com", "check_revocation": true }
```

Only `host` is required. `port` defaults to 443, `server_name` to `host`, and
`check_revocation` to `true`.

The answer is the deep probe's own shape — `status`, `certificate`,
`validation`, `chain`, `revocation`, `connect_ip`, `probed_at` — the same one
the inventory stores, described in
[the discovery guide](discovery-inventory.md#the-deep-tls-probe). In short:

- `status` is `ok`, `blocked` (the SSRF guard refused the target) or
  `unreachable` (`error_class` says which way);
- PKI trust is deliberately **not** validated, so an expired, self-signed or
  mismatched certificate is still described, with `validation` reporting the
  condition;
- `revocation` is the verified OCSP/CRL answer, or `null` when
  `check_revocation` is false. It is never `good` unless a signed, current
  answer said so — see [Revocation](discovery-inventory.md#revocation).

This is how another tool asks CertMate what is being served rather than
implementing TLS again. It is rate-limited as its own category, because each
call opens a TLS connection to a third party and may fetch that CA's OCSP or
CRL.

**Boundaries.** A scoped key may only probe hosts its `allowed_domains` cover,
and `server_name` is checked too, because that is the name the probe asks the
host for. Private, loopback and other non-global addresses are refused by the
probe's SSRF guard, which answers `blocked` instead of raising.

### Inventory and discovery

The inventory is every certificate CertMate knows about: the ones it manages
and the ones it has found on your hosts or in the Certificate Transparency
logs. Discovery is what fills the second half.

#### List the inventory

**Endpoint**: `GET /api/inventory` — viewer

Returns managed and discovered certificates with an expiry forecast. Filters:
`?managed=true|false`, and the usual paging.

Since API contract **2.4** every record carries `revocation`: the last verified
OCSP/CRL answer for that certificate, as `{status, method, reason, revoked_at,
error, checked_at}`, or `null` when it was never checked. `status` is one of
`good`, `revoked`, `unknown`, `unavailable` or `not_applicable`, and only a
signed, current answer from the issuer is ever `good` or `revoked`. The
summary adds a `revocation` count per status (plus `unchecked`). What each
status means and how the answer is verified:
[Revocation](discovery-inventory.md#revocation).

#### Forget a discovered certificate

**Endpoint**: `DELETE /api/inventory/<fingerprint>` — operator

Removes a discovered record. Managed certificates are not deleted this way;
this only forgets something discovery found.

#### Adoption plan

**Endpoint**: `GET /api/inventory/<fingerprint>/adopt` — viewer

Returns what adopting that certificate would do: the create parameters
pre-filled from what was observed on the wire, and whether CertMate believes it
can take it over. Read-only, so it is safe to call before deciding.

#### Adopt it

**Endpoint**: `POST /api/inventory/<fingerprint>/adopt` — operator

Issues and manages the certificate from the observed metadata, then marks the
inventory record as adopted.

#### Discovery configuration

**Endpoint**: `GET /api/inventory/config` — viewer
**Endpoint**: `POST /api/inventory/config` — admin

Reads and updates discovery and CT-log monitoring settings.

#### Run discovery now

**Endpoint**: `POST /api/inventory/scan` — admin

Runs a discovery sweep and a CT-log poll immediately and returns both
summaries. The two are failure-isolated: one failing does not stop the other,
and the summary says which.

#### Cryptographic readiness report

**Endpoint**: `GET /api/inventory/crypto-report` — viewer

Classifies the key and signature algorithms across every managed and
discovered certificate against published deprecation timelines. It is an
inventory, not a recommendation engine: it counts what is deployed and says
what is behind. Add `?format=csv` for the per-asset table.

#### Domain registrations

**Endpoint**: `GET /api/inventory/domains` — viewer, since API contract **2.6**

When each tracked domain's *registration* expires, from RDAP, or WHOIS where
the TLD has no RDAP. One row per registrable domain, soonest expiry first; a
scoped key sees only the domains its scope covers.

```json
{
  "domains": [
    {
      "domain": "example.com",
      "status": "ok",
      "expires_at": "2026-10-29T15:57:39Z",
      "days_until_expiry": 37,
      "expiry_status": "ok",
      "registrar": "Example Registrar Inc.",
      "registry_status": ["client transfer prohibited"],
      "source": "rdap",
      "error": null,
      "checked_at": "2026-09-22T06:00:04Z",
      "first_seen": "2026-09-01T06:00:02Z"
    }
  ],
  "summary": {
    "total": 1,
    "by_status": {"ok": 1, "not_published": 0, "not_registered": 0, "unavailable": 0},
    "expiry": {"expired": 0, "30": 0, "60": 1, "90": 1}
  }
}
```

`status` is `ok`, `not_published` (the registry does not publish an expiry —
`.de`, `.eu`), `not_registered` or `unavailable`; only `ok` carries a date and a
day count. The check is configured under `domain_registration` in
`/api/inventory/config` and also runs on `POST /api/inventory/scan`, whose
answer gains a `domain_registration` summary. What each status means, and why
some TLDs are answered over WHOIS:
[Domain registration expiry](discovery-inventory.md#domain-registration-expiry).

#### Domain health

**Endpoint**: `GET /api/inventory/health` — viewer, since API contract **2.9**

The checks that are about the *name* rather than the certificate: SPF, DMARC
and MX, the DNS blocklists, the HSTS and protective headers the host serves,
what its response discloses about the software behind it, and — when it is
switched on — whether it still accepts TLS 1.0 or 1.1. Worst first, so the
answer opens on what is wrong; a scoped key sees only its own names.

```json
{
  "names": [
    {
      "name": "example.com",
      "status": "failing",
      "checks": {
        "spf": {"status": "ok", "detail": "published",
                "record": "v=spf1 include:_spf.example.net -all"},
        "dmarc": {"status": "failing",
                  "detail": "no DMARC record, so a receiver has no instruction for mail that fails authentication"},
        "mx": {"status": "ok", "detail": "2 mail exchangers",
               "hosts": ["mx1.example.net", "mx2.example.net"]},
        "blocklists": {"status": "unknown",
                       "detail": "no blocklist answered usefully — the resolver CertMate uses is almost always the reason, because the large lists refuse public resolvers. Name one of your own under dns_resolver in the discovery configuration, or in CERTMATE_DNS_RESOLVERS",
                       "unanswered": ["zen.spamhaus.org (192.0.2.13): refused this resolver"],
                       "not_covered": []},
        "hsts": {"status": "ok", "detail": "max-age 31536000s",
                 "max_age": 31536000, "includes_subdomains": true, "preload": false},
        "security_headers": {"status": "warning",
                             "detail": "no X-Content-Type-Options: nosniff",
                             "broken": [], "missing": ["no X-Content-Type-Options: nosniff"],
                             "checked_host": "www.example.com"},
        "weak_tls": {"status": "failing",
                     "detail": "the host still accepts TLS 1.0, deprecated by RFC 8996 since 2021",
                     "accepted": ["TLS 1.0"], "refused": ["TLS 1.1"], "unasked": []},
        "disclosure": {"status": "warning",
                       "detail": "the response names the software running it: Server: nginx/1.24.0",
                       "disclosed": ["Server: nginx/1.24.0"],
                       "checked_host": "www.example.com"}
      },
      "checked_at": "2026-09-22T06:30:11Z",
      "first_seen": "2026-09-01T06:30:09Z"
    }
  ],
  "summary": {"total": 1, "by_status": {"failing": 1, "warning": 0, "unknown": 0, "ok": 0}}
}
```

Every check reports one of four statuses, and `unknown` is the one to read
carefully: it means the check could not be completed, and it is **not** a pass.
A blocklist that refuses the query — which is what every public resolver gets
from Spamhaus — has said nothing about the address, and reporting that as "not
listed" is the mistake this endpoint exists not to make. Because that refusal
can arrive as a plain NXDOMAIN, indistinguishable from "not listed", each list
is first asked about its own always-listed test point; one that cannot answer
that is not asked about your domains at all, and is named in `unanswered`.
Point CertMate at a resolver of your own — `dns_resolver.nameservers` in
`/api/inventory/config`, or `CERTMATE_DNS_RESOLVERS` in the environment — and
the answers become real.

`weak_tls` is present only when `check_weak_tls` is on: it is the one check
that opens connections a host did not invite. Its `unknown` never means the
host refused the old version — it means the host was not asked, for one of
three reasons: this CertMate build could not offer that version, the host
could not be reached, or the SSRF guard declined the target. `unasked` says
which.

Mail checks and blocklists run against the *registrable* domain, because DMARC
falls back to the organisational domain; the three header checks run against
each host, because that is what serves the site, and they share one `HEAD`
request. `checked_host` says which name answered it — a redirect from the apex
to `www` within the same registrable domain is followed, so the headers
described are the page's and not the redirect's. The checks are configured under `domain_health`
in `/api/inventory/config` and also run on `POST /api/inventory/scan`, whose
answer gains a `domain_health` summary. What each check means:
[Domain health](discovery-inventory.md#domain-health).

#### Is a newer CertMate out

**Endpoint**: `GET /api/web/update-check` — session, viewer

```json
{ "status": "outdated", "running": "2.34.0", "latest": "v2.35.0" }
```

**Off by default, and it stays off until an operator turns it on.**
`docs/ca-providers.md` offers the private CA for air-gapped systems, and an
instance nobody asked to reach the internet must not reach it — so with
`update_check.enabled` unset this answers `disabled` and no request is made.
`disabled` and `unknown` are separate answers on purpose: the first means you
did not ask, the second means CertMate asked GitHub and could not find out,
which is a reason to look at egress rules rather than at CertMate.

`unknown` is never rendered as `current`. An air-gapped instance told daily
that it is up to date, while running a release with a known defect, is worse
served than one told nothing.

The answer is cached for a day, so the footer polling it on every page load
does not make an instance into a source of traffic.

### Deployment

#### Deploy-hook history

**Endpoint**: `GET /api/deploy/history` — admin

What ran, when, and whether it succeeded.

#### Deploys waiting for a window

**Endpoint**: `GET /api/deploy/pending` — admin

Certificates that were renewed but whose deploy hook is being held until the
configured maintenance window opens.

#### Dry-run a deploy hook

**Endpoint**: `POST /api/deploy/test/<hook_id>` — admin

Runs the hook without a real certificate change, so a broken hook is found
before a renewal depends on it.

#### Run a certificate's deploy hooks now

**Endpoint**: `POST /api/certificates/<domain>/deploy` — admin

Runs every enabled hook and deploy target that applies to the domain, with
`CERTMATE_EVENT=manual`. The `on_events` filter and maintenance windows are
ignored: pressing the button is the decision to deploy now.

```json
{ "ok": true, "total": 2, "succeeded": 2, "failed": 0, "results": [ ... ] }
```

It answers **200 even when `ok` is false**, so the summary can be read: deploy
hooks disabled, or nothing configured for this domain, come back as `ok: false`
with an `error` that says which. Non-2xx is reserved for a bad domain path
(`400`), a certificate that does not exist (`404 CERTIFICATE_NOT_FOUND`), a
deploy manager that is not running (`503`) and an unexpected failure (`500`).
Each `results[]` entry is one hook or target run (`hook_name`, `exit_code`,
`success`, `stdout`, `stderr`, ...), the same record `GET /api/deploy/history`
keeps.

#### Check what a domain is actually serving

**Endpoint**: `GET /api/certificates/<domain>/deployment-status` — viewer

Opens a TLS connection to the domain and compares the fingerprint of the
certificate it serves against the one CertMate holds for it. This answers
"did the new certificate reach the service", which issuance and renewal
cannot: a certificate can renew perfectly and still not be the one a load
balancer is presenting.

The verdict is cached. Add `?refresh=1` to discard the cached answer and look
again — the cache is also dropped automatically whenever the domain's
certificate changes, so a renewal does not leave a stale badge behind.

`404 CERTIFICATE_NOT_FOUND` when CertMate holds no certificate for the domain,
`400` for a domain the path rejects. A scoped key sees only its own domains.

Only what CertMate's own process can reach is reported here; a service that is
reachable from a browser but not from the container answers as unreachable,
which is what the endpoint below is for.

#### Record browser-side reachability

**Endpoint**: `POST /api/certificates/deployment-status/browser` — viewer

The dashboard reports what it could reach from the visitor's network and posts
it here. This exists because the server and the browser can see different
things: a certificate that is fine from inside the network and unreachable
from outside it is a deployment problem the server alone cannot detect.

### DNS provider accounts

#### List and add accounts

**Endpoint**: `GET /api/dns/accounts` — admin
**Endpoint**: `POST /api/dns/accounts` — admin

The multi-account surface: several credentials per provider, each with its own
`account_id`, selected per certificate.

`GET /api/dns-providers/accounts` and `POST /api/dns-providers/accounts` do the
same thing, at the same role, through a different implementation, and are
**deprecated since 2026-09-18**. They answer with `Deprecation`, `Sunset` and a
`Link` header pointing here, and the sunset date is **2027-03-18**: that is the
earliest they may stop answering, not the date they will.

Use `/api/dns/accounts`, or `/api/dns/<provider>/accounts`. That is the pair
flask-restx generates into `/api/swagger.json`, so it is what a generated
client speaks.

Deprecating does not move the contract version, which is the point of
deprecating rather than removing; the removal is what would bump the major.

#### Update or remove an account

**Endpoint**: `PUT /api/dns/<provider>/accounts/<account_id>` — admin
**Endpoint**: `DELETE /api/dns/<provider>/accounts/<account_id>` — admin

The `/api/dns-providers/accounts/<account_id>` forms of these are deprecated on
the same terms as the listing above.

#### Provider configuration

**Endpoint**: `GET /api/settings/dns-providers` — viewer

Not the same as the two above: this returns which providers are configured and
how, not the list of accounts. Credential values are masked.

### Notifications and events

#### Notification configuration

**Endpoint**: `GET /api/notifications/config` — admin
**Endpoint**: `POST /api/notifications/config` — admin

Reads and replaces the whole notifications block. POST replaces rather than
merges.

#### Send a test message

**Endpoint**: `POST /api/notifications/test` — admin

Sends through one channel without persisting anything, so a channel can be
proved before it is saved.

#### Preview a webhook payload

**Endpoint**: `POST /api/notifications/webhook/preview` — admin

Renders what a generic webhook would send for a sample event: method, URL and
header *names*. Credential values are never echoed back.

#### Webhook delivery log

**Endpoint**: `GET /api/webhooks/deliveries` — admin

Recent deliveries, newest first, so a webhook that is failing silently is
visible.

`url` is the **origin** only — `https://hooks.slack.com`, not the full
endpoint. An incoming-webhook URL carries its bearer secret in the path, so the
path, query and any `user:password@` are not kept. Entries written before this
are reduced on read as well, so the endpoint never serves one in full.

#### Send the weekly digest now

**Endpoint**: `POST /api/digest/send` — admin

Triggers the digest immediately and returns the send result, rather than
waiting for the schedule.

#### Live event stream

**Endpoint**: `GET /api/events/stream` — viewer, **session only**

Server-Sent Events for certificate lifecycle events. This is the one endpoint
on this page that a bearer token does **not** open: it requires a session
cookie, because it is built for a browser tab. A machine client should poll the
certificate endpoints or use a webhook.

### Cache

#### Cache statistics

**Endpoint**: `GET /api/cache/stats` — viewer

#### Clear the deployment cache

**Endpoint**: `POST /api/cache/clear` — admin

Audited, like any other administrative action.

### Users and API keys

#### Edit or remove a user

**Endpoint**: `PUT /api/users/<username>` — admin
**Endpoint**: `DELETE /api/users/<username>` — admin

#### Create an API key

**Endpoint**: `POST /api/keys` — admin

Refused with `409 SETUP_BOOTSTRAP_ONLY` while the instance is still in setup
mode. In that state every request is served as admin to anyone who can reach
the instance, so a key minted then would be minted by whoever was there, and
it would stay valid once setup is complete. Enable local authentication (or set
`API_BEARER_TOKEN`), sign in, then create keys. `POST /api/users` answers the
same `409` for any user after the first one while setup is incomplete: the
first admin is the bootstrap.

#### Revoke an API key

**Endpoint**: `DELETE /api/keys/<key_id>` — admin

Revocation takes effect immediately; the key stops authenticating on the next
request.

#### Confirm a key created during setup

**Endpoint**: `PATCH /api/keys/<key_id>` — admin, since API contract **2.7**

```json
{ "confirmed": true }
```

Keys that earlier versions let be created while the instance was in setup mode
(`created_by: "setup_user"`) stay valid, but `GET /api/keys` lists them with
`created_during_setup: true` and `needs_review: true`, and the startup log says
how many there are. Confirming records who vouched for the key and when
(`setup_origin_confirmed_by`, `setup_origin_confirmed_at`) and clears
`needs_review`; revoking removes it. Confirming is refused in setup mode, for a
key that was not created during setup (`400 API_KEY_NOT_CONFIRMABLE`), and for
an unknown key (`404 API_KEY_NOT_FOUND`).

### Backups and storage

#### Delete a backup

**Endpoint**: `DELETE /api/backups/delete/<backup_type>/<filename>` — admin

#### Test a CA provider

**Endpoint**: `POST /api/settings/test-ca-provider` — operator

Checks that the configured ACME directory answers, before an issuance depends
on it.

#### Backfill Azure Key Vault certificate objects

**Endpoint**: `POST /api/storage/azure-keyvault/backfill-certificates` — admin

For an instance that stored certificates as Key Vault *secrets* and later
enabled the native *certificate* surface: this creates the certificate objects
for domains that already exist as secrets. It does not re-issue anything.

---

### Storage backends

Where certificates live. The default is the local filesystem; the remote
backends are Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical
and any S3-compatible object store.

#### Read the current backend

**Endpoint**: `GET /api/storage/info` — viewer

Reports which backend is configured and, if a remote one failed to initialise,
that CertMate fell back to local disk. `/api/health` carries the same fact as a
`storage` check, which is the one to watch: an instance that believes it is
writing to Azure and is writing to an ephemeral container filesystem looks
perfectly healthy from everywhere else.

#### Change the backend

**Endpoint**: `POST /api/storage/config` — admin

#### Test a backend before committing to it

**Endpoint**: `POST /api/storage/test` — operator

Opens a connection with the credentials given and reports whether they work,
without storing them. Worth doing before `POST /api/storage/config`: a backend
that cannot authenticate is a backend that silently falls back.

#### Migrate between backends

**Endpoint**: `POST /api/storage/migrate` — admin

Copies certificates from the current backend to another. Read
`docs/storage-backends.md` before running it.

#### Backfill Azure Key Vault certificate objects

**Endpoint**: `POST /api/storage/azure-keyvault/backfill-certificates` — admin

For an instance that stored certificates as Key Vault *secrets* and later
enabled the native *certificate* surface: creates the certificate objects for
domains that already exist as secrets. It does not re-issue anything.

### Backups

#### List backups

**Endpoint**: `GET /api/backups` — viewer

#### Create one

**Endpoint**: `POST /api/backups/create` — admin

`include_secrets` decides whether the archive can restore this instance. The
default is a share-safe archive: private keys, the ACME account key and the
private CA key are left out, so it is a configuration snapshot rather than a
restorable backup. Set `CERTMATE_BACKUP_PASSPHRASE` and ask for secrets to get
one that can actually restore, encrypted at rest.

#### Download, restore, delete

**Endpoint**: `GET /api/backups/download/<backup_type>/<filename>` — admin
**Endpoint**: `POST /api/backups/restore/<backup_type>` — admin
**Endpoint**: `DELETE /api/backups/delete/<backup_type>/<filename>` — admin

Only unified backups can be restored.

#### Upload one taken elsewhere

**Endpoint**: `POST /api/backups/upload` — admin

For moving an instance to a new host: upload the archive here, then restore it.

### Monitoring

#### Metrics summary

**Endpoint**: `GET /api/metrics` — viewer

A JSON summary of what the Prometheus exporter exposes. It answers `503` when
the Prometheus client library is not installed.

The scrape target itself is the separate `/metrics` route, and it is **not**
public: it carries the same viewer requirement, because its series enumerate
every managed domain.

#### Scan for zombie domains

**Endpoint**: `POST /api/certificates/zombies/scan` — admin

Looks for managed domains whose DNS no longer resolves to anything you control.
A certificate for a name you have let go is a certificate that will keep being
renewed and can no longer be validated, and the renewal failures are the first
anyone usually hears of it.

---

## Error Handling

### Error Response Format

Every failure carries a human-readable `error` and a machine-readable `code`:

```json
{
 "error": "Certificate not found for domain: example.com",
 "code": "CERTIFICATE_NOT_FOUND"
}
```

`code` is **always a string**. Failures raised by the HTTP layer rather than by
the application — an unmatched path, a wrong method, a body over the size limit
— carry two more fields, `message` (the framework's description) and `status`
(the numeric status, which is also the status line):

```json
{
 "error": "Not Found",
 "message": "The requested URL was not found on the server.",
 "code": "NOT_FOUND",
 "status": 404
}
```

Until the contract version moved to **2.0**, `code` on that second shape was
the status *integer* while every application error used a string, so a client
could not branch on the field without checking its type first. It is one type
now, and the number a caller may have been reading is in `status` on those same
responses. The version is on every response as `X-CertMate-API-Version`. It became
**2.1** when the async issuance endpoints gained `ISSUANCE_QUEUE_FULL`, and
**2.2** when every certificate-info response gained `expired` and
`seconds_left`, and **2.3** when `POST /api/client-certs/ca/reset` was added.

### Codes

Branch on these rather than on the message text, which is written for people
and may be reworded.

| Code | Typical status | Means |
| --- | --- | --- |
| `CERTIFICATE_NOT_FOUND` | 404 | No certificate for that domain on this instance |
| `CERT_FILE_NOT_FOUND` | 404 | The certificate exists but the requested file does not |
| `JOB_NOT_FOUND` | 404 | Unknown async issuance job id |
| `DOMAIN_REQUIRED` | 400 | The request named no domain |
| `INVALID_REQUEST` / `INVALID_FORMAT` | 400 | The body failed validation |
| `INVALID_FILE` / `INVALID_FILE_TYPE` / `INVALID_PATH` | 400 | Bad file argument |
| `INVALID_KEY_FORMAT` / `KEY_FORMAT_NOT_APPLICABLE` / `KEY_CONVERSION_FAILED` | 400/422 | Key export could not be produced in the requested form |
| `AUTO_RENEW_FLAG_REQUIRED` | 400 | `enabled` missing from an auto-renew update |
| `INCOMPATIBLE_PARAMETERS` | 400 | Two request fields contradict each other |
| `AUTH_HEADER_MISSING` / `INVALID_AUTH_FORMAT` / `INVALID_AUTH_SCHEME` / `INVALID_TOKEN` / `AUTH_ERROR` | 401 | Authentication failed, and which part |
| `SESSION_REQUIRED` | 401 | The endpoint needs a browser session, not a bearer token |
| `INSUFFICIENT_ROLE` | 403 | Authenticated, but the role is too low |
| `DOMAIN_OUT_OF_SCOPE` | 403 | The API key is scoped to other domains |
| `PRIVKEY_REQUIRES_OPERATOR` | 403 | Private-key download needs operator or above |
| `CERTIFICATE_ALREADY_EXISTS` | 409 | A certificate for that domain is already managed |
| `DOMAIN_OPERATION_IN_PROGRESS` | 409 | Another create/renew holds this domain's lock |
| `METADATA_SCHEMA_DOWNGRADE` | 409 | `metadata.json` was written by a newer build; the write was refused |
| `DOMAIN_NOT_IN_SETTINGS` | 409 | The certificate exists on disk but no settings entry names it |
| `ACME_RATE_LIMITED` | 422 | The CA refused because a rate limit was reached — waiting is the fix, retrying is the cause |
| `CERTIFICATE_CREATION_FAILED` / `CERTIFICATE_REISSUE_FAILED` / `CERTIFICATE_REISSUE_REJECTED` | 422 | Issuance was attempted and refused |
| `RENEWAL_CONFIG_BROKEN` | 422 | certbot's renewal config for this lineage no longer resolves; reissue |
| `DNS_ACCOUNT_NOT_CONFIGURED` | 422 | The DNS account this certificate uses is gone from settings |
| `ISSUANCE_QUEUE_FULL` | 429 | Too much async issuance is already queued or running; the body carries the depth and the limit |
| `ADOPTION_UNAVAILABLE` | 503 | Discovery/adoption is not available on this build |
| `ASYNC_ISSUANCE_DISABLED` | 503 | Async issuance is switched off |
| `CERTIFICATE_CREATION_ERROR` / `CERTIFICATE_RENEWAL_ERROR` / `CERTIFICATE_REISSUE_ERROR` / `CERTIFICATE_DOWNLOAD_ERROR` / `AUTO_RENEW_UPDATE_FAILED` | 500 | The operation failed unexpectedly; the server log has the cause |
| `INTERNAL_SERVER_ERROR` | 500 | An exception escaped a handler |
| `NOT_FOUND`, `METHOD_NOT_ALLOWED`, `REQUEST_ENTITY_TOO_LARGE`, … | 4xx | Refused by the HTTP layer; the symbol is the status name |

### Common HTTP Status Codes

| Code | Meaning             | Example                   |
| ---- | ------------------- | ------------------------- |
| 200  | Success             | Certificate listed        |
| 201  | Created             | Certificate created       |
| 400  | Bad Request         | Missing required field    |
| 401  | Unauthorized        | Invalid/missing token     |
| 403  | Forbidden           | Role or domain scope      |
| 404  | Not Found           | Certificate doesn't exist |
| 409  | Conflict            | Operation already running |
| 422  | Unprocessable       | Issuance refused by the CA |
| 429  | Too Many Requests   | Rate limit exceeded       |
| 500  | Server Error        | Internal error            |
| 503  | Service Unavailable | OCSP/CRL not available    |

### Example Error

```bash
curl http://localhost:8000/api/client-certs/invalid-id \
 -H "Authorization: Bearer TOKEN"

# Response
{
 "error": "Certificate not found: invalid-id",
 "message": "Certificate not found: invalid-id",
 "code": "NOT_FOUND",
 "status": 404
}
```

---

## Audit Logging

Certificate-lifecycle operations and configuration/access-control changes are
recorded to an audit log. This includes the security-relevant lifecycle paths —
successful and failed create, renew, reissue, deploy, and auto-renew toggles,
plus **unattended (scheduler-driven) renewals** — each attributed to the actor
that performed it and the trigger that caused it.

### Log format

The audit log is written to `logs/audit/certificate_audit.log`. Each line is a
standard Python log line whose message is the JSON audit entry:

```
2026-06-15 18:00:00 - certmate.audit - INFO - {"timestamp": "...", ...}
```

To recover the JSON, split each line on the literal ` - INFO - ` and parse the
remainder. Note two time bases: the line prefix timestamp is **local** server
time, while the JSON `timestamp` field is **UTC** (ISO-8601). Read it live with:

```bash
tail -f logs/audit/certificate_audit.log
```

### Entry shape

```json
{
  "timestamp": "2026-06-15T18:00:00.000000+00:00",
  "operation": "renew",
  "resource_type": "certificate",
  "resource_id": "api.example.com",
  "status": "success",
  "user": "api_key:renew-bot",
  "ip_address": "10.0.0.9",
  "details": {"force": false},
  "error": null,
  "actor": {
    "kind": "agent",
    "id": "9f2c…",
    "label": "api_key:renew-bot",
    "token_prefix": "cm_1a2b",
    "agent_session": "sess-9f2"
  },
  "trigger": {"cause": "agent"}
}
```

- **`actor.kind`** — `user` (a human session / OIDC login), `api_token` (an API
  key or the legacy global bearer token), `agent` (an API key explicitly flagged
  as an AI/MCP agent — see below), `scheduler` (an unattended renewal job), or
  `system`. It is derived **only from the authenticated identity**.
- **`actor.id` / `token_prefix`** — the stable API key id and token prefix behind
  the action (absent for the legacy global bearer token, which cannot be told
  apart per-caller — prefer scoped keys).
- **`actor.agent_session` / `agent_id`** — the values of the client-supplied
  `X-CertMate-Agent-Session` / `X-CertMate-Agent-Id` headers (the MCP server
  sends them). These are an **informational claim only**: they are recorded for
  correlation but never change `actor.kind`, so a non-agent caller cannot forge
  an `agent` attribution.
- **`trigger.cause`** — `manual`, `api`, `agent`, `scheduled_renewal`, or
  `event`; for scheduled renewals `trigger.job_id` names the job.

To have an agent's actions recorded as `actor.kind="agent"`, create a scoped API
key with `is_agent: true` (a checkbox on Settings → API Keys, or `is_agent` in
`POST /api/keys`) and point the MCP server at it. See the [MCP guide](./mcp.md).

### Reading the audit log over the API

`GET /api/activity?limit=N` returns the most recent entries (admin/viewer,
bounded to 500).

It can also be **narrowed**, by any of `operation`, `resource_type`,
`resource_id`, `user` and `status`:

```bash
# Which users were created while the instance was still in setup mode?
curl -H "Authorization: Bearer $TOKEN" \
  "https://certmate.local/api/activity?operation=create&resource_type=user&user=setup_user"
```

A filter is **not** applied to the tail an unfiltered call would return. The
search walks backwards until it has `limit` matches or reaches the start of the
log, because "matches among the last hundred" would answer "there are none" for
anything older.

The response carries `complete` for exactly that reason:

| `complete` | entries | means |
|---|---|---|
| `true` | empty | there are none — safe to act on |
| `true` | some | all of them, and there are no more |
| `false` | some | it stopped at `limit`; there may be older matches |
| `false` | empty | it could not read the log — **not** "there are none" |

An unfiltered call always reports `complete: true`: the last `limit` entries
*are* the whole answer to "what happened recently".

### Tamper-evidence (hash chain)

Alongside the human-readable log, every entry is appended to a tamper-evident
SHA-256 **hash chain** at `data/audit/certificate_audit.chain.jsonl`. Each record
is `{seq, entry, prev_hash, hash}` where `hash` commits to the entry and the
previous record's hash, and `seq` is a gap-free counter — so any modification,
deletion, or reorder by anyone who cannot recompute the whole chain is
detectable and localizable. It is on by default; disable with
`CERTMATE_AUDIT_CHAIN=0`.

**Verify from the API:** `GET /api/audit/verify` (admin) returns the verifier
result and HTTP `200` when intact or `409` when broken:

```json
{"ok": true, "count": 128, "first_seq": 0, "last_seq": 127, "head_hash": "5ee1…", "reason": "intact"}
```

**Verify off-box:** the standalone verifier depends only on the Python standard
library, so an auditor can run it without installing or trusting CertMate:

```bash
python -m modules.core.audit_verify data/audit/certificate_audit.chain.jsonl
# OK: audit chain intact (128 entries, seq 0..127)
# or: FAIL: audit chain broken at seq 42: hash mismatch at seq 42: entry was modified
```

Exit code `0` intact, `1` broken (with the offending `seq` and reason), `2`
missing/unreadable.

### Signed export bundle (third-party verifiable)

The instance holds an Ed25519 signing key, persisted at `data/.audit_signing_key`
(generated on first run, `0600`; override with `AUDIT_SIGNING_KEY_FILE` to hold
it off-box). Its public identity is exposed at `GET /api/audit/public-key`
(admin): `{algorithm, public_key_pem, fingerprint}`. The chain head is signed
into periodic checkpoints (`certificate_audit.checkpoints.jsonl`).

`GET /api/audit/export` (admin, optional `?from_seq`/`?to_seq`) returns a signed,
self-verifying bundle — `{manifest, entries, bundle_signature}`. The manifest
pins the instance fingerprint, public key, seq range and `head_hash`; the
signature is over the canonical manifest, which (via `head_hash`) transitively
commits to every entry. An auditor verifies it **off the box** without running
or trusting CertMate, optionally pinning the key out of band:

```bash
python -m modules.core.audit_verify --bundle bundle.json --pubkey instance.pem
# OK: audit bundle intact and signed (128 entries, seq 0..127; signed by 0m2V5lDmnkPWOUHX)
```

The verifier checks the chain structure, that the manifest matches the entries,
the Ed25519 signature, and that the fingerprint matches the (optionally pinned)
public key.

**Partial slices.** A full export starts at the genesis and is
`format_version: 1`. A slice that starts mid-chain (`?from_seq=N` past the first
entry) is `format_version: 2` and additionally carries `anchor_prev_hash` /
`anchor_seq` in the manifest — the predecessor hash its first entry continues
from — so the fragment can be verified even though it has no genesis. The anchor
is inside the signed manifest, so the signature attests it. The verifier reports
such a bundle as a **partial slice** and names the anchor seq: it proves the
entries from the anchor forward are authentic and ordered, and proves nothing
about what came before. Verifiers older than v2.23.0 report `unsupported bundle
format_version 2` for an anchored slice; full exports remain byte-compatible
with them.

> **Threat-model honesty.** The chain + signature detect any interior
> modification, deletion, or reorder, and tie an export to this instance's
> public key — for anyone who does not hold the signing key. They do **not**
> bind the operator, who holds the key and could re-sign a rewritten chain, and
> tail truncation is only caught by comparing exports over time (a later export
> with fewer entries) or against an externally held checkpoint. Fully
> constraining the operator requires shipping the signed checkpoints to an
> external append-only sink — opt-in external anchoring, a planned follow-up not
> yet shipped. See [compliance.md](./compliance.md).

---

## Certificate Types

### API mTLS

For API client authentication via mutual TLS.

```
cert_usage: "api-mtls"
```

### VPN

For VPN client authentication.

```
cert_usage: "vpn"
```

### Custom Usage Types

You can use any custom usage type string:

```
cert_usage: "custom-application"
```

---

## Best Practices

### Security

1. **Protect Your Token**
 - Keep tokens secret
 - Rotate tokens regularly
 - Use HTTPS in production

2. **Certificate Management**
 - Enable auto-renewal
 - Monitor expiration dates
 - Review audit logs regularly
 - Revoke compromised certs immediately

3. **Rate Limiting**
 - Respect rate limits
 - Implement exponential backoff
 - Batch operations when possible

### Performance

1. **Use Batch Operations**
 - Import multiple certs at once
 - Reduces API calls
 - Better error reporting

2. **Filter Results**
 - Use query parameters
 - Filter by usage or status
 - Reduces data transfer

3. **Cache When Appropriate**
 - Cache certificate metadata
 - Refresh periodically
 - Check expiration locally

---


---

<div align="center">

[← Back to Documentation](./README.md) • [Quick Start →](./guide.md) • [Architecture →](./architecture.md)

</div>
