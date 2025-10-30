# 📡 CertMate Client Certificates - API Reference

## Overview

The CertMate Client Certificates API provides REST endpoints for complete certificate management with authentication, rate limiting, and audit logging.

**Base URL**: `http://localhost:5000/api`
**Authentication**: Bearer Token (required on all endpoints)
**Content-Type**: `application/json`

---

## Authentication

All API endpoints require Bearer token authentication.

### Header Format

```
Authorization: Bearer YOUR_TOKEN
```

### Example Request

```bash
curl -X GET http://localhost:5000/api/client-certs \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json"
```

---

## Rate Limiting

API endpoints have rate limits to prevent abuse:

| Endpoint | Limit | Per |
|----------|-------|-----|
| General | 100 | minute |
| Create Certificate | 30 | minute |
| Batch Operations | 10 | minute |
| OCSP Status | 200 | minute |
| CRL Download | 60 | minute |

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

### Certificate Management

#### 1. Create Certificate

**Endpoint**: `POST /client-certs/create`

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
curl -X POST http://localhost:5000/api/client-certs/create \
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

**Endpoint**: `GET /client-certs`

List all client certificates with optional filtering.

**Query Parameters**:
- `usage` (optional) - Filter by usage type (e.g., `api-mtls`)
- `revoked` (optional) - Filter by status (`true` or `false`)
- `search` (optional) - Search in common name

**Response** (200 OK):
```json
{
  "certificates": [
    {
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
curl http://localhost:5000/api/client-certs \
  -H "Authorization: Bearer TOKEN"

# Filter by usage type
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
  -H "Authorization: Bearer TOKEN"

# List only revoked
curl "http://localhost:5000/api/client-certs?revoked=true" \
  -H "Authorization: Bearer TOKEN"

# Search by common name
curl "http://localhost:5000/api/client-certs?search=user1" \
  -H "Authorization: Bearer TOKEN"
```

---

#### 3. Get Certificate Details

**Endpoint**: `GET /client-certs/<identifier>`

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
curl http://localhost:5000/api/client-certs/cert-001 \
  -H "Authorization: Bearer TOKEN"
```

---

#### 4. Download Certificate Files

**Endpoint**: `GET /client-certs/<identifier>/download/<type>`

Download certificate, private key, or CSR file.

**Parameters**:
- `identifier` - Certificate ID
- `type` - File type: `crt`, `key`, or `csr`

**Response** (200 OK):
- Content-Type: `application/octet-stream`
- File attachment with proper naming

**Examples**:
```bash
# Download certificate
curl http://localhost:5000/api/client-certs/cert-001/download/crt \
  -H "Authorization: Bearer TOKEN" \
  -o certificate.crt

# Download private key
curl http://localhost:5000/api/client-certs/cert-001/download/key \
  -H "Authorization: Bearer TOKEN" \
  -o private.key

# Download CSR
curl http://localhost:5000/api/client-certs/cert-001/download/csr \
  -H "Authorization: Bearer TOKEN" \
  -o request.csr
```

---

#### 5. Revoke Certificate

**Endpoint**: `POST /client-certs/<identifier>/revoke`

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
curl -X POST http://localhost:5000/api/client-certs/cert-001/revoke \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "compromised"
  }'
```

---

#### 6. Renew Certificate

**Endpoint**: `POST /client-certs/<identifier>/renew`

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
curl -X POST http://localhost:5000/api/client-certs/cert-001/renew \
  -H "Authorization: Bearer TOKEN"
```

---

#### 7. Get Statistics

**Endpoint**: `GET /client-certs/stats`

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
curl http://localhost:5000/api/client-certs/stats \
  -H "Authorization: Bearer TOKEN"
```

---

#### 8. Batch Import Certificates

**Endpoint**: `POST /client-certs/batch`

Create multiple certificates from CSV data in single request.

**Request**:
```json
{
  "headers": ["common_name", "email", "organization", "cert_usage", "days_valid"],
  "rows": [
    ["user1@example.com", "user1@example.com", "ACME Corp", "api-mtls", "365"],
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
  "certificates": [
    {
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
curl -X POST http://localhost:5000/api/client-certs/batch \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "headers": ["common_name", "email", "organization"],
    "rows": [
      ["user1@example.com", "user1@example.com", "ACME Corp"],
      ["user2@example.com", "user2@example.com", "ACME Corp"]
    ]
  }'
```

---

### OCSP & CRL

#### 9. OCSP Status Query

**Endpoint**: `GET /ocsp/status/<serial_number>`

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
curl http://localhost:5000/api/ocsp/status/12345678 \
  -H "Authorization: Bearer TOKEN"
```

---

#### 10. CRL Distribution

**Endpoint**: `GET /crl/download/<format_type>`

Download Certificate Revocation List.

**Parameters**:
- `format_type` - `pem`, `der`, or `info`

**Response**:
- For `pem` and `der`: File attachment
- For `info`: JSON with CRL metadata

**Examples**:
```bash
# Download CRL in PEM format
curl http://localhost:5000/api/crl/download/pem \
  -H "Authorization: Bearer TOKEN" \
  -o ca.crl

# Download CRL in DER format
curl http://localhost:5000/api/crl/download/der \
  -H "Authorization: Bearer TOKEN" \
  -o ca.crl

# Get CRL info
curl http://localhost:5000/api/crl/download/info \
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
  "revoked_serials": [
    12345678,
    87654321
  ]
}
```

---

## Error Handling

### Error Response Format

```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "status": 400
}
```

### Common HTTP Status Codes

| Code | Meaning | Example |
|------|---------|---------|
| 200 | Success | Certificate listed |
| 201 | Created | Certificate created |
| 400 | Bad Request | Missing required field |
| 401 | Unauthorized | Invalid/missing token |
| 404 | Not Found | Certificate doesn't exist |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Server Error | Internal error |
| 503 | Service Unavailable | OCSP/CRL not available |

### Example Error

```bash
curl http://localhost:5000/api/client-certs/invalid-id \
  -H "Authorization: Bearer TOKEN"

# Response
{
  "error": "Certificate not found: invalid-id",
  "code": 404,
  "status": 404
}
```

---

## Audit Logging

All API requests are logged for audit purposes.

### Logged Information

- Timestamp
- Operation (create, revoke, download, etc.)
- Resource ID
- User/IP address
- Status (success/failure)
- Response time
- Error details (if any)

### Accessing Audit Logs

```bash
tail -f logs/audit/certificate_audit.log
```

Each entry is JSON formatted for easy parsing:
```json
{
  "timestamp": "2024-10-30T18:00:00Z",
  "operation": "create",
  "resource_type": "certificate",
  "resource_id": "cert-001",
  "status": "success",
  "user": "admin@example.com",
  "ip_address": "192.168.1.1",
  "details": {
    "common_name": "user@example.com",
    "usage": "api-mtls"
  },
  "error": null
}
```

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

## Webhook Integration (Future)

Coming in v1.1:
- Certificate expiration notifications
- Revocation alerts
- Auto-renewal status
- Rate limit notifications

---

<div align="center">

[← Back to Documentation](./README.md) • [Quick Start →](./guide.md) • [Architecture →](./architecture.md)

</div>
