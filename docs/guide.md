# CertMate Client Certificates - User Guide

## Getting Started

### Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run CertMate
python app.py

# 3. Open dashboard
# Navigate to: http://localhost:8000/client-certificates
```

### First Steps

1. **Generate CA** - Automatically created on first run
2. **Access Dashboard** - Go to `/client-certificates`
3. **Create Certificate** - Use the web form or API
4. **Download Files** - Get cert, key, and CSR

---

## Web Dashboard

### Dashboard Features

**URL**: `http://localhost:8000/client-certificates`

#### Statistics Panel
- Total certificates
- Active count
- Revoked count
- Breakdown by usage type

#### Certificate Table
- List all certificates
- Search by common name
- Filter by usage type
- Filter by status
- Sort by creation date

#### Create Certificate Form

**Form Fields**:
- Common Name (required)
- Email Address
- Organization
- Organizational Unit
- Usage Type (VPN, API-mTLS, etc.)
- Days Valid (default: 365)
- Generate Key (checkbox)
- Notes

**Example**:
```
Common Name: user@example.com
Email: user@example.com
Organization: ACME Corp
Usage Type: api-mtls
Days Valid: 365
```

#### Bulk CSV Import

1. Click "Bulk Import" tab
2. Prepare CSV file with headers:
 ```
 common_name,email,organization,cert_usage,days_valid
 user1@example.com,user1@example.com,ACME Corp,api-mtls,365
 user2@example.com,user2@example.com,ACME Corp,vpn,365
 ```
3. Drag and drop or click to upload
4. Review preview
5. Click "Import"

---

## Common Tasks

### Create a Single Certificate

#### Via Web Dashboard

1. Go to `/client-certificates`
2. Fill in the "Create Certificate" form
3. Click "Create"
4. Certificate appears in the table

#### Via API

```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true
 }'
```

---

### Download Certificate Files

#### Via Web Dashboard

1. Find certificate in the table
2. Click the "Download" icon ()
3. Select file type:
 - **CRT** - Certificate (public)
 - **KEY** - Private key (keep secret)
 - **CSR** - Certificate Signing Request

#### Via API

```bash
# Download certificate
curl http://localhost:8000/api/client-certs/CERT_ID/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o my-cert.crt

# Download key
curl http://localhost:8000/api/client-certs/CERT_ID/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o my-key.key
```

---

### Revoke a Certificate

#### Via Web Dashboard

1. Find certificate in table
2. Click the "Revoke" button ()
3. Enter revocation reason (optional)
4. Confirm

#### Via API

```bash
curl -X POST http://localhost:8000/api/client-certs/CERT_ID/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "reason": "compromised"
 }'
```

**Revocation Reasons**:
- `compromised` - Key was compromised
- `superseded` - Replaced by new certificate
- `unspecified` - General revocation
- Any custom reason

---

### Renew a Certificate

#### Via Web Dashboard

1. Find certificate in table
2. Click the "Renew" button ()
3. Confirm renewal

#### Via API

```bash
curl -X POST http://localhost:8000/api/client-certs/CERT_ID/renew \
 -H "Authorization: Bearer TOKEN"
```

**Note**: Renewal creates a new certificate with:
- Same common name
- New serial number
- Fresh expiration date
- Original ID updated

---

### List and Filter Certificates

#### Via Web Dashboard

1. Go to certificate table
2. Use "Search" box for common name
3. Use "Usage Type" dropdown to filter
4. Use "Status" dropdown (Active/Revoked)
5. Click "Apply Filters"

#### Via API

```bash
# List all
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filter by usage
curl "http://localhost:8000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Filter by status
curl "http://localhost:8000/api/client-certs?revoked=false" \
 -H "Authorization: Bearer TOKEN"

# Search
curl "http://localhost:8000/api/client-certs?search=user@" \
 -H "Authorization: Bearer TOKEN"
```

---

### Check Certificate Status (OCSP)

#### Via API

```bash
curl http://localhost:8000/api/ocsp/status/SERIAL_NUMBER \
 -H "Authorization: Bearer TOKEN"
```

**Response**:
```json
{
 "certificate_status": "good",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z"
}
```

---

### Get Revocation List (CRL)

#### Download CRL

```bash
# PEM format
curl http://localhost:8000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# DER format
curl http://localhost:8000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl
```

#### Get CRL Info

```bash
curl http://localhost:8000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

---

## Batch Operations

### CSV Format

```csv
common_name,email,organization,cert_usage,days_valid
user1@example.com,user1@example.com,ACME Corp,api-mtls,365
user2@example.com,user2@example.com,ACME Corp,vpn,365
user3@example.com,user3@example.com,ACME Corp,api-mtls,730
```

### Required Columns

- `common_name` - Certificate subject (required)

### Optional Columns

- `email` - Email address
- `organization` - Organization name
- `organizational_unit` - Department name
- `cert_usage` - Usage type
- `days_valid` - Validity in days

### Via Web Dashboard

1. Go to "Bulk Import" tab
2. Upload CSV file
3. Review preview
4. Click "Import All"

### Via API

```bash
curl -X POST http://localhost:8000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "headers": ["common_name", "email", "organization"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
 ["user2@example.com", "user2@example.com", "ACME Corp"],
 ["user3@example.com", "user3@example.com", "ACME Corp"]
 ]
 }'
```

### Import Results

Returns success/failure counts:
```json
{
 "total": 3,
 "successful": 3,
 "failed": 0,
 "errors": [],
 "certificates": [{"identifier": "cert-batch-001", "common_name": "user1@example.com"},
 {"identifier": "cert-batch-002", "common_name": "user2@example.com"},
 {"identifier": "cert-batch-003", "common_name": "user3@example.com"}
 ]
}
```

---

## Certificate Usage Types

### API mTLS

For API client mutual TLS authentication.

```
Usage Type: api-mtls
Typical Validity: 1 year (365 days)
```

### VPN

For VPN client authentication.

```
Usage Type: vpn
Typical Validity: 1-2 years (365-730 days)
```

### Custom Types

You can create certificates for any custom usage:

```
Usage Type: custom-application
Usage Type: internal-service
Usage Type: mobile-app
```

---

## Auto-Renewal

### Configuration

- **Check Time**: Daily at 3 AM
- **Threshold**: 30 days before expiry
- **Action**: Automatic renewal if enabled

### Enabling Auto-Renewal

Auto-renewal is enabled by default. To check status:

```bash
curl http://localhost:8000/api/client-certs/CERT_ID \
 -H "Authorization: Bearer TOKEN"
```

Look for:
```json
{
 "renewal": {
 "renewal_enabled": true,
 "renewal_threshold_days": 30
 }
}
```

### Renewal Behavior

When auto-renewed:
- New certificate created
- Same CN (common name)
- New serial number
- New expiration date
- Original ID remains same
- Old certificate replaced

---

## Troubleshooting

### Common Issues

#### Certificate Creation Failed

**Error**: `Failed to create certificate`

**Solutions**:
1. Check common name is valid
2. Verify all required fields
3. Check CA is initialized
4. Review logs for details

#### File Download Failed

**Error**: `File not found`

**Solutions**:
1. Verify certificate ID exists
2. Check file type (crt, key, csr)
3. Ensure certificate hasn't been deleted
4. Check disk space

#### Rate Limit Exceeded

**Error**: `HTTP 429 Too Many Requests`

**Solutions**:
1. Wait before retrying
2. Use batch operations
3. Implement exponential backoff
4. Check limit for your endpoint

### Checking Logs

View application logs:
```bash
tail -f logs/certmate.log
```

View audit logs:
```bash
tail -f logs/audit/certificate_audit.log
```

---

## Security Best Practices

### Private Keys

- **NEVER** share your private keys
- **NEVER** commit keys to git
- Store keys securely
- Use 0600 file permissions

### Certificates

- Monitor expiration dates
- Renew before expiry
- Revoke compromised certs immediately
- Keep audit logs for compliance

### API Tokens

- Rotate tokens regularly
- Use HTTPS in production
- Don't hardcode tokens
- Use environment variables

### Revocation

Always revoke when:
- Key is compromised
- Certificate is replaced
- User leaves organization
- Service is decommissioned

---

## Performance Tips

### For Large Batches

Use batch operations instead of individual creates:
```bash
# Good: One request for 1000 certs
POST /api/client-certs/batch

# Bad: 1000 requests for 1000 certs
POST /api/client-certs/create × 1000
```

### For Filtering

Filter on the server side:
```bash
# Good: Server filters
GET /api/client-certs?usage=api-mtls

# Bad: Client filters all
GET /api/client-certs
```

### For Monitoring

Use statistics endpoint:
```bash
GET /api/client-certs/stats
```

---

## Support

### Documentation

- [API Reference](./api.md) - All endpoints
- [Architecture](./architecture.md) - System design
- [Changelog](./CHANGELOG.md) - Version history

### Testing

See `test_e2e_complete.py` for usage examples.

---

<div align="center">

[← Back to Documentation](./README.md) • [API Reference →](./api.md) • [Architecture →](./architecture.md)

</div>
