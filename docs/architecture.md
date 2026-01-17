# CertMate Client Certificates - Architecture

## System Overview

```

 Web UI Layer 
 (/client-certificates web dashboard) 

 

 API Layer 
 (/api/client-certs, /api/ocsp, /api/crl) 
 (REST endpoints with Flask-RESTX) 

 

 Managers Layer 
 
 ClientCertificateManager (lifecycle + metadata) 
 OCSPResponder (certificate status queries) 
 CRLManager (revocation list generation) 
 AuditLogger (operation tracking) 
 SimpleRateLimiter (request throttling) 
 

 

 Core Modules Layer 
 
 PrivateCAGenerator (CA management) 
 CSRHandler (CSR validation & creation) 
 ClientCertificateManager (cert operations) 
 OCSPResponder (status responses) 
 CRLManager (revocation lists) 
 AuditLogger (logging) 
 RateLimitConfig/SimpleRateLimiter (limiting) 
 

 

 Cryptography & Storage Layer 
 
 Cryptography Library (OpenSSL) 
 File System Storage (data/certs/) 
 Storage Backends (Azure, AWS, Vault, etc) 
 

```

---

## Core Components

### 1. PrivateCAGenerator (`modules/core/private_ca.py`)

**Purpose**: Generate and manage the self-signed Certificate Authority

**Key Features**:
- Generates 4096-bit RSA keys for CA
- 10-year validity period
- Self-signed certificates with proper extensions
- CA backup and restore functionality
- CRL signing capability

**Files Created**:
- `data/certs/ca/ca.crt` - CA certificate (PEM)
- `data/certs/ca/ca.key` - CA private key (PEM, 0600 permissions)
- `data/certs/ca/ca_metadata.json` - CA metadata
- `data/certs/ca/crl.pem` - Certificate Revocation List

**Key Methods**:
```python
initialize() # Initialize or load existing CA
sign_certificate_request() # Sign a CSR
generate_crl() # Generate CRL from revoked serials
get_crl_pem() # Get CRL in PEM format
```

---

### 2. CSRHandler (`modules/core/csr_handler.py`)

**Purpose**: Validate, parse, and create Certificate Signing Requests

**Key Features**:
- Create new CSRs with private keys (2048 or 4096-bit)
- Validate PEM-encoded CSRs
- Extract CSR information (CN, Org, Email, SAN, etc.)
- Support for Subject Alternative Names (SANs)
- Save CSR and key pairs to disk

**Key Methods**:
```python
create_csr() # Create new CSR with private key
validate_csr_pem() # Validate and load CSR from PEM
get_csr_info() # Extract information from CSR
save_csr_and_key() # Save CSR and key to files
```

---

### 3. ClientCertificateManager (`modules/core/client_certificates.py`)

**Purpose**: Complete lifecycle management of client certificates

**Key Features**:
- Create certificates (with CA-signed or CSR)
- List/filter certificates (by usage, status, search)
- Revoke certificates with audit trail
- Renew certificates (same CN, new serial)
- Auto-renewal scheduling
- Metadata storage (JSON per certificate)
- Support for 30k+ concurrent certificates

**Storage Structure**:
```
data/certs/client/
 api-mtls/ # Certificates for API mTLS
 cert-001/
 cert.crt
 cert.key
 cert.csr
 metadata.json
 vpn/ # Certificates for VPN
 cert-002/
 ...
 other/ # Other usage types
 ...
```

**Metadata Structure** (JSON):
```json
{
 "type": "client_certificate",
 "identifier": "cert-001",
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "country": "US",
 "state": "California",
 "locality": "San Francisco",
 "serial_number": "12345678901234567890",
 "key_usage": ["digitalSignature", "keyEncipherment"],
 "extended_key_usage": ["serverAuth", "clientAuth"],
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
 "renewal_threshold_days": 30,
 "last_renewed_at": null
 }
}
```

**Key Methods**:
```python
create_client_certificate() # Create new certificate
list_client_certificates() # List with optional filters
get_certificate_metadata() # Get cert metadata
get_certificate_file() # Get cert/key/csr file
revoke_certificate() # Revoke with reason
renew_certificate() # Renew certificate
check_renewals() # Auto-renewal check
get_statistics() # Get usage statistics
```

---

### 4. OCSPResponder (`modules/core/ocsp_crl.py`)

**Purpose**: Provide Online Certificate Status Protocol (OCSP) responses

**Key Features**:
- Query certificate status (good/revoked/unknown)
- Generate OCSP responses
- Real-time status lookups
- Support for multiple status types

**Statuses**:
- `good` - Certificate is valid
- `revoked` - Certificate has been revoked
- `unknown` - Certificate not found

**Key Methods**:
```python
get_cert_status() # Get certificate status
generate_ocsp_response() # Generate OCSP response
```

**Response Format**:
```json
{
 "response_status": "successful",
 "certificate_status": "good|revoked|unknown",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z",
 "next_update": null,
 "responder_name": "CertMate OCSP Responder",
 "revocation_time": null,
 "revocation_reason": null
}
```

---

### 5. CRLManager (`modules/core/ocsp_crl.py`)

**Purpose**: Generate and distribute Certificate Revocation Lists

**Key Features**:
- Generate CRL with all revoked certificates
- Distribute in PEM and DER formats
- Store CRL metadata and info
- Automatic CRL updates

**Key Methods**:
```python
get_revoked_serials() # Get revoked certificate serials
update_crl() # Generate/update CRL
get_crl_pem() # Get CRL in PEM format
get_crl_der() # Get CRL in DER format
get_crl_info() # Get CRL metadata
```

---

### 6. AuditLogger (`modules/core/audit.py`)

**Purpose**: Track all certificate operations for compliance and debugging

**Key Features**:
- JSON format logging
- Persistent audit file
- Track operations, users, IP addresses
- Query entries by resource or time

**Log Format**:
```json
{
 "timestamp": "2024-10-30T18:00:00Z",
 "operation": "create|revoke|renew|download|batch_import",
 "resource_type": "certificate|endpoint",
 "resource_id": "cert-001",
 "status": "success|failure|denied",
 "user": "admin@example.com",
 "ip_address": "192.168.1.1",
 "details": {},
 "error": null
}
```

**Log File**: `logs/audit/certificate_audit.log`

**Key Methods**:
```python
log_certificate_created() # Log cert creation
log_certificate_revoked() # Log revocation
log_certificate_renewed() # Log renewal
log_certificate_downloaded() # Log downloads
log_batch_operation() # Log batch operations
log_api_request() # Log API requests
get_recent_entries() # Get latest audit entries
get_entries_by_resource() # Get entries for a resource
```

---

### 7. Rate Limiting (`modules/core/rate_limit.py`)

**Purpose**: Protect API from abuse with request rate limiting

**Configuration**:
- Default: 100 req/min
- Certificate creation: 30 req/min (expensive)
- Batch operations: 10 req/min (very expensive)
- OCSP status: 200 req/min (cheap)
- CRL download: 60 req/min

**Key Classes**:
```python
RateLimitConfig # Configuration holder
SimpleRateLimiter # In-memory limiter
rate_limit_decorator # Flask endpoint decorator
```

**Response on Rate Limit**:
```json
{
 "error": "Rate limit exceeded",
 "message": "Too many requests. Please try again later.",
 "retry_after": 60
}
```

HTTP Status: `429 Too Many Requests`

---

## Data Flow

### Certificate Creation Flow

```
User/API Request
 ↓
ClientCertificateManager.create_client_certificate()
 Generate CSR (or accept provided CSR)
 Sign CSR with private CA
 Create metadata.json
 Store cert/key/csr files
 Log in audit trail
 Return cert data
 ↓
Response to User
```

### Certificate Revocation Flow

```
User/API Request (revoke endpoint)
 ↓
ClientCertificateManager.revoke_certificate()
 Load certificate metadata
 Update revocation status
 Save updated metadata
 Log in audit trail
 Trigger CRL update
 Return success
 ↓
Response to User
```

### OCSP Query Flow

```
Client OCSP Request (serial number)
 ↓
OCSPResponder.get_cert_status()
 Search certificate by serial
 Check revocation status
 Return status (good/revoked/unknown)
 ↓
OCSPResponder.generate_ocsp_response()
 Format OCSP response
 Add timestamps
 Return response
 ↓
Response to Client
```

---

## Storage Architecture

### Directory Structure

```
data/certs/
 ca/ # Certificate Authority
 ca.crt # CA certificate (public)
 ca.key # CA private key (0600)
 ca_metadata.json # CA metadata
 crl.pem # Certificate Revocation List

 client/ # Client certificates
 api-mtls/ # API mTLS certificates
 cert-001/
 cert.crt
 cert.key
 cert.csr
 metadata.json
 ...
 vpn/ # VPN certificates
 ...
 other/ # Other usage types
 ...

 crl/ # CRL storage
 (generated CRLs)
```

### Metadata Files

Each certificate has a `metadata.json` file containing:
- Certificate identification (CN, serial, fingerprint)
- Subject information (Org, email, location)
- Validity dates
- Revocation status and history
- Renewal configuration
- Custom notes

---

## Security Model

### Key Protection

- **File Permissions**: 0600 (read/write for owner only)
- **Key Format**: PEM with OpenSSL Traditional format
- **No Key Encryption**: Keys stored encrypted at REST if using storage backends

### Certificate Signing

- **Signature Algorithm**: SHA256withRSA
- **Key Size**: 4096-bit RSA for CA, 2048/4096-bit for clients
- **Validity**: Configurable (default 1 year for client certs)

### Access Control

- **Authentication**: Bearer token on all API endpoints
- **Authorization**: Token-based (can be extended with roles)
- **Rate Limiting**: Per-endpoint protection

### Audit Trail

- All operations logged with timestamp
- User and IP address tracking
- Immutable audit log file
- Query-able for compliance

---

## Scalability

### Certificate Storage

- **Linear Scalability**: Directory-based storage
- **Capacity**: Tested with 30k+ certificates
- **Performance**: Efficient O(n) directory scans

### API Performance

- **Rate Limiting**: Prevents resource exhaustion
- **Stateless Design**: Can run multiple instances
- **Batch Operations**: Handles 100-30k certs per request

### Auto-Renewal

- **Scheduled**: Daily at 3 AM (configurable)
- **Threshold**: 30 days before expiry (configurable)
- **Graceful**: Continues on errors, logs for review

---

## Deployment Considerations

### Minimum Requirements

- Python 3.9+
- 100MB disk space for CA and initial certificates
- 50MB for audit logs per 1M operations
- Low memory footprint

### Production Recommendations

- Use storage backend (Azure, AWS, Vault) for HA
- Enable audit logging for compliance
- Configure rate limiting based on load
- Regular CRL updates (daily or on revocation)
- Backup CA keys and metadata
- Monitor audit logs for suspicious activity

### High Availability

For multi-instance deployments:
1. Use shared storage backend for certificates
2. Synchronize audit logs to central location
3. Use load balancer with sticky sessions
4. Monitor rate limit counters across instances

---

## Integration Points

### With CertMate Main System

- Uses existing CertMate storage backends
- Integrated in app.py managers
- Part of Flask-RESTX API structure
- Scheduled with APScheduler

### External Systems

- Can export certificates via API
- Can query status via OCSP
- Can retrieve CRL for validation
- Supports webhook/callback integration (future)

---

## Future Extensibility

### Planned Enhancements

1. **CA Password Protection** - Encrypt CA keys with password
2. **Advanced Audit** - Role-based access control
3. **Webhook Notifications** - On certificate events
4. **Certificate Signing** - Accept CSRs from external sources
5. **Hardware Tokens** - PKCS#11 support for HSMs

### Extension Points

1. **Storage Backends** - Already supports multiple backends
2. **Audit Sinks** - Can send audit logs to external systems
3. **API Middleware** - Add custom authentication/authorization
4. **Notification System** - Integrate with alerting systems

---

## Monitoring & Observability

### Key Metrics

- Certificate counts (total, active, revoked, expiring soon)
- API endpoint performance
- Rate limit violations
- Audit log volume
- Auto-renewal success/failure rate

### Health Checks

- CA availability
- Audit logger functionality
- Rate limiter responsiveness
- CRL generation status

---

<div align="center">

[← Back to Documentation](./README.md) • [Quick Start →](./guide.md) • [API Reference →](./api.md)

</div>
