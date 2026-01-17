# CertMate Certificate Management Architecture Analysis

## Executive Summary

CertMate is a modern SSL/TLS certificate management system with a modular, extensible architecture designed for multi-cloud environments. The current implementation focuses on **server-side certificates (Domain Validation certificates)** through Let's Encrypt, DigiCert ACME, and Private CAs. The architecture is well-positioned to support client certificates with minimal modifications.

---

## 1. Current Certificate Storage and Management

### 1.1 Storage Model

CertMate employs a **dual-storage approach**:

1. **Primary: Pluggable Storage Backends**
 - **Local Filesystem** (default): Certificates stored in `certificates/{domain}/` with proper file permissions (600 for private keys, 644 for certs)
 - **Azure Key Vault**: Enterprise secret management with HSM protection
 - **AWS Secrets Manager**: Scalable cloud-native secret storage
 - **HashiCorp Vault**: Industry-standard secret management system
 - **Infisical**: Open-source modern secret management

2. **Metadata Storage**
 - JSON-based metadata file (`metadata.json`) alongside certificate files
 - Contains DNS provider info, creation timestamp, staging flag, account ID
 - Tracked across all storage backends

### 1.2 Certificate File Organization on Disk

```
certificates/
 example.com/
 cert.pem # Server certificate
 chain.pem # Intermediate certificates
 fullchain.pem # cert + chain (required by many apps)
 privkey.pem # Private key (600 permissions)
 metadata.json # Certificate metadata
 live/
 example.com/ # Certbot's symlinks (resolved before storage)
 work/ # Certbot working directory
 logs/ # Certbot logs
```

**Key Design Principle**: Symlinks are resolved and actual files copied to parent directory for storage backend compatibility.

---

## 2. Certificate Metadata Structure

The system tracks comprehensive metadata for each certificate:

```json
{
 "domain": "example.com",
 "dns_provider": "cloudflare",
 "created_at": "2025-01-15T10:30:00.000000",
 "renewed_at": "2025-10-15T10:30:00.000000", // Optional
 "email": "admin@example.com",
 "staging": false,
 "account_id": "production",
 "certificate_type": "DV", // Currently only DV for server certs
 "inferred": false
}
```

**Metadata Usage**:
- Determines which DNS provider credentials to use for renewal
- Tracks certificate lifecycle
- Identifies certificate source and configuration

---

## 3. Certificate API Exposure

### 3.1 REST API Endpoints (Flask-RESTX)

**Core Certificate Endpoints**:
```
GET /api/certificates # List all certificates
POST /api/certificates # Create new certificate
GET /api/certificates/<domain> # Get certificate info
POST /api/certificates/<domain>/renew
GET /api/certificates/<domain>/download # ZIP download
```

**API Response Model**:
```json
{
 "domain": "example.com",
 "exists": true,
 "expiry_date": "2026-01-15 10:30:00",
 "days_left": 350,
 "days_until_expiry": 350,
 "needs_renewal": false,
 "dns_provider": "cloudflare"
}
```

### 3.2 Web Interface Endpoints

**Web-based Operations**:
```
GET /api/web/certificates # List certificates
POST /api/web/certificates/create # Create (async background task)
GET /api/web/certificates/<domain>/download
POST /api/web/certificates/<domain>/renew # Async background task
```

### 3.3 File Download Endpoints

**Direct Download**:
```
GET /<domain>/tls # Download fullchain.pem
GET /api/certificates/<domain>/download # Download as ZIP
```

---

## 4. Current UI/Web Interface Structure

### 4.1 Pages

1. **Dashboard (`/` - index.html)**
 - List all certificates with status
 - Shows domain, expiry date, days left, needs renewal status
 - DNS provider information
 - Create new certificate form
 - Renew/Download buttons per certificate

2. **Settings (`/settings` - settings.html)**
 - Email configuration
 - Default DNS provider selection
 - Multi-account management per provider
 - CA provider configuration
 - Storage backend configuration
 - Auto-renewal toggle

3. **Help (`/help` - help.html)**
 - Documentation and quick reference

### 4.2 Create Certificate Form (index.html)

**Current Form Fields**:
- Domain Name (text input, wildcard support)
- Certificate Authority (dropdown: Let's Encrypt, DigiCert, Private CA)
- DNS Provider (dropdown with 19+ providers)
- Account Selection (when multi-account configured)

**Missing for Client Certificates**:
- Certificate type selection
- Key usage specification
- Client certificate specific fields (CN, OU, etc.)
- Key size/algorithm selection

---

## 5. Certificate File Organization Details

### 5.1 File Naming Convention

Currently standardized on Let's Encrypt's Certbot output:
- `cert.pem` - Server certificate only
- `chain.pem` - Intermediate CA chain
- `fullchain.pem` - cert + chain (common app requirement)
- `privkey.pem` - Private key (RSA 2048-bit from Certbot)

### 5.2 Storage Backend Implementation

Each backend implements `CertificateStorageBackend` ABC:

```python
class CertificateStorageBackend(ABC):
 def store_certificate(domain, cert_files, metadata) -> bool
 def retrieve_certificate(domain) -> (files_dict, metadata_dict)
 def list_certificates() -> List[domains]
 def delete_certificate(domain) -> bool
 def certificate_exists(domain) -> bool
 def get_backend_name() -> str
```

**Backend Selection**: Determined by `settings.json` `certificate_storage.backend` field.

---

## 6. Current Certificate Type and Key Usage Support

### 6.1 Supported Certificate Types

**Current Implementation**:
- **DV (Domain Validation)** - Only type supported
- Configured in CA provider definitions:
 - Let's Encrypt: `['DV']`
 - DigiCert: `['DV', 'OV', 'EV']` (only DV fully implemented)
 - Private CA: `['Private']`

### 6.2 Key Usage Constraints

**Current Limitations**:
- **Fixed to server-side TLS**: `key_usage` hardcoded in Certbot
- **Key Type**: Always RSA via Certbot defaults
- **Key Size**: Certbot default (typically 2048-bit RSA)
- **Extended Key Usage**: serverAuth only (no clientAuth)

**Evidence from Code**:
- No `keyUsage` extension control in `certificates.py`
- No `extendedKeyUsage` specification for client auth
- No client certificate-specific metadata fields

---

## 7. Database/Storage Structure for Metadata

### 7.1 Metadata Storage Strategy

1. **Local Filesystem Backend**:
 - `metadata.json` file per domain
 - Stored alongside certificate files
 - File-based, not database

2. **Remote Backends** (Azure/AWS/Vault):
 - Metadata stored as JSON string in secret
 - Combined with cert files in single secret per domain
 - Secret naming: `certmate/certificates/{domain}`

### 7.2 Settings Persistence

**Single Source of Truth**: `data/settings.json`

```json
{
 "email": "admin@example.com",
 "domains": ["example.com", "*.example.com"],
 "auto_renew": true,
 "dns_provider": "cloudflare",
 "dns_providers": {
 "cloudflare": {
 "accounts": {
 "production": {"api_token": "..."},
 "staging": {"api_token": "..."}
 }
 }
 },
 "ca_providers": { // Optional, auto-populated
 "letsencrypt": {...},
 "digicert": {...}
 },
 "certificate_storage": {...}
}
```

### 7.3 Multi-Account Support Structure

DNS Provider Configuration:
```json
"dns_providers": {
 "cloudflare": {
 "accounts": {
 "production": {"api_token": "prod-token"},
 "staging": {"api_token": "staging-token"},
 "dr": {"api_token": "dr-token"}
 }
 }
}
```

CA Provider Configuration:
```json
"ca_providers": {
 "digicert": {
 "accounts": {
 "production": {"eab_key_id": "...", "eab_hmac_key": "..."},
 "staging": {"eab_key_id": "...", "eab_hmac_key": "..."}
 }
 }
}
```

---

## 8. Certificate Request/Creation Flow

### 8.1 Creation Process (Sequence)

```
1. User Submits Form (domain, CA provider, DNS provider, account)
 ↓
2. Validate Inputs
 - Domain format check
 - Email required check
 - CA provider availability
 - DNS provider account existence
 ↓
3. Get DNS Configuration
 - Resolve account ID if not specified
 - Load account credentials from settings
 - Validate account config exists
 ↓
4. Get CA Configuration
 - Load CA provider account config
 - Prepare EAB credentials if required (DigiCert)
 - Get ACME server URL (production or staging)
 ↓
5. Create Certificate Directory
 - mkdir -p certificates/{domain}
 - Create work/ and logs/ subdirectories
 ↓
6. Build Certbot Command
 - Base command: certbot certonly --non-interactive
 - Add CA provider specifics (--server, --eab-kid, --eab-hmac-key)
 - Add DNS plugin (--{dns_provider}, --{dns_provider}-credentials)
 - Add propagation timeout
 ↓
7. Create DNS Credentials File
 - Provider-specific credential file creation
 - Temporary file for certbot use
 - Secure permissions (600)
 ↓
8. Execute Certbot
 - Run with 30-minute timeout
 - Capture stdout/stderr
 - Clean up credentials file
 - Clean up environment variables (Route53)
 ↓
9. Handle Certbot Success
 - Resolve symlinks in live/ directory
 - Copy actual certificate files to domain root
 - Store in configured backend
 ↓
10. Save Metadata
 - Create metadata.json with DNS provider info
 - Store alongside certificate files
 - Update in backend
 ↓
11. Return Success Response
 - Return domain, DNS provider, duration
```

### 8.2 Key Manager Classes

**CertificateManager** (`modules/core/certificates.py`):
- `create_certificate(domain, email, dns_provider, dns_config, account_id, ca_provider, ca_account_id, staging)`
- `renew_certificate(domain)`
- `get_certificate_info(domain)`
- `check_renewals()` - Auto-renewal task

**CAManager** (`modules/core/ca_manager.py`):
- `build_certbot_command()` - Constructs certbot with CA-specific args
- `get_ca_config(ca_provider, account_id)`
- `requires_eab(ca_provider)`
- `get_eab_credentials(ca_provider, account_config)`

**DNSManager** (`modules/core/dns_providers.py`):
- `get_dns_provider_account_config(provider, account_id)`
- `list_dns_provider_accounts(provider)`
- `create_dns_account(provider, account_id, config)`

### 8.3 Renewal Process

**Auto-Renewal Trigger**: `check_renewals()` runs via APScheduler
- Checks all domains in settings
- Gets certificate info for each
- Compares against `renewal_threshold_days` (default 30)
- Executes renewal if needed

**Renewal Command**:
```bash
certbot renew --cert-name {domain} --quiet \
 --config-dir {domain_dir} \
 --work-dir {domain_dir}/work \
 --logs-dir {domain_dir}/logs
```

---

## 9. Architecture Extensibility Assessment for Client Certificates

### 9.1 Strong Points for Extension

1. **Modular Storage Backend System**
 - Abstract `CertificateStorageBackend` class
 - Easy to add new storage types
 - Works seamlessly with new certificate types

2. **Multi-Account Support**
 - Infrastructure exists for account-per-environment
 - Can support different CA/DNS configs per cert type

3. **Pluggable CA Providers**
 - CAManager handles multiple ACME endpoints
 - Can add client-cert specific ACME flows
 - Support for custom ACME servers (Private CA)

4. **Metadata System**
 - Flexible JSON metadata per certificate
 - Can extend with certificate type, key usage, etc.
 - Already captured alongside cert files

5. **API Design**
 - RESTful endpoints
 - Model-based validation (Flask-RESTX)
 - Easy to extend with new resource classes

6. **Configuration Structure**
 - JSON-based settings (easy to extend)
 - Per-domain and per-provider configs
 - Environment variable support

### 9.2 Areas Requiring Modification

1. **Certificate Type Support**
 - Need to add `certificate_type` to metadata
 - Extend API models to include type field
 - Add UI controls for certificate type selection

2. **Certbot Integration**
 - Client certs may not work with Certbot's default plugins
 - Might need custom ACME client or wrapper
 - Certbot assumes server certificate defaults (key size, algorithm)

3. **Key Usage/Extended Key Usage**
 - No current mechanism for specifying keyUsage extensions
 - Certbot doesn't support custom extensions directly
 - Might need post-processing of certificates

4. **Directory Structure**
 - Client cert storage may need different naming convention
 - Could use `client-certificates/{identifier}/` vs `certificates/{domain}/`
 - Metadata schema needs certificate type awareness

5. **Web UI**
 - Currently domain-centric
 - Client certs might use different identifiers (CN, serial, etc.)
 - Form fields and display logic need updates

6. **Renewal Logic**
 - Currently domain-based expiry checking
 - Client cert identifiers might differ
 - Need flexible renewal trigger mechanism

---

## 10. Current Limitations for Client Certificate Support

### 10.1 Fundamental Issues

1. **Certbot Limitation**
 - Certbot is designed for server certificates (TLS hosts)
 - DNS-01 challenge appropriate for server certs only
 - Client certs don't own DNS domains
 - Would need different challenge mechanism or manual issuance

2. **ACME Protocol Limitation (for client certs)**
 - ACME (RFC 8555) designed for server authentication
 - DNS-01 challenge not applicable to client certs
 - Some CAs support "device" certificates via proofing

3. **Certificate Identifier Mismatch**
 - Current system: domains → certificate files
 - Client certs: serial numbers, CNs, identifiers
 - Directory/naming convention incompatible

4. **Metadata Schema**
 - No fields for client cert-specific info (client type, permissions, etc.)
 - No revocation tracking per client cert
 - No serial number management

5. **Storage Organization**
 - One certificate per domain design
 - Client certs might be N certificates per entity
 - Would need to rethink storage organization

---

## 11. Recommended Architecture for Client Certificates

### 11.1 Proposed Additions

1. **New Certificate Type Structure**
 ```json
 {
 "domain": "example.com", // Keep for server certs
 "certificate_identifier": "unique-id", // For client certs
 "certificate_type": "server|client|device|iot",
 "key_usage": {
 "key_cert_sign": false,
 "crl_sign": false,
 "digital_signature": true,
 "non_repudiation": false,
 "key_encipherment": true,
 "data_encipherment": false,
 "key_agreement": false
 },
 "extended_key_usage": ["serverAuth", // For server certs
 "clientAuth" // For client certs
 ],
 "subject": {
 "CN": "identifier",
 "O": "organization",
 "OU": "unit",
 "C": "country"
 }
 }
 ```

2. **Separate Storage Paths**
 ```
 certificates/
 server/ # Server certificates
 example.com/
 cert.pem
 privkey.pem
 metadata.json
 
 client/ # Client certificates
 {identifier}/
 cert.pem
 privkey.pem
 csr.pem # Certificate signing request
 metadata.json
 ```

3. **Extended Metadata for Client Certs**
 ```json
 {
 "certificate_type": "client",
 "client_identifier": "device-001",
 "issuance_method": "manual|acme|csr",
 "issuer_ca": "private_ca",
 "revoked": false,
 "revocation_date": null,
 "serial_number": "1234567890ABCDEF",
 "key_algorithm": "RSA|ECDSA",
 "key_size": 2048,
 "public_key_hash": "sha256:..."
 }
 ```

4. **New API Endpoints**
 ```
 # Server certificates (existing)
 GET /api/certificates
 POST /api/certificates
 
 # Client certificates (new)
 GET /api/client-certificates
 POST /api/client-certificates
 GET /api/client-certificates/<identifier>
 PUT /api/client-certificates/<identifier>
 DELETE /api/client-certificates/<identifier>
 POST /api/client-certificates/<identifier>/revoke
 GET /api/client-certificates/<identifier>/download
 
 # CSR operations (new)
 POST /api/client-certificates/csr/create
 POST /api/client-certificates/csr/<id>/submit
 ```

5. **Issuance Methods**
 - **Manual CSR Upload**: Admin uploads CSR, signed by CA
 - **Direct Issuance**: CA provider issues directly
 - **ACME (future)**: If CA supports ACME for client certs
 - **Root Cert Signing**: Self-sign within private CA

### 11.2 Implementation Strategy

1. **Phase 1: Infrastructure** (No breaking changes)
 - Add `certificate_type` field to metadata
 - Create `client_certificates/` storage path
 - Extend StorageManager for type-aware operations
 - Add certificate type to API models

2. **Phase 2: Client Cert Management**
 - Create ClientCertificateManager class
 - Implement CSR creation and submission
 - Add certificate signing workflows
 - Support manual cert upload

3. **Phase 3: Web UI Updates**
 - Add certificate type toggle
 - Create client cert management tab
 - Add CSR generation interface
 - Add revocation management

4. **Phase 4: Advanced Features**
 - Certificate chain building
 - Batch client cert issuance
 - ACME support (if applicable)
 - Audit logging for client certs

---

## Conclusion

CertMate's architecture is **well-designed and extensible** for client certificate support. The modular backend system, metadata infrastructure, and multi-account support provide a strong foundation. The main challenges are:

1. **Certification method**: Certbot won't work; need direct CA API or manual signing
2. **Identifier model**: Shift from domain-centric to generic identifiers
3. **Storage organization**: Add certificate type awareness
4. **Key usage configuration**: Extend metadata with EKU/key usage fields

The recommended approach is incremental:
1. Separate storage paths for server vs client certs
2. Extend metadata schema for cert type awareness
3. Add ClientCertificateManager for client-specific operations
4. Support manual CSR submission as primary mechanism
5. Gradually add CA-specific issuance methods

**Backward Compatibility**: All changes can be additive, preserving existing server certificate functionality.

