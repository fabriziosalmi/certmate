================================================================================
CERTMATE CERTIFICATE MANAGEMENT ARCHITECTURE - COMPREHENSIVE OVERVIEW
================================================================================

QUICK FACTS:
- Architecture Style: Modular, pluggable, multi-tenant capable
- Primary Language: Python 3.9+ (Flask, Flask-RESTX)
- Storage: Local filesystem default, with 4 cloud backends (Azure, AWS, Vault, Infisical)
- Certificate Authority: Let's Encrypt, DigiCert ACME, Private CA
- DNS Providers: 19+ supported (Cloudflare, AWS Route53, Azure, Google, Digital Ocean, etc.)
- Web Framework: Flask with Tailwind CSS frontend
- API Style: REST (Flask-RESTX with Swagger/OpenAPI)
- Test Coverage: Extensive (modular design with manager classes)
- Current Certificate Type: Server-side TLS only (DV, OV, EV validation types)

================================================================================
1. CERTIFICATE STORAGE MODEL
================================================================================

STORAGE ARCHITECTURE:
┌─────────────────────────────────────────────────────────────────┐
│ StorageManager (configurable via settings.json)                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
├─> LocalFileSystemBackend (default)                             │
│   └─ certificates/{domain}/ directory structure               │
│                                                                │
├─> AzureKeyVaultBackend                                         │
│   └─ Secret per domain in Azure Key Vault                     │
│                                                                │
├─> AWSSecretsManagerBackend                                     │
│   └─ Secret per domain in AWS Secrets Manager                 │
│                                                                │
├─> HashiCorpVaultBackend (v1 and v2 support)                   │
│   └─ Secret per domain in HashiCorp Vault                     │
│                                                                │
└─> InfisicalBackend                                             │
    └─ Secret per domain in Infisical                           │
└─────────────────────────────────────────────────────────────────┘

FILE STRUCTURE (Local Filesystem):
certificates/
├── example.com/
│   ├── cert.pem           ← Server certificate (public)
│   ├── chain.pem          ← Intermediate CA certificates
│   ├── fullchain.pem      ← cert.pem + chain.pem (commonly required)
│   ├── privkey.pem        ← Private key (600 permissions)
│   ├── metadata.json      ← Certificate metadata (see section 2)
│   ├── live/example.com/  ← Certbot symlinks (resolved before storage)
│   ├── work/              ← Certbot working directory
│   └── logs/              ← Certbot logs
├── wildcard.example.com/
│   └── [same structure as above]
└── api.example.org/
    └── [same structure as above]

METADATA STORAGE:
- JSON file stored per certificate
- Same storage backend as certificate files
- Contains certificate lifecycle info
- Keys: domain, dns_provider, created_at, renewed_at, email, staging, account_id

================================================================================
2. CERTIFICATE METADATA TRACKED
================================================================================

Current Metadata Fields:
{
  "domain": "example.com",                    # Primary identifier
  "dns_provider": "cloudflare",               # Which DNS provider was used
  "created_at": "2025-01-15T10:30:00.000000", # ISO timestamp
  "renewed_at": "2025-10-15T10:30:00.000000", # Optional, updated on renewal
  "email": "admin@example.com",               # Certificate contact email
  "staging": false,                           # True if created in staging
  "account_id": "production",                 # Which DNS account was used
  "certificate_type": "DV",                   # Currently only DV (Domain Validation)
  "inferred": false                           # True if metadata was inferred from existing cert
}

MISSING FOR CLIENT CERTIFICATES:
- extended_key_usage (needs clientAuth for client certs)
- key_usage (needs different values for client certs)
- client_identifier (client certs don't use domains)
- serial_number (important for client cert tracking)
- revocation_date (for tracking revoked client certs)
- key_algorithm (to track RSA vs ECDSA)
- key_size (to track 2048, 4096, etc.)

================================================================================
3. CERTIFICATE API EXPOSURE
================================================================================

REST API ENDPOINTS (Flask-RESTX):
GET    /api/health                          Health check
GET    /api/certificates                    List all certificates
POST   /api/certificates                    Create new certificate
GET    /api/certificates/<domain>           Get certificate info
POST   /api/certificates/<domain>/renew     Renew certificate
GET    /api/certificates/<domain>/download  Download as ZIP

WEB API ENDPOINTS (Form-based):
GET    /api/web/certificates                List certificates
POST   /api/web/certificates/create         Create (async, background task)
GET    /api/web/certificates/<domain>/download
POST   /api/web/certificates/<domain>/renew (async, background task)

DIRECT FILE DOWNLOAD:
GET    /<domain>/tls                        Download fullchain.pem

API RESPONSE MODEL:
{
  "domain": "example.com",
  "exists": true,
  "expiry_date": "2026-01-15 10:30:00",
  "days_left": 350,
  "days_until_expiry": 350,                 # Alias for days_left
  "needs_renewal": false,
  "dns_provider": "cloudflare"
}

AUTHENTICATION:
- Bearer token in Authorization header
- Token stored in settings.json as api_bearer_token
- Environment variable override: API_BEARER_TOKEN

================================================================================
4. WEB INTERFACE STRUCTURE
================================================================================

PAGE STRUCTURE:
Dashboard (/)
├─ Create New Certificate Form
│  ├─ Domain Name input
│  ├─ Certificate Authority selector (Let's Encrypt, DigiCert, Private CA)
│  ├─ DNS Provider selector (19+ options)
│  ├─ Account selector (if multi-account configured)
│  └─ Create button
├─ Certificate List Table
│  ├─ Domain
│  ├─ Expiry Date
│  ├─ Days Left (color coded: green/yellow/red)
│  ├─ Needs Renewal status
│  ├─ DNS Provider
│  └─ Actions: Download, Renew, Delete buttons
└─ Status indicators (CA providers supported, DNS plugins available)

Settings Page (/settings)
├─ Basic Configuration
│  ├─ Email address (required)
│  ├─ Default DNS Provider
│  ├─ Auto-renewal toggle
│  └─ Renewal threshold (days)
├─ Multi-Account Management
│  ├─ Per-provider account configuration
│  └─ Per-provider account selection
├─ CA Provider Configuration
│  ├─ Let's Encrypt settings
│  ├─ DigiCert settings (EAB credentials)
│  └─ Private CA settings
└─ Storage Backend Configuration
   ├─ Backend type selector
   └─ Backend-specific credentials

Help Page (/help)
├─ Documentation
├─ API reference
└─ Quick start guides

TECH STACK:
- Frontend: Tailwind CSS, vanilla JavaScript
- Backend: Flask, Flask-RESTX (REST API with Swagger)
- Icons: Font Awesome
- Dark Mode: System preference detection

================================================================================
5. CERTIFICATE FILE ORGANIZATION
================================================================================

DIRECTORY STRUCTURE:
/root/certificates/
├── example.com/                    # One directory per domain
│   ├── cert.pem                    # Server cert only (Not trusted root)
│   ├── chain.pem                   # Intermediate certs (chain for validation)
│   ├── fullchain.pem               # cert + chain (fullchain for most apps)
│   ├── privkey.pem                 # Private key (mode 600)
│   ├── metadata.json               # Certificate metadata
│   ├── live/example.com/           # Certbot's symlink directory
│   │   ├── cert.pem               # -> ../../../archive/example.com/cert1.pem
│   │   ├── chain.pem              # -> ../../../archive/example.com/chain1.pem
│   │   ├── fullchain.pem          # -> ../../../archive/example.com/fullchain1.pem
│   │   └── privkey.pem            # -> ../../../archive/example.com/privkey1.pem
│   ├── archive/example.com/        # Actual certificate files (versioned)
│   │   ├── cert1.pem, cert2.pem, ...
│   │   ├── chain1.pem, chain2.pem, ...
│   │   ├── fullchain1.pem, fullchain2.pem, ...
│   │   └── privkey1.pem, privkey2.pem, ...
│   ├── work/                       # Certbot working directory
│   └── logs/                       # Certbot logs
├── *.example.com/                  # Wildcard domain handling
├── api.example.org/
└── internal.example.net/

NAMING CONVENTIONS:
- Domain-based directory structure: certificates/{domain}/
- Standard PEM file names: cert.pem, chain.pem, fullchain.pem, privkey.pem
- Versioned archives: archive/{domain}/cert1.pem, cert2.pem, etc.
- Metadata: metadata.json per domain

FILE PERMISSIONS:
- privkey.pem: 600 (owner read/write only)
- *.pem (public): 644 (owner rw, group/other read)
- Directories: 700 (owner rwx)

STORAGE BACKEND COMPATIBILITY:
- All backends store certificate files as separate entries
- Symlinks are resolved before storage
- Metadata is stored as JSON alongside files
- Each domain has isolated storage

================================================================================
6. CERTIFICATE TYPES AND KEY USAGE
================================================================================

SUPPORTED CERTIFICATE TYPES (In Code):
Server Certificates (currently only fully implemented):
- Let's Encrypt: ['DV'] (Domain Validation only)
- DigiCert: ['DV', 'OV', 'EV'] (DV fully implemented, OV/EV partially)
- Private CA: ['Private']

CLIENT CERTIFICATES:
- Not currently supported
- Would require: clientAuth in Extended Key Usage
- Current Certbot integration doesn't support client certs

KEY USAGE LIMITATIONS:
- No control over keyUsage extension
- No control over extendedKeyUsage extension (always serverAuth)
- Key type always RSA (via Certbot defaults)
- Key size: Certbot default (typically 2048-bit)
- No ECDSA support
- No custom extensions

EVIDENCE:
- ca_manager.py defines certificate_types but only for documentation
- certificates.py has no keyUsage/extendedKeyUsage parameters
- Certbot command is fixed (no custom extension flags)
- No post-processing of certificates to add extensions

================================================================================
7. DATABASE/STORAGE STRUCTURE FOR METADATA
================================================================================

SETTINGS PERSISTENCE:
File: data/settings.json (single JSON file, not a database)

Structure:
{
  "email": "admin@example.com",
  "domains": ["example.com", "*.example.com", "api.example.org"],
  "auto_renew": true,
  "renewal_threshold_days": 30,
  "api_bearer_token": "secure-token-here",
  "setup_completed": false,
  "dns_provider": "cloudflare",                    # Default provider
  "dns_providers": {                               # Multi-account structure
    "cloudflare": {
      "accounts": {
        "production": {"api_token": "prod-token"},
        "staging": {"api_token": "staging-token"},
        "dr": {"api_token": "dr-token"}
      }
    },
    "route53": {
      "accounts": {
        "production": {"access_key_id": "...", "secret_access_key": "..."},
        "staging": {"access_key_id": "...", "secret_access_key": "..."}
      }
    }
  },
  "ca_providers": {                                # CA configuration
    "letsencrypt": {
      "accounts": {
        "default": {
          "email": "admin@example.com",
          "staging": false
        }
      }
    },
    "digicert": {
      "accounts": {
        "production": {
          "acme_url": "https://acme.digicert.com/v2/DV",
          "eab_key_id": "key-id",
          "eab_hmac_key": "hmac-key",
          "email": "admin@example.com"
        }
      }
    }
  },
  "certificate_storage": {                         # Storage backend config
    "backend": "local_filesystem",
    "cert_dir": "certificates",
    "azure_keyvault": {...},                       # If using Azure
    "aws_secrets_manager": {...},                  # If using AWS
    "hashicorp_vault": {...},                      # If using HashiCorp
    "infisical": {...}                             # If using Infisical
  },
  "dns_propagation_seconds": {                     # Per-provider timeouts
    "cloudflare": 60,
    "route53": 60,
    "azure": 180,
    "google": 120,
    ...
  }
}

MULTI-ACCOUNT PATTERN:
"dns_providers": {
  "cloudflare": {
    "accounts": {
      "production": { ... },       # Account ID as key
      "staging": { ... },
      "dr": { ... }
    }
  }
}

Settings.json is the ONLY persistent data storage for:
- Email address
- Domain list
- Default providers
- Account credentials (all DNS and CA)
- Storage backend configuration
- API bearer token
- Renewal settings

Per-Certificate Metadata (metadata.json files):
- Stored in certificates/{domain}/metadata.json
- Tracks which DNS provider was used
- Tracks creation/renewal timestamps
- NOT stored in settings.json

================================================================================
8. CERTIFICATE REQUEST HANDLING FLOW
================================================================================

CREATE CERTIFICATE FLOW (in certificates.py):

1. Validate Input
   ├─ Check domain is not empty
   ├─ Check email is provided
   └─ Check CA/DNS providers exist

2. Get CA Configuration
   ├─ Load ca_providers from settings
   ├─ Get account config if specified
   ├─ Prepare EAB credentials if required (DigiCert)
   └─ Get ACME server URL

3. Get DNS Configuration
   ├─ Load dns_providers from settings
   ├─ Resolve account ID (use specified or find default)
   └─ Get account credentials

4. Create Output Directory
   └─ mkdir -p certificates/{domain}/{work,logs}

5. Build Certbot Command
   ├─ certbot certonly --non-interactive --agree-tos
   ├─ --email {email}
   ├─ --server {acme_url}
   ├─ --eab-kid/--eab-hmac-key (if required)
   ├─ --{dns_plugin} (e.g., --dns-cloudflare)
   ├─ --{dns_plugin}-credentials {cred_file}
   ├─ --{dns_plugin}-propagation-seconds {timeout}
   └─ -d {domain}

6. Create DNS Credentials File
   └─ Provider-specific format written to temp file

7. Execute Certbot
   ├─ Run with 30-minute timeout
   ├─ Capture output
   ├─ Clean up credentials file
   └─ Clean up environment variables (Route53)

8. Handle Success
   ├─ Resolve symlinks in live/{domain}/
   ├─ Copy actual files to domain root
   ├─ Store via configured backend
   └─ Create metadata.json

9. Return Response
   └─ Include domain, DNS provider, duration, CA provider

RENEWAL FLOW:

Auto-Renewal Trigger: APScheduler runs check_renewals() periodically
├─ Load settings
├─ For each domain in domains list:
│  ├─ Get certificate info
│  ├─ Calculate days_left
│  ├─ Compare against renewal_threshold_days
│  └─ If needs_renewal: execute renewal
└─ Run certbot renew --cert-name {domain} --quiet

Manual Renewal: User clicks "Renew" button
├─ API endpoint POST /api/certificates/{domain}/renew
├─ Loads metadata to get DNS provider used
├─ Runs certbot renew --cert-name {domain} --quiet
└─ Returns success/failure

KEY MANAGER CLASSES:
- CertificateManager: create_certificate(), renew_certificate(), get_certificate_info()
- CAManager: build_certbot_command(), get_ca_config(), requires_eab()
- DNSManager: get_dns_provider_account_config(), list_dns_provider_accounts()
- StorageManager: store_certificate(), retrieve_certificate(), list_certificates()

================================================================================
9. EXTENSIBILITY FOR CLIENT CERTIFICATES
================================================================================

STRONG POINTS:
✓ Modular storage backend system (CertificateStorageBackend ABC)
✓ Flexible metadata structure (JSON, can be extended)
✓ Multi-account support infrastructure (easily adapted)
✓ Pluggable CA providers (CAManager extensible)
✓ RESTful API design (easy to add new endpoints)
✓ JSON-based configuration (no database migration issues)
✓ Backward-compatible architecture (additive changes possible)

WEAK POINTS:
✗ Certbot doesn't support client certificates
✗ Domain-centric storage model (client certs don't have domains)
✗ No keyUsage/extendedKeyUsage configuration
✗ Directory structure assumes one cert per domain
✗ Renewal logic assumes domain-based expiry checking
✗ Web UI optimized for server certificates

RECOMMENDED MODIFICATIONS:
1. Add certificate_type field to metadata
2. Separate storage paths: certificates/{server|client}/{identifier}/
3. Create ClientCertificateManager class
4. Add CSR support (manual CA signing)
5. Extend API models with certificate type fields
6. Add revocation tracking for client certs
7. Implement different renewal logic per certificate type

================================================================================
10. CURRENT LIMITATIONS FOR CLIENT CERTIFICATES
================================================================================

FUNDAMENTAL ISSUES:

1. Certbot Limitation
   - Certbot designed for server-side TLS certificates
   - Uses DNS-01 ACME challenge (requires domain ownership)
   - Client certs don't own DNS domains
   - Would need alternative challenge mechanism

2. ACME Protocol Limitation
   - RFC 8555 (ACME) designed for server authentication
   - DNS-01 challenge not applicable to client certs
   - Some CAs support "device" certificates via proofing

3. Certificate Identifier Mismatch
   - Current: domains map to certificate paths (example.com → certificates/example.com/)
   - Client certs: serial numbers, CNs, device IDs
   - Would require new directory structure

4. Metadata Schema Gap
   - No extended_key_usage field (needs clientAuth)
   - No key_usage customization
   - No serial number tracking
   - No revocation state tracking
   - No client type field (device, IoT, mobile, etc.)

5. Storage Organization Assumptions
   - "One certificate per domain" assumption
   - Client certs could be N per entity
   - Multi-cert per identifier not supported

6. Renewal Logic
   - Currently domain-based: checks certificate for domain.com
   - Client certs: multiple certificates, different lifecycle
   - Would need flexible renewal mechanism

================================================================================
SUMMARY & RECOMMENDATIONS
================================================================================

CertMate's architecture is WELL-SUITED for client certificate support with
targeted modifications:

STRENGTHS:
- Modular, extensible design
- Pluggable storage backends
- Multi-account infrastructure
- Flexible metadata system
- Clean API structure

REQUIRED CHANGES FOR CLIENT CERTIFICATES:
1. Extend metadata schema (certificate_type, key_usage, serial_number)
2. Separate storage organization (server vs client paths)
3. Replace Certbot with alternative CA integration (direct API, manual CSR)
4. Add client-specific management features (revocation, batching)
5. Update Web UI for non-domain identifiers

IMPLEMENTATION STRATEGY:
Phase 1: Infrastructure (metadata, storage paths)
Phase 2: ClientCertificateManager class
Phase 3: Web UI updates
Phase 4: Advanced features (revocation, batch operations)

BACKWARD COMPATIBILITY:
All changes can be additive - existing server certificate functionality
remains unchanged.

Full detailed analysis available in: CERTIFICATE_ARCHITECTURE_ANALYSIS.md
