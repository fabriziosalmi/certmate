# CertMate Architecture - Quick Reference Guide

## High-Level Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────┐
│                         CertMate Application                              │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │ Web Layer (Flask)                                              │   │
│  ├─────────────────────────────────────────────────────────────────┤   │
│  │ ┌─────────────┐  ┌──────────────┐  ┌──────────────┐            │   │
│  │ │ Dashboard   │  │   Settings   │  │    Help      │            │   │
│  │ │  (index)    │  │ (settings)   │  │  (help)      │            │   │
│  │ └──────┬──────┘  └──────┬───────┘  └──────┬───────┘            │   │
│  │        └───────────────┬────────────────────┘                  │   │
│  │                        ↓                                       │   │
│  │  REST API (Flask-RESTX)    Web Routes (Form-based)            │   │
│  │  /api/certificates/*       /api/web/certificates/*            │   │
│  └──────────────────────────┬──────────────────────────────────────┘   │
│                             ↓                                          │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Manager Layer (Core Business Logic)                             │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │                                                                  │  │
│  │  ┌──────────────────┐  ┌──────────────────┐                    │  │
│  │  │ CertificateManager│  │   CAManager      │                    │  │
│  │  │ create_cert()    │  │ build_certbot()  │                    │  │
│  │  │ renew_cert()     │  │ get_ca_config()  │                    │  │
│  │  │ get_cert_info()  │  │ requires_eab()   │                    │  │
│  │  └────────┬─────────┘  └────────┬─────────┘                    │  │
│  │           │                     │                              │  │
│  │  ┌────────v──────────┐  ┌───────v─────────┐                   │  │
│  │  │  DNSManager       │  │StorageManager   │                   │  │
│  │  │ get_account_cfg() │  │store_cert()     │                   │  │
│  │  │ list_accounts()   │  │retrieve_cert()  │                   │  │
│  │  │ create_account()  │  │list_certs()     │                   │  │
│  │  └────────┬──────────┘  └───────┬─────────┘                   │  │
│  │           │                     │                              │  │
│  │  ┌────────v──────────────────────v──────────┐                 │  │
│  │  │ AuthManager, SettingsManager,            │                 │  │
│  │  │ CacheManager, FileOperations             │                 │  │
│  │  └────────┬───────────────────────────────┘                   │  │
│  │           │                                                    │  │
│  └───────────┼────────────────────────────────────────────────────┘  │
│              ↓                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Execution Layer (External Tools)                                │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │                                                                  │  │
│  │              ┌─────────────────┐                                │  │
│  │              │     Certbot     │  (server certs only)           │  │
│  │              │  certonly       │  via DNS-01 ACME challenge     │  │
│  │              │  renew          │                                │  │
│  │              └────────┬────────┘                                │  │
│  │                       ↓                                         │  │
│  │     DNS Provider API  /  ACME Server                            │  │
│  │     (Cloudflare, AWS, Azure, etc.)  (Let's Encrypt, DigiCert)   │  │
│  │                                                                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                 ↓                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Storage Layer (Pluggable Backends)                              │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │                                                                  │  │
│  │  Local Filesystem  │  Azure Key Vault  │  AWS Secrets Manager   │  │
│  │  AWS HashiCorp     │  Infisical        │                        │  │
│  │  Vault             │                   │                        │  │
│  │                                                                  │  │
│  │  Stores: cert.pem, chain.pem, fullchain.pem, privkey.pem,      │  │
│  │          metadata.json                                          │  │
│  │                                                                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                 ↓                                      │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │ Configuration Layer                                              │  │
│  ├──────────────────────────────────────────────────────────────────┤  │
│  │                                                                  │  │
│  │  settings.json  ←  Email, domains, DNS providers, CA config,    │  │
│  │                    storage backend, renewal settings           │  │
│  │                                                                  │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

## Certificate Storage Model

```
StorageManager (Interface)
    ↓
CertificateStorageBackend (Abstract Base Class)
    ├─ store_certificate(domain, cert_files, metadata)
    ├─ retrieve_certificate(domain)
    ├─ list_certificates()
    ├─ delete_certificate(domain)
    ├─ certificate_exists(domain)
    └─ get_backend_name()
        ↓
    Multiple Implementations:
    ├─ LocalFileSystemBackend      → certificates/{domain}/ (default)
    ├─ AzureKeyVaultBackend         → Azure Key Vault secrets
    ├─ AWSSecretsManagerBackend     → AWS Secrets Manager
    ├─ HashiCorpVaultBackend        → HashiCorp Vault
    └─ InfisicalBackend            → Infisical
```

## Certificate Creation Flow (Sequence Diagram)

```
User/API
  │
  ├─ POST /api/certificates {domain, email, dns_provider, ca_provider}
  │
  ↓
CertificateManager.create_certificate()
  ├─ Validate inputs (domain, email, CA/DNS provider exist)
  │
  ├─ Get CA Config (CAManager.get_ca_config)
  │   └─ Load ca_providers from settings.json
  │   └─ Get EAB credentials if DigiCert
  │   └─ Get ACME server URL
  │
  ├─ Get DNS Config (DNSManager.get_dns_provider_account_config)
  │   └─ Load dns_providers from settings.json
  │   └─ Get account credentials
  │
  ├─ Create directories: certificates/{domain}/ with work/ and logs/
  │
  ├─ Build Certbot Command (CAManager.build_certbot_command)
  │   ├─ certbot certonly --non-interactive --agree-tos
  │   ├─ --server {acme_server_url}
  │   ├─ --email {email}
  │   ├─ --{dns_plugin} (e.g., --dns-cloudflare)
  │   ├─ --{dns_plugin}-credentials {temp_cred_file}
  │   ├─ --{dns_plugin}-propagation-seconds {timeout}
  │   ├─ --eab-kid/--eab-hmac-key (if DigiCert)
  │   └─ -d {domain}
  │
  ├─ Execute Certbot
  │   ├─ Run with 30-minute timeout
  │   ├─ Certbot performs DNS-01 challenge
  │   ├─ Gets signed certificate from CA
  │   └─ Output to live/example.com/
  │
  ├─ Post-Process
  │   ├─ Resolve symlinks in live/
  │   ├─ Copy to domain root: cert.pem, chain.pem, fullchain.pem, privkey.pem
  │   └─ Clean up credentials file
  │
  ├─ Store Certificate
  │   ├─ StorageManager.store_certificate(domain, {cert_files}, metadata)
  │   └─ Store to configured backend (local FS, Azure, AWS, etc.)
  │
  ├─ Create Metadata
  │   └─ metadata.json with domain, dns_provider, created_at, email, etc.
  │
  └─ Return Response
      └─ {domain, dns_provider, ca_provider, duration, success: true}
```

## Data Model - Certificate Metadata

```json
{
  "domain": "example.com",
  "dns_provider": "cloudflare",
  "created_at": "2025-01-15T10:30:00.000000",
  "renewed_at": "2025-10-15T10:30:00.000000",
  "email": "admin@example.com",
  "staging": false,
  "account_id": "production",
  "certificate_type": "DV",
  "inferred": false
}
```

**Stored at**: `certificates/{domain}/metadata.json` (and in remote backends)

## Configuration Structure - settings.json

```json
{
  "email": "admin@example.com",
  "domains": ["example.com", "*.example.com", "api.example.org"],
  "auto_renew": true,
  "renewal_threshold_days": 30,
  "api_bearer_token": "secure-token",
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {
      "accounts": {
        "production": {"api_token": "token-prod"},
        "staging": {"api_token": "token-staging"}
      }
    }
  },
  "ca_providers": {
    "letsencrypt": {
      "accounts": {
        "default": {"email": "admin@example.com"}
      }
    }
  },
  "certificate_storage": {
    "backend": "local_filesystem",
    "cert_dir": "certificates"
  }
}
```

## API Endpoints Summary

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | /api/health | Health check |
| GET | /api/certificates | List all certificates |
| POST | /api/certificates | Create new certificate |
| GET | /api/certificates/{domain} | Get certificate info |
| POST | /api/certificates/{domain}/renew | Renew certificate |
| GET | /api/certificates/{domain}/download | Download as ZIP |
| GET | /api/web/certificates | List (web UI) |
| POST | /api/web/certificates/create | Create (async) |
| GET | /{domain}/tls | Direct fullchain download |

## Manager Classes Hierarchy

```
CertMateApp (main application)
├─ FileOperations           # File I/O, backups
├─ SettingsManager          # Load/save settings.json
├─ AuthManager              # Token validation
├─ CertificateManager       # Create/renew/info
├─ CAManager                # CA provider config, Certbot building
├─ DNSManager               # DNS provider accounts
├─ CacheManager             # Deployment cache
└─ StorageManager           # Backend abstraction
```

## Storage Paths

```
Root Directory
├─ certificates/            # Certificate storage (configured per backend)
│  ├─ example.com/
│  │  ├─ cert.pem
│  │  ├─ chain.pem
│  │  ├─ fullchain.pem
│  │  ├─ privkey.pem
│  │  └─ metadata.json
│  ├─ *.example.com/
│  └─ api.example.org/
├─ data/                    # Configuration
│  └─ settings.json
├─ backups/                 # Backup storage
│  └─ unified/             # Unified backups (atomic snapshots)
├─ logs/                    # Application logs
└─ certificates/{domain}/live/  # Certbot-managed symlinks
```

## Certificate Type Support Matrix

| Feature | Current | Client Certs |
|---------|---------|--------------|
| Storage | Multiple backends | Would use same |
| Metadata | Basic fields | Needs extension |
| Issuance | Certbot + ACME | Manual CSR needed |
| API | REST endpoints | Would add new |
| Web UI | Domain-centric | Needs redesign |
| Renewal | Domain-based | Identifier-based |
| Key Usage | serverAuth only | clientAuth needed |

## Key Technologies

```
Backend
├─ Python 3.9+
├─ Flask (web framework)
├─ Flask-RESTX (REST API)
├─ APScheduler (scheduled tasks)
├─ Certbot (ACME client)
├─ Azure SDK / boto3 / hvac / infisical (cloud SDKs)
└─ OpenSSL (certificate parsing)

Frontend
├─ HTML5
├─ Tailwind CSS
├─ JavaScript (vanilla)
├─ Font Awesome (icons)
└─ Dark mode support

Deployment
├─ Docker / Docker Compose
├─ Kubernetes compatible
└─ Flask CORS enabled
```

## Important Limitations

1. **Certbot-only**: Current implementation tied to Certbot, which doesn't support client certificates
2. **Domain-centric**: Directory structure assumes one cert per domain
3. **Server-cert focused**: No extended key usage configuration
4. **No DB**: Single JSON file for config (no migrations needed)
5. **DNS-01 only**: ACME challenges via DNS (not HTTP-01 or other)

## Recommended Architecture for Client Certs

1. **Separate storage**: `certificates/{server|client}/{identifier}/`
2. **Extend metadata**: Add `certificate_type`, `extended_key_usage`, `serial_number`
3. **New manager**: `ClientCertificateManager` for client-specific operations
4. **Alternative issuance**: Direct CA API or manual CSR submission (Certbot won't work)
5. **Backward compatible**: All changes additive, no breaking changes needed

---

**For complete details, see**: 
- `ARCHITECTURE_SUMMARY.md` - Detailed technical overview
- `CERTIFICATE_ARCHITECTURE_ANALYSIS.md` - Deep dive analysis
