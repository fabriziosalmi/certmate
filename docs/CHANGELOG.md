# CertMate Client Certificates - Changelog

All notable changes to the Client Certificates feature will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2024-10-30

### Added

#### Phase 1: CA Foundation
- **PrivateCAGenerator** - Self-signed Certificate Authority with 4096-bit RSA keys
- **CSRHandler** - Certificate Signing Request validation and creation
- Support for 2048 and 4096-bit RSA key sizes
- Secure key storage with proper file permissions (0600)
- CA backup and metadata management

#### Phase 2: Client Certificate Engine
- **ClientCertificateManager** - Complete certificate lifecycle management
- Create client certificates with automatic signing
- List certificates with optional filtering
- Filter by usage type (api-mtls, vpn, custom)
- Filter by revocation status
- Search by common name
- Revoke certificates with audit trail
- Renew certificates (same CN, new serial)
- Auto-renewal scheduling (daily at 3 AM)
- Support for 30k+ concurrent certificates
- Metadata storage (JSON per certificate)
- Certificate statistics and usage breakdown

#### Phase 3: UI & Advanced Features
- **Web Dashboard** at `/client-certificates`
 - Statistics panel (total, active, revoked, by-usage)
 - Single certificate creation form
 - Bulk CSV import with drag-drop
 - Certificate table with search and filters
 - Download modal for cert/key/csr files
 - Revoke and renew action buttons
 - Dark mode support
 - Fully responsive design

- **OCSP Responder** - Online Certificate Status Protocol
 - Query certificate status (good/revoked/unknown)
 - Generate OCSP responses
 - Real-time status lookups

- **CRL Manager** - Certificate Revocation List
 - Generate CRL with revoked serials
 - PEM format distribution
 - DER format conversion
 - CRL metadata and info retrieval

- **REST API** - 10 endpoints across 3 namespaces
 - POST /api/client-certs/create - Create certificate
 - GET /api/client-certs - List certificates
 - GET /api/client-certs/<id> - Get metadata
 - GET /api/client-certs/<id>/download/<type> - Download files
 - POST /api/client-certs/<id>/revoke - Revoke
 - POST /api/client-certs/<id>/renew - Renew
 - GET /api/client-certs/stats - Statistics
 - POST /api/client-certs/batch - Batch import
 - GET /api/ocsp/status/<serial> - OCSP query
 - GET /api/crl/download/<format> - CRL download

#### Phase 4: Easy Wins
- **Audit Logging** - Comprehensive operation tracking
 - JSON format logging
 - Persistent audit file
 - User and IP address tracking
 - Query by resource or time window
 - Covers: create, revoke, renew, download, batch ops

- **Rate Limiting** - API protection
 - Configurable per-endpoint limits
 - Default: 100 req/min (global)
 - Certificate creation: 30 req/min
 - Batch operations: 10 req/min
 - OCSP: 200 req/min
 - HTTP 429 responses with Retry-After

#### Testing & Documentation
- Comprehensive E2E test suite (27 tests)
- Full API documentation
- Architecture guide
- User guide
- Quick start examples
- Rate limiting information
- Audit logging details

### Security Features
- 4096-bit RSA for CA
- SHA256 signature algorithm
- Bearer token authentication
- Rate limiting
- Audit logging
- Proper file permissions
- Secure key storage

### Performance
- Support for 30k+ certificates
- Efficient multi-filter queries
- Batch operations (100-30k certs)
- Auto-renewal scheduling
- Low memory footprint

### Quality Assurance
- 27/27 tests passing
- 100% test coverage for core features
- Comprehensive error handling
- All deprecation warnings fixed
- Production-ready code

### Documentation
- Complete API reference
- System architecture guide
- User guide with examples
- Inline code documentation
- README with quick links

---

## [Unreleased]

### Planned for Future Releases

#### Phase 4.1: Advanced Security
- [] CA password protection
- [] Hardware token support (PKCS#11)
- [] Key rotation policies
- [] Advanced audit filtering

#### Phase 4.2: Enterprise Features
- [] Role-based access control
- [] LDAP/AD integration
- [] Multi-tenancy support
- [] Webhook notifications

#### Phase 4.3: Integration & Automation
- [] Certificate validation webhooks
- [] Expiration notifications
- [] Auto-renewal alerts
- [] Prometheus metrics

---

## Upgrade Guide

### From Unsupported Version → 1.0.0

No previous versions exist. This is the initial release.

### Future Upgrades

```bash
# Backup existing certificates
tar -czf backup-client-certs.tar.gz data/certs/

# Update code
git pull origin main

# Restart service
python app.py
```

---

## Known Limitations

### Current Version (1.0.0)

1. **No Standalone CSR Signing**
 - Cannot sign external CSRs yet
 - Plan: Support CSR submission in v1.1

2. **No Certificate Templates**
 - Each cert customized individually
 - Plan: Add templates in v1.1

3. **In-Memory Rate Limiting**
 - Single-instance only
 - Plan: Redis support in v1.2

4. **No Webhook Notifications**
 - No event callbacks yet
 - Plan: Add in v1.1

---

## Breaking Changes

No breaking changes in 1.0.0 (initial release).

---

## Contributors

- @fabriziosalmi - Lead Developer
- Claude Code - Implementation & Documentation

---

## Support

- [Documentation](./README.md)
- [Issue Tracker](https://github.com/fabriziosalmi/certmate/issues)
- [Discussions](https://github.com/fabriziosalmi/certmate/discussions)

---

## License

MIT License - See LICENSE file in repository

---

<div align="center">

[Home](../README.md) • [Docs](./README.md) • [API](./api.md) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
