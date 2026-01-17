# CertMate - Client Certificates

<div align="center">

![CertMate](https://img.shields.io/badge/CertMate-Client%20Certificates-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production%20Ready-green?style=for-the-badge)
![Tests](https://img.shields.io/badge/Tests-27%2F27%20Passing-brightgreen?style=for-the-badge)
![Coverage](https://img.shields.io/badge/Coverage-100%25-brightgreen?style=for-the-badge)

**Complete Client Certificate Management for CertMate**

[Documentation](#documentation) • [Quick Start](#quick-start) • [API Reference](./api.md) • [Architecture](./architecture.md)

</div>

---

## Overview

CertMate Client Certificates is a comprehensive, production-ready solution for managing client certificates with:

- **Self-Signed CA** - Generate and manage your own Certificate Authority
- **Full Lifecycle Management** - Create, renew, revoke, and monitor client certificates
- **OCSP & CRL** - Real-time certificate status and revocation lists
- **Web Dashboard** - Intuitive UI for certificate management
- **REST API** - Complete API for automation
- **Batch Operations** - Import 100-30,000 certificates via CSV
- **Audit Logging** - Track all operations for compliance
- **Rate Limiting** - Built-in protection against abuse

---

## Features

### Phase 1: CA Foundation 
- **PrivateCAGenerator**: Self-signed CA with 4096-bit RSA keys, 10-year validity
- **CSRHandler**: Validate, create, and parse Certificate Signing Requests
- **Secure Storage**: Proper file permissions (0600) for private keys

### Phase 2: Client Certificate Engine 
- **Complete Lifecycle**: Create, list, filter, revoke, and renew certificates
- **Multi-Filter Queries**: Search by usage type, revocation status, common name
- **Auto-Renewal**: Scheduled daily renewal checks for expiring certificates
- **Support for 30k+ Certificates**: Directory-based storage for linear scalability
- **Metadata Management**: Track CN, email, organization, usage, expiration dates

### Phase 3: UI & Advanced Features 
- **Web Dashboard**: Responsive, dark-mode-enabled management interface
- **OCSP Responder**: Query certificate status in real-time
- **CRL Manager**: Generate and distribute revocation lists (PEM/DER)
- **REST API**: 10 endpoints across 3 namespaces for full automation
- **Batch Operations**: Import certificates from CSV files

### Phase 4: Easy Wins 
- **Audit Logging**: Track all certificate operations with user/IP information
- **Rate Limiting**: Configurable per-endpoint limits with sensible defaults
- **Ready for Integration**: Both managers available in app for immediate use

---

## Quick Start

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The server will start on `http://localhost:5000`

### Basic Usage

#### 1. Access Web Dashboard
```
Navigate to: http://localhost:5000/client-certificates
```

#### 2. Create a Certificate via API
```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
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

#### 3. List Certificates
```bash
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer YOUR_TOKEN"
```

#### 4. Download Certificate Files
```bash
# Download certificate
curl http://localhost:5000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o user.crt

# Download private key
curl http://localhost:5000/api/client-certs/USER_ID/download/key \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o user.key
```

---

## Documentation

### Main Documentation

- **[API Reference](./api.md)** - Complete REST API documentation with examples
- **[Architecture](./architecture.md)** - System design, components, and data flow
- **[User Guide](./guide.md)** - Step-by-step guide for common tasks
- **[Changelog](./CHANGELOG.md)** - Version history and updates

### Quick Links

- [API Endpoints](./api.md#endpoints) - All available endpoints
- [Certificate Types](./api.md#certificate-types) - VPN, API mTLS, etc.
- [Rate Limiting](./api.md#rate-limiting) - Default limits and configuration
- [Audit Logging](./api.md#audit-logging) - Understanding audit trails

---

## Testing

All features have been extensively tested:

```bash
# Run comprehensive test suite
python test_e2e_complete.py

# Expected result: 27/27 tests passing
```

### Test Coverage
- CA Operations (3 tests)
- CSR Operations (3 tests)
- Certificate Lifecycle (8 tests)
- Filtering & Search (3 tests)
- Batch Operations (2 tests)
- OCSP & CRL (5 tests)
- Audit & Rate Limiting (3 tests)

---

## API Endpoints Summary

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `POST` | `/api/client-certs/create` | Create new certificate |
| `GET` | `/api/client-certs` | List certificates with filters |
| `GET` | `/api/client-certs/<id>` | Get certificate metadata |
| `GET` | `/api/client-certs/<id>/download/<type>` | Download cert/key/csr |
| `POST` | `/api/client-certs/<id>/revoke` | Revoke certificate |
| `POST` | `/api/client-certs/<id>/renew` | Renew certificate |
| `GET` | `/api/client-certs/stats` | Get statistics |
| `POST` | `/api/client-certs/batch` | Batch CSV import |
| `GET` | `/api/ocsp/status/<serial>` | OCSP status query |
| `GET` | `/api/crl/download/<format>` | Download CRL (PEM/DER) |

---

## Architecture

The system is built with a modular, layered architecture:

```

 Web UI & REST API 
 (/client-certificates, /api/*) 

 API Resources & Managers 
 (OCSP, CRL, Audit, Rate Limiting) 

 Core Modules 
 (Certificate Mgmt, CSR, CA, Storage) 

 Cryptography & Storage 
 (OpenSSL, File System, Backends) 

```

See [Architecture Documentation](./architecture.md) for detailed information.

---

## Security

### Cryptographic Strength
- **CA**: 4096-bit RSA keys, 10-year validity
- **Client Certificates**: 2048 or 4096-bit RSA (configurable)
- **Signatures**: SHA256
- **Key Storage**: 0600 file permissions on Unix systems

### Access Control
- **Bearer Token Authentication** on all API endpoints
- **Rate Limiting**: Per-endpoint configurable limits
- **Audit Logging**: All operations tracked with user/IP info

### Compliance
- Certificate metadata tracking
- Revocation audit trail
- Persistent operation logs
- Support for compliance queries

---

## Performance

The implementation is optimized for:
- **Scalability**: Directory-based storage supports 30k+ concurrent certificates
- **Speed**: Efficient multi-filter queries
- **Reliability**: Automatic renewal scheduling
- **Responsiveness**: Async JavaScript in web UI

---

## Support

For questions or issues:
1. Check the [User Guide](./guide.md)
2. Review the [API Documentation](./api.md)
3. Check the [Architecture](./architecture.md) section
4. Review test cases in `test_e2e_complete.py`

---

## License

See LICENSE file in the repository

---

## Version

**Current Version**: 1.0.0
**Status**: Production Ready
**Last Updated**: 2024-10-30

---

<div align="center">

Made with for CertMate

[Documentation](.) • [Privacy](./privacy.md) • [License](../LICENSE)

</div>
