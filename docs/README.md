# CertMate Documentation

Welcome to the CertMate documentation. This folder contains comprehensive guides for all features.

---

## Quick Navigation

### Getting Started
- **[Installation Guide](./installation.md)** — Setup, dependencies, production deployment
- **[Docker Guide](./docker.md)** — Docker builds, multi-platform, Docker Compose

### Core Features
- **[DNS Providers](./dns-providers.md)** — 22 DNS providers, multi-account, domain alias
- **[CA Providers](./ca-providers.md)** — Let's Encrypt, DigiCert, Private CA
- **[Client Certificates](./guide.md)** — Client cert lifecycle, web dashboard, batch ops

### Reference
- **[API Reference](./api.md)** — Complete REST API documentation
- **[Architecture](./architecture.md)** — System design, components, data flow
- **[Testing Guide](./testing.md)** — Test framework, CI/CD, coverage
- **[Changelog](./CHANGELOG.md)** — Version history and updates

---

## Documentation by Audience

### For New Users

1. **[Installation](./installation.md)** — Get CertMate running
2. **[DNS Providers](./dns-providers.md)** — Configure your DNS provider
3. **[Client Certificates Guide](./guide.md)** — Create your first certificate

### For Developers

1. **[API Reference](./api.md)** — All endpoints with examples
2. **[Architecture](./architecture.md)** — System internals and design
3. **[Testing Guide](./testing.md)** — How to write and run tests

### For Administrators

1. **[Docker Deployment](./docker.md)** — Production Docker setup
2. **[CA Providers](./ca-providers.md)** — Configure certificate authorities
3. **[DNS Providers](./dns-providers.md#multi-account-support)** — Enterprise multi-account setup

---

## Feature Overview

### Server Certificates
- **22 DNS providers** for Let's Encrypt DNS-01 challenges
- **Multiple CA providers**: Let's Encrypt, DigiCert ACME, Private CA
- **Multi-account support** per DNS provider
- **Pluggable storage backends**: Local, Azure Key Vault, AWS, Vault, Infisical
- **Auto-renewal** with configurable thresholds
- **Docker support** with multi-platform builds (ARM64 + AMD64)

### Client Certificates
- **Self-signed CA** with 4096-bit RSA keys
- **Full lifecycle management** — create, renew, revoke, monitor
- **OCSP & CRL** — real-time status and revocation lists
- **Web dashboard** at `/client-certificates`
- **Batch operations** — import 100-30,000 certificates via CSV
- **Audit logging** and **rate limiting**

---

## API Endpoints Quick Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/client-certs/create` | Create certificate |
| GET | `/api/client-certs` | List certificates |
| GET | `/api/client-certs/<id>` | Get metadata |
| GET | `/api/client-certs/<id>/download/<type>` | Download cert/key/csr |
| POST | `/api/client-certs/<id>/revoke` | Revoke certificate |
| POST | `/api/client-certs/<id>/renew` | Renew certificate |
| GET | `/api/client-certs/stats` | Get statistics |
| POST | `/api/client-certs/batch` | Batch CSV import |
| GET | `/api/ocsp/status/<serial>` | OCSP status |
| GET | `/api/crl/download/<format>` | Download CRL |

See [API Reference](./api.md#endpoints) for full documentation.

---

## Testing

All features are thoroughly tested:

```bash
# Run E2E tests
python test_e2e_complete.py

# Result: 27/27 tests passing
```

Test coverage includes:
- CA Operations
- CSR Operations
- Certificate Lifecycle
- Filtering & Search
- Batch Operations
- OCSP & CRL
- Audit & Rate Limiting

---

## Security Features

- **4096-bit RSA** for CA keys
- **SHA256** signature algorithm
- **Bearer token** authentication
- **Rate limiting** on all endpoints
- **Audit logging** of all operations
- **File permissions** 0600 for private keys

---

## Performance

- Directory-based storage designed for large certificate volumes
- Efficient **multi-filter queries**
- **Auto-renewal** scheduling
- **Batch operations** with error tracking

---

## Need Help?

1. **Installation Issues?** → See [Installation Section](./guide.md#installation)
2. **API Questions?** → See [API Reference](./api.md)
3. **Architecture Questions?** → See [Architecture Doc](./architecture.md)
4. **Something Else?** → Check the [Changelog](./CHANGELOG.md)

---

## File Structure

```
docs/
  README.md            ← You are here
  index.md             ← Client certificates landing page
  installation.md      ← Installation & setup
  dns-providers.md     ← DNS providers & multi-account
  ca-providers.md      ← Certificate Authority providers
  docker.md            ← Docker build & deployment
  testing.md           ← Testing framework & CI/CD
  guide.md             ← Client certificates user guide
  api.md               ← Complete API reference
  architecture.md      ← System architecture
  CHANGELOG.md         ← Version history
```

---

## Learning Path

**Beginner** → [Start Here](./index.md) → [Getting Started](./guide.md)

**Developer** → [API Reference](./api.md) → [Architecture](./architecture.md)

**Advanced** → [Full API Docs](./api.md) → [Architecture Details](./architecture.md)

---

## Important Links

- **Web Dashboard**: `http://localhost:8000/client-certificates`
- **API Docs**: `http://localhost:8000/docs/`
- **Health Check**: `http://localhost:8000/health`
- **Audit Logs**: `logs/audit/certificate_audit.log`

---

## Status Dashboard

| Component | Status | Tests |
|-----------|--------|-------|
| CA Foundation | Ready | 3/3 |
| CSR Handler | Ready | 3/3 |
| Cert Manager | Ready | 8/8 |
| Filtering | Ready | 3/3 |
| Batch Ops | Ready | 2/2 |
| OCSP/CRL | Ready | 5/5 |
| Audit/Rate Limit | Ready | 3/3 |
| **Total** | **Ready** | **27/27** |

---

## Quick Examples

### Create a Certificate via API

```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365
 }'
```

### List Certificates

```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer YOUR_TOKEN"
```

### Download Certificate

```bash
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o certificate.crt
```

See [API Guide](./api.md) for more examples.

---

## License

CertMate is licensed under the MIT License. See LICENSE file in the repository.

---

## Questions or Issues?

- Check the relevant documentation page
- Review the test files for usage examples
- Check the [API Reference](./api.md) for endpoint details

---

<div align="center">

**Made with for CertMate**

[Home](../README.md) • [Documentation](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
