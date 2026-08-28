# CertMate Documentation

Welcome to the CertMate documentation. This folder contains comprehensive guides for all features.

---

## Quick Navigation

### Getting Started
- **[Installation Guide](./installation.md)** — Setup, dependencies, production deployment
- **[Docker Guide](./docker.md)** — Docker builds, multi-platform, Docker Compose
- **[Kubernetes Notes](./kubernetes.md)** — Production resources, OOM sizing, runtime patching

### Core Features
- **[DNS Providers](./dns-providers.md)** — supported providers, multi-account, domain alias
- **[CA Providers](./ca-providers.md)** — Let's Encrypt, DigiCert, Private CA
- **[Client Certificates](./guide.md)** — Client cert lifecycle, web dashboard, batch ops
- **[Model Context Protocol (MCP) Server](./mcp.md)** — Standalone Node.js server for AI agent integrations

### Reference
- **[API Reference](./api.md)** — Complete REST API documentation
- **[Architecture](./architecture.md)** — System design, components, data flow
- **[Testing Guide](./testing.md)** — Test framework, CI/CD, coverage
- **[Certificate Discovery & Inventory](./discovery-inventory.md)** — probe/CT-log discovery, inventory, adopt, crypto readiness
- **[Deploy Hooks](./deploy-hooks.md)** — post-issuance hooks: configuration, testing, output redaction
- **[Webhooks](./webhooks.md)** — generic webhooks: payload templates, authentication, signature verification
- **[Compliance](./compliance.md)** — audit chain, actor attribution, NIS2/eIDAS posture
- **[Deployment Probes](./probes.en.md)** — verifying a renewed certificate is actually served

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
2. **[Kubernetes Notes](./kubernetes.md)** — Production pod sizing and operational patching
3. **[CA Providers](./ca-providers.md)** — Configure certificate authorities
4. **[DNS Providers](./dns-providers.md#multi-account-support)** — Enterprise multi-account setup

---

## Feature Overview

### Server Certificates
- **two dozen+ DNS providers** for Let's Encrypt DNS-01 challenges (see [DNS Providers](./dns-providers.md) for the full list)
- **Multiple CA providers**: Let's Encrypt, DigiCert, Private CA
- **Multi-account support** per DNS provider
- **Pluggable storage backends**: Local, Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical, S3-compatible
- **Auto-renewal** with configurable thresholds
- **Docker support** with multi-platform builds (ARM64 + AMD64)
- **Log Sanitizer** — Automatically redacts API tokens, private keys, and sensitive credentials from CertMate logs
- **Zombie Certificate Scanner** — Multi-threaded filesystem scanner to identify and clean up orphan certificates
- **Model Context Protocol (MCP) Server** — Standalone Node.js server to integrate with agentic AI assistants

### Client Certificates
- **Self-signed CA** with 4096-bit RSA keys
- **Full lifecycle management** — create, renew, revoke, monitor
- **OCSP & CRL** — real-time status and revocation lists
- **Web dashboard** at `/client-certificates`
- **Batch operations** — import client certificates in bulk via CSV (up to 100 rows per request)
- **Audit logging** and **rate limiting**

---

## API Endpoints Quick Reference

| Method | Endpoint                                 | Description           |
| ------ | ---------------------------------------- | --------------------- |
| POST   | `/api/client-certs/create`               | Create certificate    |
| GET    | `/api/client-certs`                      | List certificates     |
| GET    | `/api/client-certs/<id>`                 | Get metadata          |
| GET    | `/api/client-certs/<id>/download/<type>` | Download cert/key/csr |
| POST   | `/api/client-certs/<id>/revoke`          | Revoke certificate    |
| POST   | `/api/client-certs/<id>/renew`           | Renew certificate     |
| GET    | `/api/client-certs/stats`                | Get statistics        |
| POST   | `/api/client-certs/batch`                | Batch CSV import      |
| GET    | `/api/ocsp/status/<serial>`              | OCSP status           |
| GET    | `/api/crl/download/<format>`             | Download CRL          |

See [API Reference](./api.md#endpoints) for full documentation.

---

## Testing

All features are thoroughly tested:

```bash
# Run tests
# The UI suite drives Playwright against a live server and cannot share
# a process with the rest; e2e needs a running instance. Same selection
# `make test` and scripts/release.sh use.
pytest -v --tb=short -m "not ui and not e2e"
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

- Supports **30k+ concurrent certificates**
- Efficient **multi-filter queries**
- **Auto-renewal** scheduling
- **Batch operations** with error tracking

---

## Need Help?

1. **Installation Issues?** → See [Installation Section](./guide.md#installation)
2. **API Questions?** → See [API Reference](./api.md)
3. **Architecture Questions?** → See [Architecture Doc](./architecture.md)
4. **Something Else?** → Open an [issue](https://github.com/fabriziosalmi/certmate/issues)

---

## File Structure

<!-- Checked by tests/test_docs_navigation.py: this listing must match
     what is actually on disk. It used to omit six pages. -->

```
docs/
  README.md               this file — documentation index  <- you are here
  THEME_MIGRATION.md      one-off theme migration record
  api.md                  complete REST API reference
  architecture.md         system architecture
  ca-providers.md         certificate authorities
  compliance.md           audit chain, attribution, NIS2/eIDAS
  deploy-hooks.md         post-issuance deploy hooks
  webhooks.md             generic webhooks: payload templates, auth, signature
  discovery-inventory.md  discovery, inventory, adopt, crypto readiness
  dns-providers.md        DNS providers, multi-account, domain alias
  docker.md               Docker build and deployment
  guide.md                client-certificate user guide
  index.md                client-certificate landing page
  installation.md         installation and setup
  kubernetes.md           Kubernetes production notes and Helm chart
  mcp.md                  MCP server for AI agents
  probes.en.md            deployment probes
  testing.md              test framework and CI/CD
```

---

## Learning Path

**Beginner** → [Start Here](./guide.md) → [Getting Started](./guide.md)

**Developer** → [API Reference](./api.md) → [Architecture](./architecture.md)

**Advanced** → [Full API Docs](./api.md) → [Architecture Details](./architecture.md)

---

## Important Links

- **Web Dashboard**: `http://localhost:8000/client-certificates`
- **API Docs**: `http://localhost:8000/docs/`
- **Health Check**: `http://localhost:8000/health`
- **Audit Logs**: `logs/audit/certificate_audit.log`

---

## Test status

There is no hand-maintained scorecard here. A table of test counts is stale the day after it is written — this one said `27/27` while the suite had grown past two thousand.

The authoritative signal is CI on `main`: the badges at the top of the [project README](../README.md), and the coverage floor enforced in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

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

---

**Current Version**: 2.26.1

<div align="center">

[Home](../README.md) • [Documentation](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
