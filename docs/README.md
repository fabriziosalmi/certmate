# 📖 CertMate Documentation

Welcome to the CertMate documentation! This folder contains comprehensive guides for all features.

## 🎫 Client Certificates Documentation

**Status**: ✅ Production Ready | **Version**: 1.0.0 | **Tests**: 27/27 Passing

### Quick Navigation

- **[📌 Start Here](./index.md)** - Main landing page with overview
- **[🚀 Quick Start Guide](./guide.md)** - Get up and running in minutes
- **[📡 API Reference](./api.md)** - Complete REST API documentation
- **[🏗️ Architecture](./architecture.md)** - System design and components
- **[📝 Changelog](./CHANGELOG.md)** - Version history and updates

---

## 📚 Documentation Sections

### For New Users
Start with these if you're new to CertMate Client Certificates:

1. **[Getting Started](./guide.md#getting-started)**
   - Installation and setup
   - First certificate creation
   - Web dashboard tour

2. **[Common Tasks](./guide.md#common-tasks)**
   - Creating certificates
   - Batch importing
   - Downloading files
   - Renewing and revoking

### For Developers
Use these if you're integrating with the API:

1. **[API Reference](./api.md)**
   - All endpoints documented
   - Request/response examples
   - Error handling
   - Rate limiting info

2. **[Architecture](./architecture.md)**
   - System components
   - Data flow
   - Security model
   - Scalability design

### For Administrators
Use these to manage and monitor the system:

1. **[Audit Logging](./api.md#audit-logging)**
   - How to access audit logs
   - Understanding log entries

2. **[Rate Limiting](./api.md#rate-limiting)**
   - Default limits
   - Configuration
   - Per-endpoint limits

---

## 🎯 Feature Overview

### Phase 1: CA Foundation ✅
- Self-signed Certificate Authority (4096-bit RSA)
- CSR validation and creation
- Secure key storage

### Phase 2: Client Certificate Engine ✅
- Complete lifecycle management
- Multi-filter queries and search
- Auto-renewal scheduling
- Support for 30k+ certificates

### Phase 3: UI & Advanced Features ✅
- Web dashboard at `/client-certificates`
- OCSP real-time status queries
- CRL generation and distribution
- REST API (10 endpoints)
- Batch CSV import

### Phase 4: Easy Wins ✅
- Comprehensive audit logging
- API rate limiting
- Production-ready security

---

## 🔗 API Endpoints Quick Reference

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

## 🧪 Testing

All features are thoroughly tested:

```bash
# Run E2E tests
python test_e2e_complete.py

# Result: 27/27 tests passing
```

Test coverage includes:
- ✅ CA Operations
- ✅ CSR Operations
- ✅ Certificate Lifecycle
- ✅ Filtering & Search
- ✅ Batch Operations
- ✅ OCSP & CRL
- ✅ Audit & Rate Limiting

---

## 🔐 Security Features

- **4096-bit RSA** for CA keys
- **SHA256** signature algorithm
- **Bearer token** authentication
- **Rate limiting** on all endpoints
- **Audit logging** of all operations
- **File permissions** 0600 for private keys

---

## 📊 Performance

- Supports **30k+ concurrent certificates**
- Efficient **multi-filter queries**
- **Auto-renewal** scheduling
- **Batch operations** with error tracking

---

## 🆘 Need Help?

1. **Installation Issues?** → See [Installation Section](./guide.md#installation)
2. **API Questions?** → See [API Reference](./api.md)
3. **Architecture Questions?** → See [Architecture Doc](./architecture.md)
4. **Something Else?** → Check the [Changelog](./CHANGELOG.md)

---

## 📝 File Structure

```
docs/
├── README.md              ← You are here
├── index.md              ← Main landing page
├── guide.md              ← User guide & getting started
├── api.md                ← Complete API reference
├── architecture.md       ← System design & components
└── CHANGELOG.md          ← Version history
```

---

## 🎓 Learning Path

**Beginner** → [Start Here](./index.md) → [Getting Started](./guide.md)

**Developer** → [API Reference](./api.md) → [Architecture](./architecture.md)

**Advanced** → [Full API Docs](./api.md) → [Architecture Details](./architecture.md)

---

## 📌 Important Links

- **Web Dashboard**: `http://localhost:5000/client-certificates`
- **API Docs**: `http://localhost:5000/docs/`
- **Health Check**: `http://localhost:5000/health`
- **Audit Logs**: `logs/audit/certificate_audit.log`

---

## 📊 Status Dashboard

| Component | Status | Tests |
|-----------|--------|-------|
| CA Foundation | ✅ Ready | 3/3 |
| CSR Handler | ✅ Ready | 3/3 |
| Cert Manager | ✅ Ready | 8/8 |
| Filtering | ✅ Ready | 3/3 |
| Batch Ops | ✅ Ready | 2/2 |
| OCSP/CRL | ✅ Ready | 5/5 |
| Audit/Rate Limit | ✅ Ready | 3/3 |
| **Total** | **✅ Ready** | **27/27** |

---

## 💡 Quick Examples

### Create a Certificate via API

```bash
curl -X POST http://localhost:5000/api/client-certs/create \
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
curl http://localhost:5000/api/client-certs \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Download Certificate

```bash
curl http://localhost:5000/api/client-certs/USER_ID/download/crt \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -o certificate.crt
```

See [API Guide](./api.md) for more examples.

---

## 📄 License

CertMate is licensed under the MIT License. See LICENSE file in the repository.

---

## 🙋 Questions or Issues?

- Check the relevant documentation page
- Review the test files for usage examples
- Check the [API Reference](./api.md) for endpoint details

---

<div align="center">

**Made with ❤️ for CertMate**

[Home](../README.md) • [Documentation](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
