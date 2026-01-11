# 🔐 CertMate - SSL Certificate Management System

**CertMate** is a powerful SSL certificate management system for modern infrastructure. Multi-DNS provider support, Docker-ready, comprehensive REST API.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://hub.docker.com/)

📖 **Full Documentation**: https://github.com/fabriziosalmi/certmate

---

## ✨ Key Features

- **🔄 Zero-Downtime Automation** - Auto-renewal 30 days before expiry
- **🌐 22 DNS Providers** - Cloudflare, AWS, Azure, GCP, Hetzner, and more
- **🏛️ Multiple CA Support** - Let's Encrypt, DigiCert ACME, Private CAs
- **💾 Unified Backups** - Atomic snapshots of settings and certificates
- **🔒 Multiple Storage Backends** - Local, Azure Key Vault, AWS Secrets Manager, Vault, Infisical
- **📦 Enterprise Ready** - Multi-account support, REST API, monitoring
- **🚀 Simple Integration** - One-URL certificate downloads

## 🚀 Quick Start

### Docker Compose (Recommended)

```bash
# 1. Create docker-compose.yml
version: '3.8'
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    container_name: certmate
    ports:
      - "8000:8000"
    environment:
      - API_BEARER_TOKEN=your_secure_token_here
      - CLOUDFLARE_TOKEN=your_cloudflare_token  # Or other DNS provider
    volumes:
      - ./data:/app/data
      - ./certificates:/app/certificates
      - ./letsencrypt:/app/letsencrypt
    restart: unless-stopped

# 2. Start the service
docker-compose up -d

# 3. Access the dashboard
open http://localhost:8000
```

### Standalone Docker

```bash
docker run -d \
  --name certmate \
  -p 8000:8000 \
  -e API_BEARER_TOKEN=your_secure_token_here \
  -e CLOUDFLARE_TOKEN=your_token \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/certificates:/app/certificates \
  -v $(pwd)/letsencrypt:/app/letsencrypt \
  fabriziosalmi/certmate:latest
```

## 🌐 Supported DNS Providers

| Provider | Multi-Account | Status |
|----------|--------------|--------|
| Cloudflare | ✅ | ✅ Stable |
| AWS Route53 | ✅ | ✅ Stable |
| Azure DNS | ✅ | ✅ Stable |
| Google Cloud DNS | ✅ | ✅ Stable |
| DigitalOcean | ✅ | ✅ Stable |
| PowerDNS | ✅ | ✅ Stable |
| RFC2136 | ✅ | ✅ Stable |
| Linode | ➖ | ✅ Stable |
| Gandi | ➖ | ✅ Stable |
| OVH | ➖ | ✅ Stable |
| Namecheap | ➖ | ✅ Stable |
| Vultr | ➖ | ✅ Stable |
| DNS Made Easy | ➖ | ✅ Stable |
| NS1 | ➖ | ✅ Stable |
| Hetzner | ➖ | ✅ Stable |
| Porkbun | ➖ | ✅ Stable |
| GoDaddy | ➖ | ✅ Stable |
| Hurricane Electric | ➖ | ✅ Stable |
| Dynu | ➖ | ✅ Stable |
| ArvanCloud | ➖ | ✅ Stable |
| Infomaniak | ➖ | ✅ Stable |
| ACME-DNS | ➖ | ✅ Stable |

## 🏛️ Certificate Authority Providers

- **Let's Encrypt** - Free, automated certificates (default)
- **DigiCert ACME** - Enterprise-grade with EAB support
- **Private CA** - Internal/corporate CAs with ACME

## 💾 Storage Backends

- **Local Filesystem** - Default, secure file storage
- **Azure Key Vault** - Enterprise secret management
- **AWS Secrets Manager** - Scalable AWS integration
- **HashiCorp Vault** - Industry-standard secrets
- **Infisical** - Modern open-source platform

## 📊 API Usage

```bash
# Create certificate
curl -X POST "http://localhost:8000/api/certificates/create" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "email": "admin@example.com"
  }'

# Download certificate (ZIP)
curl "http://localhost:8000/api/certificates/example.com/download" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -o certificate.zip

# Renew certificate
curl -X POST "http://localhost:8000/api/certificates/example.com/renew" \
  -H "Authorization: Bearer YOUR_TOKEN"

# List certificates
curl "http://localhost:8000/api/certificates" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 🔧 Environment Variables

### Required
- `API_BEARER_TOKEN` - Secure API access token

### DNS Provider (choose one)
- **Cloudflare**: `CLOUDFLARE_TOKEN`
- **AWS Route53**: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`
- **Azure**: `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`
- **GCP**: `GOOGLE_PROJECT_ID`, `GOOGLE_APPLICATION_CREDENTIALS`
- **DigitalOcean**: `DIGITALOCEAN_TOKEN`
- **Hetzner**: `HETZNER_API_TOKEN`
- See [documentation](https://github.com/fabriziosalmi/certmate/blob/main/DNS_PROVIDERS.md) for all providers

### Optional
- `SECRET_KEY` - Flask secret key (auto-generated if not set)
- `FLASK_ENV` - Environment mode (default: production)
- `HOST` - Bind address (default: 0.0.0.0)
- `PORT` - Listen port (default: 8000)

## 🔒 Security Best Practices

1. **Strong API Token**: Use 32+ character random token
2. **File Permissions**: Automatic secure permissions (600/700)
3. **Secrets Management**: Use environment variables or storage backends
4. **HTTPS**: Use reverse proxy (nginx/traefik) for production
5. **Network Isolation**: Deploy in private network when possible

## 📦 Volume Mounts

```yaml
volumes:
  - ./data:/app/data              # Settings, cache, audit logs
  - ./certificates:/app/certificates  # SSL certificates
  - ./letsencrypt:/app/letsencrypt   # Let's Encrypt config
  - ./backups:/app/backups           # Backup files (optional)
  - ./logs:/app/logs                 # Application logs (optional)
```

## 🐳 Multi-Platform Support

Images available for:
- `linux/amd64` - x86_64 systems
- `linux/arm64` - ARM64/Apple Silicon

Docker automatically pulls the correct architecture.

## 🔄 Backup & Recovery

CertMate includes unified atomic backups:

```bash
# Create backup via API
curl -X POST "http://localhost:8000/api/backups/create" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"type": "unified"}'

# List backups
curl "http://localhost:8000/api/backups" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Restore from backup
curl -X POST "http://localhost:8000/api/backups/restore/unified" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{"filename": "backup_20240101_120000.tar.gz"}'
```

## 📈 Health Monitoring

```bash
# Health check endpoint
curl http://localhost:8000/health

# Response
{
  "status": "healthy",
  "version": "1.6.0",
  "uptime": "24h 15m",
  "certificates": 42,
  "storage": "local_filesystem"
}
```

## 🆘 Troubleshooting

### Container won't start
```bash
# Check logs
docker logs certmate

# Verify permissions
ls -la data/ certificates/ letsencrypt/
```

### DNS validation fails
- Verify DNS provider credentials
- Check DNS propagation: `dig _acme-challenge.example.com TXT`
- Review logs for specific errors

### Certificate not renewing
- Check auto-renew is enabled in settings
- Verify renewal threshold (default: 30 days)
- Manual renewal: API POST `/api/certificates/{domain}/renew`

## 📚 Documentation

- **GitHub Repository**: https://github.com/fabriziosalmi/certmate
- **Full README**: https://github.com/fabriziosalmi/certmate/blob/main/README.md
- **Installation Guide**: https://github.com/fabriziosalmi/certmate/blob/main/INSTALLATION.md
- **DNS Providers**: https://github.com/fabriziosalmi/certmate/blob/main/DNS_PROVIDERS.md
- **CA Providers**: https://github.com/fabriziosalmi/certmate/blob/main/CA_PROVIDERS.md
- **Multi-Account Setup**: https://github.com/fabriziosalmi/certmate/blob/main/MULTI_ACCOUNT_EXAMPLES.md
- **API Documentation**: http://localhost:8000/docs/

## 🤝 Contributing

Contributions welcome! See [CONTRIBUTING.md](https://github.com/fabriziosalmi/certmate/blob/main/CONTRIBUTING.md)

## 📄 License

MIT License - see [LICENSE](https://github.com/fabriziosalmi/certmate/blob/main/LICENSE)

## 🔗 Links

- **Source Code**: https://github.com/fabriziosalmi/certmate
- **Docker Hub**: https://hub.docker.com/r/fabriziosalmi/certmate
- **Issue Tracker**: https://github.com/fabriziosalmi/certmate/issues
- **Discussions**: https://github.com/fabriziosalmi/certmate/discussions

---

**Made with ❤️ for the DevOps community**
