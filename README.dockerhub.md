# CertMate - SSL Certificate Management System

<div align="center">

<img src="https://raw.githubusercontent.com/fabriziosalmi/certmate/main/certmate_logo.png" alt="CertMate Logo" width="180">

</div>

**CertMate** is an SSL certificate management system for modern infrastructure. Multi-DNS provider support, Docker-ready, comprehensive REST API.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://hub.docker.com/)

 **Full Documentation**: https://github.com/fabriziosalmi/certmate

---

## Key Features

- **Zero-Downtime Automation** - Auto-renewal 30 days before expiry
- **23 DNS Providers** - Cloudflare, AWS, Azure, GCP, Hetzner, SOLIDserver, and more
- **Multiple CA Support** - Let's Encrypt, DigiCert ACME, Private CAs
- **Unified Backups** - Atomic snapshots of settings and certificates
- **Multiple Storage Backends** - Local, Azure Key Vault, AWS Secrets Manager, Vault, Infisical
- **Enterprise Ready** - Multi-account support, REST API, monitoring
- **Simple Integration** - One-URL certificate downloads

## Quick Start

### Docker Compose (recommended)

One file, this image, nothing to build:

```bash
mkdir certmate && cd certmate
curl -fsSLO https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/docker-compose.yml
printf 'API_BEARER_TOKEN=%s\nSECRET_KEY=%s\nCERTMATE_BACKUP_PASSPHRASE=%s\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
```

Open `http://127.0.0.1:8000`. The first page creates the administrator account and asks for the `API_BEARER_TOKEN` from `.env` to authorize it. The file pins the latest release, keeps its data in named volumes and listens on loopback only. [What each setting does, and how to upgrade.](https://github.com/fabriziosalmi/certmate/blob/main/docs/docker.md#production-with-docker-compose)

### Standalone Docker

```bash
docker run -d --name certmate \
  -p 127.0.0.1:8000:8000 \
  -e API_BEARER_TOKEN="$(openssl rand -hex 32)" \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  -v certmate_logs:/app/logs \
  -v certmate_backups:/app/backups \
  fabriziosalmi/certmate:latest
```

Write the two values down (or use an env file): the first-run screen asks for the token, and a new `SECRET_KEY` signs everyone out.

## Supported DNS Providers

| Provider           | Multi-Account | Status |
| ------------------ | ------------- | ------ |
| Cloudflare         |               | Stable |
| AWS Route53        |               | Stable |
| Azure DNS          |               | Stable |
| Google Cloud DNS   |               | Stable |
| DigitalOcean       |               | Stable |
| PowerDNS           |               | Stable |
| RFC2136            |               | Stable |
| Linode             |               | Stable |
| Gandi              |               | Stable |
| OVH                |               | Stable |
| Namecheap          |               | Stable |
| Vultr              |               | Stable |
| DNS Made Easy      |               | Stable |
| NS1                |               | Stable |
| Hetzner            |               | Stable |
| Porkbun            |               | Stable |
| GoDaddy            |               | Stable |
| Hurricane Electric |               | Stable |
| Dynu               |               | Stable |
| ArvanCloud         |               | Stable |
| Infomaniak         |               | Stable |
| ACME-DNS           |               | Stable |

## Certificate Authority Providers

- **Let's Encrypt** - Free, automated certificates (default)
- **DigiCert ACME** - Enterprise-grade with EAB support
- **Private CA** - Internal/corporate CAs with ACME

## Storage Backends

- **Local Filesystem** - Default, secure file storage
- **Azure Key Vault** - Enterprise secret management
- **AWS Secrets Manager** - Scalable AWS integration
- **HashiCorp Vault** - Industry-standard secrets
- **Infisical** - Modern open-source platform

## API Usage

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

## Environment Variables

- `API_BEARER_TOKEN` - Bearer token for the API; the first-run screen asks for it to create the admin. `API_BEARER_TOKEN_FILE` reads it from a file instead and takes precedence
- `SECRET_KEY` - Key that signs login sessions. `SECRET_KEY_FILE` reads it from a file instead and takes precedence
- `CERTMATE_BACKUP_PASSPHRASE` - Without it, automatic backups are masked and cannot restore the instance; with it they are complete and encrypted at rest
- `CLOUDFLARE_TOKEN` - Optional: creates a Cloudflare DNS account on first start
- `LETSENCRYPT_EMAIL` - Optional: overrides the ACME contact email set in the UI
- `BEHIND_PROXY` - `true` when a trusted reverse proxy sets `X-Forwarded-*`
- `PORT` - Listen port inside the container (default 8000)
- `FLASK_ENV` - Environment mode (default: production)

**DNS providers other than Cloudflare are not configured through environment variables.** Route53, Azure, Google Cloud DNS, DigitalOcean, Hetzner and the rest are added in the web UI (Settings → DNS Providers) or through the API. See the [DNS provider guide](https://github.com/fabriziosalmi/certmate/blob/main/docs/dns-providers.md).

The bind address is fixed to `0.0.0.0` inside the container; publish it as `-p 127.0.0.1:8000:8000` to reach it on loopback only.

## Security Best Practices

1. **Strong API Token**: Use 32+ character random token
2. **File Permissions**: Automatic secure permissions (600/700)
3. **Secrets Management**: Use environment variables or storage backends
4. **HTTPS**: Use reverse proxy (nginx/traefik) for production
5. **Network Isolation**: Deploy in private network when possible

## Volume Mounts

| Path | Holds |
| --- | --- |
| `/app/certificates` | Certificates and their private keys |
| `/app/data` | Settings, users, inventory, audit chain |
| `/app/backups` | Backup archives |
| `/app/logs` | Application logs |

Use named volumes: Docker creates them with the ownership CertMate needs. A bind mount to a host directory must be prepared first (`chgrp -R 0 <dir> && chmod -R g+rwX <dir>`), because CertMate runs as a non-root user and refuses to start on a directory it cannot write.

## Multi-Platform Support

Images available for:
- `linux/amd64` - x86_64 systems
- `linux/arm64` - ARM64/Apple Silicon

Docker automatically pulls the correct architecture.

## Backup & Recovery

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

## Health Monitoring

```bash
# Health check endpoint
curl http://localhost:8000/health

# Response
{
 "status": "healthy",
 "version": "2.45.0",
 "checks": {
  "cert_dir": "ok",
  "disk_space": "ok",
  "disk_free_mb": 94504,
  "scheduler": "running"
 }
}
```

## Troubleshooting

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

## Documentation

- **GitHub Repository**: https://github.com/fabriziosalmi/certmate
- **Full README**: https://github.com/fabriziosalmi/certmate/blob/main/README.md
- **Installation Guide**: https://github.com/fabriziosalmi/certmate/blob/main/docs/installation.md
- **DNS Providers**: https://github.com/fabriziosalmi/certmate/blob/main/docs/dns-providers.md
- **CA Providers**: https://github.com/fabriziosalmi/certmate/blob/main/docs/ca-providers.md
- **Multi-Account Setup**: https://github.com/fabriziosalmi/certmate/blob/main/docs/dns-providers.md#multi-account-support
- **API Documentation**: http://localhost:8000/docs/

## Contributing

Contributions welcome! See [CONTRIBUTING.md](https://github.com/fabriziosalmi/certmate/blob/main/CONTRIBUTING.md)

## License

MIT License - see [LICENSE](https://github.com/fabriziosalmi/certmate/blob/main/LICENSE)

## Links

- **Source Code**: https://github.com/fabriziosalmi/certmate
- **Docker Hub**: https://hub.docker.com/r/fabriziosalmi/certmate
- **Issue Tracker**: https://github.com/fabriziosalmi/certmate/issues
- **Discussions**: https://github.com/fabriziosalmi/certmate/discussions

---
