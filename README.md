# CertMate - Certificate Lifecycle Management

<div align="center">

<img src="certmate_logo.png" alt="CertMate Logo" width="180">

**CertMate** is a self-hosted certificate lifecycle management platform: it issues and renews TLS certificates, **discovers the ones you did not issue**, keeps a single inventory of what exists across your estate — what is served where, who issued it, when it expires, which cryptography it uses — and deploys renewed certificates to where they are needed. It supports 29 DNS providers, runs its own private CA for internal names, keeps a tamper-evident audit trail of every operation, and exposes all of it through a REST API.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-try%20it%20now-2563eb?logo=probot&logoColor=white)](https://demo.certmate.org)
[![Video Guide](https://img.shields.io/badge/Video%20Guide-CertMate%20in%2060%20seconds-FF0000?logo=youtube&logoColor=white)](https://www.youtube.com/playlist?list=PLM-wnWN4g5XA)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://hub.docker.com/)
[![API Documentation](https://img.shields.io/badge/API-Swagger-green)](#api-usage)
[![PyPI - certmate-cli](https://img.shields.io/pypi/v/certmate-cli?label=certmate-cli&color=3775A9)](https://pypi.org/project/certmate-cli/)
[![CI](https://github.com/fabriziosalmi/certmate/actions/workflows/ci.yml/badge.svg)](https://github.com/fabriziosalmi/certmate/actions/workflows/ci.yml)
[![Build Multi-Platform Docker Images](https://github.com/fabriziosalmi/certmate/actions/workflows/docker-multiplatform.yml/badge.svg)](https://github.com/fabriziosalmi/certmate/actions/workflows/docker-multiplatform.yml)
[![CodeQL](https://github.com/fabriziosalmi/certmate/actions/workflows/codeql.yml/badge.svg)](https://github.com/fabriziosalmi/certmate/actions/workflows/codeql.yml)
[![OSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/fabriziosalmi/certmate/badge)](https://securityscorecards.dev/viewer/?uri=github.com/fabriziosalmi/certmate)
[![codecov](https://codecov.io/gh/fabriziosalmi/certmate/branch/main/graph/badge.svg)](https://codecov.io/gh/fabriziosalmi/certmate)
[![European Open Source](https://img.shields.io/badge/European%20Open%20Source-Catalogue-0046ad)](https://europeanopensource.eu/)
[![Listed on Hacker News](https://img.shields.io/badge/Listed%20on-Hacker%20News-F0652F)](https://news.ycombinator.com/item?id=44427452)
[![Listed on Reddit](https://img.shields.io/badge/Listed%20on-Reddit-FF4500)](https://www.reddit.com/r/selfhosted/comments/1lkvbcj/ssl_certificates_automation/)
[![Shared on Mastodon](https://img.shields.io/badge/Shared%20on-Mastodon-6364FF)](https://mastodon.social/@nixCraft/114799880340326467)
[![As seen on LinkedIn](https://img.shields.io/badge/As%20seen%20on-LinkedIn-0A66C2)](https://www.linkedin.com/posts/labyrinthlabs_github-fabriziosalmicertmate-ssl-certificate-activity-7434531689097248768-Ac63)
 
![screenshot1](screenshot_1.png)

[Quick Start](#quick-start-with-docker) • [Video Guide](https://www.youtube.com/playlist?list=PLM-wnWN4g5XA) • [CLI](#command-line-interface) • [Documentation](#documentation) • [Installation](#installation-methods) • [DNS Providers](#supported-dns-providers) • [CA Providers](docs/ca-providers.md) • [Storage Backends](#certificate-storage-configuration) • [Backup and Recovery](#backup-and-recovery) • [API Reference](#api-usage)

</div>

---

## Ecosystem

CertMate is the open-source core of a small, focused toolset:

- **[certmate-tools](https://github.com/fabriziosalmi/certmate-tools)** — free, privacy-first, client-side TLS / certificate / ACME diagnostics (runs entirely in your browser).
- **[certmate-agent](https://github.com/fabriziosalmi/certmate-agent)** — conversational assistant over the docs.
- **[nis2-public](https://github.com/fabriziosalmi/nis2-public)** — NIS2 continuous posture management & remediation.

**Enterprise / high-scale** — multi-tenant, mTLS, white-label and NIS2-aligned deployments are available through *CertMate-ng* (source-available, BSL 1.1, EU-built). For access or a deployment discussion, email **fabrizio.salmi@gmail.com**.

---

## Command-line interface

The whole certificate lifecycle from your terminal — `pip install certmate-cli`:

![CertMate CLI — the full SSL certificate lifecycle from the terminal](demo/certmate-cli.gif)

```bash
pip install certmate-cli

export CERTMATE_URL=https://certmate.example.com
export CERTMATE_TOKEN=...                 # omit on a fresh (setup-mode) instance

certmate health
certmate cert create app.example.com --dns cloudflare --wait   # issue, block until live
certmate cert ls
certmate cert info app.example.com
certmate audit verify
```

`certmate-cli` is a thin layer over **`certmate-sdk`** (`pip install certmate-sdk`) — a small,
`httpx`-based Python client for the same REST API the web UI and MCP server drive. Both are
first-party, live in [`clients/`](clients/), and are published to PyPI. The clip above is a real
issuance over DNS-01 (Let's Encrypt staging); see [`demo/`](demo/).

---

## AI agents (MCP server)

CertMate ships a first-party **Model Context Protocol** server, so an assistant like Claude can
drive the same REST API the web UI and the CLI use — with the same auth and the same audit trail.
It lives in [`mcp/`](mcp/), is Node.js (>= 20), and exposes **16 tools**: inventory and status
(`certmate_list_certificates`, `certmate_get_certificate`, `certmate_diagnostics`,
`certmate_get_activity`, …), lifecycle operations (`certmate_create_certificate`,
`certmate_renew_certificate`, `certmate_get_job`, `certmate_set_auto_renew`, …), and delivery
(`certmate_download_certificate`, `certmate_deploy_certificate`).

```bash
cd mcp && npm install
```

```jsonc
// claude_desktop_config.json — or any MCP-capable client
{
  "mcpServers": {
    "certmate": {
      "command": "node",
      "args": ["/path/to/certmate/mcp/index.js"],
      "env": {
        "CERTMATE_URL": "https://certmate.example.com",
        "CERTMATE_TOKEN": "<a scoped API key with is_agent: true>"
      }
    }
  }
}
```

**Give it a scoped key, not your admin token.** A key created with `is_agent: true` (a checkbox
under Settings → API Keys, or `is_agent` in `POST /api/keys`) makes every action the agent takes
land in the audit chain as `actor.kind="agent"` rather than being indistinguishable from a human
operator — which is the difference between an audit trail and a rumour. Scope the key to the
domains the agent is allowed to touch.

Full tool reference, attribution model and safety notes: **[docs/mcp.md](docs/mcp.md)**.

---

## Why CertMate?

CertMate solves the complexity of SSL certificate management in modern distributed architectures. Whether you're running a single application or managing certificates across multiple datacenters, CertMate provides:

- **Zero-Downtime Automation** - Certificates renew automatically (30 days before expiry by default; earlier in the life of a certificate that lives under 60 days — see [when a certificate renews](docs/guide.md#when-a-certificate-renews)), with deploy hooks to reload services
- **Multi-Cloud Support** - Cloudflare, AWS, Azure, GCP, Akamai Edge DNS, Hetzner, Porkbun, GoDaddy and the rest — [docs/dns-providers.md](docs/dns-providers.md) has the full list
- **Enterprise-Ready** - RBAC, scoped API keys, Docker, Kubernetes, REST API, and monitoring built-in
- **Simple Integration** - One-URL certificate downloads for easy automation
- **Security-First** - Role-based access control, scoped API keys, audit logging, HMAC-signed webhooks
- **Unified Backup System** - Atomic backups of settings and certificates ensuring data consistency
- **Real-Time Dashboard** - SSE-powered live updates, command palette, keyboard shortcuts, dark mode

> **CertMate runs as a single instance.** Its renewal scheduler runs inside the
> web process, so a second replica is a second scheduler issuing against the
> same certificate store — duplicate ACME orders, and the CA's
> duplicate-certificate rate limit. The Helm chart refuses to render more than
> one replica rather than let that happen quietly.
>
> This is a deliberate design choice, not a missing feature: one writer is what
> makes certificate state safe without a distributed lock service. It scales
> *up* (a single instance manages thousands of certificates across many
> datacenters), not *out*. For availability, run active/standby with the data
> volume on shared storage and fail over — see
> [Availability and failover](docs/architecture.md#availability-and-failover).

## Key Features

### **Certificate Management**
- **Multiple CA Providers** - Support for Let's Encrypt, ZeroSSL, Google Trust Services, Actalis, DigiCert ACME, Sectigo, SSL.com, and Private CAs
- **Let's Encrypt Integration** - Free, automated SSL certificates, with the staging environment available as a dedicated CA entry for testing
- **DigiCert ACME Support** - Enterprise-grade certificates with External Account Binding (EAB)
- **Actalis Support** - Free 90-day DV certificates from a European CA via ACME with EAB
- **Private CA Support** - Internal/corporate CAs with custom trust bundles and ACME compatibility
- **Wildcard Support** - Single certificate for `*.example.com` and `example.com`
- **Multi-Domain Certificates** - SAN certificates for multiple domains
- **DNS Alias via CNAME Delegation** - Delegate ACME DNS validation to an alternative domain using standard CNAME records
- **Automatic Renewal** - One rule for every lifetime, and the CA's renewal window (ARI) can move it; each certificate says when it renews (`renews_at`)
- **Certificate Validation** - Real-time SSL certificate status checking
- **Per-Certificate CA Selection** - Choose different CAs for different certificates
- **Zombie Certificate Scanner** - multi-threaded probe that asks whether the names in your managed certificates still resolve and answer, so a domain you have let go is visible before its renewals start failing

### **Multi-DNS Provider Support**
- **Multi-Account Support** - Manage multiple accounts per provider for enterprise environments
- **Cloudflare** - Global CDN with edge locations worldwide (Multi-Account)
- **AWS Route53** - Amazon's scalable DNS service (Multi-Account)
- **Azure DNS** - Microsoft's cloud DNS solution (Multi-Account)
- **Google Cloud DNS** - Google's high-performance DNS (Multi-Account)
- **DigitalOcean** - Cloud infrastructure DNS (Multi-Account)
- **PowerDNS** - Open-source DNS server with REST API (Multi-Account)

### **Enterprise Features**
- **Role-Based Access Control** - Three-tier RBAC with viewer, operator, and admin roles
- **Scoped API Keys** - Create, revoke, and manage API keys with per-key role and optional expiration
- **Multi-Account Management** - Support multiple accounts per DNS provider for enterprise workflows
- **REST API** - Complete programmatic control with Swagger/OpenAPI docs
- **Web Dashboard** - Modern, responsive UI built with Tailwind CSS and Alpine.js
- **Setup Wizard** - Guided first-run configuration for DNS, CA, and authentication
- **Real-Time Updates** - Server-Sent Events (SSE) push live status to the dashboard
- **Docker Ready** - Full containerization with Docker Compose
- **Kubernetes Compatible** - Deploy in any Kubernetes cluster
- **Monitoring Integration** - Health checks, Prometheus metrics, and structured JSON logging

### **Backup and Recovery**
- **Unified Backups** - Atomic snapshots of both settings and certificates ensuring data consistency
- **Automatic Backups** - Settings and certificates backed up automatically on changes
- **Manual Backup Creation** - On-demand backup creation via web UI or API
- **Comprehensive Coverage** - Backs up DNS configurations, certificates, and application settings
- **Retention Management** - 50 most recent archives per type, and nothing older than 30 days — both constants; keep disaster-recovery archives off the host
- **Easy Restore** - Simple restore process from any backup point with atomic consistency
- **Download Support** - Export backups for external storage and disaster recovery

### **Certificate Storage Backends**
- **Local Filesystem** - Default secure local storage with proper file permissions (600/700)
- **Azure Key Vault** - Enterprise-grade secret management with Azure integration and HSM protection
- **AWS Secrets Manager** - Scalable secret storage with AWS ecosystem integration and cross-region replication
- **HashiCorp Vault** - Industry-standard secret management with versioning, audit logging, and fine-grained policies
- **Infisical** - Modern open-source secret management with team collaboration and end-to-end encryption
- **S3-Compatible Object Storage** - One backend for any S3 endpoint via a configurable endpoint URL (Hetzner, Contabo, OVHcloud, Scaleway, Exoscale, Wasabi, MinIO, AWS) — ideal for EU-sovereign object storage; no extra dependency
- **Pluggable Architecture** - Easy to extend with additional storage backends
- **Migration Support** - Seamless migration between storage backends without downtime
- **Backward Compatibility** - Existing installations continue working without changes

### **Notifications & Automation**
- **Multi-Channel Notifications** - Email (SMTP), Slack, Discord, Google Chat, Telegram, ntfy, Gotify, and generic webhooks
- **Webhook HMAC Signatures** - SHA-256 signed payloads for secure webhook verification
- **Deploy Hooks** - Post-issuance shell commands to reload Nginx/Apache or run custom scripts
- **Expiry Warnings** - `certificate_expiring` at 14/7/3/1 days (at the renewal threshold when auto-renew is off), and `domain_expiring` for the domain registration itself at 60/30/14/7/1 days. Each threshold is announced once per expiry date
- **Weekly Digest** - Scheduled email summary of certificate status and upcoming renewals
- **SSE Real-Time Events** - Live push updates for certificate operations and deploy hook results

### **Security & Compliance**
- **Role-Based Access Control** - Viewer, operator, and admin roles with hierarchical permissions
- **Scoped API Keys** - Create keys with specific roles and optional expiration dates
- **Bearer Token Authentication** - Secure API access control
- **File Permissions** - Proper certificate file security (600/700)
- **Audit Logging** - Complete certificate lifecycle tracking with timeline view
- **Environment Variables** - Secure credential management
- **Rate Limit Handling** - Let's Encrypt rate limit awareness
- **Log Sanitizer** - Automatically redacts sensitive parameters, private keys, and API tokens from application logs

### **User Interface**
- **Command Palette** - Cmd+K / Ctrl+K quick search and navigation
- **Keyboard Shortcuts** - Power-user shortcuts for navigation and common actions
- **Dark Mode** - System-aware dark/light theme toggle
- **Mobile-Friendly** - Responsive layout with bottom tab bar on small screens
- **Activity Timeline** - Chronological view of all certificate and system events

### **Developer Experience**
- **One-URL Downloads** - Simple certificate retrieval for automation (`/api/certificates/{domain}/download`)
- **Individual Component Downloads** - Fetch cert, key, chain, or fullchain separately
- **Multiple Output Formats** - PEM, ZIP, individual files
- **SDK Examples** - Python, Bash, Ansible, Terraform examples
- **Webhook Support** - Certificate lifecycle notifications with HMAC verification
- **Deploy Hook API** - Configure and test post-issuance hooks via REST API
- **Backup API** - Programmatic backup creation and restoration
- **Swagger & ReDoc** - Interactive API documentation at `/docs/` and `/redoc/`
- **Model Context Protocol (MCP) Server** - Built-in Node.js MCP server providing tools for agentic AI assistants to manage certificates and run diagnostics

## Supported DNS Providers

CertMate supports a wide range of DNS providers through Let's Encrypt DNS-01 challenge via individual certbot plugins that provide reliable, well-tested DNS challenge support. The complete list is in the table below. **Multi-account support** is available for major providers, enabling enterprise-grade deployments with separate accounts for production, staging, and disaster recovery.

| Provider               | Credentials Required          | Multi-Account | Use Case                        | Availability |
| ---------------------- | ----------------------------- | ------------- | ------------------------------- | ------------ |
| **Cloudflare**         | API Token                     | **Yes**       | Global CDN, Free tier available | **Stable** |
| **AWS Route53**        | Access Key, Secret Key        | **Yes**       | AWS infrastructure, Enterprise  | **Stable** |
| **Azure DNS**          | Service Principal credentials | **Yes**       | Microsoft ecosystem             | **Stable** |
| **Google Cloud DNS**   | Service Account JSON          | **Yes**       | Google Cloud Platform           | **Stable** |
| **DigitalOcean**       | API Token                     | **Yes**       | Cloud infrastructure            | **Stable** |
| **PowerDNS**           | API URL, API Key              | **Yes**       | Self-hosted, On-premises        | **Separate install** |
| **EfficientIP SOLIDserver** | Host, API Credentials     | **Yes**       | Enterprise DDI / Smart Architecture | **Stable** |
| **RFC2136**            | Nameserver, TSIG Key/Secret   | **Yes**       | Standard DNS update protocol    | **Stable** |
| **Linode** (Akamai Connected Cloud) | API Key             | Single        | Cloud hosting                   | **Stable** |
| **Akamai Edge DNS**    | EdgeGrid (.edgerc) credentials| Single        | Enterprise managed DNS          | **Stable** |
| **Gandi**              | API Token                     | Single        | Domain registrar                | **Stable** |
| **OVH**                | API Credentials               | Single        | European hosting                | **Stable** |
| **Namecheap**          | Username, API Key             | Single        | Domain registrar                | **Unavailable** |
| **Vultr**              | API Key                       | Single        | Global cloud infrastructure     | **Stable** |
| **DNS Made Easy**      | API Key, Secret Key           | Single        | Enterprise DNS management       | **Stable** |
| **NS1**                | API Key                       | Single        | Intelligent DNS platform        | **Stable** |
| **Hetzner** (legacy DNS) | API Token                   | Single        | European cloud hosting          | **Stable** |
| **Hetzner Cloud**      | API Token                     | Single        | Hetzner Cloud DNS (hcloud)      | **Stable** |
| **Porkbun**            | API Key, Secret Key           | Single        | Domain registrar with DNS       | **Stable** |
| **GoDaddy**            | API Key, Secret               | Single        | Popular domain registrar        | **Stable** |
| **Hurricane Electric** | Username, Password            | Single        | Free DNS hosting                | **Extended image** |
| **Dynu**               | API Token                     | Single        | Dynamic DNS service             | **Extended image** |
| **ArvanCloud**         | API Key                       | Single        | Iranian cloud provider          | **Stable** |
| **Infomaniak**         | API Token                     | Single        | Swiss ISP & cloud provider      | **Stable** |
| **ACME-DNS**           | JSON Config                   | Single        | Generic ACME-DNS server         | **Stable** |
| **Scaleway**           | API Token (secret key)        | Single        | European cloud (EU-sovereign)   | **Separate install** |
| **deSEC**              | API Token                     | Single        | Free, non-profit DNSSEC DNS     | **Stable** |
| **DuckDNS**            | Token                         | Single        | Free dynamic DNS                | **Stable** |
| **Custom Script**      | User-provided hook scripts    | Single        | Any provider via custom hooks   | **Stable** |

**What the availability column means.** Until now it said `Stable` on all
twenty-nine rows, which is not a status — a column with one value cannot be
wrong about any particular provider, and four of them were wrong:

| Value | Meaning |
| ----- | ------- |
| **Stable** | The plugin is pinned in `requirements.txt`, so it is in the default image. |
| **Extended image** | Pinned in `requirements-extended.txt`. Build with `--build-arg EXTRA_REQUIREMENTS=requirements-extended.txt`. |
| **Separate install** | Not shipped in any image. Build a derived image that installs it (below), in its own environment where noted. |
| **Unavailable** | No usable plugin exists for the supported stack. CertMate can be configured for it, but issuance will fail. |

`Namecheap` is the **Unavailable** one: the only release on PyPI is
`certbot-dns-namecheap` 1.0.0, an alpha targeting Python 2.7-3.8, incompatible
with certbot 2.x on Python 3.12 — as `NamecheapStrategy`'s own docstring has
said all along. Use ACME-DNS or the custom-script hook for Namecheap domains.
`Scaleway` is alpha (0.0.7, declares Python 2.7 support) and `PowerDNS` pulls
`dns-lexicon<=3.5.6`, which conflicts with the rest of the extended set — hence
its own environment.

The image ships no pip, so a separately installed plugin goes into a derived
image, which puts a pip back for its own build only:

```dockerfile
FROM fabriziosalmi/certmate:latest
USER root
RUN /opt/venv/bin/python -m ensurepip && \
    /opt/venv/bin/python -m pip install --no-cache-dir certbot-dns-scaleway==0.0.7 && \
    /opt/venv/bin/python -m pip uninstall -y pip
USER certmate
```

`certbot plugins` inside that image then lists `dns-scaleway`.

### Provider Categories

- **Enterprise Multi-Account**: Cloudflare, AWS Route53, Azure DNS, Google Cloud DNS, DigitalOcean, PowerDNS, RFC2136
- **Cloud Providers**: AWS Route53, Azure DNS, Google Cloud DNS, DigitalOcean, Linode, Akamai Edge DNS, Vultr, Hetzner
- **Enterprise DNS**: Cloudflare, DNS Made Easy, NS1, PowerDNS, EfficientIP SOLIDserver
- **Domain Registrars**: Gandi, OVH, Namecheap, Porkbun, GoDaddy 
- **European Providers**: OVH, Gandi, Hetzner
- **Free Services**: Hurricane Electric, Dynu
- **Standard Protocols**: RFC2136 (for BIND and compatible servers)

### Multi-Account Benefits

For supported providers, you can configure multiple accounts to enable:

- **Environment Separation**: Different accounts for production, staging, and development
- **Multi-Region Management**: Separate accounts for different geographical regions
- **Team Isolation**: Department-specific accounts with tailored permissions
- **Disaster Recovery**: Backup accounts for high-availability scenarios
- **Permission Scoping**: Accounts with minimal required permissions for security

> **Detailed Setup Instructions**: See [DNS Providers Guide](docs/dns-providers.md) for provider-specific configuration. 
> **Step-by-Step Installation**: See [Installation Guide](docs/installation.md) for complete setup guide. 
> **Multi-Account Examples**: See [DNS Providers Guide](docs/dns-providers.md#multi-account-support) for enterprise configuration examples.

## Quick Start with Docker

Get CertMate running in under 5 minutes with Docker Compose. One file, the published image, nothing to clone or build.

### Prerequisites
- Docker 20.10+ with Docker Compose v2 (`docker compose`)
- A domain with DNS managed by a supported provider

### 1. Download and configure

```bash
mkdir certmate && cd certmate
curl -fsSLO https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/docker-compose.yml
printf 'API_BEARER_TOKEN=%s\nSECRET_KEY=%s\nCERTMATE_BACKUP_PASSPHRASE=%s\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
```

`.env` now holds the three secrets CertMate needs: the API token (also asked once by the first-run screen to create the admin), the session signing key, and the backup passphrase. Optionally add `CLOUDFLARE_TOKEN=...` to bootstrap a Cloudflare DNS account; every other DNS provider is configured in the web UI. What each setting does, and how to upgrade: [docs/docker.md](docs/docker.md#production-with-docker-compose).

> **Storage Backends**: By default, certificates are stored locally. For enterprise deployments, you can configure Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical, or any S3-compatible object storage via the web interface after startup. See [Storage Backends](#certificate-storage-configuration) for details.

> **Backup Best Practices**: CertMate includes a unified backup system that creates atomic snapshots of both settings and certificates. **Set `CERTMATE_BACKUP_PASSPHRASE`.** With it, every automatic backup is complete and encrypted at rest, so it can actually restore this instance; without it, automatic backups keep their credentials masked and are configuration snapshots that cannot. The backup list marks which archives can restore, and Settings disables Restore on the ones that cannot. Then keep a copy off the host — archives on the host are pruned after 30 days, and a lost volume takes them with it. `POST /api/backups/upload` brings one back.

### 2. Start

```bash
docker compose up -d
docker compose ps
docker compose logs -f certmate
```

CertMate listens on `127.0.0.1:8000` only. For remote access, put a reverse proxy in front and set `BEHIND_PROXY=true` in `.env`.

To build from source instead, clone the repository and use its root `docker-compose.yml` (development).

### 3. Access CertMate

| Service                  | URL                          | Description                           |
| ------------------------ | ---------------------------- | ------------------------------------- |
| **Web Dashboard**        | http://localhost:8000        | Main certificate management interface |
| **API Documentation**    | http://localhost:8000/docs/  | Interactive Swagger/OpenAPI docs      |
| **Alternative API Docs** | http://localhost:8000/redoc/ | ReDoc documentation                   |
| **Health Check**         | http://localhost:8000/health | Service health monitoring             |

### 4. Create Your First Certificate

Using the Web Interface:
1. Navigate to http://localhost:8000
2. Go to Settings and configure your DNS provider
3. Add your domain (e.g. `example.com`)
4. Click "Create Certificate"

Using the API:
```bash
curl -X POST "http://localhost:8000/api/certificates/create" \
 -H "Authorization: Bearer your_api_token_here" \
 -H "Content-Type: application/json" \
 -d '{"domain": "example.com"}'
```

## Installation Methods

Choose the installation method that best fits your environment:

### Docker (Recommended)
Isolated, reproducible, and the way CertMate is tested and released. Run **one**
container (see the single-instance note above); give it more CPU and memory
rather than more replicas. **Published images cover two architectures**: AMD64 (Intel/AMD) and ARM64 (Apple Silicon, ARM servers). ARM v7 (32-bit Raspberry Pi) is not published; build it yourself with `docker buildx build --platform linux/arm/v7 -t YOUR_DOCKERHUB_USERNAME/certmate:armv7 --push .` (see [Docker](docs/docker.md#manual-docker-buildx)).

The production Compose bundle is one file that runs the published image; the [Quick Start](#quick-start-with-docker) above shows the commands. To build the image yourself instead, clone the repository and run `docker compose up -d` with its root `docker-compose.yml`, after preparing its bind-mounted directories as its comments describe.

**Multi-Platform Support:**
```bash
# Build for multiple architectures (ARM64 + AMD64); add --push to publish the result
docker buildx build --platform linux/amd64,linux/arm64 -t YOUR_DOCKERHUB_USERNAME/certmate:latest .

# Build and push to Docker Hub for all platforms
docker buildx build --platform linux/amd64,linux/arm64 -t YOUR_DOCKERHUB_USERNAME/certmate:latest --push .

# Use pre-built multi-platform image (bound to localhost; put it behind a
# reverse proxy and enable authentication before exposing it externally)
docker run --platform linux/arm64 -d --name certmate --env-file .env -p 127.0.0.1:8000:8000 fabriziosalmi/certmate:latest
```

> **Multi-Platform Guide**: See [Docker Guide](docs/docker.md) for comprehensive multi-architecture setup instructions.

### Python Virtual Environment
Ideal for development and testing environments.

```bash
# Create and activate virtual environment
python3 -m venv certmate-env
source certmate-env/bin/activate # On Windows: certmate-env\Scripts\activate

# Install dependencies
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
pip install -r requirements.txt

# Set environment variables
export API_BEARER_TOKEN="your_token_here"
export CLOUDFLARE_TOKEN="your_cloudflare_token"

# Run the application
python app.py
```

### Kubernetes
For container orchestration and managed rollouts. **`replicas: 1` is not an
example value** — it is the supported configuration, and the Helm chart fails at
template time if you change it.

Install the Helm chart, published to GHCR on every release:

```bash
kubectl create namespace certmate
kubectl -n certmate create secret generic certmate-secrets \
  --from-literal=API_BEARER_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=CERTMATE_BACKUP_PASSPHRASE="$(openssl rand -hex 32)"
helm install certmate oci://ghcr.io/fabriziosalmi/charts/certmate \
  --namespace certmate --set secrets.existingSecret=certmate-secrets
```

[CertMate on Kubernetes](docs/kubernetes.md) covers the first login, Argo CD and Flux, production sizing and OOM troubleshooting. Every chart value is in the [chart README](charts/certmate/README.md).

### Linux server with systemd
One command on Debian, Ubuntu, Fedora, RHEL, Rocky or Alma Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/install.sh | sudo sh
```

The installer puts CertMate in `/opt/certmate` with its own Python 3.12 (fetched by [uv](https://docs.astral.sh/uv/), so the system Python is not touched), generates the secrets into `/etc/certmate/certmate.env`, and starts the `certmate` systemd service on `127.0.0.1:8000`. Run it again to upgrade: certificates, data and configuration stay. Details and options: [docs/installation.md](docs/installation.md#linux-server-with-systemd).

To set the service up by hand instead, follow the next section.

## Service Setup

For production deployments, CertMate should run as a system service. This section provides comprehensive instructions for setting up CertMate with systemd on Linux distributions.

### Prerequisites

- Linux system with systemd
- Python 3.12
- Root/sudo access

### 1. Create Dedicated System User

Create a dedicated user for running CertMate:

```bash
# Create system user and group
sudo useradd --system --shell /bin/false --home-dir /opt/certmate --create-home certmate

# Set proper ownership
sudo chown -R certmate:certmate /opt/certmate
```

### 2. Prepare Application Directory

Set up the application in `/opt/certmate`:

```bash
# Clone straight into the path. `useradd --create-home` above populated
# /opt/certmate from /etc/skel, so it is not empty and `mv certmate /opt/`
# fails with "Directory not empty" — leaving the next steps to run in a
# directory with no application in it.
sudo -u certmate git clone https://github.com/fabriziosalmi/certmate.git /opt/certmate
cd /opt/certmate

# Create Python virtual environment
sudo -u certmate python3 -m venv venv
sudo -u certmate ./venv/bin/pip install -r requirements.txt

# Create necessary directories. All four: the startup writeability probe
# in modules/factory.py checks certificates, data, backups AND logs,
# and raises at boot if any of them is not writable.
sudo -u certmate mkdir -p certificates data backups logs
```

### 3. Configure Environment Variables

Create environment file for the service:

```bash
# Create environment file
# The unit reads /etc/certmate/certmate.env (see certmate.service), not a
# .env in the application directory.
sudo install -d -m 750 /etc/certmate
sudo tee /etc/certmate/certmate.env > /dev/null <<EOF
# SECURITY: Change this token!
API_BEARER_TOKEN=your_super_secure_api_token_here_change_this
EOF

# PORT has no effect here: the port is the literal in the unit's ExecStart
# (--bind 0.0.0.0:8000), and nothing in the application reads PORT under
# gunicorn. To change it, edit ExecStart. PORT is honoured only by the
# container image.

# Set proper permissions
sudo chown root:certmate /etc/certmate/certmate.env
sudo chmod 640 /etc/certmate/certmate.env
```

### 4. Install systemd Service

Install and configure the systemd service:

```bash
# Copy service file
sudo cp /opt/certmate/certmate.service /etc/systemd/system/

# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable certmate

# Start the service
sudo systemctl start certmate
```

### 5. Verify Service Status

Check that the service is running correctly:

```bash
# Check service status
sudo systemctl status certmate

# View recent logs
sudo journalctl -u certmate --lines=50

# Follow logs in real-time
sudo journalctl -u certmate -f
```

### 6. Service Management Commands

Common commands for managing the CertMate service:

```bash
# Start service
sudo systemctl start certmate

# Stop service
sudo systemctl stop certmate

# Restart service
sudo systemctl restart certmate

# Reload service configuration
sudo systemctl reload certmate

# Check if service is enabled
sudo systemctl is-enabled certmate

# Check if service is active
sudo systemctl is-active certmate

# Disable service from starting on boot
sudo systemctl disable certmate
```

### 7. File Permissions

Ensure proper file permissions for security:

```bash
# Set ownership
sudo chown -R certmate:certmate /opt/certmate

# Set directory permissions
sudo chmod 755 /opt/certmate
sudo chmod 750 /opt/certmate/certificates /opt/certmate/data /opt/certmate/backups /opt/certmate/logs

# Set file permissions
sudo chmod 644 /opt/certmate/*.py /opt/certmate/*.md
sudo chmod 640 /etc/certmate/certmate.env
sudo chmod 755 /opt/certmate/venv/bin/*
```

### Security Notes

- **API Bearer Token**: Always change the default API bearer token in `/etc/certmate/certmate.env`
- **File Permissions**: The service runs with restricted permissions and limited filesystem access
- **Network Access**: The service binds to `0.0.0.0:8000` by default - consider using a reverse proxy for production
- **Environment File**: The `.env` file contains sensitive data and should be readable only by the `certmate` user
- **Certificates**: Generated certificates are stored in `/opt/certmate/certificates` with restricted access

### Troubleshooting Service Setup

If the service fails to start:

1. **Check service status**: `sudo systemctl status certmate`
2. **View logs**: `sudo journalctl -u certmate --lines=100`
3. **Verify permissions**: Ensure the `certmate` user can read all necessary files
4. **Test manually**: `sudo -u certmate /opt/certmate/venv/bin/python /opt/certmate/app.py`
5. **Check dependencies**: `sudo -u certmate /opt/certmate/venv/bin/certbot --version` — the ACME client is the dependency that breaks first when the pins drift.

For more detailed installation instructions, see the [Installation Guide](docs/installation.md).

## Single Sign-On (OIDC/SSO)

Signing in through an OpenID Connect provider (Keycloak, Authentik, Okta, Google Workspace, Microsoft Entra), mapping its groups to CertMate roles, and how accounts are provisioned and linked are in [docs/sso.md](docs/sso.md).

## API Usage

The REST API is documented in [docs/api.md](docs/api.md): the endpoints, the
role each one needs, request and response shapes, and examples, including a
script that installs a certificate and reloads nginx. A running instance also
serves its OpenAPI description at `/api/swagger.json` and Swagger UI at
`/docs/`. From a terminal or from Python, use the [CLI and SDK](clients/README.md);
for AI agents, the [MCP server](docs/mcp.md).

The two calls most automation needs, issuing a certificate and fetching one of
its files:

```
POST /api/certificates/create
GET  /api/certificates/{domain}/download/{cert|chain|fullchain|privkey|combined}
```

## Configuration Guide

### Environment Variables

| Variable           | Required | Default        | Description                         |
| ------------------ | -------- | -------------- | ----------------------------------- |
| `API_BEARER_TOKEN`      |          | auto-generated | Bearer token for API authentication |
| `API_BEARER_TOKEN_FILE` |          | -              | Path to a file containing the API bearer token (takes precedence over `API_BEARER_TOKEN`) |
| `SECRET_KEY`            |          | auto-generated | Flask secret key for sessions       |
| `SECRET_KEY_FILE`       |          | -              | Path to a file containing the Flask secret key (takes precedence over `SECRET_KEY`). **If set and unreadable or empty, CertMate refuses to start** rather than inventing one: a secret that failed to mount is a configuration error, and a fresh key would sign out every user on every restart |
| `PORT`             |          | `8000`         | Server port (honoured by the container entrypoint) |
| `FLASK_ENV`        |          | `production`   | Flask environment. `production` refuses `--debug`  |
| `CERTMATE_LOG_FILE` |         | -              | Also write logs to this path. Off by default: the container logs to stdout, which is what `docker logs` and log shippers expect. Set it (e.g. `/app/logs/certmate.log`) to keep a file on the mounted volume — it is what the web UI's log stream reads |
| `CERTMATE_LOG_MAX_BYTES` |    | `10485760`     | Rotate the log file at this size (10 MB). File logging is always rotated — there is no way to configure an unbounded one |
| `CERTMATE_LOG_BACKUP_COUNT` | | `5`            | How many rotated files to keep (~60 MB ceiling with the default size) |
| `CERTMATE_AUDIT_LOG_MAX_BYTES` | | `10485760`  | Rotate the human-readable audit log (`logs/audit/certificate_audit.log`) at this size. `0` disables rotation. Does **not** apply to the tamper-evident hash chain in `data/audit/`, which is never rotated |
| `CERTMATE_AUDIT_LOG_BACKUP_COUNT` | | `5`       | How many rotated audit logs to keep. Note the Activity page tails only the active file, so it shows fewer entries immediately after a roll |
| `CERTMATE_LOG_LEVEL` |        | `INFO`         | DEBUG / INFO / WARNING / ERROR |
| `CERTMATE_LOG_JSON` |         | `true`         | JSON log lines (set `false` for human-readable) |

#### Deployment and networking

| Variable           | Required | Default        | Description                         |
| ------------------ | -------- | -------------- | ----------------------------------- |
| `BEHIND_PROXY`     |          | `false`        | Trust `X-Forwarded-*` from one reverse proxy hop (`ProxyFix`). Set it only when a proxy actually sits in front: with it on and no proxy, a client can forge its own address, which is what the login rate limit is keyed on |
| `PREFERRED_URL_SCHEME` |      | -              | Set to `https` when TLS terminates in front of CertMate. It marks the session cookie `Secure`, so the browser stops sending it over plain HTTP |
| `CORS_ORIGINS`     |          | -              | Comma-separated origins allowed to call the API from a browser. Empty means the built-in default; this is not a way to open the API to everyone |
| `ACME_CHALLENGES_DIR` |       | `<cwd>/data/acme-challenges` | Where http-01 tokens are written and served from. Override it when the webroot is somewhere else; the hook, the pre-creation and the route all read this one value |
| `LETSENCRYPT_EMAIL` |         | -              | ACME account email. **Takes precedence over the value saved in the UI**, so an instance that keeps changing its email back is usually this |
| `CLOUDFLARE_TOKEN` |          | -              | Seeds the default Cloudflare DNS account on first start, so a container can be brought up already able to issue. Once settings.json exists the stored value is what is used |

#### Security behaviour

| Variable           | Required | Default        | Description                         |
| ------------------ | -------- | -------------- | ----------------------------------- |
| `CERTMATE_ENABLE_HSTS` |      | `false`        | Send `Strict-Transport-Security`, and mark the session cookie `Secure`. Only set it when TLS really terminates in front — an HSTS header on a plain-HTTP instance locks browsers out of it |
| `SESSION_TIMEOUT_HOURS` |     | `8`            | How long a login session stays valid. The server record and the browser cookie both use this value, so they cannot drift apart |
| `CERTMATE_ALLOW_INTERNAL_WEBHOOKS` | | `false` | Allow notification webhooks to private, loopback and link-local addresses. Off by default because a webhook URL is operator-supplied and an SSRF into the host network is the obvious abuse |
| `CERTMATE_PROBE_ALLOW_PRIVATE` | |  `false`      | Same relaxation for the certificate probe behind `POST /api/probe` (discovery sweeps ignore it and use `monitored_endpoints.allow_private` from settings): allow it to connect to private addresses. Needed to probe a service on the same host, and it removes an SSRF guard |
| `CERTMATE_AUDIT_CHAIN` |      | `1`            | Set `0` to stop writing the tamper-evident audit hash chain. A kill switch, not a tuning knob: with it off, `/api/audit/verify` can no longer prove the log was not edited |
| `AUDIT_SIGNING_KEY_FILE` |    | -              | Path to an Ed25519 private key that signs audit checkpoints, so the key can live off this box. If set and unreadable, signing is DISABLED rather than a new key generated — a fresh key would fork the instance's identity and make earlier signatures unverifiable |
| `CERTMATE_ALLOW_SCHEMA_DOWNGRADE` | | `0`       | Set `1` to let this build read and overwrite a `settings.json` or `metadata.json` written by a NEWER version. It will drop fields it does not understand — that is the whole reason it refuses by default |

#### Client certificates

The private CA that signs client certificates is created once, on the first
start. These name it before that happens, so a new instance does not have to
boot as `CertMate CA` and then be reset. A variable left unset — or empty, which
is how the compose files pass one you did not set — keeps the default for its
field. `client_ca_subject` in settings, when present, takes precedence. Like
that setting, they are read **only when the CA is created**: changing them
later does not replace an existing CA, so every client certificate it signed
keeps verifying. To apply them to an instance that already has a CA, restart
with the new values and send `POST /api/client-certs/ca/reset` without a
`subject` ([docs/api.md](docs/api.md#rebuild-the-client-certificate-authority)).

| Variable                                 | Required | Default                 | Description |
| ---------------------------------------- | -------- | ----------------------- | ----------- |
| `CERTMATE_CLIENT_CA_COUNTRY`             |          | `CH`                    | Country (`C`) of the client CA. A two-letter ISO 3166-1 code; anything else stops the start before a key is written |
| `CERTMATE_CLIENT_CA_STATE`               |          | `Switzerland`           | State or province (`ST`) of the client CA |
| `CERTMATE_CLIENT_CA_ORGANIZATION`        |          | `CertMate`              | Organisation (`O`) of the client CA |
| `CERTMATE_CLIENT_CA_ORGANIZATIONAL_UNIT` |          | `Certificate Authority` | Organisational unit (`OU`) of the client CA |
| `CERTMATE_CLIENT_CA_COMMON_NAME`         |          | `CertMate CA`           | Common name (`CN`) of the client CA: the issuer name every client certificate shows |
| `CERTMATE_CLIENT_CERT_DEFAULT_COUNTRY`   |          | `CH`                    | Country of a client certificate issued without one: a create request that leaves it out, every CSV batch row, and every renewal. A value in the request wins. Not a two-letter code: the instance refuses to start, naming the variable |
| `CERTMATE_CLIENT_CERT_DEFAULT_STATE`     |          | `Switzerland`           | State or province of a client certificate issued without one, in the same cases |

#### Timing and diagnostics

| Variable           | Required | Default        | Description                         |
| ------------------ | -------- | -------------- | ----------------------------------- |
| `CERTMATE_DOMAIN_LOCK_TIMEOUT` | | `5`         | Seconds to wait for a domain's lock before answering 409 "operation in progress". Clamped to 0-60 |
| `CERTMATE_CERT_INFO_CACHE_TTL` | | `60`        | Seconds a parsed certificate's details stay cached. `0` re-reads from disk on every request. Clamped to 0-3600 |
| `CERTMATE_ISSUANCE_WORKERS` | | `2`            | Threads serving asynchronous issuance jobs. Clamped to 1-16; each one can be running a certbot subprocess |
| `CERTMATE_CERT_DIR` |    | `<install>/certificates` | Where issued certificates live. Absolute, or relative to the working directory. The local storage backend follows it too, unless `certificate_storage.cert_dir` names a directory of its own |
| `CERTMATE_DATA_DIR` |    | `<install>/data`         | Settings, the certificate inventory and the audit chain |
| `CERTMATE_BACKUP_DIR` |  | `<install>/backups`      | Where backups are written and restored from |
| `CERTMATE_LOGS_DIR` |    | `<install>/logs`         | Application and audit logs |
| `CERTMATE_ISSUANCE_QUEUE_LIMIT` | | `20`        | How much unfinished issuance may exist at once, counting queued and running jobs. Clamped to 1-500. Beyond it the async endpoints answer `429 ISSUANCE_QUEUE_FULL` instead of accepting work that will not be reached for hours |
| `CERTMATE_ISSUANCE_JOB_HISTORY` | | `200`      | How many finished issuance jobs stay queryable via `/api/certificates/jobs`. Clamped to 20-2000 |
| `CERTMATE_EVENT_WORKERS` |    | `4`            | Threads dispatching event listeners (deploy hooks, cache invalidation). Clamped to 1-32. Nothing is dropped when they are busy; the backlog is logged instead |
| `CERTMATE_EVENT_MAX_STREAMS` |    | `4`            | Live `/api/web/events/stream` connections held at once. Each one occupies a gunicorn thread and the image runs `--workers 1 --threads 8`, so this leaves half the pool for ordinary requests. Past it the route answers `503` with `Retry-After`. Clamped to 1-64 |
| `CERTMATE_EVENT_STREAM_SECONDS` |    | `900`          | How long one event stream is held before it is closed and the browser reconnects. `EventSource` reconnects on its own, so this is invisible — it bounds what a forgotten tab can hold. Clamped to 30-86400 |
| `CERTMATE_EVENT_DRAIN_SECONDS` |    | `5`            | How long a shutdown waits for queued event dispatches to start before giving up on them. Clamped to 0-60. Whatever is left is logged with its event and domain, so a deploy hook that never ran after a renewal is named rather than lost |
| `CERTMATE_CERTBOT_PROBE_TTL` |    | `300`          | Seconds before the certbot readiness answer is re-checked. Clamped to 30-3600. The probe used to run once per process, so a transient failure at boot made the instance permanently unready and a certbot that broke later never turned `/health/ready` red |
| `CERTMATE_PROBE_TIMEOUT_SECONDS` | | `5`       | Connection timeout of the certificate probe used by discovery sweeps and `POST /api/probe`. Clamped to 1-30. The deployment check has its own, `CERTMATE_TLS_PROBE_TIMEOUT_SECONDS` |
| `CERTMATE_LAST_USED_PERSIST_SECONDS` | | `60`  | How often a session's "last used" timestamp is written to disk. `0` writes on every request, which is the original behaviour and one write per request |
| `CERTMATE_SLOW_REQUEST_LOGGING` | | `true`       | Log a warning, with the thread's stack, for requests that outlive the threshold below. The stack is what makes a hung request diagnosable after the fact |
| `CERTMATE_SLOW_REQUEST_THRESHOLD_SECONDS` | | `30` | How long a request must run before it is reported |
| `CERTMATE_SLOW_REQUEST_SCAN_SECONDS` | | `10`  | How often the watchdog looks for requests that are still running |
| `CERTMATE_SLOW_REQUEST_REPEAT_SECONDS` | | threshold | How often a still-running request is reported again |

> **Bind address is not an environment variable.** The container always binds
> `0.0.0.0` inside its own network namespace; to expose it only on loopback,
> publish it that way — `-p 127.0.0.1:8000:8000`. Running `app.py` directly
> (development only) takes `--host` / `--port` / `--debug` as CLI flags.
> `HOST` and `FLASK_DEBUG` are read by nothing, and setting them has never
> had any effect (#429).

### DNS Provider Configuration

#### Cloudflare Setup
1. Go to [Cloudflare API Tokens](https://dash.cloudflare.com/profile/api-tokens)
2. Click "Create Token" → "Custom token"
3. Set permissions:
 - **Zone**: `DNS:Edit` + `Zone:Read`
 - **Zone Resources**: Include specific zones or all zones
4. Copy the generated token

```bash
# Environment variable
CLOUDFLARE_TOKEN=your_cloudflare_api_token_here
```

#### AWS Route53 Setup
1. Create IAM user with Route53 permissions
2. Attach policy: `Route53FullAccess` or custom policy:

```json
{
 "Version": "2012-10-17",
 "Statement": [{
 "Effect": "Allow",
 "Action": ["route53:ListHostedZones",
 "route53:GetChange",
 "route53:ChangeResourceRecordSets"
 ],
 "Resource": "*"
 }
 ]
}
```

```bash
# Environment variables
AWS_ACCESS_KEY_ID=your_access_key_id
AWS_SECRET_ACCESS_KEY=your_secret_access_key
AWS_DEFAULT_REGION=us-east-1
```

#### Azure DNS Setup
1. Create Service Principal:
```bash
az ad sp create-for-rbac --name "CertMate" --role "DNS Zone Contributor" --scopes "/subscriptions/{subscription-id}/resourceGroups/{resource-group}"
```

```bash
# Environment variables
AZURE_SUBSCRIPTION_ID=your_subscription_id
AZURE_RESOURCE_GROUP=your_resource_group_name
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
```

#### Google Cloud DNS Setup
1. Create service account with DNS Administrator role
2. Download JSON key file

```bash
# Environment variables
GOOGLE_PROJECT_ID=your_project_id
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

#### PowerDNS Setup
```bash
# Environment variables
POWERDNS_API_URL=https://your-powerdns-server:8081
POWERDNS_API_KEY=your_api_key
```

### Certificate Storage Configuration

Where certificates and keys are kept, the six storage backends, the SDK each one needs in the Docker image, and how to migrate between them are in [docs/storage.md](docs/storage.md).

### Directory Structure

```
certmate/
 app.py # Main Flask application
 requirements.txt # Python dependencies
 docker-compose.yml # Docker Compose configuration
 Dockerfile # Container build instructions
 nginx.conf.example # Nginx reverse proxy config template (copy to nginx.conf)
 .env.example # Environment template
 README.md # This documentation
 CONTRIBUTING.md # Contribution guidelines
 docs/ # Comprehensive documentation
 certificates/ # Certificate storage
 {domain}/
 cert.pem # Server certificate
 chain.pem # Certificate chain
 fullchain.pem # Full chain
 privkey.pem # Private key
 data/ # Application data
 settings.json # Persistent settings
 logs/ # Application logs
 letsencrypt/ # Let's Encrypt working directory
 config/ # Certbot configuration
 work/ # Certbot working files
 logs/ # Certbot logs
 modules/ # Modular backend
 core/ # Core modules
 deployer.py # Deploy hooks manager
 notifier.py # Notification channels
 events.py # SSE event bus
 digest.py # Weekly digest
 audit.py # Audit logger
 shell.py # Shell executor
 web/ # Web routes
 api/ # API resources
 templates/ # Web interface templates
 index.html # Main dashboard
 settings.html # Settings page
 activity.html # Activity timeline
 help.html # Help & documentation
 static/js/ # Frontend modules
 dashboard.js # Dashboard logic
 settings.js # Settings components
 cmd-palette.js # Cmd+K palette
 shortcuts.js # Keyboard shortcuts
```

## Security & Best Practices

### Security Considerations

#### Authentication & Authorization
- **Role-Based Access Control**: Assign viewer, operator, or admin roles to each user
- **Scoped API Keys**: Create API keys with specific role permissions and optional expiration
- **Per-Domain Scoping (`allowed_domains`)**: Restrict a scoped API key to a list of domain patterns. Supports exact (`example.com`) and wildcard (`*.example.com`) forms; the wildcard matches subdomains only, not the apex. An operation on an existing certificate needs every name the certificate covers to be in scope, as creating it does. Client certificates, backups and the inventory configuration belong to the instance, not to a domain, so a key restricted this way cannot use those routes; `/metrics` answers it with the series about its own domains only. An admin key cannot be restricted to domains: creating one is refused, and one stored by an earlier release acts as an operator within its domains. Out-of-scope requests return `403 DOMAIN_OUT_OF_SCOPE` and are recorded in the audit log. Leave the field empty for unrestricted access (legacy behavior).
- **HMAC-SHA256 Token Hashing**: API tokens are hashed with a server-side HMAC secret, preventing offline brute-force even if the settings file is leaked (backward compatible with pre-2.2.6 SHA-256 hashes)
- **Strong Bearer Tokens**: Use cryptographically secure tokens (32+ characters)
- **Token Rotation**: Regularly rotate API tokens and revoke unused keys
- **Environment Variables**: Never commit tokens to version control
- **HTTPS Only**: Always use HTTPS in production environments
- **IP Restrictions**: Implement firewall rules to restrict access

#### Settings API Hardening
- **Strict Field Whitelist on `POST /api/settings`**: only documented configuration keys are accepted. Sensitive fields (`api_bearer_token`, `deploy_hooks`, `users`, `api_keys`, `local_auth_enabled`) **cannot** be written through the generic settings endpoint — each has its own dedicated endpoint with its own audit:
  - Users → `POST /api/users`
  - API keys → `POST /api/keys`
  - Deploy hooks → `POST /api/deploy/config`
  - Local auth toggle → `POST /api/auth/config` (admin-only)
  Unknown or rejected keys are returned in a `400` response with a `hint` field pointing at the correct endpoint.
- **Audit Trail for Configuration Changes**: every mutation to settings, the auth-config toggle, users, scoped API keys, and deploy hooks is recorded with operator identity and source IP. Authorization denials (out-of-scope domain access, blocked field writes) are recorded too. Logs are written to `data/audit/certificate_audit.log` as one JSON object per line — pipeable into your SIEM of choice.

#### The Setup Window
Until the first operator credential exists — a local admin with local auth enabled, `API_BEARER_TOKEN`, or OIDC — every request is served as admin to anyone who can reach the instance. So during setup CertMate only **bootstraps**: it creates the first admin and turns login on. API keys and further users are refused with `409 SETUP_BOOTSTRAP_ONLY` until setup is complete, because anything created in that window would be created by whoever was there and would outlive it. API keys that an older version let be created during setup stay valid but are flagged in Settings → API Keys and in the startup log, until an operator confirms or revokes each one.

#### Certificate Security
- **File Permissions**: Private keys stored with `600` permissions
- **Directory Permissions**: Certificate directories with `700` permissions
- **Backup Encryption**: Encrypt certificate backups
- **Access Logging**: Monitor certificate access patterns

#### Secret Storage Hardening
CertMate stores DNS provider credentials, ACME account keys, and (legacy) bearer tokens inside `data/settings.json`. The bearer token itself is migrated to an HMAC-SHA256 hash on first save, but **DNS provider credentials remain in the file in their original form** so they can be passed to certbot plugins. The file is created with `0600` permissions, which is the first line of defense. Recommended hardening, in order of effort:

1. **Use an external secret backend** (already supported): point `certificate_storage.backend` at HashiCorp Vault, Infisical, AWS Secrets Manager, or Azure Key Vault. Issued certificates are stored there transparently, keeping the bearer token + DNS credentials in `settings.json` as the only on-disk secret surface.
2. **Encrypt the underlying volume**: run CertMate's `data/` directory on a LUKS-encrypted partition (Linux), an encrypted APFS volume (macOS), or a Kubernetes `Secret` mounted in a `tmpfs`. This protects credentials at rest even if the host disk is removed or imaged.
3. **Run as a dedicated non-root user** with `data/` owned by that user and `0700` mode. Verify with `ls -la data/` — only the CertMate process user should be able to read the file.
4. **Avoid bind-mounting `data/` from untrusted sources** in Docker. Use a named volume managed by Docker, or a CSI-provisioned volume in Kubernetes, rather than a bind from a multi-tenant host.
5. **Rotate credentials regularly**: DNS provider credentials can be rotated independently of CertMate — issue a new token in the provider console, update Settings, then revoke the old token. CertMate will pick up the new credentials on the next renewal.

> CertMate does **not** currently encrypt secrets at the application layer. If your threat model requires that the same operator who can read `settings.json` should still not be able to read DNS credentials, use option (1) above and configure the per-provider credentials in the external secret backend rather than in CertMate's settings.

#### Network Security
```bash
# Example firewall rules (iptables)
# Allow only specific IPs to access CertMate
iptables -A INPUT -p tcp --dport 8000 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -s 192.168.0.0/16 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j DROP
```

The rules above confine **inbound** access. You can also confine **outbound**
traffic: route CertMate's HTTP(S) egress through a forward proxy and deny it any
other route to the internet, so it can reach only your CA, DNS provider, object
storage, and notification endpoints. With [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager)
v3.9.0+ this is a built-in default-deny egress allowlist. See
[Confining outbound traffic](docs/installation.md#confining-outbound-traffic-egress-hardening)
for a worked example.

### Performance Optimization

#### Production Deployment
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  certmate:
    image: certmate:latest
    deploy:
      # CertMate runs an in-process renewal scheduler and per-domain locks, so
      # it must run as a SINGLE writer. Multiple replicas (or >1 gunicorn
      # worker) each fire the renewal check and would issue duplicate ACME
      # orders and hit the CA's duplicate-certificate rate limit. A host-local
      # flock guards multiple workers/containers on a *shared* data volume, but
      # the safe default is one writer. For HA, front a single active instance
      # rather than scaling this service.
      replicas: 1
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
    environment:
      - FLASK_ENV=production
      # The worker and thread counts are fixed in the image
      # (`--workers 1 --threads 8`): one worker because the scheduler runs
      # in-process and a second would duplicate every renewal. GUNICORN_TIMEOUT
      # is the one that is read.
      - GUNICORN_TIMEOUT=300   # the image default; raise it for slow DNS providers
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s
```

#### Load Balancing with Nginx
```nginx
upstream certmate_backend {
 server certmate1:8000;
 server certmate2:8000;
 server certmate3:8000;
}

server {
 listen 443 ssl http2;
 server_name certmate.company.com;
 
 ssl_certificate /etc/ssl/certs/certmate.company.com/fullchain.pem;
 ssl_certificate_key /etc/ssl/certs/certmate.company.com/privkey.pem;
 
 location / {
 proxy_pass http://certmate_backend;
 proxy_set_header Host $host;
 proxy_set_header X-Real-IP $remote_addr;
 proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
 proxy_set_header X-Forwarded-Proto $scheme;
 
 # API rate limiting
 limit_req zone=api burst=10 nodelay;
 }
}
```

### Backup and Recovery

CertMate provides comprehensive backup and recovery capabilities built directly into the application, ensuring your certificates and configuration data are always protected.

#### Unified Backup System

**What is Unified Backup?**
- **Atomic Operation**: Creates a single ZIP file containing both settings and certificates
- **Data Consistency**: Ensures settings and certificates are always in sync
- **Prevents Corruption**: Eliminates configuration/certificate mismatches
- **Simplified Management**: One file per snapshot. A disaster-recovery archive (`include_secrets=true`) contains everything needed for complete restoration; the default share-safe archive contains certificates, chains, metadata, the audit chain and the inventory — no credentials and no private keys

**Two kinds of archive:**
- **Share-safe**: settings with every credential masked, and **no private keys** — no ACME `privkey.pem`, no ACME account key, no private-CA key, no `.pfx`. Certificates, chains, metadata, the audit chain and the inventory are all there. The manifest says so (`secrets_masked`, `key_material_excluded`). Such an archive cannot restore an instance on its own: `GET /api/backups` reports it with `can_restore: false` and Settings disables its Restore button. The restore API does not read `can_restore`. It refuses a share-safe archive when this instance already holds certificates; otherwise it restores it, keeping the credentials already in this instance's `settings.json`, or — on an instance with no `settings.json` — leaving every credential masked, to be re-entered before the next renewal.
- **Disaster recovery**: plaintext settings and every key — encrypted at rest when `CERTMATE_BACKUP_PASSPHRASE` is set. This is the archive to keep off-site.

**Which one you get automatically depends on one thing:** whether a backup passphrase is
configured. With `CERTMATE_BACKUP_PASSPHRASE` set, automatic backups are disaster-recovery
archives, encrypted at rest. Without it they stay share-safe, because a complete archive
that cannot be encrypted would be a plaintext credential dump written to disk on every
settings change. Without a passphrase, the instance logs a notice once per process, at the first automatic backup it takes.

CertMate never generates or stores that passphrase: keeping it beside the archive it
protects would make the encryption meaningless. It is yours to set and to keep.

`POST /api/backups/create` with `{"include_secrets": true}` (admin, audited) still takes a
disaster-recovery archive on demand, passphrase or not — a deliberate opt-in.

**Getting a backup back onto a new instance:** `POST /api/backups/upload` (admin,
`multipart/form-data`, field `file`), or the *Restore From Elsewhere* control in Settings.
Uploading only stores the archive under a name CertMate generates — the name you send is
discarded. Restoring it is a separate, explicit step, so an upload is never destructive on
its own.

**Automatic Backups:**
- **Unified Snapshots** - Automatically created when DNS providers, domains, certificates, or application settings are modified. Disaster-recovery archives when `CERTMATE_BACKUP_PASSPHRASE` is set, share-safe otherwise (see above)
- **Retention** - Two rules, whichever hits first: the 50 most recent archives per type are kept (`MAX_BACKUPS_PER_TYPE`), **and any archive older than 30 days is deleted regardless of how few there are** (`BACKUP_RETENTION_DAYS`). Both are constants, not settings. This is why a disaster-recovery archive must be kept off the host: one left in `backups/unified/` is deleted after 30 days like any other. Logging in no longer writes a backup, so routine sign-ins do not consume restore points
- **Automatic Cleanup** - Pruning runs after every backup, applying both rules above

**Manual Backups:**
- **On-Demand Creation** - Create backups anytime via the web interface or API
- **Download Support** - Export backups for external storage and disaster recovery
- **Comprehensive Coverage** - Includes all DNS configurations, certificates, and application settings

#### Web Interface Backup Management

Access backup features from the Settings page:

```html
<!-- Create backup -->
<button onclick="createBackup('unified', this)">Create Backup</button>

<!-- View and manage existing backups -->
- Download backups for external storage
- Restore from any backup point with atomic consistency
- View backup contents and metadata
- Delete specific backups manually
```

#### API Backup Operations

**Create Backup:**
```bash
# Create backup (settings + certificates); "type" is required
curl -X POST "http://localhost:8000/api/backups/create" \
 -H "Authorization: Bearer your_token" \
 -H "Content-Type: application/json" \
 -d '{"type": "unified", "reason": "manual_backup"}'

# Response (201)
{
 "message": "Backup created successfully",
 "backups": [
 {"type": "unified", "filename": "backup_20241225_120000_123456_manual_backup.zip"}
 ],
 "secrets_masked": true,
 "recommendation": null
}
```

Archives are named `backup_<YYYYmmdd_HHMMSS_ffffff>_<reason>.zip` (UTC timestamp), or
`.zip.enc` when `CERTMATE_BACKUP_PASSPHRASE` is set.

**List and Download Backups:**
```bash
# List all backups
curl -H "Authorization: Bearer your_token" \
 "http://localhost:8000/api/backups"

# Download backup
curl -H "Authorization: Bearer your_token" \
 "http://localhost:8000/api/backups/download/unified/backup_20241225_120000_123456_manual_backup.zip" \
 -o backup.zip
```

#### Backup File Structure

**Backup File (ZIP):**
```
backup_20260821_120000_000000_manual.zip
 backup_metadata.json  # manifest: secrets_masked, key_material_excluded, key_files_excluded, encrypted
 settings.json         # application settings — credentials masked in a share-safe archive, plaintext in a DR one
 certificates/
   domain1.com/
     cert.pem
     chain.pem
     fullchain.pem
     privkey.pem       # DR archive only (include_secrets=true); absent from a share-safe archive
     metadata.json
     live/ archive/ renewal/ accounts/   # certbot lineage (keys under accounts/ and live/ DR only)
 data/
   certs/ca/ca.crt      # ca.key: DR only
   certs/client/...     # client certificates (.key/.pfx: DR only)
   audit/ inventory/
```

#### Recovery Procedures

**Backup Restoration:**

*Web Interface:*
1. Navigate to Settings → Backup Management
2. Select the backup to restore from
3. Confirm restoration (restores both settings and certificates atomically)
4. The page reloads the restored settings; nothing is restarted
5. Verify all certificates and configurations are working

*API Restoration:*
```bash
# Restore from backup
curl -X POST "http://localhost:8000/api/backups/restore/unified" \
 -H "Authorization: Bearer your_token" \
 -H "Content-Type: application/json" \
 -d '{"filename": "backup_20241225_120000_123456_manual_backup.zip", "create_backup_before_restore": true}'
```

#### External Backup Integration

For additional protection, integrate with external backup systems:

**Automated External Backup Script:**
```bash
#!/bin/bash
# /opt/scripts/backup-certmate-external.sh

BACKUP_DIR="/backup/certmate/$(date +%Y%m%d_%H%M%S)"
CERT_DIR="/opt/certmate/certificates"
DATA_DIR="/opt/certmate/data"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Download the newest backup that can restore (there is no "latest" alias;
# the list is ordered oldest to newest by name)
LATEST=$(curl -s -H "Authorization: Bearer $API_TOKEN" http://localhost:8000/api/backups \
 | jq -r '[.unified[] | select(.can_restore)] | last | .filename // empty')
[ -n "$LATEST" ] || { echo "No restorable backup on this instance" >&2; exit 1; }
curl -H "Authorization: Bearer $API_TOKEN" \
 "http://localhost:8000/api/backups/download/unified/$LATEST" \
 -o "$BACKUP_DIR/$LATEST"

# Backup certificates directory
tar -czf "$BACKUP_DIR/certificates.tar.gz" "$CERT_DIR"

# Backup application data
tar -czf "$BACKUP_DIR/data.tar.gz" "$DATA_DIR"

# Encrypt backups (optional)
gpg --cipher-algo AES256 --compress-algo 1 --symmetric \
 --output "$BACKUP_DIR/$LATEST.gpg" \
 "$BACKUP_DIR/$LATEST"

# Cleanup old backups
find /backup/certmate -type d -mtime +$RETENTION_DAYS -exec rm -rf {} \;

echo "External backup completed: $BACKUP_DIR"
```

#### Recovery Procedure
```bash
#!/bin/bash
# Recovery from backup

BACKUP_DATE="20241225_120000"
BACKUP_DIR="/backup/certmate/$BACKUP_DATE"

# Stop services
docker-compose down

# Restore certificates
tar -xzf "$BACKUP_DIR/certificates.tar.gz" -C /opt/certmate/

# Restore data
tar -xzf "$BACKUP_DIR/data.tar.gz" -C /opt/certmate/

# Set permissions
chown -R 1000:1000 /opt/certmate/certificates
chmod -R 700 /opt/certmate/certificates

# Start services
docker-compose up -d

echo "Recovery completed from backup: $BACKUP_DATE"
```

#### Downgrades & Recovery

Downgrading to a version older than the one that wrote `settings.json` is not supported and may result in a broken configuration or loss of accounts. If you see a `DOWNGRADE DETECTED` message in the logs after rolling back, **restore the most recent backup that can actually restore**.

> **Not every backup is a restore point.** Unless `CERTMATE_BACKUP_PASSPHRASE`
> was set when the backup was taken, automatic backups are written with secrets
> masked and **cannot restore this instance** — they are configuration
> snapshots. On an instance that has never had a passphrase set, the newest
> archive is almost certainly one of those, so picking "the latest" by
> timestamp picks one that will be refused. Ask the API which ones qualify: it
> reports `can_restore` per archive, and `restore_blocked_reason` when it is
> false.

```bash
# Which backups can actually restore, newest first
curl -s -H "Authorization: Bearer $API_TOKEN" http://localhost:8000/api/backups \
  | jq -r '.unified[] | "\(.filename)  can_restore=\(.can_restore)  \(.restore_blocked_reason // "")"'

# Restore the newest one whose can_restore is true
curl -H "Authorization: Bearer $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"filename": "backup_YYYYmmdd_HHMMSS_ffffff_<reason>.zip", "create_backup_before_restore": true}' \
  http://localhost:8000/api/backups/restore/unified
```

If nothing reports `can_restore: true`, this instance has no restore point.
Set `CERTMATE_BACKUP_PASSPHRASE`, take a backup immediately, and keep a copy
off this node — see [Backup and Recovery](#backup-and-recovery).

If you have lost the admin password and cannot log in, use the emergency reset script (requires container shell access):

```bash
docker exec -it certmate python scripts/reset_admin_password.py
```

## Monitoring & Observability

Health endpoints, Prometheus metrics with a ready-made dashboard and alert rules, logs, and notification channels are in [docs/monitoring.md](docs/monitoring.md).

## Troubleshooting Guide

Common failures (certificate creation, API authentication, containers, the deployment-status badge, DNS providers), debug logging, and how to report a bug are in [docs/troubleshooting.md](docs/troubleshooting.md).

## Documentation

**Prefer watching?** [CertMate in 60 seconds](https://www.youtube.com/playlist?list=PLM-wnWN4g5XA) is a video guide of 24 one-minute shorts, made from the documentation on [certmate.org](https://certmate.org).

### Complete Documentation Set

| Document                                           | Description                         | Target Audience       |
| -------------------------------------------------- | ----------------------------------- | --------------------- |
| **[README.md](README.md)**                         | Main documentation and quick start  | All users             |
| **[docs/installation.md](docs/installation.md)**   | Installation and deployment         | System administrators |
| **[docs/dns-providers.md](docs/dns-providers.md)** | DNS provider setup                  | DevOps engineers      |
| **[docs/custom-dns-script.md](docs/custom-dns-script.md)** | Any DNS provider with no plugin, via your own hooks | DevOps engineers      |
| **[docs/ca-providers.md](docs/ca-providers.md)**   | Certificate Authority configuration | Enterprise users      |
| **[docs/docker.md](docs/docker.md)**               | Docker and multi-platform builds    | DevOps engineers      |
| **[docs/testing.md](docs/testing.md)**             | Testing framework and CI/CD         | Developers            |
| **[docs/architecture.md](docs/architecture.md)**   | System architecture                 | Developers            |
| **[docs/api.md](docs/api.md)**                     | Client certificates API reference   | Developers            |
| **[docs/mcp.md](docs/mcp.md)**                     | MCP server for AI agents: tools, auth, audit attribution | Developers, SRE |
| **[docs/guide.md](docs/guide.md)**                 | Step-by-step guide for common tasks | All users             |
| **[docs/discovery-inventory.md](docs/discovery-inventory.md)** | Discovery, inventory, adopt, crypto readiness, domain registration + health | SRE, security |
| **[docs/deploy-hooks.md](docs/deploy-hooks.md)**   | Post-issuance deploy hooks          | DevOps engineers      |
| **[docs/csr-only-certificates.md](docs/csr-only-certificates.md)** | Issuing from a CSR when the key stays on the device | Appliance operators |
| **[docs/webhooks.md](docs/webhooks.md)**           | Generic webhooks: payload templates, auth, signature verification | Integrators |
| **[docs/compliance.md](docs/compliance.md)**       | Audit chain, attribution, NIS2/eIDAS posture | Compliance, security |
| **[docs/kubernetes.md](docs/kubernetes.md)**       | Install with Helm, Argo CD or Flux; pod sizing, OOM troubleshooting | SRE              |
| **[docs/probes.en.md](docs/probes.en.md)**         | Deployment probe configuration      | DevOps engineers      |
| **[docs/sso.md](docs/sso.md)**                   | OpenID Connect sign-in, role mapping, provisioning | Administrators |
| **[docs/monitoring.md](docs/monitoring.md)**     | Health endpoints, metrics, logs, notification channels | SRE, operators |
| **[docs/storage.md](docs/storage.md)**           | Storage backends, what each needs, migration | System administrators |
| **[docs/troubleshooting.md](docs/troubleshooting.md)** | Common failures, debug logging, reporting a bug | All users |
| **[CONTRIBUTING.md](CONTRIBUTING.md)**             | Development and contribution guide  | Developers            |
| **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)**       | Community guidelines                | Contributors          |

### Online Resources

- **API Documentation**: http://your-server:8000/docs/ (Swagger UI)
- **Alternative API Docs**: http://your-server:8000/redoc/ (ReDoc)
- **GitHub Repository**: https://github.com/fabriziosalmi/certmate
- **Docker Hub**: https://hub.docker.com/r/fabriziosalmi/certmate
- **Issue Tracker**: https://github.com/fabriziosalmi/certmate/issues

### Examples Repository

Check out our examples repository for:
- Production deployment configurations
- Integration scripts for popular tools
- Terraform modules
- Kubernetes manifests
- CI/CD pipeline examples

### Community Contributions

We welcome contributions! Areas where we need help:
- **Documentation** - Tutorials, use cases, translations
- **Testing** - DNS provider testing, edge cases
- **Integrations** - New DNS providers, monitoring tools
- **Features** - UI improvements, API enhancements

## Commercial Support & Consulting

Running CertMate in production? I offer paid support, custom development, and
security consulting — certificate/TLS automation, hardening, WAF, and cloud
detection & alerting. Reach out: **[fabrizio.salmi@gmail.com](mailto:fabrizio.salmi@gmail.com)**.

## Contributing

We love contributions! CertMate is an open-source project and we welcome:

### Types of Contributions
- **Bug Reports** - Help us identify and fix issues
- **Feature Requests** - Suggest new functionality
- **Documentation** - Improve guides and examples
- **Testing** - Test new features and edge cases
- **Code** - Submit pull requests with improvements

### Quick Start for Contributors

```bash
# Fork and clone the repository
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate

# Create the development environment (.venv, from requirements.lock + the test requirements)
make setup
source .venv/bin/activate

# Lint, security-scan and test: the checks CI gates on (`make help` lists the rest)
make check

# Start development server
python app.py
```

A bare `pytest` is not the way to run the suite: it includes the Playwright `ui` tests, which
need Docker. `make test` runs the selection [CONTRIBUTING.md](CONTRIBUTING.md) documents.

### Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

## License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ by Fabrizio Salmi**

[Star us on GitHub](https://github.com/fabriziosalmi/certmate) • [Report Bug](https://github.com/fabriziosalmi/certmate/issues) • [Request Feature](https://github.com/fabriziosalmi/certmate/issues/new?template=feature_request.md)

<br>

<a href="https://europeanopensource.eu/">
  <img src="https://raw.githubusercontent.com/European-OpenSource/media-kit/main/assets/logo/light/Logo%20-%20standard.svg" alt="European Open Source" height="28">
</a>
<br>
<sub>Listed in the European Open Source Catalogue</sub>

</div>
