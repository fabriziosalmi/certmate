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

[Quick Start](#quick-start-with-docker) • [Video Guide](https://www.youtube.com/playlist?list=PLM-wnWN4g5XA) • [CLI](#command-line-interface) • [Documentation](#documentation) • [Installation](#installation-methods) • [DNS Providers](#supported-dns-providers) • [CA Providers](docs/ca-providers.md) • [Storage Backends](docs/storage.md) • [Backup and Recovery](docs/backup.md) • [API Reference](#api-usage)

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

Every provider, the credentials it needs, and whether the Docker image includes
its plugin are in [docs/dns-providers.md](docs/dns-providers.md).

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

To set it up by hand: [docs/installation.md](docs/installation.md#setting-it-up-by-hand).

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

Every environment variable, with its default and what it changes, is in [docs/configuration.md](docs/configuration.md).

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

How CertMate protects what it holds (deploy hooks, credentials in
`settings.json`, the endpoints that privileged settings go through, how tokens
are stored, the audit log, the setup window) is in
[SECURITY.md](SECURITY.md#security-model-notes). Backups, restoring, and
recovering from a downgrade or a lost admin password are in
[docs/backup.md](docs/backup.md). Running it in production:
[Docker Compose](docs/docker.md#production-with-docker-compose), and behind a
reverse proxy with outbound traffic confined in
[docs/installation.md](docs/installation.md#production-deployment).

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
| **[docs/configuration.md](docs/configuration.md)** | Every environment variable    | System administrators |
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
| **[docs/backup.md](docs/backup.md)**             | Backups, restoring, lost admin password | System administrators |
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
