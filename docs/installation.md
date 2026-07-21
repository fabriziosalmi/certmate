# Installation Guide

This guide covers all methods of installing and deploying CertMate.

---

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Docker (optional, for containerized deployment)

---

## Method 1: Direct Installation

### 1. Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
```

### 2. Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment

Create a `.env` file:

```bash
cp .env.example .env
# Edit .env with your settings
```

### 5. Start the Application

```bash
python app.py
```

---

## Method 2: Docker Installation

### Using Docker Compose (Recommended)

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker-compose up -d
```

### Using Docker Build

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker build -t certmate .
docker run -p 8000:8000 --env-file .env -v ./certificates:/app/certificates certmate
```

> For advanced Docker deployment including multi-platform builds, see the [Docker Guide](./docker.md).

---

## System Dependencies

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install python3-dev python3-venv build-essential libssl-dev libffi-dev
```

### CentOS / RHEL / Rocky

```bash
sudo yum install python3-devel gcc openssl-devel libffi-devel
```

### macOS

```bash
brew install python3 openssl libffi
```

---

## DNS Provider Setup

After installation, configure your DNS provider credentials. See the [DNS Providers Guide](./dns-providers.md) for detailed setup instructions for every supported provider.

Quick setup for common providers:

### Cloudflare

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Create a new API token with `Zone:DNS:Edit` permissions
3. Add the token in CertMate Settings

### AWS Route53

1. Create IAM user with Route53 permissions
2. Generate access keys
3. Add credentials in CertMate Settings

### Azure DNS

1. Create a Service Principal
2. Assign DNS Zone Contributor role
3. Configure subscription details in CertMate Settings

### Google Cloud DNS

1. Create a Service Account with DNS Administrator role
2. Download JSON key file
3. Upload in CertMate Settings

---

## Environment Variables

```bash
# API Authentication (auto-generated if neither is set)
# Option A: inline value
API_BEARER_TOKEN=your_secure_token_here
# Option B: path to a file containing the token (takes precedence over API_BEARER_TOKEN)
API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token

# Flask session secret key (auto-generated if neither is set)
# Option A: inline value
SECRET_KEY=your_flask_secret_key
# Option B: path to a file containing the key (takes precedence over SECRET_KEY)
SECRET_KEY_FILE=/run/secrets/secret_key

# Reverse proxy — set to 'true' when CertMate is fronted by Nginx,
# HAProxy, Traefik, Cloudflare, etc. Without this, request.remote_addr
# resolves to the proxy's IP for every request, which collapses per-
# client rate-limiting into a single bucket. See the "Behind a reverse
# proxy" section under Production Deployment for details.
BEHIND_PROXY=true

# Backup encryption at rest (optional, recommended).
# When set, unified backups are written as encrypted .zip.enc files
# (PBKDF2-SHA256 key derivation + Fernet/AES) instead of cleartext .zip.
# Backups embed every certificate private key, so without this an
# exfiltrated backup file is a full key compromise. The same passphrase
# must be present to restore. Deliberately env-only: a passphrase stored
# in settings.json would itself end up inside plaintext backups.
CERTMATE_BACKUP_PASSPHRASE=choose-a-long-random-passphrase

# DNS Providers (choose one or multiple)
CLOUDFLARE_TOKEN=your_cloudflare_token
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AZURE_SUBSCRIPTION_ID=your_azure_subscription
AZURE_TENANT_ID=your_azure_tenant
AZURE_CLIENT_ID=your_azure_client
AZURE_CLIENT_SECRET=your_azure_secret
GOOGLE_PROJECT_ID=your_gcp_project
POWERDNS_API_URL=https://your-powerdns:8081
POWERDNS_API_KEY=your_powerdns_key
```

### Resolution Order

| Variable | Precedence |
|----------|------------|
| `API_BEARER_TOKEN_FILE` | Highest — if set, `API_BEARER_TOKEN` is never read |
| `API_BEARER_TOKEN` | Used only when `API_BEARER_TOKEN_FILE` is absent |
| *(generated)* | Fallback when neither is set or the value fails validation |
| `SECRET_KEY_FILE` | Highest — if set, `SECRET_KEY` is never read |
| `SECRET_KEY` | Used only when `SECRET_KEY_FILE` is absent |
| *(generated + persisted)* | Written to `data/.secret_key` so sessions survive restarts |

> **Docker Secrets tip**: Use `API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token` and `SECRET_KEY_FILE=/run/secrets/secret_key` with Docker Swarm or Kubernetes secrets to avoid putting sensitive values in environment variables.

---

## Production Deployment

### Behind a reverse proxy

If CertMate sits behind a reverse proxy (Nginx, HAProxy, Traefik,
Cloudflare, Kubernetes Ingress) — which is the recommended way to run
it for TLS termination — set `BEHIND_PROXY=true` in the container
environment. This enables Werkzeug's `ProxyFix` middleware so the
following trust the `X-Forwarded-*` headers from your proxy:

- `request.remote_addr` resolves to the original client IP instead of
  the proxy's IP. Rate limiting, audit-log entries, and the
  "invalid API token attempt from X" warnings all become per-client
  instead of per-proxy.
- The proxy's scheme / host / prefix headers are honored, which keeps
  generated URLs and cookie scopes correct.

```yaml
# docker-compose.yml snippet
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    environment:
      BEHIND_PROXY: "true"
    volumes:
      - ./data:/app/data
```

**When NOT to enable it.** If you expose CertMate directly to the
network with no proxy in front, leave `BEHIND_PROXY` unset. With it
set, anyone who can reach the listener could spoof `X-Forwarded-For`
and bypass per-client rate limits. The proxy is the trust boundary.

Your proxy must of course forward the headers. Nginx example:

```nginx
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

#### Example: Zion (Rust TLS gateway + WAF)

[Zion](https://github.com/fabriziosalmi/zion) is a high-performance Rust TLS
reverse proxy with a built-in WAF — a good fit in front of CertMate when you
want TLS 1.3 termination and request filtering at the edge. CertMate stays on
plain HTTP on the internal network; Zion terminates TLS and forwards.

`zion.toml`:

```toml
[server]
listen_http  = "0.0.0.0:8080"
listen_https = "0.0.0.0:8443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"   # your cert, or use Zion's ACME (--features acme)
key_path  = "/etc/ssl/zion/tls.key"
min_version = "1.3"
alpn = ["h2", "http/1.1"]

[upstream.backend]
url = "http://certmate:8000"

# Catch-all to the backend. The explicit "/" route is harmless and documents
# intent; recent Zion also auto-registers "/" for a root catch-all.
[[route]]
path = "/"
upstream = "backend"

[[route]]
path = "/{*rest}"
upstream = "backend"
```

`docker-compose.yml`:

```yaml
services:
  certmate:
    image: certmate:latest          # the published image, or your local build
    environment:
      BEHIND_PROXY: "true"          # trust Zion's X-Forwarded-* headers
    expose:
      - "8000"                       # internal only; not published to the host
    volumes:
      - ./data:/app/data

  zion:
    image: zion:latest              # the published image, or your local build
    depends_on:
      - certmate
    environment:
      ZION_CONFIG: /etc/zion/zion.toml
    volumes:
      - ./zion.toml:/etc/zion/zion.toml:ro
      - ./certs:/etc/ssl/zion:ro
    ports:
      - "443:8443"                   # host 443 -> Zion's HTTPS listener
      - "80:8080"                    # host 80  -> Zion's HTTP listener
```

Keep `BEHIND_PROXY=true` on the CertMate service: Zion appends
`X-Forwarded-For`, so this makes per-client rate limiting, audit entries and the
auth-failure warnings resolve to the real client IP rather than Zion's.

> **`/metrics` is served by Zion, not proxied.** Zion exposes its own Prometheus
> endpoint at `/metrics` (`zion_*` series for the proxy), which shadows
> CertMate's `/metrics`. Scrape them separately: Zion's `/metrics` from inside
> the host / cluster network (Zion gates it to private source IPs and returns
> 403 to public clients), and CertMate's `certmate_*` directly against the
> internal `certmate:8000` with an admin Bearer token (see
> [`monitoring/`](../monitoring/) for the dashboard and scrape config).

### Confining outbound traffic (egress hardening)

CertMate makes outbound connections to ACME Certificate Authorities, DNS
provider APIs, object storage, and notification webhooks over HTTP(S), plus
SMTP for email notifications. You can confine and audit the **HTTP(S)** traffic
by routing it through a **forward proxy** and denying CertMate any other route
to the internet.

CertMate's HTTP(S) clients (`requests`, `certbot`, webhook delivery via
`urllib`, `boto3`) honor the standard `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`
environment variables, so no code changes are needed. **SMTP is the
exception:** email notifications use `smtplib`, which opens a direct TCP
connection and does **not** consult the HTTP-proxy variables. On a locked-down
egress network, allow your SMTP relay's `host:port` directly (a firewall /
NetworkPolicy rule), or use a webhook notification channel instead of email.

Example with [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager),
a self-hosted Squid-based forward proxy with a WAF, a DNS sinkhole, and — since
v3.9.0 — a first-class **default-deny egress allowlist** (only explicitly
approved destinations are reachable; everything else is refused):

```yaml
services:
  certmate:
    image: certmate:latest
    environment:
      HTTP_PROXY:  "http://proxy:3128"
      HTTPS_PROXY: "http://proxy:3128"
      NO_PROXY:    "localhost,127.0.0.1"
    networks:
      - egress            # CertMate can reach ONLY the proxy on this network
  # The Secure Proxy Manager stack provides the `proxy` service on :3128.
  # Attach that proxy to BOTH the `egress` network (so CertMate can reach it)
  # AND a second, non-internal network (so the proxy itself reaches the
  # internet). The proxy is then CertMate's only route out.
networks:
  egress:
    internal: true        # no gateway: CertMate has no direct internet
```

Putting CertMate on an `internal` network (no gateway) shared with the proxy
makes the proxy its **only** path out. Outbound becomes a single auditable
choke point: allow the destinations CertMate actually needs (your CA, DNS
provider, object storage, notification endpoints), deny the rest; raw-IP-literal
destinations are blocked at the proxy rather than trusted blindly. If you use
DNS-alias / CNAME delegation, also allow `cloudflare-dns.com` — CertMate
resolves those CNAMEs over DoH.

With Secure Proxy Manager v3.9.0+ this is a built-in mode rather than a manual
ACL exercise: enable **Default-deny egress** in Settings and populate the
**Egress Allowlist** with the destinations CertMate needs. Each entry is a
domain or an IP/CIDR (auto-classified), and the `/api/egress-allowlist` endpoint
lets you manage the list from IaC. A representative starter allowlist:

- your ACME CA's API host — e.g. `acme-v02.api.letsencrypt.org` (plus
  `acme-staging-v02.api.letsencrypt.org` if you issue against staging), or the
  endpoint of whichever CA you configured;
- your DNS provider's API host — varies by provider (for example
  `api.cloudflare.com`);
- your object-storage endpoint, if off-site backup is enabled;
- your notification host — the webhook, Gotify, ntfy, or Telegram endpoint, if
  used;
- `cloudflare-dns.com`, if you use DNS-alias / CNAME delegation (resolved over
  DoH, as above).

Everything else is refused at the proxy, so a misconfiguration or a compromised
dependency cannot quietly exfiltrate to an arbitrary host. For HTTPS the
allowlist matches on the host of the `CONNECT` request, so it works without TLS
interception.

- **Kubernetes:** an egress default-deny `NetworkPolicy` that permits traffic
  only to the proxy Service, plus the `HTTP(S)_PROXY` env on the Deployment.
- **systemd:** `Environment=HTTPS_PROXY=...` in the unit, plus host firewall
  rules that restrict egress to the proxy.

**HTTPS content inspection (optional, advanced).** A forward proxy sees only the
SNI / host / IP of an HTTPS connection — destination allow-deny works on that
without decryption. If you additionally enable TLS interception (SSL-bump) on
the proxy to inspect outbound *content*, CertMate must **trust the proxy's
interception CA**: point `REQUESTS_CA_BUNDLE` (and `SSL_CERT_FILE`) at a bundle
that includes it, or add it to the container's system trust store. **Exclude
(`splice`) the ACME endpoints from interception** — you do not want to MITM the
connection to your Certificate Authority, and some endpoints pin certificates.
This is not mutual TLS; it is one-way trust of a private CA.

### Storage location for the data directory

CertMate uses standard Python blocking file I/O for everything under
`data/` (settings, certificates, audit log, scheduler SQLite store).
Local disk is strongly recommended.

If you mount `data/` on a network filesystem (NFS, SMB), be aware:

- A frozen NFS server can hang Python file reads indefinitely with no
  built-in timeout. The renewal worker, the audit log writer, and the
  /health probe will all block on the same underlying mount.
- SQLite's WAL journal mode requires lock semantics that NFS does not
  always provide. CertMate logs a warning if it had to fall back to a
  weaker journal mode; correctness is preserved, but concurrency drops.

If NFS is unavoidable, mount with `soft,timeo=30,retrans=3` (or your
distro's equivalent) so I/O fails fast instead of hanging on a stalled
server, and check `data/logs/certmate.log` for the WAL-fallback line
after first start.

### Using Gunicorn

```bash
gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 app:app
```

### Using systemd

Create `/etc/systemd/system/certmate.service`:

```ini
[Unit]
Description=CertMate SSL Certificate Manager
After=network.target

[Service]
Type=simple
User=certmate
WorkingDirectory=/opt/certmate
Environment=PATH=/opt/certmate/venv/bin
ExecStart=/opt/certmate/venv/bin/gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable certmate
sudo systemctl start certmate
```

### Using Docker in Production

```yaml
version: '3.8'
services:
  certmate:
    build: .
    ports:
      - "8000:8000"
    environment:
      - API_BEARER_TOKEN=${API_BEARER_TOKEN}
      - CLOUDFLARE_TOKEN=${CLOUDFLARE_TOKEN}
    volumes:
      - ./certificates:/app/certificates
      - ./data:/app/data
    restart: unless-stopped
```

---

## Troubleshooting

### DNS Plugin Version Conflicts

If you encounter version conflicts, use these specific versions:

```txt
certbot==4.1.1
certbot-dns-cloudflare==4.1.1
certbot-dns-route53==4.1.1
certbot-dns-azure==2.6.1
certbot-dns-google==4.1.1
certbot-dns-powerdns==0.2.1
```

> Most DNS plugins require Certbot 4.1.1. The Azure plugin has independent versioning (2.6.1) and PowerDNS is a newer plugin (0.2.1).

### Manual Dependency Installation

If automatic installation fails, install DNS providers individually:

```bash
# Core certbot
pip install certbot==4.1.1

# Cloudflare
pip install certbot-dns-cloudflare==4.1.1

# AWS Route53
pip install certbot-dns-route53==4.1.1 boto3==1.35.76

# Azure DNS
pip install certbot-dns-azure==2.6.1 azure-identity==1.19.0 azure-mgmt-dns==8.1.0

# Google Cloud DNS
pip install certbot-dns-google==4.1.1 google-cloud-dns==0.35.0

# PowerDNS
pip install certbot-dns-powerdns==0.2.1
```

### Validation Commands

```bash
# Check certbot plugins
certbot plugins --text

# Verify service is running
curl -X GET http://localhost:8000/api/health
```

---

## Support

If you encounter issues:

1. Check the logs for specific errors
2. Verify your DNS provider credentials
3. See the [DNS Providers Guide](./dns-providers.md) for provider-specific troubleshooting
4. See the [Testing Guide](./testing.md) for running diagnostics

---

<div align="center">

[← Back to Documentation](./README.md) • [DNS Providers →](./dns-providers.md) • [Docker →](./docker.md)

</div>
