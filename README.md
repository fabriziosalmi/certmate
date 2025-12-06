# 🔐 CertMate - SSL Certificate Management System

<div align="center">

**CertMate** is a powerful SSL certificate management system designed for modern infrastructure. Built with multi-DNS provider support, Docker containerization, and comprehensive REST API, it's the perfect solution for managing certificates across multiple datacenters and cloud environments.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://hub.docker.com/)
[![API Documentation](https://img.shields.io/badge/API-Swagger-green)](http://localhost:8000/docs/)
[![CI](https://github.com/fabriziosalmi/certmate/actions/workflows/ci.yml/badge.svg)](https://github.com/fabriziosalmi/certmate/actions/workflows/ci.yml)
 
![screenshot1](screenshot_1.png)
![screenshot2](screenshot_2.png)

[🚀 Quick Start](#-quick-start-with-docker) • [📖 Documentation](#-documentation) • [🔧 Installation](#-installation-methods) • [🌐 DNS Providers](#-supported-dns-providers) • [🏛️ CA Providers](CA_PROVIDERS.md) • [🏛️ Storage Backends](#️-certificate-storage-configuration) • [💾 Backup & Recovery](#-backup--recovery) • [📊 API Reference](#-api-usage)

</div>

---

## 🌟 Why CertMate?

CertMate solves the complexity of SSL certificate management in modern distributed architectures. Whether you're running a single application or managing certificates across multiple datacenters, CertMate provides:

- **🔄 Zero-Downtime Automation** - Certificates renew automatically 30 days before expiry
- **🌐 Multi-Cloud Support** - Works with 19 DNS providers (Cloudflare, AWS, Azure, GCP, Hetzner, Porkbun, GoDaddy, and more)
- **🚀 Enterprise-Ready** - Docker, Kubernetes, REST API, and monitoring built-in
- **📦 Simple Integration** - One-URL certificate downloads for easy automation
- **🔒 Security-First** - Bearer token authentication, secure file permissions, audit logging
- **💾 Unified Backup System** - Atomic backups of settings and certificates ensuring data consistency

## ✨ Key Features

### 🔐 **Certificate Management**
- **Multiple CA Providers** - Support for Let's Encrypt, DigiCert ACME, and Private CAs
- **Let's Encrypt Integration** - Free, automated SSL certificates with staging/production environments
- **DigiCert ACME Support** - Enterprise-grade certificates with External Account Binding (EAB)
- **Private CA Support** - Internal/corporate CAs with custom trust bundles and ACME compatibility
- **Wildcard Support** - Single certificate for `*.example.com` and `example.com`
- **Multi-Domain Certificates** - SAN certificates for multiple domains
- **Domain Alias Support** - Use alternative domains for DNS validation (e.g., centralized validation domain)
- **Automatic Renewal** - Smart renewal 30 days before expiry
- **Certificate Validation** - Real-time SSL certificate status checking
- **Per-Certificate CA Selection** - Choose different CAs for different certificates

### 🌐 **Multi-DNS Provider Support**
- **Multi-Account Support** - Manage multiple accounts per provider for enterprise environments
- **Cloudflare** - Global CDN with edge locations worldwide (✨ Multi-Account)
- **AWS Route53** - Amazon's scalable DNS service (✨ Multi-Account)
- **Azure DNS** - Microsoft's cloud DNS solution (✨ Multi-Account)
- **Google Cloud DNS** - Google's high-performance DNS (✨ Multi-Account)
- **DigitalOcean** - Cloud infrastructure DNS (✨ Multi-Account)
- **PowerDNS** - Open-source DNS server with REST API (✨ Multi-Account)

### 🚀 **Enterprise Features**
- **Multi-Account Management** - Support multiple accounts per DNS provider for enterprise workflows
- **REST API** - Complete programmatic control with Swagger/OpenAPI docs
- **Web Dashboard** - Modern, responsive UI built with Tailwind CSS
- **Docker Ready** - Full containerization with Docker Compose
- **Kubernetes Compatible** - Deploy in any Kubernetes cluster
- **High Availability** - Stateless design for horizontal scaling
- **Monitoring Integration** - Health checks and structured logging

### 💾 **Backup & Recovery**
- **🔄 Unified Backups** - Atomic snapshots of both settings and certificates ensuring data consistency
- **Automatic Backups** - Settings and certificates backed up automatically on changes
- **Manual Backup Creation** - On-demand backup creation via web UI or API
- **Comprehensive Coverage** - Backs up DNS configurations, certificates, and application settings
- **Retention Management** - Configurable retention policies with automatic cleanup
- **Easy Restore** - Simple restore process from any backup point with atomic consistency
- **Download Support** - Export backups for external storage and disaster recovery

### 🏛️ **Certificate Storage Backends**
- **Local Filesystem** - Default secure local storage with proper file permissions (600/700)
- **🔷 Azure Key Vault** - Enterprise-grade secret management with Azure integration and HSM protection
- **🟠 AWS Secrets Manager** - Scalable secret storage with AWS ecosystem integration and cross-region replication
- **⚫ HashiCorp Vault** - Industry-standard secret management with versioning, audit logging, and fine-grained policies
- **🟣 Infisical** - Modern open-source secret management with team collaboration and end-to-end encryption
- **🔧 Pluggable Architecture** - Easy to extend with additional storage backends
- **🔄 Migration Support** - Seamless migration between storage backends without downtime
- **⚡ Backward Compatibility** - Existing installations continue working without changes

### 🔒 **Security & Compliance**
- **Bearer Token Authentication** - Secure API access control
- **File Permissions** - Proper certificate file security (600/700)
- **Audit Logging** - Complete certificate lifecycle tracking
- **Environment Variables** - Secure credential management
- **Rate Limit Handling** - Let's Encrypt rate limit awareness

### 💻 **Developer Experience**
- **One-URL Downloads** - Simple certificate retrieval for automation
- **Multiple Output Formats** - PEM, ZIP, individual files
- **SDK Examples** - Python, Bash, Ansible, Terraform examples
- **Webhook Support** - Certificate renewal notifications
- **Backup API** - Programmatic backup creation and restoration
- **Extensive Documentation** - API docs, guides, and examples

## 🌐 Supported DNS Providers

CertMate supports **19 DNS providers** through Let's Encrypt DNS-01 challenge via individual certbot plugins that provide reliable, well-tested DNS challenge support. **Multi-account support** is available for major providers, enabling enterprise-grade deployments with separate accounts for production, staging, and disaster recovery.

| Provider | Credentials Required | Multi-Account | Use Case | Status |
|----------|---------------------|---------------|----------|---------|
| **🔶 Cloudflare** | API Token | ✅ **Yes** | Global CDN, Free tier available | ✅ **Stable** |
| **🟠 AWS Route53** | Access Key, Secret Key | ✅ **Yes** | AWS infrastructure, Enterprise | ✅ **Stable** |
| **🔵 Azure DNS** | Service Principal credentials | ✅ **Yes** | Microsoft ecosystem | ✅ **Stable** |
| **🟢 Google Cloud DNS** | Service Account JSON | ✅ **Yes** | Google Cloud Platform | ✅ **Stable** |
| **🔷 DigitalOcean** | API Token | ✅ **Yes** | Cloud infrastructure | ✅ **Stable** |
| **⚫ PowerDNS** | API URL, API Key | ✅ **Yes** | Self-hosted, On-premises | ✅ **Stable** |
| **🔷 RFC2136** | Nameserver, TSIG Key/Secret | ✅ **Yes** | Standard DNS update protocol | ✅ **Stable** |
| **🟣 Linode** | API Key | ➖ Single | Cloud hosting | ✅ **Stable** |
| **🟡 Gandi** | API Token | ➖ Single | Domain registrar | ✅ **Stable** |
| **🔴 OVH** | API Credentials | ➖ Single | European hosting | ✅ **Stable** |
| **🟢 Namecheap** | Username, API Key | ➖ Single | Domain registrar | ✅ **Stable** |
| **🟦 Vultr** | API Key | ➖ Single | Global cloud infrastructure | ✅ **Stable** |
| **🔺 DNS Made Easy** | API Key, Secret Key | ➖ Single | Enterprise DNS management | ✅ **Stable** |
| **🟣 NS1** | API Key | ➖ Single | Intelligent DNS platform | ✅ **Stable** |
| ** Hetzner** | API Token | ➖ Single | European cloud hosting | ✅ **Stable** |
| **🟡 Porkbun** | API Key, Secret Key | ➖ Single | Domain registrar with DNS | ✅ **Stable** |
| **🟢 GoDaddy** | API Key, Secret | ➖ Single | Popular domain registrar | ✅ **Stable** |
| **🔵 Hurricane Electric** | Username, Password | ➖ Single | Free DNS hosting | ✅ **Stable** |
| **🔶 Dynu** | API Token | ➖ Single | Dynamic DNS service | ✅ **Stable** |

### 🌟 Provider Categories

- **Enterprise Multi-Account**: Cloudflare, AWS Route53, Azure DNS, Google Cloud DNS, DigitalOcean, PowerDNS, RFC2136
- **Cloud Providers**: AWS Route53, Azure DNS, Google Cloud DNS, DigitalOcean, Linode, Vultr, Hetzner
- **Enterprise DNS**: Cloudflare, DNS Made Easy, NS1, PowerDNS
- **Domain Registrars**: Gandi, OVH, Namecheap, Porkbun, GoDaddy  
- **European Providers**: OVH, Gandi, Hetzner
- **Free Services**: Hurricane Electric, Dynu
- **Standard Protocols**: RFC2136 (for BIND and compatible servers)

### 🏢 Multi-Account Benefits

For supported providers, you can configure multiple accounts to enable:

- **Environment Separation**: Different accounts for production, staging, and development
- **Multi-Region Management**: Separate accounts for different geographical regions
- **Team Isolation**: Department-specific accounts with tailored permissions
- **Disaster Recovery**: Backup accounts for high-availability scenarios
- **Permission Scoping**: Accounts with minimal required permissions for security

> 📚 **Detailed Setup Instructions**: See [DNS_PROVIDERS.md](DNS_PROVIDERS.md) for provider-specific configuration.  
> 🔧 **Step-by-Step Installation**: See [INSTALLATION.md](INSTALLATION.md) for complete setup guide.  
> 🏢 **Multi-Account Examples**: See [MULTI_ACCOUNT_EXAMPLES.md](MULTI_ACCOUNT_EXAMPLES.md) for enterprise configuration examples.

## 🚀 Quick Start with Docker

Get CertMate running in under 5 minutes with Docker Compose:

### Prerequisites
- Docker 20.10+
- Docker Compose 2.0+
- Domain with DNS managed by supported provider

### 1. Clone and Setup

```bash
# Clone the repository
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate

# Copy environment template
cp .env.example .env
```

### 2. Configure Environment

Edit `.env` file with your credentials:

```bash
# 🔒 Required: API Security
API_BEARER_TOKEN=your_super_secure_api_token_here_change_this

# 🌐 DNS Provider Configuration (choose one or multiple)

# Option 1: Cloudflare (Recommended for beginners)
CLOUDFLARE_TOKEN=your_cloudflare_api_token_here

# Option 2: AWS Route53
# AWS_ACCESS_KEY_ID=your_aws_access_key
# AWS_SECRET_ACCESS_KEY=your_aws_secret_key
# AWS_DEFAULT_REGION=us-east-1

# Option 3: Azure DNS
# AZURE_SUBSCRIPTION_ID=your_azure_subscription_id
# AZURE_RESOURCE_GROUP=your_resource_group
# AZURE_TENANT_ID=your_tenant_id
# AZURE_CLIENT_ID=your_client_id
# AZURE_CLIENT_SECRET=your_client_secret

# Option 4: Google Cloud DNS
# GOOGLE_PROJECT_ID=your_gcp_project_id
# GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# Option 5: PowerDNS
# POWERDNS_API_URL=https://your-powerdns-server:8081
# POWERDNS_API_KEY=your_powerdns_api_key

# ⚙️ Optional: Application Settings
SECRET_KEY=your_flask_secret_key_here
FLASK_ENV=production
HOST=0.0.0.0
PORT=8000
```

> 💡 **Storage Backends**: By default, certificates are stored locally. For enterprise deployments, you can configure Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, or Infisical via the web interface after startup. See [🏛️ Storage Backends](#️-certificate-storage-configuration) for details.

> 🔄 **Backup Best Practices**: CertMate v1.2.0 includes a unified backup system that creates atomic snapshots of both settings and certificates. After setup, create your first backup from Settings → Backup Management.

### 3. Deploy

```bash
# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f certmate
```

### 4. Access CertMate

| Service | URL | Description |
|---------|-----|-------------|
| **Web Dashboard** | http://localhost:8000 | Main certificate management interface |
| **API Documentation** | http://localhost:8000/docs/ | Interactive Swagger/OpenAPI docs |
| **Alternative API Docs** | http://localhost:8000/redoc/ | ReDoc documentation |
| **Health Check** | http://localhost:8000/health | Service health monitoring |

### 5. Create Your First Certificate

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

## 📋 Installation Methods

Choose the installation method that best fits your environment:

### 🐳 Docker (Recommended)
Perfect for production deployments with isolation and easy scaling. **Supports multiple architectures**: AMD64 (Intel/AMD), ARM64 (Apple Silicon, ARM servers), and ARM v7 (Raspberry Pi).

```bash
# Quick start with Docker Compose
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
cp .env.example .env
# Edit .env with your configuration
docker-compose up -d
```

**Multi-Platform Support:**
```bash
# Build for multiple architectures (ARM64 + AMD64)
./build-multiplatform.sh

# Build and push to Docker Hub for all platforms
./build-multiplatform.sh -r YOUR_DOCKERHUB_USERNAME -p

# Use pre-built multi-platform image
docker run --platform linux/arm64 -d --name certmate --env-file .env -p 8000:8000 USERNAME/certmate:latest
```

> 📚 **Multi-Platform Guide**: See [DOCKER_MULTIPLATFORM.md](DOCKER_MULTIPLATFORM.md) for comprehensive multi-architecture setup instructions.

### 🐍 Python Virtual Environment
Ideal for development and testing environments.

```bash
# Create and activate virtual environment
python3 -m venv certmate-env
source certmate-env/bin/activate  # On Windows: certmate-env\Scripts\activate

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

### ☸️ Kubernetes
For container orchestration and high availability deployments.

```yaml
# Example Kubernetes deployment
apiVersion: apps/v1
kind: Deployment
metadata:
  name: certmate
spec:
  replicas: 2
  selector:
    matchLabels:
      app: certmate
  template:
    metadata:
      labels:
        app: certmate
    spec:
      containers:
      - name: certmate
        image: certmate:latest
        ports:
        - containerPort: 8000
        env:
        - name: API_BEARER_TOKEN
          valueFrom:
            secretKeyRef:
              name: certmate-secrets
              key: api-token
        volumeMounts:
        - name: certificates
          mountPath: /app/certificates
      volumes:
      - name: certificates
        persistentVolumeClaim:
          claimName: certmate-certificates
```

### 📦 System Package Installation
For system-wide installation on Linux distributions.

```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt update
sudo apt install python3 python3-pip python3-venv certbot openssl

# Clone and install
git clone https://github.com/fabriziosalmi/certmate.git
sudo mv certmate /opt/
cd /opt/certmate
sudo pip3 install -r requirements.txt

# Create systemd service (see Service Setup section below for detailed instructions)
sudo cp certmate.service /etc/systemd/system/
sudo systemctl enable certmate
sudo systemctl start certmate
```

> 📖 **Detailed Instructions**: See [INSTALLATION.md](INSTALLATION.md) for complete setup guides for each method.

## 🛠️ Service Setup

For production deployments, CertMate should run as a system service. This section provides comprehensive instructions for setting up CertMate with systemd on Linux distributions.

### Prerequisites

- Linux system with systemd
- Python 3.9 or higher
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
# If not already done, clone the repository
git clone https://github.com/fabriziosalmi/certmate.git
sudo mv certmate /opt/
cd /opt/certmate

# Create Python virtual environment
sudo -u certmate python3 -m venv venv
sudo -u certmate ./venv/bin/pip install -r requirements.txt

# Create necessary directories
sudo -u certmate mkdir -p certificates data
```

### 3. Configure Environment Variables

Create environment file for the service:

```bash
# Create environment file
sudo tee /opt/certmate/.env > /dev/null <<EOF
# 🔒 SECURITY: Change this token!
API_BEARER_TOKEN=your_super_secure_api_token_here_change_this

# Optional: Set specific host/port
HOST=127.0.0.1
PORT=8000

# Optional: Enable debug mode (not recommended for production)
FLASK_DEBUG=false
EOF

# Set proper permissions
sudo chown certmate:certmate /opt/certmate/.env
sudo chmod 600 /opt/certmate/.env
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
sudo chmod 750 /opt/certmate/certificates /opt/certmate/data

# Set file permissions
sudo chmod 644 /opt/certmate/*.py /opt/certmate/*.md
sudo chmod 600 /opt/certmate/.env
sudo chmod 755 /opt/certmate/venv/bin/*
```

### 🔒 Security Notes

- **API Bearer Token**: Always change the default API bearer token in `/opt/certmate/.env`
- **File Permissions**: The service runs with restricted permissions and limited filesystem access
- **Network Access**: The service binds to `0.0.0.0:8000` by default - consider using a reverse proxy for production
- **Environment File**: The `.env` file contains sensitive data and should be readable only by the `certmate` user
- **Certificates**: Generated certificates are stored in `/opt/certmate/certificates` with restricted access

### 🔍 Troubleshooting Service Setup

If the service fails to start:

1. **Check service status**: `sudo systemctl status certmate`
2. **View logs**: `sudo journalctl -u certmate --lines=100`
3. **Verify permissions**: Ensure the `certmate` user can read all necessary files
4. **Test manually**: `sudo -u certmate /opt/certmate/venv/bin/python /opt/certmate/app.py`
5. **Check dependencies**: `sudo -u certmate /opt/certmate/venv/bin/python validate_dependencies.py`

For more detailed installation instructions, see [INSTALLATION.md](INSTALLATION.md).

## 📊 API Usage

CertMate provides a comprehensive REST API for programmatic certificate management. All endpoints require Bearer token authentication.

### 🔐 Authentication

Include the Authorization header in all API requests:

```bash
Authorization: Bearer your_api_token_here
```

### 📍 Core Endpoints

#### Health & Status
```bash
# Health check
GET /health

# API documentation
GET /docs/          # Swagger UI
GET /redoc/         # ReDoc documentation

# Prometheus/OpenMetrics monitoring
GET /metrics        # Prometheus-compatible metrics
GET /api/metrics    # JSON metrics summary
```

#### Settings Management
```bash
# Get current settings
GET /api/settings
Authorization: Bearer your_token_here

# Update settings
POST /api/settings
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {
      "api_token": "your_cloudflare_token"
    }
  },
  "domains": [
    {
      "domain": "example.com",
      "dns_provider": "cloudflare"
    }
  ],
  "email": "admin@example.com",
  "auto_renew": true
}
```

#### Certificate Management
```bash
# List all certificates
GET /api/certificates
Authorization: Bearer your_token_here

# Create new certificate
POST /api/certificates/create
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "domain": "example.com",
  "dns_provider": "cloudflare",  # Optional, uses default from settings
  "account_id": "production"     # Optional, specify which account to use
}

# Create certificate with specific account
POST /api/certificates/create
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "domain": "staging.example.com",
  "dns_provider": "cloudflare",
  "account_id": "staging"
}

# Create certificate with domain alias (centralized DNS validation)
POST /api/certificates/create
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "domain": "example.com",
  "dns_provider": "cloudflare",
  "domain_alias": "_acme-challenge.validation.example.org"
}
# This creates a certificate for example.com but performs DNS validation
# on _acme-challenge.validation.example.org instead. Useful when:
# - The primary domain doesn't support DNS API
# - You want to centralize DNS validations on a single domain
# - There are DNS restrictions on the primary domain

# Renew certificate
POST /api/certificates/example.com/renew
Authorization: Bearer your_token_here

# Download certificate (ZIP format)
GET /api/certificates/example.com/download
Authorization: Bearer your_token_here

# Check certificate deployment status
GET /api/certificates/example.com/deployment-status
Authorization: Bearer your_token_here
```

#### Multi-Account Management
```bash
# Add multiple accounts for a provider
POST /api/settings/dns-providers/cloudflare/accounts
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "account_id": "production",
  "config": {
    "name": "Production Environment",
    "description": "Main production Cloudflare account",
    "api_token": "your_production_token_here"
  }
}

# List all accounts for a provider
GET /api/settings/dns-providers/cloudflare/accounts
Authorization: Bearer your_token_here

# Set default account for a provider
PUT /api/settings/dns-providers/cloudflare/default-account
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "account_id": "production"
}

# Update account configuration
PUT /api/settings/dns-providers/cloudflare/accounts/staging
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "config": {
    "name": "Staging & Testing",
    "description": "Updated staging environment",
    "api_token": "new_staging_token_here"
  }
}
```

#### Storage Backend Management
```bash
# Get current storage backend information
GET /api/storage/info
Authorization: Bearer your_token_here

# Update storage backend configuration
POST /api/storage/config
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "backend": "azure_keyvault",
  "azure_keyvault": {
    "vault_url": "https://yourvault.vault.azure.net/",
    "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
    "client_secret": "your_client_secret"
  }
}

# Test storage backend connectivity
POST /api/storage/test
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "backend": "aws_secrets_manager",
  "config": {
    "region": "us-east-1",
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  }
}

# Migrate certificates between storage backends
POST /api/storage/migrate
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "source_backend": "local_filesystem",
  "target_backend": "azure_keyvault",
  "source_config": {
    "cert_dir": "certificates"
  },
  "target_config": {
    "vault_url": "https://yourvault.vault.azure.net/",
    "tenant_id": "...",
    "client_id": "...",
    "client_secret": "..."
  }
}
```

#### Backup Management
```bash
# List all available backups
GET /api/backups
Authorization: Bearer your_token_here

# Create new backup
POST /api/backups/create
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "reason": "manual_backup"
}

# Download specific backup
GET /api/backups/download/unified/{filename}
Authorization: Bearer your_token_here

# Example:
GET /api/backups/download/unified/unified_backup_20241225_120000.zip

# Restore from backup
POST /api/backups/restore/unified
Authorization: Bearer your_token_here
Content-Type: application/json

{
  "filename": "unified_backup_20241225_120000.zip",
  "create_backup_before_restore": true
}
```

### 🎯 Automation-Friendly Download URL

**The most powerful feature for infrastructure automation:**

```bash
# Download certificates via simple URL pattern
GET /{domain}/tls
Authorization: Bearer your_token_here
```

This endpoint returns a ZIP file containing all certificate files:
- `cert.pem` - Server certificate
- `chain.pem` - Intermediate certificate chain  
- `fullchain.pem` - Full certificate chain (cert + chain)
- `privkey.pem` - Private key

### 💼 Integration Examples

#### cURL Download
```bash
curl -H "Authorization: Bearer your_token_here" \
     -o example.com-tls.zip \
     https://your-certmate-server.com/example.com/tls
```

#### Python SDK Example
```python
import requests
import zipfile
from pathlib import Path

class CertMateClient:
    def __init__(self, base_url, token):
        self.base_url = base_url.rstrip('/')
        self.headers = {"Authorization": f"Bearer {token}"}
    
    def download_certificate(self, domain, extract_to=None):
        """Download and optionally extract certificate for domain"""
        url = f"{self.base_url}/{domain}/tls"
        
        response = requests.get(url, headers=self.headers)
        response.raise_for_status()
        
        zip_path = f"{domain}-tls.zip"
        with open(zip_path, 'wb') as f:
            f.write(response.content)
        
        if extract_to:
            Path(extract_to).mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
        
        return zip_path
    
    def list_certificates(self):
        """List all managed certificates"""
        response = requests.get(f"{self.base_url}/api/certificates", 
                              headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def create_certificate(self, domain, dns_provider=None):
        """Create new certificate for domain"""
        data = {"domain": domain}
        if dns_provider:
            data["dns_provider"] = dns_provider
            
        response = requests.post(f"{self.base_url}/api/certificates/create",
                               json=data, headers=self.headers)
        response.raise_for_status()
        return response.json()
    
    def renew_certificate(self, domain):
        """Renew existing certificate"""
        response = requests.post(f"{self.base_url}/api/certificates/{domain}/renew",
                               headers=self.headers)
        response.raise_for_status()
        return response.json()

class CertMateClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"}
    
    def create_certificate(self, domain, dns_provider=None, account_id=None):
        """Create a new certificate with optional account specification"""
        data = {"domain": domain}
        if dns_provider:
            data["dns_provider"] = dns_provider
        if account_id:
            data["account_id"] = account_id
        
        response = requests.post(
            f"{self.base_url}/api/certificates/create",
            headers=self.headers,
            json=data
        )
        return response.json()
    
    def add_dns_account(self, provider, account_id, config):
        """Add a new DNS provider account"""
        response = requests.post(
            f"{self.base_url}/api/settings/dns-providers/{provider}/accounts",
            headers=self.headers,
            json={"account_id": account_id, "config": config}
        )
        return response.json()
    
    def list_dns_accounts(self, provider):
        """List all accounts for a DNS provider"""
        response = requests.get(
            f"{self.base_url}/api/settings/dns-providers/{provider}/accounts",
            headers=self.headers
        )
        return response.json()
    
    def download_certificate(self, domain, extract_to=None):
        """Download certificate as ZIP file"""
        response = requests.get(
            f"{self.base_url}/{domain}/tls",
            headers=self.headers
        )
        
        if extract_to and response.status_code == 200:
            with zipfile.ZipFile(io.BytesIO(response.content)) as zip_file:
                zip_file.extractall(extract_to)
                print(f"Certificate extracted to {extract_to}")
        
        return response

# Usage example
client = CertMateClient("https://certmate.company.com", "your_token_here")

# Add multiple Cloudflare accounts
client.add_dns_account("cloudflare", "production", {
    "name": "Production Environment",
    "description": "Main production account",
    "api_token": "prod_token_here"
})

client.add_dns_account("cloudflare", "staging", {
    "name": "Staging Environment", 
    "description": "Development and testing",
    "api_token": "staging_token_here"
})

# Create certificates with specific accounts
client.create_certificate("api.company.com", "cloudflare", "production")
client.create_certificate("staging.company.com", "cloudflare", "staging")

# Download certificate
client.download_certificate("api.company.com", extract_to="/etc/ssl/certs/api/")
```

#### Infrastructure as Code Examples

**Terraform Provider Example:**
```hcl
# Configure the CertMate provider
terraform {
  required_providers {
    certmate = {
      source = "local/certmate"
      version = "~> 1.0"
    }
  }
}

provider "certmate" {
  endpoint = "https://certmate.company.com"
  token    = var.certmate_token
}

# Create certificates for multiple domains with different accounts
resource "certmate_certificate" "api" {
  domain       = "api.company.com"
  dns_provider = "cloudflare"
  account_id   = "production"
}

resource "certmate_certificate" "web" {
  domain       = "web.company.com" 
  dns_provider = "route53"
  account_id   = "main-aws"
}

resource "certmate_certificate" "staging" {
  domain       = "staging.company.com"
  dns_provider = "cloudflare"
  account_id   = "staging"
}

# Download certificates to local files
data "certmate_certificate_download" "api" {
  domain = certmate_certificate.api.domain
}

# Use in nginx configuration
resource "kubernetes_secret" "api_tls" {
  metadata {
    name      = "api-tls"
    namespace = "default"
  }
  
  type = "kubernetes.io/tls"
  
  data = {
    "tls.crt" = data.certmate_certificate_download.api.fullchain_pem
    "tls.key" = data.certmate_certificate_download.api.private_key_pem
  }
}
```
**Bash Automation Script:**
```bash
#!/bin/bash
set -euo pipefail

# Configuration
CERTMATE_URL="https://certmate.company.com"
API_TOKEN="${CERTMATE_TOKEN}"
DOMAIN="${1:-example.com}"
CERT_DIR="/etc/ssl/certs/${DOMAIN}"
BACKUP_DIR="/backup/certs/${DOMAIN}/$(date +%Y%m%d_%H%M%S)"

# Functions
log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $*" >&2
}

create_backup() {
    if [[ -d "$CERT_DIR" ]]; then
        log "Creating backup of existing certificates"
        mkdir -p "$BACKUP_DIR"
        cp -r "$CERT_DIR"/* "$BACKUP_DIR/" || true
    fi
}

download_certificate() {
    log "Downloading certificate for ${DOMAIN}"
    
    # Download with retry logic
    for i in {1..3}; do
        if curl -f -H "Authorization: Bearer $API_TOKEN" \
                -o "${DOMAIN}-tls.zip" \
                "$CERTMATE_URL/$DOMAIN/tls"; then
            log "Certificate downloaded successfully"
            return 0
        else
            log "Download attempt $i failed, retrying..."
            sleep 5
        fi
    done
    
    log "Failed to download certificate after 3 attempts"
    return 1
}

extract_certificate() {
    log "Extracting certificate to ${CERT_DIR}"
    mkdir -p "$CERT_DIR"
    unzip -o "${DOMAIN}-tls.zip" -d "$CERT_DIR"
    
    # Set proper permissions
    chmod 600 "$CERT_DIR"/*.pem
    chown root:ssl-cert "$CERT_DIR"/*.pem
}

reload_services() {
    log "Reloading web services"
    systemctl reload nginx || log "Failed to reload nginx"
    systemctl reload apache2 || log "Failed to reload apache2"
    systemctl reload haproxy || log "Failed to reload haproxy"
}

cleanup() {
    rm -f "${DOMAIN}-tls.zip"
}

# Main execution
main() {
    log "Starting certificate update for ${DOMAIN}"
    
    create_backup
    download_certificate
    extract_certificate
    reload_services
    cleanup
    
    log "Certificate update completed for ${DOMAIN}"
}

# Trap cleanup on exit
trap cleanup EXIT

# Run main function
main "$@"
```

**Advanced Ansible Playbook:**
```yaml
---
- name: Manage SSL certificates with CertMate multi-account support
  hosts: web_servers
  vars:
    certmate_url: "https://certmate.company.com"
    certmate_token: "{{ vault_certmate_token }}"
  
  tasks:
    - name: Configure Cloudflare accounts
      uri:
        url: "{{ certmate_url }}/api/settings/dns-providers/cloudflare/accounts"
        method: POST
        headers:
          Authorization: "Bearer {{ certmate_token }}"
          Content-Type: "application/json"
        body_format: json
        body:
          account_id: "{{ item.account_id }}"
          config:
            name: "{{ item.name }}"
            description: "{{ item.description }}"
            api_token: "{{ item.api_token }}"
      loop:
        - account_id: "production"
          name: "Production Environment"
          description: "Main production Cloudflare account"
          api_token: "{{ vault_cloudflare_prod_token }}"
        - account_id: "staging"
          name: "Staging Environment"
          description: "Development and testing account"
          api_token: "{{ vault_cloudflare_staging_token }}"
    
    - name: Create certificates with specific accounts
      uri:
        url: "{{ certmate_url }}/api/certificates/create"
        method: POST
        headers:
          Authorization: "Bearer {{ certmate_token }}"
          Content-Type: "application/json"
        body_format: json
        body:
          domain: "{{ item.domain }}"
          dns_provider: "{{ item.provider }}"
          account_id: "{{ item.account_id }}"
      loop:
        - domain: "api.company.com"
          provider: "cloudflare"
          account_id: "production"
        - domain: "staging.company.com"
          provider: "cloudflare"
          account_id: "staging"
        - domain: "test.company.com"
          provider: "route53"
          account_id: "backup-aws"
    
    - name: Download and deploy certificates
      block:
        - name: Download certificate
          uri:
            url: "{{ certmate_url }}/{{ item }}/tls"
            headers:
              Authorization: "Bearer {{ certmate_token }}"
            dest: "/tmp/{{ item }}-tls.zip"
        
        - name: Extract certificate
          unarchive:
            src: "/tmp/{{ item }}-tls.zip"
            dest: "/etc/ssl/certs/{{ item }}/"
            remote_src: yes
            owner: root
            group: ssl-cert
            mode: '0640'
      loop:
        - "api.company.com"
        - "staging.company.com"
        - "test.company.com"
```

**Production-Ready Ansible Playbook:**
```yaml
---
- name: Enterprise SSL certificate management with CertMate
  hosts: web_servers
  become: yes
  vars:
    certmate_url: "https://certmate.company.com"
    api_token: "{{ vault_certmate_token }}"
    certificate_domains:
      - name: "api.company.com"
        dns_provider: "cloudflare"
        nginx_sites: ["api"]
        services_to_reload: ["nginx"]
      - name: "web.company.com"
        dns_provider: "route53"
        nginx_sites: ["web", "admin"]
        services_to_reload: ["nginx", "haproxy"]
  
  tasks:
    - name: Create certificate directories
      file:
        path: "/etc/ssl/certs/{{ item.name }}"
        state: directory
        owner: root
        group: ssl-cert
        mode: '0750'
      loop: "{{ certificate_domains }}"
      
    - name: Check certificate expiry
      uri:
        url: "{{ certmate_url }}/api/certificates/{{ item.name }}/deployment-status"
        method: GET
        headers:
          Authorization: "Bearer {{ api_token }}"
      register: cert_status
      loop: "{{ certificate_domains }}"
      
    - name: Create new certificates if needed
      uri:
        url: "{{ certmate_url }}/api/certificates/create"
        method: POST
        headers:
          Authorization: "Bearer {{ api_token }}"
          Content-Type: "application/json"
        body_format: json
        body:
          domain: "{{ item.name }}"
          dns_provider: "{{ item.dns_provider }}"
      loop: "{{ certificate_domains }}"
      when: cert_status.results[ansible_loop.index0].json.needs_renewal | default(false)
      
    - name: Download certificates
      uri:
        url: "{{ certmate_url }}/{{ item.name }}/tls"
        method: GET
        headers:
          Authorization: "Bearer {{ api_token }}"
        dest: "/tmp/{{ item.name }}-tls.zip"
        creates: "/tmp/{{ item.name }}-tls.zip"
      loop: "{{ certificate_domains }}"
      
    - name: Extract certificates
      unarchive:
        src: "/tmp/{{ item.name }}-tls.zip"
        dest: "/etc/ssl/certs/{{ item.name }}/"
        owner: root
        group: ssl-cert
        mode: '0640'
        remote_src: yes
      loop: "{{ certificate_domains }}"
      notify: 
        - reload nginx
        - reload haproxy
        - restart services
      
    - name: Verify certificate installation
      openssl_certificate:
        path: "/etc/ssl/certs/{{ item.name }}/fullchain.pem"
        provider: assertonly
        has_expired: no
        valid_in: 86400  # Valid for at least 1 day
      loop: "{{ certificate_domains }}"
      
    - name: Update nginx SSL configuration
      template:
        src: "nginx-ssl.conf.j2"
        dest: "/etc/nginx/sites-available/{{ item.1 }}"
        backup: yes
      loop: "{{ certificate_domains | subelements('nginx_sites') }}"
      notify: reload nginx
      
    - name: Cleanup temporary files
      file:
        path: "/tmp/{{ item.name }}-tls.zip"
        state: absent
      loop: "{{ certificate_domains }}"
  
  handlers:
    - name: reload nginx
      systemd:
        name: nginx
        state: reloaded
        
    - name: reload haproxy
      systemd:
        name: haproxy
        state: reloaded
        
    - name: restart services
      systemd:
        name: "{{ item }}"
        state: restarted
      loop: "{{ services_to_restart | default([]) }}"
```

## ⚙️ Configuration Guide

### 🔧 Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `API_BEARER_TOKEN` | ✅ | - | Bearer token for API authentication |
| `SECRET_KEY` | ❌ | auto-generated | Flask secret key for sessions |
| `HOST` | ❌ | `127.0.0.1` | Server bind address |
| `PORT` | ❌ | `8000` | Server port |
| `FLASK_ENV` | ❌ | `production` | Flask environment |
| `FLASK_DEBUG` | ❌ | `false` | Enable debug mode |

### 🌐 DNS Provider Configuration

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
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "route53:ListHostedZones",
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

### 🏛️ Certificate Storage Configuration

CertMate supports multiple storage backends for certificates, providing flexibility for different deployment scenarios and security requirements. By default, certificates are stored locally on the filesystem, but you can configure enterprise-grade storage backends for enhanced security and compliance.

> 💡 **Choosing the Right Storage Backend:**
> - **Local Filesystem**: Perfect for development, testing, and small deployments
> - **Azure Key Vault**: Best for Azure-native environments and Microsoft ecosystem integration
> - **AWS Secrets Manager**: Ideal for AWS infrastructure and cross-region deployments
> - **HashiCorp Vault**: Excellent for multi-cloud environments and advanced secret management
> - **Infisical**: Great for teams wanting open-source secret management with collaboration features

#### 📁 Local Filesystem (Default)
The default storage backend stores certificates in the local filesystem with secure permissions:

```bash
# Default certificate directory
certificates/
└── example.com/
    ├── cert.pem      # Server certificate
    ├── chain.pem     # Certificate chain
    ├── fullchain.pem # Full chain
    └── privkey.pem   # Private key (600 permissions)
```

**Configuration:**
- **Directory**: `certificates` (configurable)
- **Permissions**: `600` for private keys, `644` for certificates
- **Backup**: Included in automatic backups
- **Use Cases**: Development, testing, single-server deployments

**Benefits:**
- ✅ Zero configuration required
- ✅ No external dependencies
- ✅ Fast access and operations
- ✅ Perfect for getting started

#### 🔷 Azure Key Vault
Store certificates securely in Azure Key Vault for enterprise-grade secret management:

**Required Dependencies:**
```bash
pip install -r requirements-azure-storage.txt
```

**Configuration:**
```json
{
  "certificate_storage": {
    "backend": "azure_keyvault",
    "azure_keyvault": {
      "vault_url": "https://yourvault.vault.azure.net/",
      "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_secret": "your_client_secret"
    }
  }
}
```

**Benefits:**
- ✅ Azure-native secret management
- ✅ Compliance and audit capabilities (SOC 2, ISO 27001, FIPS 140-2)
- ✅ Hardware security module (HSM) protection
- ✅ Azure RBAC integration and managed identity support
- ✅ Automatic backup and disaster recovery

**Use Cases:**
- Azure-based infrastructure
- Enterprise compliance requirements
- Multi-region Azure deployments
- Integration with Azure DevOps and ARM templates

#### 🟠 AWS Secrets Manager
Integrate with AWS Secrets Manager for scalable secret storage:

**Required Dependencies:**
```bash
pip install -r requirements-aws-storage.txt
```

**Configuration:**
```json
{
  "certificate_storage": {
    "backend": "aws_secrets_manager",
    "aws_secrets_manager": {
      "region": "us-east-1",
      "access_key_id": "AKIAIOSFODNN7EXAMPLE",
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }
}
```

**Benefits:**
- ✅ AWS-native secret management
- ✅ Automatic encryption at rest with AWS KMS
- ✅ Cross-region replication for high availability
- ✅ IAM-based access control and fine-grained permissions
- ✅ Integration with AWS CloudTrail for audit logging
- ✅ Automatic rotation capabilities

**Use Cases:**
- AWS-based infrastructure
- Multi-region deployments
- Integration with ECS, EKS, Lambda
- Compliance with AWS security best practices

#### ⚫ HashiCorp Vault
Use industry-standard HashiCorp Vault for advanced secret management:

**Required Dependencies:**
```bash
pip install -r requirements-vault-storage.txt
```

**Configuration:**
```json
{
  "certificate_storage": {
    "backend": "hashicorp_vault",
    "hashicorp_vault": {
      "vault_url": "https://vault.example.com:8200",
      "vault_token": "hvs.xxxxxxxxxxxxxxxxxxxx",
      "mount_point": "secret",
      "engine_version": "v2"
    }
  }
}
```

**Benefits:**
- ✅ Industry-standard secret management
- ✅ Secret versioning and rollback capabilities
- ✅ Comprehensive audit logging and monitoring
- ✅ Fine-grained access policies and dynamic secrets
- ✅ Multi-cloud and hybrid cloud support
- ✅ Advanced authentication methods (LDAP, Kubernetes, AWS IAM)

**Use Cases:**
- Multi-cloud environments
- Complex organizational security requirements
- Dynamic secret generation
- Integration with CI/CD pipelines and Kubernetes

#### 🟣 Infisical
Modern open-source secret management with team collaboration:

**Required Dependencies:**
```bash
pip install -r requirements-infisical-storage.txt
```

**Configuration:**
```json
{
  "certificate_storage": {
    "backend": "infisical",
    "infisical": {
      "site_url": "https://app.infisical.com",
      "client_id": "your_client_id",
      "client_secret": "your_client_secret",
      "project_id": "your_project_id",
      "environment": "prod"
    }
  }
}
```

**Benefits:**
- ✅ Open-source secret management with transparency
- ✅ End-to-end encryption for maximum security
- ✅ Team collaboration features and role-based access
- ✅ Multi-environment support (dev, staging, prod)
- ✅ Git-like versioning for secrets
- ✅ Self-hostable for complete control

**Use Cases:**
- Team-based development workflows
- Open-source preference
- Self-hosted secret management
- Multi-environment certificate management
Integrate with AWS Secrets Manager for scalable secret storage:

**Required Dependencies:**
```bash
pip install -r requirements-aws-storage.txt
```

**Configuration:**
```json
{
  "certificate_storage": {
    "backend": "aws_secrets_manager",
    "aws_secrets_manager": {
      "region": "us-east-1",
      "access_key_id": "AKIAIOSFODNN7EXAMPLE",
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }
  }
}
```

**Benefits:**
- AWS-native secret management
- Automatic encryption at rest
- Cross-region replication
- IAM-based access control

#### HashiCorp Vault
Use industry-standard HashiCorp Vault for advanced secret management:

**Required Dependencies:**
```bash
pip install -r requirements-vault-storage.txt
```

**Configuration:**
```json
{
  "certificate_storage": {
    "backend": "hashicorp_vault",
    "hashicorp_vault": {
      "vault_url": "https://vault.example.com:8200",
      "vault_token": "hvs.xxxxxxxxxxxxxxxxxxxx",
      "mount_point": "secret",
      "engine_version": "v2"
    }
  }
}
```

**Benefits:**
- ✅ Industry-standard secret management
- ✅ Secret versioning and rollback capabilities
- ✅ Comprehensive audit logging and monitoring
- ✅ Fine-grained access policies and dynamic secrets
- ✅ Multi-cloud and hybrid cloud support
- ✅ Advanced authentication methods (LDAP, Kubernetes, AWS IAM)

**Use Cases:**
- Multi-cloud environments
- Complex organizational security requirements
- Dynamic secret generation
- Integration with CI/CD pipelines and Kubernetes

#### 🟣 Infisical
Modern open-source secret management with team collaboration:

**Required Dependencies:**
```bash
pip install -r requirements-infisical-storage.txt
```

**Configuration:**
```json
{
  "certificate_storage": {
    "backend": "infisical",
    "infisical": {
      "site_url": "https://app.infisical.com",
      "client_id": "your_client_id",
      "client_secret": "your_client_secret",
      "project_id": "your_project_id",
      "environment": "prod"
    }
  }
}
```

**Benefits:**
- ✅ Open-source secret management with transparency
- ✅ End-to-end encryption for maximum security
- ✅ Team collaboration features and role-based access
- ✅ Multi-environment support (dev, staging, prod)
- ✅ Git-like versioning for secrets
- ✅ Self-hostable for complete control

**Use Cases:**
- Team-based development workflows
- Open-source preference
- Self-hosted secret management
- Multi-environment certificate management

#### 📦 Quick Installation Guide

**Install All Storage Backends:**
```bash
# Install all storage backends at once
pip install -r requirements-storage-all.txt
```

**Install Individual Storage Backends:**
```bash
# Azure Key Vault only
pip install -r requirements-azure-storage.txt

# AWS Secrets Manager only  
pip install -r requirements-aws-storage.txt

# HashiCorp Vault only
pip install -r requirements-vault-storage.txt

# Infisical only
pip install -r requirements-infisical-storage.txt
```

**Requirements File Overview:**
- `requirements-storage-all.txt` - All storage backends (recommended for production)
- `requirements-azure-storage.txt` - Azure Key Vault dependencies
- `requirements-aws-storage.txt` - AWS Secrets Manager dependencies  
- `requirements-vault-storage.txt` - HashiCorp Vault dependencies
- `requirements-infisical-storage.txt` - Infisical dependencies
- `requirements-minimal.txt` - Base CertMate without storage backends

#### ⚙️ Configuring Storage Backends

**Via Web Interface:**
1. Navigate to Settings → Certificate Storage Backend
2. Select your preferred backend from the dropdown
3. Configure the required credentials and settings
4. Test the connection to verify configuration
5. Save settings and optionally migrate existing certificates

**Via API:**
```bash
# Test storage backend connectivity before switching
curl -X POST "http://localhost:8000/api/storage/test" \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "backend": "azure_keyvault",
    "config": {
      "vault_url": "https://yourvault.vault.azure.net/",
      "tenant_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "client_secret": "your_client_secret"
    }
  }'

# Get current storage backend information
curl -X GET "http://localhost:8000/api/storage/info" \
  -H "Authorization: Bearer your_token"

# Update storage backend configuration
curl -X POST "http://localhost:8000/api/storage/config" \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "backend": "hashicorp_vault",
    "config": {
      "vault_url": "https://vault.example.com:8200",
      "vault_token": "hvs.xxxxxxxxxxxxxxxxxxxx",
      "mount_point": "secret",
      "engine_version": "v2"
    }
  }'
```

**🔄 Migrating Between Backends:**

*Zero-Downtime Migration Process:*
1. Configure the new storage backend
2. Test connectivity and verify access
3. Use the migration tool in Settings or API
4. Verify all certificates are accessible in new backend
5. Optionally clean up old storage

*Migration via API:*
```bash
# Migrate all certificates from current backend to new backend
curl -X POST "http://localhost:8000/api/storage/migrate" \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "target_backend": "aws_secrets_manager",
    "target_config": {
      "region": "us-east-1",
      "access_key_id": "AKIAIOSFODNN7EXAMPLE", 
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    },
    "verify_migration": true
  }'
```

*Migration Benefits:*
- ✅ Zero downtime during migration
- ✅ Automatic verification of migrated certificates
- ✅ Rollback capability if issues are detected
- ✅ Preservation of certificate metadata and permissions
curl -X POST "http://localhost:8000/api/storage/migrate" \
  -H "Authorization: Bearer your_token" \
  -H "Content-Type: application/json" \
  -d '{
    "source_backend": "local_filesystem",
    "target_config": {
      "backend": "azure_keyvault",
      "azure_keyvault": {...}
    }
  }'
```

**Backward Compatibility:**
- Existing installations continue working without changes
- New storage backends are opt-in
- Migration is non-destructive (copies certificates)
- Local filesystem remains the default backend

### 📁 Directory Structure

```
certmate/
├── 📄 app.py                    # Main Flask application
├── 📄 requirements.txt          # Python dependencies
├── 📄 docker-compose.yml        # Docker Compose configuration
├── 📄 Dockerfile               # Container build instructions
├── 📄 nginx.conf               # Nginx reverse proxy config
├── 📄 .env.example             # Environment template
├── 📚 README.md                # This documentation
├── 📚 INSTALLATION.md          # Detailed installation guide
├── 📚 DNS_PROVIDERS.md         # DNS provider configuration
├── 📚 CONTRIBUTING.md          # Contribution guidelines
├── 📁 certificates/            # Certificate storage
│   └── 📁 {domain}/
│       ├── 🔐 cert.pem         # Server certificate
│       ├── 🔐 chain.pem        # Certificate chain
│       ├── 🔐 fullchain.pem    # Full chain
│       └── 🔐 privkey.pem      # Private key
├── 📁 data/                    # Application data
│   └── ⚙️ settings.json        # Persistent settings
├── 📁 logs/                    # Application logs
├── 📁 letsencrypt/             # Let's Encrypt working directory
│   ├── 📁 config/              # Certbot configuration
│   ├── 📁 work/                # Certbot working files
│   └── 📁 logs/                # Certbot logs
└── 📁 templates/               # Web interface templates
    ├── 🌐 index.html           # Main dashboard
    └── ⚙️ settings.html        # Settings page
```

## 🔒 Security & Best Practices

### 🛡️ Security Considerations

#### Authentication & Authorization
- **Strong Bearer Tokens**: Use cryptographically secure tokens (32+ characters)
- **Token Rotation**: Regularly rotate API tokens
- **Environment Variables**: Never commit tokens to version control
- **HTTPS Only**: Always use HTTPS in production environments
- **IP Restrictions**: Implement firewall rules to restrict access

#### Certificate Security
- **File Permissions**: Private keys stored with `600` permissions
- **Directory Permissions**: Certificate directories with `700` permissions
- **Backup Encryption**: Encrypt certificate backups
- **Access Logging**: Monitor certificate access patterns

#### Network Security
```bash
# Example firewall rules (iptables)
# Allow only specific IPs to access CertMate
iptables -A INPUT -p tcp --dport 8000 -s 10.0.0.0/8 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -s 192.168.0.0/16 -j ACCEPT
iptables -A INPUT -p tcp --dport 8000 -j DROP
```

### ⚡ Performance Optimization

#### Production Deployment
```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  certmate:
    image: certmate:latest
    deploy:
      replicas: 2
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
    environment:
      - FLASK_ENV=production
      - GUNICORN_WORKERS=4
      - GUNICORN_THREADS=2
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

### 🔄 Backup & Recovery

CertMate provides comprehensive backup and recovery capabilities built directly into the application, ensuring your certificates and configuration data are always protected.

#### 🔄 Unified Backup System

**What is Unified Backup?**
- **Atomic Operation**: Creates a single ZIP file containing both settings and certificates
- **Data Consistency**: Ensures settings and certificates are always in sync
- **Prevents Corruption**: Eliminates configuration/certificate mismatches
- **Simplified Management**: One backup file contains everything needed for complete restoration

**Automatic Backups:**
- **Unified Snapshots** - Automatically created when DNS providers, domains, certificates, or application settings are modified
- **Retention Management** - Configurable retention policy (default: 10 most recent backups)
- **Automatic Cleanup** - Old backups are automatically removed based on retention settings

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
# Create backup (settings + certificates)
curl -X POST "http://localhost:8000/api/backups/create" \
     -H "Authorization: Bearer your_token" \
     -H "Content-Type: application/json" \
     -d '{"reason": "manual_backup"}'

# Response includes backup file information
{
  "success": true,
  "backup_file": "unified_backup_20241225_120000.zip",
  "size": "2.5MB",
  "contents": {
    "settings": true,
    "certificates": 15
  }
}
```

**List and Download Backups:**
```bash
# List all backups
curl -H "Authorization: Bearer your_token" \
     "http://localhost:8000/api/backups"

# Download backup
curl -H "Authorization: Bearer your_token" \
     "http://localhost:8000/api/backups/download/unified/unified_backup_20241225_120000.zip" \
     -o backup.zip
```

#### Backup File Structure

**Backup File (ZIP):**
```
unified_backup_20241225_120000.zip
├── settings.json                    # Complete application settings
│   ├── timestamp: "2024-12-25T12:00:00Z"
│   ├── version: "1.2.0"
│   ├── dns_providers: {...}
│   ├── domains: [...]
│   └── settings: {...}
└── certificates/                    # All certificate files
    ├── domain1.com/
    │   ├── cert.pem
    │   ├── chain.pem
    │   ├── fullchain.pem
    │   └── privkey.pem
    └── domain2.com/
        ├── cert.pem
        ├── chain.pem
        ├── fullchain.pem
        └── privkey.pem
```

#### Recovery Procedures

**Backup Restoration:**

*Web Interface:*
1. Navigate to Settings → Backup Management
2. Select the backup to restore from
3. Confirm restoration (restores both settings and certificates atomically)
4. Application will restart to apply new settings
5. Verify all certificates and configurations are working

*API Restoration:*
```bash
# Restore from backup
curl -X POST "http://localhost:8000/api/backups/restore/unified" \
     -H "Authorization: Bearer your_token" \
     -H "Content-Type: application/json" \
     -d '{"filename": "unified_backup_20241225_120000.zip", "create_backup_before_restore": true}'
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

# Download latest backup via API
curl -H "Authorization: Bearer $API_TOKEN" \
     "http://localhost:8000/api/backups/download/unified/latest" \
     -o "$BACKUP_DIR/certmate_backup.zip"

# Backup certificates directory
tar -czf "$BACKUP_DIR/certificates.tar.gz" "$CERT_DIR"

# Backup application data
tar -czf "$BACKUP_DIR/data.tar.gz" "$DATA_DIR"

# Encrypt backups (optional)
gpg --cipher-algo AES256 --compress-algo 1 --symmetric \
    --output "$BACKUP_DIR/certmate_backup.zip.gpg" \
    "$BACKUP_DIR/certmate_backup.zip"

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

#### Recovery Procedures

**Web Interface Recovery:**
1. Navigate to Settings → Backup Management
2. Select the backup to restore from
3. Choose restore type (settings, certificates, or both)
4. Confirm restoration
5. Application will restart if settings are restored

**API Recovery:**
```bash
# Restore settings from backup
curl -X POST "http://localhost:8000/api/backup/restore/settings" \
     -H "Authorization: Bearer your_token" \
     -H "Content-Type: application/json" \
     -d '{"backup_id": "settings_20241225_120000"}'

# Restore certificates from backup
curl -X POST "http://localhost:8000/api/backup/restore/certificates" \
     -H "Authorization: Bearer your_token" \
     -H "Content-Type: application/json" \
     -d '{"backup_id": "certificates_20241225_120000"}'
```

**Manual Recovery from External Backup:**
```bash
#!/bin/bash
# /opt/scripts/backup-certmate.sh

BACKUP_DIR="/backup/certmate/$(date +%Y%m%d_%H%M%S)"
CERT_DIR="/opt/certmate/certificates"
DATA_DIR="/opt/certmate/data"
RETENTION_DAYS=30

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup certificates
tar -czf "$BACKUP_DIR/certificates.tar.gz" "$CERT_DIR"

# Backup application data
tar -czf "$BACKUP_DIR/data.tar.gz" "$DATA_DIR"

# Backup database if using external DB
# mysqldump certmate > "$BACKUP_DIR/database.sql"

# Encrypt backups
gpg --cipher-algo AES256 --compress-algo 1 --symmetric \
    --output "$BACKUP_DIR/certificates.tar.gz.gpg" \
    "$BACKUP_DIR/certificates.tar.gz"

# Cleanup old backups
find /backup/certmate -type d -mtime +$RETENTION_DAYS -exec rm -rf {} \;

echo "Backup completed: $BACKUP_DIR"
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
gpg --decrypt "$BACKUP_DIR/certificates.tar.gz.gpg" | \
    tar -xzf - -C /opt/certmate/

# Restore data
tar -xzf "$BACKUP_DIR/data.tar.gz" -C /opt/certmate/

# Set permissions
chown -R 1000:1000 /opt/certmate/certificates
chmod -R 700 /opt/certmate/certificates

# Start services
docker-compose up -d

echo "Recovery completed from backup: $BACKUP_DATE"
```

## 📊 Monitoring & Observability

### 🔍 Health Monitoring

#### Built-in Health Checks
```bash
# Basic health check
curl -f http://localhost:8000/health

# Detailed health with auth
curl -H "Authorization: Bearer your_token" \
     http://localhost:8000/api/certificates
```

#### Prometheus Metrics Integration
```python
# Add to app.py for Prometheus monitoring
from prometheus_client import Counter, Histogram, generate_latest

# Metrics
certificate_requests = Counter('certmate_certificate_requests_total', 
                              'Total certificate requests', ['domain', 'status'])
certificate_expiry = Histogram('certmate_certificate_expiry_days',
                              'Days until certificate expiry', ['domain'])

@app.route('/metrics')
def metrics():
    return generate_latest()
```

#### Log Aggregation
```yaml
# docker-compose.logging.yml
version: '3.8'
services:
  certmate:
    logging:
      driver: "fluentd"
      options:
        fluentd-address: localhost:24224
        tag: certmate
        fluentd-async-connect: "true"
        
  fluentd:
    image: fluent/fluentd:v1.14
    volumes:
      - ./fluentd/conf:/fluentd/etc
      - ./logs:/var/log/fluentd
    ports:
      - "24224:24224"
      - "24224:24224/udp"
```

### 📈 Grafana Dashboard Example
```json
{
  "dashboard": {
    "title": "CertMate SSL Certificate Monitoring",
    "panels": [
      {
        "title": "Certificate Expiry Status",
        "targets": [
          {
            "expr": "certmate_certificate_expiry_days < 30",
            "legendFormat": "Expiring Soon ({{domain}})"
          }
        ],
        "alert": {
          "conditions": [
            {
              "query": {"queryType": "", "refId": "A"},
              "reducer": {"type": "last", "params": []},
              "evaluator": {"params": [30], "type": "lt"}
            }
          ],
          "executionErrorState": "alerting",
          "frequency": "1h",
          "handler": 1,
          "name": "Certificate Expiring",
          "noDataState": "no_data",
          "notifications": []
        }
      }
    ]
  }
}
```

### 🚨 Alerting Configuration

#### Webhook Notifications
```python
# Add webhook notification support
import requests

def send_webhook_notification(domain, event_type, details):
    webhook_url = os.getenv('WEBHOOK_URL')
    if not webhook_url:
        return
        
    payload = {
        'domain': domain,
        'event': event_type,
        'timestamp': datetime.now().isoformat(),
        'details': details
    }
    
    try:
        requests.post(webhook_url, json=payload, timeout=10)
    except Exception as e:
        logger.error(f"Failed to send webhook: {e}")
```

#### Slack Integration Example
```bash
# Slack notification script
#!/bin/bash
SLACK_WEBHOOK="your_slack_webhook_url"
DOMAIN="$1"
STATUS="$2"
MESSAGE="Certificate for $DOMAIN: $STATUS"

curl -X POST -H 'Content-type: application/json' \
    --data "{\"text\":\"🔐 $MESSAGE\"}" \
    "$SLACK_WEBHOOK"
```

## 🔧 Troubleshooting Guide

### 🚨 Common Issues & Solutions

#### Certificate Creation Failures

**Issue**: `DNS validation failed`
```bash
# Check DNS propagation
dig TXT _acme-challenge.example.com @8.8.8.8

# Verify DNS provider credentials
curl -H "Authorization: Bearer cf_token" \
     "https://api.cloudflare.com/client/v4/user/tokens/verify"
```

**Issue**: `Rate limit exceeded`
```bash
# Let's Encrypt rate limits:
# - 50 certificates per registered domain per week
# - 5 duplicate certificates per week
# - 300 new orders per account per 3 hours

# Check rate limit status
curl "https://crt.sh/?q=example.com&output=json" | jq length
```

**Issue**: `Permission denied accessing certificate files`
```bash
# Fix file permissions
sudo chown -R certmate:certmate /opt/certmate/certificates
sudo chmod -R 700 /opt/certmate/certificates
sudo chmod 600 /opt/certmate/certificates/*/privkey.pem
```

#### API Authentication Issues

**Issue**: `401 Unauthorized`
```bash
# Verify token format
curl -H "Authorization: Bearer your_token_here" \
     http://localhost:8000/api/certificates

# Check token in settings
docker exec certmate cat /app/data/settings.json | jq .api_bearer_token
```

**Issue**: `Token not found`
```bash
# Reset API token
docker exec -it certmate python -c "
import json
with open('/app/data/settings.json', 'r+') as f:
    data = json.load(f)
    data['api_bearer_token'] = 'new_secure_token_here'
    f.seek(0)
    json.dump(data, f, indent=2)
    f.truncate()
"
```

#### Docker & Container Issues

**Issue**: `Container won't start`
```bash
# Check logs
docker-compose logs certmate

# Verify environment variables
docker-compose config

# Check port conflicts
netstat -tulpn | grep :8000
```

**Issue**: `Volume mount issues`
```bash
# Fix volume permissions
sudo chown -R 1000:1000 ./certificates ./data ./logs

# Check volume mounts
docker inspect certmate | jq '.[0].Mounts'
```

#### DNS Provider Specific Issues

**Cloudflare**:
```bash
# Verify API token permissions
curl -X GET "https://api.cloudflare.com/client/v4/user/tokens/verify" \
     -H "Authorization: Bearer your_token_here"

# Check zone access
curl -X GET "https://api.cloudflare.com/client/v4/zones" \
     -H "Authorization: Bearer your_token_here"
```

**AWS Route53**:
```bash
# Test AWS credentials
aws sts get-caller-identity

# Check Route53 permissions
aws route53 list-hosted-zones
```

**Azure DNS**:
```bash
# Verify service principal
az login --service-principal \
    -u $AZURE_CLIENT_ID \
    -p $AZURE_CLIENT_SECRET \
    --tenant $AZURE_TENANT_ID

# Check DNS zone access
az network dns zone list
```

### 🔍 Debug Mode

Enable debug logging for troubleshooting:

```bash
# Environment variable
FLASK_DEBUG=true
FLASK_ENV=development

# Or in Docker Compose
docker-compose -f docker-compose.yml -f docker-compose.debug.yml up
```

### ⚠️ Known Issues (v1.2.0)

#### API Test Failures
**Issue**: Some API endpoints may fail during rapid testing  
**Workaround**: Add delays between API calls in automated tests:
```bash
# Add delay between test calls
sleep 0.1
```

### 📋 Support Checklist

Before seeking help, please provide:

- [ ] CertMate version/commit hash
- [ ] DNS provider being used
- [ ] Error messages from logs
- [ ] Steps to reproduce the issue
- [ ] Environment details (Docker, Python version, OS)

```bash
# Collect system information
echo "=== CertMate Debug Info ==="
echo "Version: $(docker exec certmate python -c 'import app; print(getattr(app, "__version__", "unknown"))')"
echo "Python: $(docker exec certmate python --version)"
echo "OS: $(docker exec certmate cat /etc/os-release | head -2)"
echo "Certbot: $(docker exec certmate certbot --version)"
echo "DNS Plugins: $(docker exec certmate pip list | grep certbot-dns)"
echo "Certificates: $(docker exec certmate ls -la /app/certificates)"
echo "Settings: $(docker exec certmate cat /app/data/settings.json | jq .)"
```

## 📖 Documentation

### 📚 Complete Documentation Set

| Document | Description | Target Audience |
|----------|-------------|-----------------|
| **[README.md](README.md)** | Main documentation and quick start | All users |
| **[INSTALLATION.md](INSTALLATION.md)** | Detailed installation instructions | System administrators |
| **[DNS_PROVIDERS.md](DNS_PROVIDERS.md)** | DNS provider setup guides | DevOps engineers |
| **[CA_PROVIDERS.md](CA_PROVIDERS.md)** | Certificate Authority configuration | Enterprise users |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Development and contribution guide | Developers |
| **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)** | Community guidelines | Contributors |

### 🔗 Online Resources

- **API Documentation**: http://your-server:8000/docs/ (Swagger UI)
- **Alternative API Docs**: http://your-server:8000/redoc/ (ReDoc)
- **GitHub Repository**: https://github.com/fabriziosalmi/certmate
- **Docker Hub**: https://hub.docker.com/r/certmate/certmate
- **Issue Tracker**: https://github.com/fabriziosalmi/certmate/issues

### 📝 Examples Repository

Check out our examples repository for:
- Production deployment configurations
- Integration scripts for popular tools
- Terraform modules
- Kubernetes manifests
- CI/CD pipeline examples

### 🤝 Community Contributions

We welcome contributions! Areas where we need help:
- **Documentation** - Tutorials, use cases, translations
- **Testing** - DNS provider testing, edge cases
- **Integrations** - New DNS providers, monitoring tools
- **Features** - UI improvements, API enhancements

## 🤝 Contributing

We love contributions! CertMate is an open-source project and we welcome:

### 🛠️ Types of Contributions
- **🐛 Bug Reports** - Help us identify and fix issues
- **💡 Feature Requests** - Suggest new functionality
- **📖 Documentation** - Improve guides and examples
- **🧪 Testing** - Test new features and edge cases
- **💻 Code** - Submit pull requests with improvements

### 🚀 Quick Start for Contributors

```bash
# Fork and clone the repository
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate

# Create development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Set up pre-commit hooks
pre-commit install

# Run tests
pytest

# Start development server
python app.py
```

### 📋 Contribution Guidelines

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

<div align="center">

**Made with ❤️ by Fabrizio Salmi**

[⭐ Star us on GitHub](https://github.com/fabriziosalmi/certmate) • [🐛 Report Bug](https://github.com/fabriziosalmi/certmate/issues) • [💡 Request Feature](https://github.com/fabriziosalmi/certmate/issues/new?template=feature_request.md)

</div>
