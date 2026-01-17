# Installation Guide

This guide will help you install CertMate with multi-DNS provider support.

## Prerequisites

- Python 3.9 or higher
- pip (Python package manager)
- Docker (optional, for containerized deployment)

## Method 1: Direct Installation

### 1. Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
```

### 2. Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate # On Windows: venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Validate Installation

```bash
python validate_dependencies.py
```

### 5. Configure Environment

Create a `.env` file:

```bash
cp .env.example .env
# Edit .env with your settings
```

### 6. Start the Application

```bash
python app.py
```

## Method 2: Docker Installation

### 1. Using Docker Compose (Recommended)

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker-compose up -d
```

### 2. Using Docker Build

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker build -t certmate .
docker run -p 8000:8000 --env-file .env -v ./certificates:/app/certificates certmate
```

## Troubleshooting

### Common Issues

#### 1. DNS Plugin Version Conflicts

If you encounter version conflicts, use these specific versions:

```txt
certbot==4.1.1
certbot-dns-cloudflare==4.1.1
certbot-dns-route53==4.1.1
certbot-dns-azure==2.6.1
certbot-dns-google==4.1.1
certbot-dns-powerdns==0.2.1
```

**Important**: Most DNS plugins require Certbot 4.1.1. The Azure DNS plugin has independent versioning (2.6.1) and PowerDNS is a newer plugin (0.2.1).

#### 2. Missing System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3-dev python3-venv build-essential libssl-dev libffi-dev
```

**CentOS/RHEL/Rocky:**
```bash
sudo yum install python3-devel gcc openssl-devel libffi-devel
```

**macOS:**
```bash
brew install python3 openssl libffi
```

#### 3. Azure DNS Plugin Issues

The Azure DNS plugin has a different versioning scheme. If you encounter issues:

```bash
pip install certbot-dns-azure==2.6.1 --force-reinstall
```

#### 4. PowerDNS Plugin Issues

PowerDNS plugin is newer and has limited versions:

```bash
pip install certbot-dns-powerdns==0.2.1
```

#### 5. Google Cloud DNS Setup

Make sure you have the Google Cloud SDK dependencies:

```bash
pip install google-cloud-dns==0.35.0
```

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
# Check if all dependencies are installed
python validate_dependencies.py

# Test the API
python test_dns_providers.py

# Check certbot plugins
certbot plugins --text

# Verify service is running
curl -X GET http://localhost:5000/api/health
```

## DNS Provider Setup

### Cloudflare

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Create a new API token
3. Set permissions: `Zone:DNS:Edit`
4. Add the token to your settings

### AWS Route53

1. Create IAM user with Route53 permissions
2. Generate access keys
3. Add credentials to settings

### Azure DNS

1. Create a Service Principal
2. Assign DNS Zone Contributor role
3. Get subscription details and credentials

### Google Cloud DNS

1. Create a Service Account
2. Assign DNS Administrator role
3. Download JSON key file

### PowerDNS

1. Enable API in PowerDNS configuration
2. Set API key
3. Note the API URL

## Environment Variables

```bash
# API Authentication
API_BEARER_TOKEN=your_secure_token_here

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

# Optional
SECRET_KEY=your_flask_secret_key
```

## Production Deployment

### Using Gunicorn

```bash
gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
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
ExecStart=/opt/certmate/venv/bin/gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
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

## Support

If you encounter issues:

1. Run the validation script: `python validate_dependencies.py`
2. Check the logs for specific errors
3. Verify your DNS provider credentials
4. Test with the test script: `python test_dns_providers.py`
5. Check our documentation: [DNS_PROVIDERS.md](DNS_PROVIDERS.md)
