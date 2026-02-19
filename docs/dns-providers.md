# DNS Providers

CertMate supports **22 DNS providers** for Let's Encrypt DNS-01 challenges through individual certbot plugins.

---

## Supported Providers

| Provider | Plugin | Credentials Required | Category |
|----------|--------|---------------------|----------|
| **Cloudflare** | `certbot-dns-cloudflare` | API Token | Major Cloud |
| **AWS Route53** | `certbot-dns-route53` | Access Key, Secret Key | Major Cloud |
| **Azure DNS** | `certbot-dns-azure` | Service Principal | Major Cloud |
| **Google Cloud DNS** | `certbot-dns-google` | Service Account JSON | Major Cloud |
| **PowerDNS** | `certbot-dns-powerdns` | API URL, API Key | Enterprise |
| **DNS Made Easy** | `certbot-dns-dnsmadeeasy` | API Key, Secret Key | Enterprise |
| **NS1** | `certbot-dns-nsone` | API Key | Enterprise |
| **DigitalOcean** | `certbot-dns-digitalocean` | API Token | Cloud |
| **Linode** | `certbot-dns-linode` | API Key | Cloud |
| **Vultr** | `certbot-dns-vultr` | API Key | Cloud |
| **Hetzner** | `certbot-dns-hetzner` | API Token | Cloud |
| **Gandi** | `certbot-dns-gandi` | API Token | Registrar |
| **Namecheap** | `certbot-dns-namecheap` | Username, API Key | Registrar |
| **Porkbun** | `certbot-dns-porkbun` | API Key, Secret Key | Registrar |
| **GoDaddy** | `certbot-dns-godaddy` | API Key, Secret | Registrar |
| **OVH** | `certbot-dns-ovh` | API Credentials | Regional |
| **Infomaniak** | `certbot-dns-infomaniak` | API Token | Regional |
| **ArvanCloud** | `certbot-dns-arvancloud` | API Key | Regional |
| **RFC2136** | `certbot-dns-rfc2136` | Nameserver, TSIG Key | Standard Protocol |
| **ACME-DNS** | `certbot-acme-dns` | API URL, Username, Password | Specialized |
| **Hurricane Electric** | `certbot-dns-he-ddns` | Username, Password | Free DNS |
| **Dynu** | `certbot-dns-dynudns` | API Token | Dynamic DNS |

---

## Configuration

### Via Web Interface

1. Navigate to **Settings**
2. Select your DNS provider from the dropdown
3. Fill in the required credentials
4. Save settings

### Via API

```bash
curl -X POST http://localhost:8000/api/settings \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "dns_provider": "cloudflare",
    "dns_providers": {
      "cloudflare": {
        "api_token": "your_cloudflare_token"
      }
    }
  }'
```

---

## Provider Setup Examples

### Cloudflare

```json
{
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {
      "api_token": "your_cloudflare_api_token"
    }
  }
}
```

### AWS Route53

```json
{
  "dns_provider": "route53",
  "dns_providers": {
    "route53": {
      "access_key_id": "AKIAIOSFODNN7EXAMPLE",
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "region": "us-east-1"
    }
  }
}
```

### Azure DNS

```json
{
  "dns_provider": "azure",
  "dns_providers": {
    "azure": {
      "subscription_id": "your_subscription_id",
      "resource_group": "your_resource_group",
      "tenant_id": "your_tenant_id",
      "client_id": "your_client_id",
      "client_secret": "your_client_secret"
    }
  }
}
```

### Google Cloud DNS

```json
{
  "dns_provider": "google",
  "dns_providers": {
    "google": {
      "project_id": "your_project_id",
      "service_account_key": "{ ... service account JSON ... }"
    }
  }
}
```

### PowerDNS

```json
{
  "dns_provider": "powerdns",
  "dns_providers": {
    "powerdns": {
      "api_url": "https://your-powerdns-server:8081",
      "api_key": "your_powerdns_api_key"
    }
  }
}
```

### Vultr

```json
{
  "dns_provider": "vultr",
  "dns_providers": {
    "vultr": {
      "api_key": "your_vultr_api_key"
    }
  }
}
```

### DNS Made Easy

```json
{
  "dns_provider": "dnsmadeeasy",
  "dns_providers": {
    "dnsmadeeasy": {
      "api_key": "your_api_key",
      "secret_key": "your_secret_key"
    }
  }
}
```

### NS1

```json
{
  "dns_provider": "nsone",
  "dns_providers": {
    "nsone": {
      "api_key": "your_nsone_api_key"
    }
  }
}
```

### RFC2136

For BIND or other RFC2136-compatible DNS servers (including **Technitium DNS Server**):

```json
{
  "dns_provider": "rfc2136",
  "dns_providers": {
    "rfc2136": {
      "nameserver": "ns.example.com",
      "tsig_key": "mykey",
      "tsig_secret": "base64-encoded-secret",
      "tsig_algorithm": "HMAC-SHA512"
    }
  }
}
```

> **Technitium DNS**: Enable Dynamic Updates in Zone Options, create a TSIG Key (e.g., `certmate-key` with HMAC-SHA512), then use the generated secret in the configuration above.

### Hetzner

```json
{
  "dns_provider": "hetzner",
  "dns_providers": {
    "hetzner": {
      "api_token": "your_hetzner_api_token"
    }
  }
}
```

### Infomaniak

```json
{
  "dns_provider": "infomaniak",
  "dns_providers": {
    "infomaniak": {
      "api_token": "your_infomaniak_api_token"
    }
  }
}
```

> Get the API token from Infomaniak Manager (API section with "Domain" scope).

### Porkbun

```json
{
  "dns_provider": "porkbun",
  "dns_providers": {
    "porkbun": {
      "api_key": "your_porkbun_api_key",
      "secret_key": "your_porkbun_secret_key"
    }
  }
}
```

### GoDaddy

```json
{
  "dns_provider": "godaddy",
  "dns_providers": {
    "godaddy": {
      "api_key": "your_godaddy_api_key",
      "secret": "your_godaddy_secret"
    }
  }
}
```

### OVH

```json
{
  "dns_provider": "ovh",
  "dns_providers": {
    "ovh": {
      "endpoint": "ovh-eu",
      "application_key": "your_app_key",
      "application_secret": "your_app_secret",
      "consumer_key": "your_consumer_key"
    }
  }
}
```

### Hurricane Electric

```json
{
  "dns_provider": "he-ddns",
  "dns_providers": {
    "he-ddns": {
      "username": "your_he_username",
      "password": "your_he_password"
    }
  }
}
```

### Dynu

```json
{
  "dns_provider": "dynudns",
  "dns_providers": {
    "dynudns": {
      "token": "your_dynu_api_token"
    }
  }
}
```

### ArvanCloud

```json
{
  "dns_provider": "arvancloud",
  "dns_providers": {
    "arvancloud": {
      "api_key": "your_arvancloud_api_key"
    }
  }
}
```

### ACME-DNS

```json
{
  "dns_provider": "acme-dns",
  "dns_providers": {
    "acme-dns": {
      "api_url": "https://auth.acme-dns.io",
      "username": "your_acme_username",
      "password": "your_acme_password",
      "subdomain": "your_subdomain"
    }
  }
}
```

---

## Creating Certificates

### Using Default Provider

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Using a Specific Provider

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "vultr"
  }'
```

### Using a Specific Account

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "cloudflare",
    "account_id": "production"
  }'
```

---

## Multi-Account Support

CertMate supports multiple accounts per DNS provider for enterprise environments.

### Use Cases

- **Environment separation**: Production, staging, and DR accounts
- **Multi-region**: Different accounts for US, EU, APAC domains
- **Permission isolation**: Admin vs. limited vs. CI/CD accounts

### Adding Multiple Accounts

```bash
# Add production account
curl -X POST http://localhost:8000/api/settings/dns-providers/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "production",
    "config": {
      "name": "Production Environment",
      "description": "Main production Cloudflare account",
      "api_token": "cloudflare_production_token"
    }
  }'

# Add staging account
curl -X POST http://localhost:8000/api/settings/dns-providers/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "staging",
    "config": {
      "name": "Staging Environment",
      "description": "Development and testing account",
      "api_token": "cloudflare_staging_token"
    }
  }'

# Set production as default
curl -X PUT http://localhost:8000/api/settings/dns-providers/cloudflare/default-account \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "production"}'
```

### Managing Accounts

```bash
# List all accounts for a provider
curl -X GET http://localhost:8000/api/settings/dns-providers/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Update an account
curl -X PUT http://localhost:8000/api/settings/dns-providers/cloudflare/accounts/staging \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "name": "Staging & Testing",
      "api_token": "new_staging_token"
    }
  }'

# Delete an account
curl -X DELETE http://localhost:8000/api/settings/dns-providers/cloudflare/accounts/old-account \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

### Multi-Account Configuration Structure

```json
{
  "dns_provider": "cloudflare",
  "default_accounts": {
    "cloudflare": "production",
    "route53": "main-aws"
  },
  "dns_providers": {
    "cloudflare": {
      "production": {
        "name": "Production Environment",
        "api_token": "***masked***"
      },
      "staging": {
        "name": "Staging Environment",
        "api_token": "***masked***"
      }
    },
    "route53": {
      "main-aws": {
        "name": "Main AWS Account",
        "access_key_id": "***masked***",
        "secret_access_key": "***masked***",
        "region": "us-east-1"
      }
    }
  }
}
```

### Backward Compatibility

Existing single-account configurations are automatically migrated to multi-account format on first use. No downtime or manual migration required.

---

## Multi-Master DNS & Domain Alias

When your domain is managed by multiple DNS providers simultaneously (multi-master setup), use CertMate's **domain alias** feature.

### The Problem

With multi-master DNS (e.g., deSEC + gcore), you can only configure one DNS provider per certificate request — but ACME validation requires creating `_acme-challenge` TXT records.

### The Solution

1. **Create a validation domain** on a CertMate-supported provider (e.g., `validation.example.org` on Cloudflare)
2. **Add CNAME records** in all your DNS providers pointing to the validation domain:
   ```dns
   _acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
   ```
3. **Request the certificate** with `domain_alias`:
   ```bash
   curl -X POST http://localhost:8000/api/certificates/create \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "domain": "example.com",
       "dns_provider": "cloudflare",
       "domain_alias": "_acme-challenge.validation.example.org"
     }'
   ```

### Benefits

- Works regardless of which DNS provider serves the query
- No synchronization needed between providers
- Works with providers not natively supported by CertMate (deSEC, gcore)
- Keep DNS API credentials limited to the validation domain

### Wildcard Certificates with Domain Alias

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "*.example.com",
    "dns_provider": "cloudflare",
    "domain_alias": "_acme-challenge.validation.example.org"
  }'
```

### Troubleshooting Domain Alias

```bash
# Verify CNAME propagation
dig @8.8.8.8 _acme-challenge.example.com CNAME +short
# Should return: _acme-challenge.validation.example.org.

# Check TXT record creation after requesting a certificate
dig _acme-challenge.validation.example.org TXT
```

---

## Environment Variables

Set DNS provider credentials via environment variables for CI/CD workflows:

```bash
# Cloudflare
CLOUDFLARE_API_TOKEN=your_token

# AWS Route53
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# Azure
AZURE_SUBSCRIPTION_ID=your_subscription_id
AZURE_RESOURCE_GROUP=your_resource_group
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret

# Google Cloud
GOOGLE_PROJECT_ID=your_project_id
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# PowerDNS
POWERDNS_API_URL=https://your-powerdns-server:8081
POWERDNS_API_KEY=your_api_key
```

### Configuration Priority (highest to lowest)

1. Environment variables
2. Domain-specific settings
3. Default account settings
4. Global provider setting
5. System default (Cloudflare)

---

## DNS Propagation Times

| Speed | Providers | Seconds |
|-------|-----------|---------|
| Very Fast | ACME-DNS | 30 |
| Fast | Cloudflare, Route53, PowerDNS | 60 |
| Medium | DigitalOcean, Linode, Google, ArvanCloud | 120 |
| Slow | Azure, Gandi, OVH | 180 |
| Very Slow | Namecheap | 300 |

---

## Security Features

- **Credential masking** in web interface and API responses
- **Secure file permissions** (600) for all credential files
- **API token validation** before certificate creation
- **Environment variable support** for CI/CD workflows
- **Audit logging** for all DNS provider operations
- **Account isolation** — each account's credentials stored separately

---

## Architecture & Developer Guide

### Key Classes

| Class | File | Purpose |
|-------|------|---------|
| `DNSManager` | `modules/core/dns_providers.py` | Multi-account config management |
| `CertificateManager` | `modules/core/certificates.py` | Certificate creation with DNS providers |
| `SettingsManager` | `modules/core/settings.py` | Settings persistence and migration |
| `Utils` | `modules/core/utils.py` | Credential file generation and validation |

### Credential Storage Methods

1. **Settings file** (`data/settings.json`) — most common
2. **Environment variables** — for CI/CD
3. **Temporary config files** (`letsencrypt/config/[provider].ini`) — created during cert requests, deleted after

### Adding a New DNS Provider

1. Add plugin to `requirements.txt`: `certbot-dns-newprovider`
2. Create config function in `modules/core/utils.py`
3. Add credentials definition in `utils.py`
4. Import and handle in `modules/core/certificates.py`
5. Add to supported providers list in `modules/core/settings.py`
6. Update documentation

See the [Architecture Guide](./architecture.md) for full implementation details.

---

## Troubleshooting

### Common Issues

| Error | Solution |
|-------|----------|
| "DNS provider not configured" | Verify all required credentials are provided |
| "Certificate creation failed" | Check DNS permissions and domain ownership |
| "Plugin not found" | Run `pip install -r requirements.txt` or rebuild Docker |
| "Provider detection failing" | Check `dns_provider` field in domain settings |

### Debug Mode

```bash
export FLASK_DEBUG=1
python app.py
```

### Testing Provider Configuration

```bash
curl -X GET http://localhost:8000/api/settings/dns-providers \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

---

## Migration Guide

### From Single Provider to Multi-Provider

Existing configurations remain unchanged. Simply add new providers:

```json
{
  "dns_providers": {
    "cloudflare": {
      "api_token": "existing_token"
    },
    "vultr": {
      "api_key": "new_vultr_api_key"
    }
  }
}
```

### Using Different Providers per Certificate

```bash
# Cloudflare for one domain
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "dns_provider": "cloudflare"}'

# Route53 for another
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "test.org", "dns_provider": "route53"}'
```

---

<div align="center">

[← Back to Documentation](./README.md) • [Installation →](./installation.md) • [CA Providers →](./ca-providers.md)

</div>
