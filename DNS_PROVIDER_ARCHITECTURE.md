# CertMate DNS Provider Architecture - Comprehensive Analysis

## Executive Summary

CertMate implements a **modular, extensible DNS provider architecture** supporting **21 DNS providers** through individual certbot plugins. The system features:

- **Multi-account support** per DNS provider
- **Domain-specific provider configuration**
- **Backward compatibility** with legacy single-account format
- **Automatic migration** between configuration formats
- **Environment variable support** for CI/CD workflows
- **Secure credential management** with file-based and environment variable storage

---

## 1. Currently Supported DNS Providers (21 Total)

### Major Cloud Providers
1. **Cloudflare** - `certbot-dns-cloudflare` - Global CDN, free tier
2. **AWS Route53** - `certbot-dns-route53` - AWS infrastructure
3. **Google Cloud DNS** - `certbot-dns-google` - Google Cloud Platform
4. **Microsoft Azure DNS** - `certbot-dns-azure` - Microsoft ecosystem

### Enterprise Providers
5. **PowerDNS** - `certbot-dns-powerdns` - Self-hosted DNS
6. **DNS Made Easy** - `certbot-dns-dnsmadeeasy` - Enterprise DNS management
7. **NS1** - `certbot-dns-nsone` - Intelligent DNS platform

### Cloud Infrastructure Providers
8. **DigitalOcean** - `certbot-dns-digitalocean` - Cloud infrastructure
9. **Linode** - `certbot-dns-linode` - Cloud hosting
10. **Vultr** - `certbot-dns-vultr` - Global cloud infrastructure
11. **Hetzner** - `certbot-dns-hetzner` - European cloud hosting

### Domain Registrars
12. **Gandi** - `certbot-dns-gandi` - Domain registrar
13. **Namecheap** - `certbot-dns-namecheap` - Domain registrar
14. **Porkbun** - `certbot-dns-porkbun` - Domain registrar with DNS
15. **GoDaddy** - `certbot-dns-godaddy` - Domain registrar

### Regional Providers
16. **OVH** - `certbot-dns-ovh` - European hosting
17. **ArvanCloud** - `certbot-dns-arvancloud` - Iranian cloud provider

### Specialized Providers
18. **RFC2136** - `certbot-dns-rfc2136` - Standard DNS update protocol (BIND-compatible)
19. **ACME-DNS** - `certbot-acme-dns` - Generic ACME-DNS server
20. **Hurricane Electric** - `certbot-dns-he-ddns` - Free DNS hosting
21. **Dynu** - `certbot-dns-dynudns` - Dynamic DNS service

---

## 2. DNS Provider Integration Architecture

### 2.1 File Structure Overview

```
certmate/
├── modules/
│   ├── core/
│   │   ├── dns_providers.py       # DNSManager class - Multi-account handling
│   │   ├── certificates.py        # Certificate creation with DNS providers
│   │   ├── settings.py            # Settings management & migrations
│   │   ├── utils.py               # DNS config file creators & validators
│   │   └── auth.py                # Authentication
│   ├── api/
│   │   ├── resources.py           # API endpoints
│   │   └── models.py              # API data models
│   └── web/
│       └── routes.py              # Web interface routes
├── app.py                          # Main Flask application
├── requirements.txt                # All certbot DNS plugins
└── DNS_PROVIDERS.md               # Documentation
```

### 2.2 Configuration File Structure

#### Single-Account Legacy Format (Deprecated)
```json
{
  "dns_providers": {
    "cloudflare": {
      "api_token": "your_token"
    }
  }
}
```

#### Multi-Account Format (Current)
```json
{
  "dns_providers": {
    "cloudflare": {
      "accounts": {
        "default": {
          "name": "Default Cloudflare Account",
          "api_token": "token_1"
        },
        "production": {
          "name": "Production Account",
          "api_token": "token_2"
        }
      }
    },
    "route53": {
      "accounts": {
        "default": {
          "access_key_id": "AKIA...",
          "secret_access_key": "...",
          "region": "us-east-1"
        }
      }
    }
  },
  "default_accounts": {
    "cloudflare": "default",
    "route53": "default"
  },
  "dns_provider": "cloudflare",
  "domains": [
    {
      "domain": "example.com",
      "dns_provider": "cloudflare",
      "account_id": "default"
    },
    {
      "domain": "test.org",
      "dns_provider": "route53",
      "account_id": "default"
    }
  ]
}
```

---

## 3. Credential Configuration & Storage

### 3.1 Storage Methods

#### Method 1: Settings File (Most Common)
- **File**: `data/settings.json`
- **Permissions**: 0o600 (owner read/write only)
- **Format**: JSON
- **Location**: Multi-account structure under `dns_providers[provider].accounts[account_id]`

#### Method 2: Environment Variables
```bash
# Cloudflare
CLOUDFLARE_TOKEN=your_token

# AWS Route53
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_DEFAULT_REGION=us-east-1

# Azure
AZURE_SUBSCRIPTION_ID=your_id
AZURE_RESOURCE_GROUP=your_group
AZURE_TENANT_ID=your_tenant
AZURE_CLIENT_ID=your_client
AZURE_CLIENT_SECRET=your_secret

# Google Cloud
GOOGLE_PROJECT_ID=your_project
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# PowerDNS
POWERDNS_API_URL=https://your-server:8081
POWERDNS_API_KEY=your_key
```

#### Method 3: Temporary Config Files
- **Created by**: `create_*_config()` functions in `modules/core/utils.py`
- **Format**: INI-style certbot credential files
- **Location**: `letsencrypt/config/[provider].ini`
- **Permissions**: 0o600
- **Lifetime**: Temporary (created during cert request, deleted after)

### 3.2 Required Credentials by Provider

| Provider | Required Fields |
|----------|-----------------|
| **cloudflare** | `api_token` |
| **route53** | `access_key_id`, `secret_access_key`, `region` (optional) |
| **azure** | `subscription_id`, `resource_group`, `tenant_id`, `client_id`, `client_secret` |
| **google** | `project_id`, `service_account_key` |
| **powerdns** | `api_url`, `api_key` |
| **digitalocean** | `api_token` |
| **linode** | `api_key` |
| **gandi** | `api_token` |
| **ovh** | `endpoint`, `application_key`, `application_secret`, `consumer_key` |
| **namecheap** | `username`, `api_key` |
| **vultr** | `api_key` |
| **dnsmadeeasy** | `api_key`, `secret_key` |
| **nsone** | `api_key` |
| **rfc2136** | `nameserver`, `tsig_key`, `tsig_secret`, `tsig_algorithm` (optional) |
| **hetzner** | `api_token` |
| **porkbun** | `api_key`, `secret_key` |
| **godaddy** | `api_key`, `secret` |
| **he-ddns** | `username`, `password` |
| **dynudns** | `token` |
| **arvancloud** | `api_key` |
| **acme-dns** | `api_url`, `username`, `password`, `subdomain` |

---

## 4. Certbot Command Construction

### 4.1 General Command Structure

```python
certbot_cmd = [
    'certbot', 'certonly',
    '--non-interactive',
    '--agree-tos',
    '--email', email,
    '--cert-name', domain,
    '--config-dir', cert_output_dir,
    '--work-dir', cert_output_dir/work,
    '--logs-dir', cert_output_dir/logs,
    '-d', domain,
    '--authenticator', plugin_name,
    '--[plugin_name]-credentials', credentials_file,
    '--[plugin_name]-propagation-seconds', propagation_time
]
```

### 4.2 Provider-Specific Handling

#### Route53 (Environment Variables)
```python
# Set environment variables instead of credentials file
os.environ['AWS_ACCESS_KEY_ID'] = dns_config['access_key_id']
os.environ['AWS_SECRET_ACCESS_KEY'] = dns_config['secret_access_key']
if dns_config.get('region'):
    os.environ['AWS_DEFAULT_REGION'] = dns_config['region']

# Add to command
certbot_cmd.extend(['--authenticator', 'dns-route53'])
certbot_cmd.extend(['--dns-route53-propagation-seconds', propagation_time])
```

#### PowerDNS (Special Handling)
```python
# Requires explicit authenticator + credentials
certbot_cmd.extend(['--authenticator', 'dns-powerdns'])
if credentials_file:
    certbot_cmd.extend(['--dns-powerdns-credentials', credentials_file])
```

#### ACME-DNS (Plugin Name Without Prefix)
```python
# Uses 'acme-dns' instead of 'dns-acme-dns'
certbot_cmd.extend(['--authenticator', 'acme-dns'])
if credentials_file:
    certbot_cmd.extend(['--acme-dns-credentials', credentials_file])
```

#### Namecheap (Special Handling)
```python
# Requires explicit authenticator
certbot_cmd.extend(['--authenticator', 'dns-namecheap'])
if credentials_file:
    certbot_cmd.extend(['--dns-namecheap-credentials', credentials_file])
```

#### Standard Providers (Cloudflare, Azure, Google, etc.)
```python
# Standard format
certbot_cmd.extend([f'--dns-{provider}'])
if credentials_file:
    certbot_cmd.extend([f'--dns-{provider}-credentials', credentials_file])
```

### 4.3 DNS Propagation Times (Provider Defaults)

```python
dns_propagation_seconds = {
    'cloudflare': 60,
    'route53': 60,
    'powerdns': 60,
    'digitalocean': 120,
    'linode': 120,
    'google': 120,
    'arvancloud': 120,
    'azure': 180,
    'gandi': 180,
    'ovh': 180,
    'namecheap': 300,
    'acme-dns': 30
}
```

---

## 5. Code Patterns for Adding a New DNS Provider

### Step 1: Add Plugin to requirements.txt
```txt
certbot-dns-newprovider
```

### Step 2: Create Configuration Function in utils.py

#### For Simple Credential Format
```python
def create_newprovider_config(api_key: str) -> Path:
    """Create NewProvider DNS credentials file."""
    return _create_config_file(
        "newprovider",
        f"dns_newprovider_api_key = {api_key}\n"
    )
```

#### For Complex Multi-Field Credentials
```python
def create_newprovider_config(api_key: str, api_secret: str) -> Path:
    """Create NewProvider DNS credentials file."""
    content = (
        f"dns_newprovider_api_key = {api_key}\n"
        f"dns_newprovider_api_secret = {api_secret}\n"
    )
    return _create_config_file("newprovider", content)
```

#### For Multi-Provider (Lexicon-based)
```python
# Add to _MULTI_PROVIDER_PLUGIN_FILES in utils.py
_MULTI_PROVIDER_PLUGIN_FILES = {
    'newprovider': 'newprovider.ini',
    # ... other providers
}

# Add to _MULTI_PROVIDER_TEMPLATE_MAP in utils.py
_MULTI_PROVIDER_TEMPLATE_MAP = {
    'newprovider': {
        'dns_newprovider_api_key': 'api_key',
        'dns_newprovider_api_secret': 'api_secret'
    },
    # ... other providers
}
```

### Step 3: Add Credentials Definition in utils.py

```python
_DNS_PROVIDER_CREDENTIALS = {
    'newprovider': ['api_key', 'api_secret'],
    # ... other providers
}
```

### Step 4: Import in certificates.py

```python
from .utils import (
    create_cloudflare_config,
    # ... other imports
    create_newprovider_config  # ADD THIS
)
```

### Step 5: Add Compatibility Function in certificates.py

In `_create_dns_config_compat()` method:

```python
elif dns_provider == 'newprovider':
    # Add newprovider handling
    return config_func(
        dns_config.get('api_key', ''),
        dns_config.get('api_secret', ''),
    )
```

### Step 6: Handle in create_certificate() Method

In the `create_certificate()` method's provider-specific section:

```python
elif dns_provider in ['newprovider']:
    credentials_file = self._create_dns_config_compat(dns_provider, dns_config)
    plugin_name = f'dns-newprovider'
```

### Step 7: Add to Supported Providers List

In `modules/core/settings.py`:

```python
supported_providers = {
    'cloudflare', 'route53', 'azure', 'google',
    # ... other providers
    'newprovider'  # ADD THIS
}
```

### Step 8: Update Documentation

- Add entry to `DNS_PROVIDERS.md` with setup example
- Add entry to documentation with required credentials
- Add test cases for the new provider

### Step 9: Add Validation Rules (Optional)

If provider has special validation needs:

```python
def validate_newprovider_config(config: dict) -> tuple:
    """Validate NewProvider configuration."""
    required = ['api_key', 'api_secret']
    for field in required:
        if not config.get(field):
            return False, f"Missing {field}"
    
    # Custom validation rules
    if len(config['api_key']) < 10:
        return False, "API key too short"
    
    return True, "Valid"
```

---

## 6. Key Classes and Modules

### 6.1 DNSManager (modules/core/dns_providers.py)

**Responsibilities**:
- Multi-account configuration management
- Account CRUD operations
- Default account management
- Provider suggestion for domains

**Key Methods**:
```python
class DNSManager:
    def get_dns_provider_account_config(provider, account_id=None, settings=None)
        """Get account config with fallback to default/first available"""
        
    def list_dns_provider_accounts(provider, settings=None)
        """List all accounts for a provider"""
        
    def suggest_dns_provider_for_domain(domain, settings=None)
        """Suggest provider based on domain patterns"""
        
    def create_dns_account(provider, account_id, account_config, settings=None)
        """Create/update DNS account"""
        
    def delete_dns_account(provider, account_id, settings=None)
        """Delete DNS account"""
        
    def set_default_account(provider, account_id, settings=None)
        """Set default account for provider"""
```

### 6.2 CertificateManager (modules/core/certificates.py)

**Responsibilities**:
- Certificate creation and renewal
- DNS provider configuration handling
- Certbot command construction and execution

**Key Methods**:
```python
class CertificateManager:
    def create_certificate(
        domain, email, dns_provider=None, dns_config=None, 
        account_id=None, staging=False, ca_provider=None, ca_account_id=None
    )
        """Create certificate with specified DNS provider"""
        
    def get_certificate_info(domain)
        """Get certificate info including DNS provider used"""
```

### 6.3 SettingsManager (modules/core/settings.py)

**Responsibilities**:
- Settings persistence
- Format migrations (legacy ← → multi-account)
- Domain-provider mappings
- Environment variable integration

**Key Methods**:
```python
class SettingsManager:
    def load_settings()
        """Load settings with automatic migration"""
        
    def save_settings(settings, backup_reason="auto")
        """Save settings with validation & backup"""
        
    def migrate_dns_providers_to_multi_account(settings)
        """Migrate old single-account to new multi-account format"""
        
    def get_domain_dns_provider(domain, settings=None)
        """Get DNS provider for specific domain"""
```

### 6.4 Utils Module (modules/core/utils.py)

**Responsibilities**:
- Configuration file generation
- Credential validation
- Token generation and validation

**Key Functions**:
```python
# Configuration creators
def create_cloudflare_config(token) → Path
def create_route53_config(access_key_id, secret_access_key) → Path
def create_azure_config(subscription_id, ...) → Path
def create_google_config(project_id, service_account_key) → Path
def create_powerdns_config(api_url, api_key) → Path
# ... and so on for each provider

# Multi-provider helper
def create_multi_provider_config(provider, config_data) → Optional[Path]

# Validation
def validate_dns_provider_account(provider, account_id, account_config)
    → Tuple[bool, str]

# Token generation
def generate_secure_token(length=40) → str
```

---

## 7. Configuration Flow Diagram

```
User Input (Web UI / API)
    ↓
[SettingsManager.save_settings()]
    ↓
Validate credentials & format
    ↓
Create/Update dns_providers structure
    ↓
Save to data/settings.json
    ↓
[Certificate Creation Request]
    ↓
[SettingsManager.get_domain_dns_provider()]
    ↓
[DNSManager.get_dns_provider_account_config()]
    ↓
Retrieve account credentials
    ↓
[CertificateManager.create_certificate()]
    ↓
[_create_dns_config_compat()]
    ↓
[create_[provider]_config()]
    ↓
Generate letsencrypt/config/[provider].ini
    ↓
Build certbot command with --authenticator + --credentials
    ↓
subprocess.run(certbot_cmd)
    ↓
Certbot uses plugin to solve DNS challenge
    ↓
Store certificate + metadata.json
```

---

## 8. Migration Strategy

### Automatic Single-Account → Multi-Account Migration

**When**: First load of old format settings

```python
# Old format detection
if 'accounts' not in provider_config:
    if any(key in provider_config for key in provider_keys):
        # This is old single-account format
        
        # Automatic migration to:
        {
            'accounts': {
                'default': {
                    'name': 'Default Account',
                    'description': 'Migrated from single-account',
                    **old_credentials
                }
            }
        }
```

**Files Involved**:
- `modules/core/settings.py::migrate_dns_providers_to_multi_account()`
- `modules/core/settings.py::_migrate_settings_format()`

**Backward Compatibility**:
```python
# get_dns_provider_account_config() handles both formats transparently
if 'accounts' in provider_config:
    # Multi-account format
    return accounts[account_id]
else:
    # Legacy single-account format
    return provider_config  # Treat whole config as account
```

---

## 9. Environment Variable Override

### Load Order (Highest to Lowest Priority)

1. **Environment Variables** (override everything)
2. **Domain-specific Settings** (domain.dns_provider, domain.account_id)
3. **Default Account Settings** (default_accounts[provider])
4. **Global Provider Setting** (dns_provider)
5. **System Defaults** (cloudflare)

### Example Override in settings.py:

```python
# After loading from settings file
if os.getenv('CLOUDFLARE_TOKEN'):
    if 'cloudflare' not in settings['dns_providers']:
        settings['dns_providers']['cloudflare'] = {'accounts': {'default': {}}}
    settings['dns_providers']['cloudflare']['accounts']['default']['api_token'] = os.getenv('CLOUDFLARE_TOKEN')

if os.getenv('LETSENCRYPT_EMAIL'):
    settings['email'] = os.getenv('LETSENCRYPT_EMAIL')
```

---

## 10. API Endpoints for DNS Providers

### GET /api/settings/dns-providers
Returns list of configured DNS providers with account details

### POST /api/certificates/create
Create certificate with optional `dns_provider` and `account_id` parameters:
```json
{
  "domain": "example.com",
  "email": "admin@example.com",
  "dns_provider": "cloudflare",
  "account_id": "production"
}
```

### GET /api/settings
Returns full settings including dns_providers structure

### POST /api/settings
Update DNS provider configuration:
```json
{
  "dns_providers": {
    "cloudflare": {
      "accounts": {
        "default": {"api_token": "..."},
        "production": {"api_token": "..."}
      }
    }
  },
  "default_accounts": {
    "cloudflare": "production"
  }
}
```

---

## 11. Testing Strategy

### Test Files
- `test_dns_provider.py` - Basic provider functionality
- `test_dns_provider_detection.py` - Domain-to-provider mapping
- `test_dns_provider_inheritance.py` - Configuration inheritance
- `test_dns_accounts.py` - Multi-account operations

### Key Test Scenarios
1. Configuration validation
2. Single-account → multi-account migration
3. Environment variable override
4. Domain-specific provider assignment
5. Default account selection
6. Account CRUD operations
7. Credential validation per provider

---

## 12. Security Considerations

### Credential Protection
- **File Permissions**: 0o600 (owner only read/write)
- **Masking**: Credentials masked in logs and UI
- **No Logs**: Credentials never logged in full
- **Temporary Files**: Credential files deleted after use
- **Environment Variables**: For CI/CD, avoid storing in files

### Validation
- **Input Validation**: All credentials validated before use
- **Format Validation**: DNS provider must be in supported list
- **Token Validation**: API tokens checked for minimum strength
- **Domain Validation**: RFC-compliant domain validation

### Best Practices
1. Store sensitive credentials in environment variables for production
2. Use different accounts for different certificate purposes
3. Rotate API tokens/keys regularly
4. Use service accounts (Azure/Google) with minimal permissions
5. Enable audit logging for DNS operations

---

## 13. Summary Table

| Aspect | Details |
|--------|---------|
| **Total Providers** | 21 DNS providers |
| **Architecture** | Plugin-based with individual certbot plugins |
| **Multi-Account** | Yes (native support) |
| **Config Format** | JSON (single file) |
| **Config Location** | `data/settings.json` |
| **Credential Storage** | File-based (JSON) + Environment variables |
| **Migration** | Automatic legacy → multi-account |
| **Per-Domain Config** | Yes (domain.dns_provider, domain.account_id) |
| **Environment Override** | Yes (CLOUDFLARE_TOKEN, AWS_*, AZURE_*, etc.) |
| **Default Provider** | Cloudflare |
| **Plugin Type** | Individual certbot DNS plugins |
| **Certificate Storage** | Local filesystem + configurable backends |
| **Metadata** | metadata.json per certificate with dns_provider |

---

## 14. Common Integration Patterns

### Pattern 1: Single Account, Single Provider
```json
{
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {
      "accounts": {
        "default": {"api_token": "..."}
      }
    }
  }
}
```

### Pattern 2: Multiple Accounts, Single Provider
```json
{
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {
      "accounts": {
        "staging": {"api_token": "..."},
        "production": {"api_token": "..."}
      }
    }
  },
  "default_accounts": {"cloudflare": "production"}
}
```

### Pattern 3: Multiple Providers
```json
{
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {"accounts": {"default": {...}}},
    "route53": {"accounts": {"default": {...}}},
    "azure": {"accounts": {"default": {...}}}
  },
  "domains": [
    {"domain": "cf.example.com", "dns_provider": "cloudflare"},
    {"domain": "aws.example.com", "dns_provider": "route53"},
    {"domain": "azure.example.com", "dns_provider": "azure"}
  ]
}
```

---

**Document Generated**: October 2024
**CertMate Version**: 1.2.1+
**API Version**: v1.2.1
