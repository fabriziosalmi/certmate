# Multi-Account DNS Provider Support - Usage Examples

This document provides practical examples of how to use the new multi-account DNS provider support in CertMate.

## 🎯 Use Cases

### Enterprise Environment
- **Production Account**: Main certificates for live domains
- **Staging Account**: Testing and development certificates  
- **DR Account**: Disaster recovery with different credentials
- **Department Accounts**: Separate accounts for different teams

### Multi-Region Setup
- **US-East Account**: Certificates for US East Coast domains
- **EU-West Account**: Certificates for European domains
- **APAC Account**: Certificates for Asia-Pacific domains

### Permission Separation
- **Admin Account**: Full access to all DNS records
- **Limited Account**: Restricted to specific zones
- **CI/CD Account**: Automated certificate management

## 🔧 API Usage Examples

### 1. Adding Multiple Cloudflare Accounts

```bash
# Add production account
curl -X POST http://localhost:5000/api/settings/dns-providers/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "production",
    "config": {
      "name": "Production Environment",
      "description": "Main production Cloudflare account with full permissions",
      "api_token": "cloudflare_production_token_here"
    }
  }'

# Add staging account
curl -X POST http://localhost:5000/api/settings/dns-providers/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "staging",
    "config": {
      "name": "Staging Environment",
      "description": "Development and testing Cloudflare account",
      "api_token": "cloudflare_staging_token_here"
    }
  }'

# Set production as default
curl -X PUT http://localhost:5000/api/settings/dns-providers/cloudflare/default-account \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "production"}'
```

### 2. Adding Multiple AWS Route53 Accounts

```bash
# Add main AWS account
curl -X POST http://localhost:5000/api/settings/dns-providers/route53/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "main-aws",
    "config": {
      "name": "Main AWS Account",
      "description": "Primary AWS account for production domains",
      "access_key_id": "AKIAIOSFODNN7EXAMPLE",
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "region": "us-east-1"
    }
  }'

# Add backup AWS account
curl -X POST http://localhost:5000/api/settings/dns-providers/route53/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "backup-aws",
    "config": {
      "name": "Backup AWS Account",
      "description": "Backup AWS account for DR scenarios",
      "access_key_id": "AKIAI44QH8DHBEXAMPLE",
      "secret_access_key": "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY",
      "region": "us-west-2"
    }
  }'
```

### 3. Creating Certificates with Specific Accounts

```bash
# Create certificate using production Cloudflare account
curl -X POST http://localhost:5000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "api.example.com",
    "dns_provider": "cloudflare",
    "account_id": "production"
  }'

# Create certificate using staging Cloudflare account
curl -X POST http://localhost:5000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "staging.example.com",
    "dns_provider": "cloudflare",
    "account_id": "staging"
  }'

# Create certificate using default account (no account_id specified)
curl -X POST http://localhost:5000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "www.example.com",
    "dns_provider": "cloudflare"
  }'
```

### 4. Managing Accounts

```bash
# List all Cloudflare accounts
curl -X GET http://localhost:5000/api/settings/dns-providers/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Response example:
{
  "provider": "cloudflare",
  "accounts": {
    "production": {
      "name": "Production Environment",
      "description": "Main production Cloudflare account with full permissions",
      "configured": true
    },
    "staging": {
      "name": "Staging Environment", 
      "description": "Development and testing Cloudflare account",
      "configured": true
    }
  },
  "default_account": "production",
  "total_accounts": 2
}

# Update an account
curl -X PUT http://localhost:5000/api/settings/dns-providers/cloudflare/accounts/staging \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "name": "Staging & Testing",
      "description": "Updated description for staging environment",
      "api_token": "new_staging_token_here"
    }
  }'

# Delete an account (only if not the last one)
curl -X DELETE http://localhost:5000/api/settings/dns-providers/cloudflare/accounts/old-account \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

### 5. Checking Provider Status

```bash
# Get DNS providers status (now includes multi-account info)
curl -X GET http://localhost:5000/api/settings/dns-providers \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Response includes:
{
  "current_provider": "cloudflare",
  "multi_account_enabled": true,
  "default_accounts": {
    "cloudflare": "production",
    "route53": "main-aws"
  },
  "available_providers": {
    "cloudflare": {
      "name": "Cloudflare",
      "configured": true,
      "account_count": 2,
      "required_fields": ["api_token"]
    },
    "route53": {
      "name": "AWS Route53",
      "configured": true,
      "account_count": 2,
      "required_fields": ["access_key_id", "secret_access_key"]
    }
  }
}
```

## 📊 Configuration Examples

### Multi-Account Configuration Structure

```json
{
  "dns_provider": "cloudflare",
  "default_accounts": {
    "cloudflare": "production",
    "route53": "main-aws",
    "azure": "prod-subscription"
  },
  "dns_providers": {
    "cloudflare": {
      "production": {
        "name": "Production Environment",
        "description": "Main production Cloudflare account",
        "api_token": "***masked***"
      },
      "staging": {
        "name": "Staging Environment",
        "description": "Development and testing",
        "api_token": "***masked***"
      },
      "dr": {
        "name": "Disaster Recovery",
        "description": "Backup account for DR scenarios",
        "api_token": "***masked***"
      }
    },
    "route53": {
      "main-aws": {
        "name": "Main AWS Account",
        "description": "Primary AWS production account",
        "access_key_id": "***masked***",
        "secret_access_key": "***masked***",
        "region": "us-east-1"
      },
      "backup-aws": {
        "name": "Backup AWS Account", 
        "description": "Secondary AWS account for DR",
        "access_key_id": "***masked***",
        "secret_access_key": "***masked***",
        "region": "us-west-2"
      }
    }
  }
}
```

### Backward Compatibility

Existing single-account configurations are automatically migrated:

```json
// Before migration (old format)
{
  "dns_providers": {
    "cloudflare": {
      "api_token": "existing_token"
    }
  }
}

// After migration (new format)
{
  "dns_providers": {
    "cloudflare": {
      "default": {
        "name": "Default Account",
        "description": "Migrated from single-account configuration",
        "api_token": "existing_token"
      }
    }
  },
  "default_accounts": {
    "cloudflare": "default"
  }
}
```

## 🔐 Security Features

1. **Credential Masking**: API responses never expose actual tokens/keys
2. **Account Isolation**: Each account's credentials are stored separately  
3. **Validation**: All accounts are validated before being saved
4. **Access Control**: Account management requires proper API authentication
5. **Audit Trail**: All account operations are logged

## 🚀 Migration Guide

### For Existing Users

1. **Automatic Migration**: Your existing configurations will be automatically migrated to multi-account format on first use
2. **No Downtime**: Existing certificates and renewals continue to work
3. **Gradual Adoption**: Add new accounts as needed, keep using existing ones

### For New Users

1. Start with a single account per provider
2. Add additional accounts as your needs grow
3. Use descriptive names and descriptions for easy management
4. Set appropriate default accounts for each provider

## 📝 Best Practices

1. **Naming Convention**: Use clear, descriptive account names (e.g., "production", "staging", "dr")
2. **Descriptions**: Add meaningful descriptions to help identify account purposes
3. **Default Accounts**: Set your most commonly used account as the default
4. **Credential Rotation**: Update account credentials regularly for security
5. **Permission Scoping**: Use accounts with minimal required permissions where possible

This multi-account support provides the flexibility needed for enterprise environments while maintaining the simplicity that makes CertMate easy to use.
