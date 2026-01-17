# Multi-Master DNS and Domain Alias Setup Guide

## Overview

This guide explains how to handle multi-master DNS setups (where you have the same zone managed by multiple DNS providers) using CertMate's **domain alias** feature.

## The Multi-Master DNS Challenge

When you have a domain (e.g., `example.com`) managed by multiple DNS providers simultaneously (multi-master setup):
- **Problem**: You need to create `_acme-challenge.example.com` TXT records for DNS-01 validation
- **Challenge**: ACME DNS validation requires creating records, but you can only configure one DNS provider per certificate request in CertMate
- **Traditional workaround**: Manually sync records between providers or use external scripts

## The Domain Alias Solution

CertMate's `domain_alias` feature solves this elegantly:

### How It Works

1. **Create a validation domain**: Set up a dedicated subdomain for DNS challenges (e.g., `validation.example.org`)
2. **Configure CNAME**: Point the _acme-challenge record from your main domain to the validation domain
3. **Use domain_alias**: Tell CertMate to perform validation on the alias domain instead

### Example Setup

#### Step 1: Configure DNS Records

In **both** your DNS providers (deSEC and gcore), add:

```dns
; For example.com in both deSEC and gcore:
_acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
```

#### Step 2: Set up validation domain

Choose **one** DNS provider for the validation domain (e.g., Cloudflare for `validation.example.org`):

```dns
; In Cloudflare (or any CertMate-supported provider):
validation.example.org. NS record already exists
```

#### Step 3: Configure CertMate

```bash
# Configure the DNS provider for your validation domain
curl -X POST http://localhost:5000/api/web/settings \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "dns_provider": "cloudflare",
 "dns_providers": {
 "cloudflare": {
 "accounts": {
 "default": {
 "api_token": "your_cloudflare_token"
 }
 }
 }
 }
 }'
```

#### Step 4: Request Certificate with Domain Alias

```bash
# Request certificate for example.com
# But perform validation on validation.example.org
curl -X POST http://localhost:5000/api/certificates/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "domain": "example.com",
 "dns_provider": "cloudflare",
 "domain_alias": "_acme-challenge.validation.example.org"
 }'
```

## Benefits of This Approach

1. **Centralized Control**: All DNS challenges go through one provider you control
2. **Multi-Master Safe**: Works regardless of which DNS provider serves the query
3. **No Synchronization**: Don't need to update multiple providers
4. **Provider Agnostic**: Works even if your primary domain is on unsupported providers (deSEC, gcore)
5. **Security**: Keep DNS API credentials limited to the validation domain

## Advanced: Wildcard Certificates

```bash
# Wildcard certificate with domain alias
curl -X POST http://localhost:5000/api/certificates/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "domain": "*.example.com",
 "dns_provider": "cloudflare",
 "domain_alias": "_acme-challenge.validation.example.org"
 }'
```

## deSEC and gcore Provider Support

### Current Status

CertMate does **not natively support** deSEC or gcore DNS providers yet. However:

1. **Certbot plugins exist**:
 - deSEC: [`certbot-dns-desec`](https://github.com/desec-io/certbot-dns-desec)
 - gcore: [`gcore-dns-certbot-plugin`](https://github.com/G-Core/gcore-dns-certbot-plugin)

2. **Workaround**: Use domain alias (as described above) to avoid needing direct integration

### Future Support

To add native support for these providers, the following would be needed:

1. Install the certbot plugin
2. Add provider configuration to CertMate
3. Create DNS strategy class for each provider
4. Update UI to include provider options

**Contribution welcome!** See `CONTRIBUTING.md` for details.

## Example: Complete Multi-Master Setup

### Scenario
- Domain: `mysite.com` 
- Primary DNS: deSEC (not supported by CertMate)
- Secondary DNS: gcore (not supported by CertMate)
- Validation domain: `acme.mydomain.net` (hosted on Cloudflare)

### Setup Steps

1. **Configure CNAME in both deSEC and gcore**:
```dns
_acme-challenge.mysite.com. 300 IN CNAME _acme-challenge.acme.mydomain.net.
```

2. **Verify CNAME propagation**:
```bash
dig _acme-challenge.mysite.com CNAME +short
# Should return: _acme-challenge.acme.mydomain.net.
```

3. **Configure CertMate with Cloudflare** (for validation domain):
```json
{
 "dns_provider": "cloudflare",
 "dns_providers": {
 "cloudflare": {
 "accounts": {
 "default": {
 "api_token": "your_cloudflare_api_token"
 }
 }
 }
 }
}
```

4. **Request certificate**:
```bash
curl -X POST http://localhost:5000/api/certificates/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "domain": "mysite.com",
 "email": "admin@mysite.com",
 "dns_provider": "cloudflare",
 "domain_alias": "_acme-challenge.acme.mydomain.net"
 }'
```

5. **How it works**:
 - Let's Encrypt requests `_acme-challenge.mysite.com`
 - Both deSEC and gcore return CNAME to `_acme-challenge.acme.mydomain.net`
 - CertMate creates TXT record at `_acme-challenge.acme.mydomain.net` via Cloudflare
 - Validation succeeds regardless of which DNS provider responds
 - Certificate is issued for `mysite.com`

## Troubleshooting

### CNAME not resolving
```bash
# Check CNAME from multiple resolvers
dig @8.8.8.8 _acme-challenge.example.com CNAME
dig @1.1.1.1 _acme-challenge.example.com CNAME
```

### Validation failing
- Ensure CNAME exists in **all** DNS providers
- Wait for DNS propagation (can take up to 48 hours, usually minutes)
- Verify the target domain is accessible from Let's Encrypt servers

### Check TXT record creation
```bash
# After requesting certificate, check if TXT record exists
dig _acme-challenge.validation.example.org TXT
```

## References

- [Certbot Domain Validation](https://eff-certbot.readthedocs.io/en/stable/using.html#dns-plugins)
- [Let's Encrypt Challenge Types](https://letsencrypt.org/docs/challenge-types/)
- [DNS-01 Challenge](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)

## Related Documentation

- [MULTI_ACCOUNT_EXAMPLES.md](MULTI_ACCOUNT_EXAMPLES.md) - Multi-account setup examples
- [DNS_PROVIDERS.md](DNS_PROVIDERS.md) - Supported DNS providers
- [API_TESTING.md](API_TESTING.md) - API usage examples
