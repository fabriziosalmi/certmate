# Certificate Authority (CA) Providers

CertMate supports multiple Certificate Authority providers, allowing you to choose the most appropriate CA for your needs.

---

## Supported CA Providers

### Let's Encrypt (Default)

- **Type**: Free, automated SSL certificates
- **Certificate Types**: Domain Validation (DV)
- **Wildcard Support**: Yes
- **EAB Required**: No
- **Best For**: Development, small businesses, personal projects

**Configuration:**
- **Environment**: Production or Staging
- **Email**: Required for certificate notifications

### DigiCert ACME

- **Type**: Enterprise-grade SSL certificates
- **Certificate Types**: DV, OV, EV
- **Wildcard Support**: Yes
- **EAB Required**: Yes
- **Best For**: Enterprise environments, commercial applications

**Configuration Requirements:**
- **ACME Directory URL**: `https://acme.digicert.com/v2/acme/directory`
- **EAB Key ID**: Provided by DigiCert
- **EAB HMAC Key**: Provided by DigiCert
- **Email**: Required for certificate notifications

### Private CA

- **Type**: Internal/Corporate Certificate Authority
- **Certificate Types**: Private/Internal
- **Wildcard Support**: Yes (depends on CA implementation)
- **EAB Required**: Optional
- **Best For**: Internal networks, corporate environments, air-gapped systems

**Compatible Software:**
- [step-ca](https://smallstep.com/docs/step-ca/)
- [Boulder](https://github.com/letsencrypt/boulder)
- [Pebble](https://github.com/letsencrypt/pebble)
- Other ACME-compatible private CAs

---

## Configuration

### Via Web Interface

1. Navigate to **Settings**
2. Scroll to **Certificate Authority (CA) Providers**
3. Select your default CA provider
4. Configure the required fields
5. Click **Test CA Connection** to verify
6. Save settings

### Default vs. Per-Certificate CA

Set a default CA for all new certificates. Override it per-certificate during creation:

1. Go to **Certificates** page
2. Select the desired CA from the **Certificate Authority** dropdown
3. Proceed with certificate creation

### Via API

```bash
# Create certificate with specific CA
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "ca_provider": "digicert"
  }'

# Test CA connection
curl -X POST http://localhost:8000/api/test-ca-provider \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_provider": "digicert",
    "config": {
      "acme_url": "https://acme.digicert.com/v2/acme/directory",
      "eab_kid": "your_key_id",
      "eab_hmac": "your_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

Some CA providers (like DigiCert) require External Account Binding to link your ACME client to your CA account.

### What is EAB?

- **Key ID**: A unique identifier for your account
- **HMAC Key**: A secret key used to sign requests

### Obtaining EAB Credentials

**DigiCert:**
1. Log into your DigiCert account
2. Navigate to ACME settings
3. Generate or retrieve your EAB Key ID and HMAC Key

**Private CA:**
- **step-ca**: EAB can be enabled/disabled per provisioner
- **Boulder**: Typically requires EAB for production
- Check your private CA documentation for specific requirements

---

## SSL Certificate Trust

### Public CAs (Let's Encrypt, DigiCert)

Certificates are automatically trusted by browsers and operating systems.

### Private CAs

For private CA certificates to be trusted:
1. Install the root CA certificate on client systems
2. Configure applications for custom trust
3. Import the root certificate into browser trust stores

You can optionally provide the root CA certificate in CertMate for trust chain verification during certificate creation.

---

## Troubleshooting

### Let's Encrypt
- **Staging URL accessible**: Verify internet connectivity
- **Email valid**: Ensure email format is correct

### DigiCert
- **Invalid EAB credentials**: Verify Key ID and HMAC Key
- **Account not authorized**: Ensure ACME is enabled on your DigiCert account
- **Wrong ACME URL**: Verify the directory URL with DigiCert support

### Private CA
- **ACME URL unreachable**: Check network connectivity
- **CA certificate invalid**: Verify PEM format and validity
- **EAB mismatch**: Check if EAB is required by your CA

### General
- Ensure DNS provider is configured correctly
- Verify domain ownership and DNS propagation
- Check firewall rules for ACME port (usually 443)

---

## Migration Between CAs

1. **New certificates** use the new default CA
2. **Existing certificates** continue using their original CA until renewal
3. **Forced migration**: Manually renew to switch to the new CA

**Best Practices:**
- Test new CA configuration before making it default
- Plan migration during maintenance windows
- Keep backups of existing certificates
- Monitor validity after migration

---

## Security Considerations

- EAB HMAC keys are not displayed after saving
- Private keys are generated locally and never transmitted
- Use HTTPS for all CA communications
- Consider VPN for private CA access

---

## Resources

### Let's Encrypt
- [Documentation](https://letsencrypt.org/docs/)
- [Rate Limits](https://letsencrypt.org/docs/rate-limits/)
- [Staging Environment](https://letsencrypt.org/docs/staging-environment/)

### DigiCert
- [ACME Documentation](https://docs.digicert.com/certificate-tools/acme-user-guide/)
- [Account Setup](https://docs.digicert.com/certificate-tools/acme-user-guide/acme-account-setup/)

### Private CA
- [step-ca Documentation](https://smallstep.com/docs/step-ca/)
- [Boulder Project](https://github.com/letsencrypt/boulder)
- [Pebble Test Server](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Back to Documentation](./README.md) • [DNS Providers →](./dns-providers.md) • [Docker →](./docker.md)

</div>
