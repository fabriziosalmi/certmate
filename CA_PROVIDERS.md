# Certificate Authority (CA) Providers in CertMate

CertMate now supports multiple Certificate Authority providers, allowing you to choose the most appropriate CA for your needs, from free automated certificates to enterprise-grade solutions.

## Supported CA Providers

### 1. Let's Encrypt (Default)
- **Type**: Free, automated SSL certificates
- **Certificate Types**: Domain Validation (DV)
- **Wildcard Support**: Yes
- **EAB Required**: No
- **Best For**: Development, small businesses, personal projects

**Configuration:**
- **Environment**: Choose between Production and Staging
- **Email**: Required for certificate notifications

### 2. DigiCert ACME
- **Type**: Enterprise-grade SSL certificates
- **Certificate Types**: DV, OV, EV
- **Wildcard Support**: Yes
- **EAB Required**: Yes
- **Best For**: Enterprise environments, commercial applications

**Configuration Requirements:**
- **ACME Directory URL**: Usually `https://acme.digicert.com/v2/acme/directory`
- **EAB Key ID**: Provided by DigiCert
- **EAB HMAC Key**: Provided by DigiCert
- **Email**: Required for certificate notifications

**Note**: You must have a DigiCert account and obtain EAB credentials before using this CA.

### 3. Private CA
- **Type**: Internal/Corporate Certificate Authority
- **Certificate Types**: Private/Internal
- **Wildcard Support**: Yes (depends on CA implementation)
- **EAB Required**: Optional (depends on CA configuration)
- **Best For**: Internal networks, corporate environments, air-gapped systems

**Configuration:**
- **ACME Directory URL**: Your private CA's ACME endpoint
- **CA Certificate**: Optional PEM-formatted root CA certificate
- **EAB Credentials**: Optional, if required by your CA
- **Email**: Required for certificate notifications

**Compatible with:**
- [step-ca](https://smallstep.com/docs/step-ca/)
- [Boulder](https://github.com/letsencrypt/boulder)
- [Pebble](https://github.com/letsencrypt/pebble)
- Other ACME-compatible private CAs

## Configuration

### Via Web Interface

1. Navigate to **Settings** in the CertMate web interface
2. Scroll to the **Certificate Authority (CA) Providers** section
3. Select your default CA provider from the dropdown
4. Configure the settings for your chosen CA provider
5. Click **Test CA Connection** to verify the configuration
6. Save your settings

### Default CA Provider

You can set a default CA provider that will be used for all new certificate requests. This can be overridden on a per-certificate basis during creation.

### Per-Certificate CA Selection

When creating a new certificate, you can optionally select a different CA provider from the default:

1. Go to the main **Certificates** page
2. In the **Create New Certificate** form
3. Select your desired CA from the **Certificate Authority** dropdown
4. Proceed with certificate creation

## External Account Binding (EAB)

Some CA providers (like DigiCert) require External Account Binding for security and account verification.

### What is EAB?
EAB is a mechanism that links your ACME client to your account with the CA provider. It consists of:
- **Key ID**: A unique identifier for your account
- **HMAC Key**: A secret key used to sign requests

### Obtaining EAB Credentials

#### DigiCert
1. Log into your DigiCert account
2. Navigate to the ACME settings
3. Generate or retrieve your EAB Key ID and HMAC Key
4. Enter these credentials in CertMate's DigiCert configuration

#### Private CA
EAB requirements vary by implementation:
- **step-ca**: EAB can be enabled/disabled per need
- **Boulder**: Typically requires EAB for production use
- Check your private CA documentation for specific requirements

## SSL Certificate Trust

### Public CAs (Let's Encrypt, DigiCert)
Certificates from public CAs are automatically trusted by browsers and operating systems.

### Private CAs
For private CA certificates to be trusted:

1. **Install Root CA Certificate**: Install your private CA's root certificate on client systems
2. **Configure Applications**: Some applications may need specific trust configuration
3. **Browser Trust**: Import the root certificate into browser trust stores

### CA Certificate in CertMate

For private CAs, you can optionally provide the root CA certificate in CertMate:
- Helps with validation during certificate creation
- Used for trust chain verification
- Should be in PEM format

## Troubleshooting

### Connection Test Failures

#### Let's Encrypt
- **Staging URL accessible**: Verify internet connectivity
- **Email valid**: Ensure email format is correct

#### DigiCert
- **Invalid EAB credentials**: Verify Key ID and HMAC Key from DigiCert account
- **Account not authorized**: Ensure your DigiCert account has ACME enabled
- **Wrong ACME URL**: Verify the directory URL with DigiCert support

#### Private CA
- **ACME URL unreachable**: Check network connectivity to your private CA
- **CA certificate invalid**: Verify PEM format and certificate validity
- **EAB mismatch**: Check if EAB is required and credentials are correct

### Certificate Creation Issues

#### General
- Ensure DNS provider is configured correctly
- Verify domain ownership and DNS propagation
- Check that the selected CA supports your domain type

#### Private CA Specific
- Verify your private CA is running and accessible
- Check firewall rules for ACME port (usually 443)
- Ensure CA has proper certificate chain configuration

## Security Considerations

### Credential Storage
- EAB HMAC keys are not displayed after saving for security
- Private keys are generated locally and never transmitted
- Use secure storage backends for production environments

### CA Trust
- Only use trusted CA providers
- Verify CA certificates and EAB credentials through official channels
- Monitor certificate transparency logs for unauthorized certificates

### Network Security
- Use HTTPS for all CA communications
- Consider VPN or private networks for private CA access
- Implement proper firewall rules for CA connectivity

## Migration Between CAs

You can change your default CA provider at any time:

1. **New Certificates**: Will use the new default CA
2. **Existing Certificates**: Will continue using their original CA until renewal
3. **Forced Migration**: Manually renew certificates to switch to the new CA

### Best Practices for Migration
- Test new CA configuration before making it default
- Plan migration during maintenance windows
- Keep backup of existing certificates during transition
- Monitor certificate validity after migration

## API Usage

### Create Certificate with Specific CA
```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "ca_provider": "digicert"
  }'
```

### Test CA Provider Connection
```bash
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

## Support and Resources

### Let's Encrypt
- [Documentation](https://letsencrypt.org/docs/)
- [Rate Limits](https://letsencrypt.org/docs/rate-limits/)
- [Staging Environment](https://letsencrypt.org/docs/staging-environment/)

### DigiCert
- [ACME Documentation](https://docs.digicert.com/certificate-tools/acme-user-guide/)
- [Account Setup](https://docs.digicert.com/certificate-tools/acme-user-guide/acme-account-setup/)
- [Support Portal](https://www.digicert.com/support/)

### Private CA Solutions
- [step-ca Documentation](https://smallstep.com/docs/step-ca/)
- [Boulder Project](https://github.com/letsencrypt/boulder)
- [Pebble Test Server](https://github.com/letsencrypt/pebble)

## Changelog

### Version 1.3.0
- Added support for multiple CA providers
- Implemented DigiCert ACME integration
- Added Private CA support with custom trust bundles
- Enhanced certificate creation with CA selection
- Added CA provider testing and validation
