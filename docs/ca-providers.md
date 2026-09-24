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
- **Email**: ACME account contact (see [Account email](#account-email))

### Let's Encrypt (Staging)

- **Type**: Test certificates from the Let's Encrypt staging environment
- **Certificate Types**: Domain Validation (DV) — NOT trusted by browsers
- **Wildcard Support**: Yes
- **EAB Required**: No
- **Best For**: Validating DNS, deployment and renewal setup without consuming production rate limits

Staging is a separate Certificate Authority entry (since v2.12.0), not a per-certificate
flag: select it as the CA when creating a certificate, or set it as the default CA while
testing. The email falls back to the Let's Encrypt account email when left empty.
Converting a staging certificate to production requires a reissue with the production CA.

### ZeroSSL

- **Type**: Free 90-day DV certificates
- **Certificate Types**: Domain Validation (DV)
- **Wildcard Support**: Yes
- **EAB Required**: Yes

**Configuration Requirements:**
- **ACME Directory URL**: `https://acme.zerossl.com/v2/DV90` (fixed, preconfigured)
- **EAB Key ID**: From the ZeroSSL Developer Dashboard
- **EAB HMAC Key**: From the ZeroSSL Developer Dashboard
- **Email**: ACME account contact (see [Account email](#account-email))

### Google Trust Services

- **Type**: Free DV certificates
- **Certificate Types**: Domain Validation (DV)
- **Wildcard Support**: Yes
- **EAB Required**: Yes

**Configuration Requirements:**
- **ACME Directory URL**: `https://dv.acme-v02.api.pki.goog/directory` (fixed, preconfigured)
- **EAB Key ID**: From your Google Cloud project
- **EAB HMAC Key**: From your Google Cloud project
- **Email**: ACME account contact (see [Account email](#account-email))

### DigiCert ACME

- **Type**: Enterprise-grade SSL certificates
- **Certificate Types**: DV, OV, EV
- **Wildcard Support**: Yes
- **EAB Required**: Yes
- **Best For**: Enterprise environments, commercial applications

**Configuration Requirements:**
- **ACME Directory URL**: `https://one.digicert.com/mpki/api/v1/acme/v2/directory`
  — the default, and **regional**. An account outside the default region has
  its own directory URL, shown in CertCentral; enter it here and issuance uses
  it. Leave it as the default and the default is used. It must be `https`.
- **EAB Key ID**: Provided by DigiCert
- **EAB HMAC Key**: Provided by DigiCert
- **Email**: ACME account contact (see [Account email](#account-email))

### Actalis

- **Type**: Free 90-day DV certificates from a European (Italian) CA
- **Certificate Types**: Domain Validation (DV)
- **Wildcard Support**: No (not offered via ACME)
- **EAB Required**: Yes
- **Best For**: EU users who want a European alternative to Let's Encrypt, eIDAS-ecosystem environments

**Configuration Requirements:**
- **ACME Directory URL**: `https://acme-api.actalis.com/acme/directory` (fixed, preconfigured)
- **EAB Key ID**: From your Actalis customer area
- **EAB HMAC Key**: From your Actalis customer area
- **Email**: ACME account contact (see [Account email](#account-email))

**Free plan limits:**
- Single-domain certificates only — a request with SAN entries is rejected with
  `Your account only grants single-domain 90-days DV certificates`
- 90-day validity
- No wildcard certificates (paid SAN plans cover up to 5 hostnames)

### SSL.com

- **Type**: Commercial certificates
- **Certificate Types**: DV, OV, EV
- **Wildcard Support**: Yes
- **EAB Required**: Yes

**Configuration Requirements:**
- **ACME Directory URL**: `https://acme.ssl.com/sslcom-dv-rsa` (fixed, preconfigured)
- **EAB Key ID**: Provided by SSL.com
- **EAB HMAC Key**: Provided by SSL.com
- **Email**: ACME account contact (see [Account email](#account-email))

### Sectigo

- **Type**: Public/commercial ACME CA via Sectigo Certificate Manager (SCM)
- **Certificate Types**: DV, OV (depending on the selected SCM account/profile)
- **Wildcard Support**: Yes, when permitted by the SCM account/profile
- **EAB Required**: Yes
- **ACME Directory URL**: Copy the HTTPS URL from the SCM ACME account details; it is account-specific
- **EAB Key ID / KID and HMAC Key**: Copy from the SCM ACME account details
- **Email**: ACME account contact (see [Account email](#account-email))

Example test configuration (the URL is **only an example**, not a universal endpoint):

```json
{
  "ca_provider": "sectigo",
  "config": {
    "acme_url": "https://acme.sectigo.com/v2/OV",
    "eab_kid": "your-sectigo-key-id",
    "eab_hmac": "your-sectigo-hmac-key",
    "email": "admin@example.com"
  }
}
```

For multiple accounts, configure `ca_providers.sectigo.accounts` in settings,
with each account holding its own `acme_url`, `eab_kid`, `eab_hmac`, and `email`.
Select an account using `ca_account_id` on the certificate creation API; if
omitted, CertMate uses `default_ca_accounts.sectigo` or the first configured account.
Renewal reuses the recorded CA account. DNS-01 (including Custom Script) and
HTTP-01 remain available; SCM may already have authorized the requested domain.
Existing Sectigo configurations under Private CA continue to work unchanged.

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

**Using a public ACME CA through Private CA:**

The Private CA entry is also the generic escape hatch for any ACME CA without a dedicated CertMate entry: point it at the CA's directory URL and, if the CA enforces account binding, fill in the optional EAB Key ID and HMAC Key. For example, Actalis works both through its dedicated entry (recommended) and as a Private CA with:

- **ACME Directory URL**: `https://acme-api.actalis.com/acme/directory`
- **EAB Key ID / HMAC Key**: from the Actalis customer area
- **CA Certificate**: leave empty (publicly trusted roots)

---

## Configuration

### Via Web Interface

1. Navigate to **Settings**
2. Scroll to **Certificate Authority (CA) Providers**
3. Select your default CA provider
4. Configure the required fields
5. Click **Test CA Connection** to check the fields
6. Save settings

**Test CA Connection** only contacts the CA for a Private CA: it fetches the
ACME directory URL (using the CA certificate, if one is given). For every other
CA it checks that the required fields are filled in (and, for DigiCert, that
the EAB credentials are not implausibly short) without contacting the CA, so a
passing test does not prove the credentials work. The first issuance does.

### Account email

The email certbot registers the ACME account with is the global `email`
setting, whichever CA issues the certificate. Saving settings in the web
interface copies the email from the **default** CA's section into that setting;
the email fields of the other CA sections are stored but not passed to
certbot. Issuance fails with `Email not configured` when the global setting is
empty.

### Default vs. Per-Certificate CA

Set a default CA for all new certificates. Override it per-certificate during creation:

1. Go to **Certificates** page
2. Select the desired CA from the **Certificate Authority** dropdown
3. Proceed with certificate creation

If the chosen CA has no saved configuration (or the requested CA account does
not exist), the request is **refused**. Issuing from a different CA is not a
substitute for the one you asked for: it was possible to ask for DigiCert and
receive a Let's Encrypt certificate with a `201`, and to ask a private CA for
an internal name and have that name published in a public certificate. The
refusal names the CA that is missing.

Let's Encrypt is the exception, and only because certbot's defaults are its
configuration: a request for it succeeds with nothing saved, and a staging
request stays on staging.

The **CA** column on the Certificates page names the authority each certificate
was issued with; the same value is `ca_provider` in the API response and in the
certificate's metadata. Certificates issued before CertMate recorded the CA
show `—` there rather than a guess.

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
curl -X POST http://localhost:8000/api/settings/test-ca-provider \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_provider": "digicert",
    "config": {
      "acme_url": "https://one.digicert.com/mpki/api/v1/acme/v2/directory",
      "eab_kid": "your_key_id",
      "eab_hmac": "your_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis and Sectigo require External Account Binding to link your ACME client to your CA account.

### What is EAB?

- **Key ID**: A unique identifier for your account
- **HMAC Key**: A secret key used to sign requests

### Obtaining EAB Credentials

**DigiCert:**
1. Log into your DigiCert account
2. Navigate to ACME settings
3. Generate or retrieve your EAB Key ID and HMAC Key

**ZeroSSL:**
- Generate EAB credentials in the ZeroSSL Developer Dashboard

**Actalis:**
1. Register a free account at [actalis.com](https://www.actalis.com/)
2. In the customer area, open **Manage with ACME**
3. Retrieve the KID and HMAC key under **ACME Credentials**

**Private CA:**
- **step-ca**: EAB can be enabled/disabled per provisioner
- Check your private CA documentation for specific requirements

---

## SSL Certificate Trust

### Public CAs (Let's Encrypt, ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis, Sectigo)

Certificates are automatically trusted by browsers and operating systems (except those from Let's Encrypt staging).

### Private CAs

For private CA certificates to be trusted:
1. Install the root CA certificate on client systems
2. Configure applications for custom trust
3. Import the root certificate into browser trust stores

You can optionally provide the root CA certificate in CertMate for trust chain verification during certificate creation.

---

## Troubleshooting

### Let's Encrypt
- **Untrusted certificate after issuance**: Check whether the certificate was issued by the staging CA — select the production "Let's Encrypt" entry and reissue
- **Rate limited**: Switch to the "Let's Encrypt (Staging)" CA entry while testing
- **Email valid**: Ensure email format is correct

### DigiCert
- **Invalid EAB credentials**: Verify Key ID and HMAC Key
- **Account not authorized**: Ensure ACME is enabled on your DigiCert account
- **Wrong ACME URL**: Verify the directory URL with DigiCert support

### Actalis
- **`Your account only grants single-domain 90-days DV certificates`**: The free plan rejects SAN/multi-domain requests — issue one certificate per hostname or upgrade the plan
- **Invalid EAB credentials**: Retrieve fresh credentials from the customer area under Manage with ACME
- **Wildcard rejected**: Wildcard certificates are not available via ACME at Actalis

### Sectigo
- **Invalid EAB credentials**: Verify the KID and HMAC against the selected SCM ACME account details
- **Unauthorized identifier/domain**: Verify the domain is authorized for the selected SCM ACME account and organization
- **Wrong ACME endpoint**: Verify the configured directory URL exactly matches the URL provided in SCM for that account

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
2. **Existing certificates** stay on the CA they were issued by: renewal runs
   `certbot renew` against the original CA, including a manual or forced renewal
3. **Moving a certificate to another CA**: reissue it with the new CA
   (`POST /api/certificates/<domain>/reissue` with `ca_provider`; see the
   [API reference](api.md))

**Best Practices:**
- Test new CA configuration before making it default
- Plan migration during maintenance windows
- Keep backups of existing certificates
- Monitor validity after migration

---

## Security Considerations

- EAB HMAC keys are not displayed after saving
- Private keys are generated locally and never sent to the CA (a remote storage backend or deploy target you configure does receive them)
- Use an `https://` ACME directory URL for a Private CA
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

### Actalis
- [How to enable ACME](https://guide.actalis.com/ssl/activation/acme)
- [ACME FAQ](https://guide.actalis.com/faq/SSL/ACME)

### Sectigo
- [Understanding SCM ACME endpoints](https://docs.sectigo.com/scm/scm-administrator/understanding-acme-endpoints.html)
- [Adding SCM ACME accounts](https://docs.sectigo.com/scm/scm-administrator/adding-acme-accounts.html)

### Private CA
- [step-ca Documentation](https://smallstep.com/docs/step-ca/)
- [Boulder Project](https://github.com/letsencrypt/boulder)
- [Pebble Test Server](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Back to Documentation](./README.md) • [DNS Providers →](./dns-providers.md) • [Docker →](./docker.md)

</div>
