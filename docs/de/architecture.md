# CertMate Architektur

Dieses Dokument beschreibt die vollständige Architektur von CertMate — sowohl das Hauptsystem für Server-Zertifikate als auch das Teilsystem für Client-Zertifikate.

---

## Inhaltsverzeichnis

- [Architektur des Hauptsystems](#architektur-des-hauptsystems)
- [Überblick-Diagramm](#überblick-diagramm)
- [Manager-Klassen](#manager-klassen)
- [Ablauf der Zertifikatserstellung](#ablauf-der-zertifikatserstellung)
- [Speicherarchitektur](#speicherarchitektur)
- [Konfigurationsstruktur](#konfigurationsstruktur)
- [API-Endpoints](#api-endpoints)
- [Technologie-Stack](#technologie-stack)
- [Architektur der Client-Zertifikate](#architektur-der-client-zertifikate)

---

## Architektur des Hauptsystems

CertMate ist ein modulares, erweiterbares SSL/TLS-Zertifikatsverwaltungssystem, das mit Python/Flask gebaut wurde. Es unterstützt mehrere CA-Anbieter, mehr als zwei Dutzend DNS-Anbieter sowie austauschbare Storage-Backends.

**Wichtige Fakten:**
- **Sprache**: Python 3.9+ (Flask, Flask-RESTX)
- **Speicher**: Lokales Dateisystem als Standard + 4 Cloud-Backends (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical)
- **CA-Anbieter**: Let's Encrypt, DigiCert ACME, Private CA
- **DNS-Anbieter**: mehr als zwei Dutzend unterstützt (Cloudflare, AWS Route53, Azure, Google und weitere — siehe [DNS-Anbieter](./dns-providers.md) für die vollständige Liste)
- **API**: REST mit Swagger/OpenAPI via Flask-RESTX
- **Aktuelle Zertifikatstypen**: Server-seitiges TLS (DV, OV, EV)

---

## Überblick-Diagramm

```
┌─────────────────────────────────────────────────────┐
│                  CertMate Application               │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │             Web Layer (Flask)                  │  │
│  │  Dashboard    Settings    Help    Client Certs │  │
│  └────────────────────┬──────────────────────────┘  │
│                       ↓                             │
│  ┌──────────────────┐   ┌────────────────────────┐  │
│  │  REST API         │   │  Web Routes            │  │
│  │  /api/certificates│   │  /api/web/certificates │  │
│  │  /api/client-certs│   │  /client-certificates  │  │
│  └────────┬─────────┘   └────────┬───────────────┘  │
│           └──────────┬───────────┘                   │
│                      ↓                               │
│  ┌───────────────────────────────────────────────┐  │
│  │          Manager Layer (Business Logic)        │  │
│  │                                               │  │
│  │  CertificateManager    CAManager              │  │
│  │  DNSManager            StorageManager         │  │
│  │  AuthManager           SettingsManager        │  │
│  │  CacheManager          FileOperations         │  │
│  │  ClientCertManager     OCSPResponder          │  │
│  │  CRLManager            AuditLogger            │  │
│  └────────────────────┬──────────────────────────┘  │
│                       ↓                             │
│  ┌───────────────────────────────────────────────┐  │
│  │          Execution Layer                       │  │
│  │  Certbot (server certs via DNS-01 ACME)       │  │
│  │  PrivateCA (client certs via direct signing)  │  │
│  └────────────────────┬──────────────────────────┘  │
│                       ↓                             │
│  ┌───────────────────────────────────────────────┐  │
│  │          Storage Layer (Pluggable Backends)    │  │
│  │  Local FS │ Azure KV │ AWS SM │ Vault │ Infis │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Manager-Klassen

```
CertMateApp (Hauptanwendung)
  ├── FileOperations          # Datei-Ein-/Ausgabe, Sicherungen
  ├── SettingsManager         # Laden/Speichern von settings.json
  ├── AuthManager             # Token-Validierung
  ├── CertificateManager      # Erstellen/Erneuern/Infos (Server-Zertifikate)
  ├── CAManager               # CA-Anbieter-Konfiguration, Certbot-Aufbau
  ├── DNSManager              # DNS-Anbieter-Konten
  ├── CacheManager            # Deployment-Cache
  ├── StorageManager          # Backend-Abstraktion
  ├── ClientCertificateManager # Lebenszyklus der Client-Zertifikate
  ├── PrivateCAGenerator      # Verwaltung der selbst-signierten CA
  ├── OCSPResponder           # Abfragen des Zertifikatsstatus
  ├── CRLManager              # Erzeugung von Sperrlisten
  └── AuditLogger             # Verfolgung von Operationen
```

---

## Ablauf der Zertifikatserstellung

### Server-Zertifikate (via Certbot + ACME)

```
1. User submits: domain, email, DNS provider, CA provider
2. Validate inputs (domain format, email, provider existence)
3. Get CA config (ACME URL, EAB credentials if DigiCert)
4. Get DNS config (account credentials from settings)
5. Create directory: certificates/{domain}/
6. Build certbot command:
   certbot certonly --non-interactive --agree-tos
     --server {acme_url}
     --email {email}
     --{dns_plugin} --{dns_plugin}-credentials {cred_file}
     --{dns_plugin}-propagation-seconds {timeout}
     --eab-kid/--eab-hmac-key (if required)
     -d {domain}
7. Create temporary DNS credentials file (600 permissions)
8. Execute certbot (30-minute timeout)
9. Resolve symlinks, copy cert files to domain root
10. Store via configured backend + create metadata.json
11. Clean up credentials file
```

### Client-Zertifikate (via Private CA)

```
1. User submits: common_name, email, organization, cert_usage
2. Initialize or load existing CA (4096-bit RSA)
3. Generate CSR (or accept provided CSR)
4. Sign CSR with private CA
5. Store cert/key/csr files + metadata.json
6. Log in audit trail
```

---

## Speicherarchitektur

### Server-Zertifikate

```
certificates/
  example.com/
    cert.pem          # Server certificate
    chain.pem         # Intermediate CA chain
    fullchain.pem     # cert + chain
    privkey.pem       # Private key (600 permissions)
    metadata.json     # Certificate metadata
```

### Client-Zertifikate

```
data/certs/
  ca/
    ca.crt            # CA certificate
    ca.key            # CA private key (600 permissions)
    ca_metadata.json  # CA metadata
    crl.pem           # Certificate Revocation List
  client/
    api-mtls/         # Certificates by usage type
      cert-001/
        cert.crt
        cert.key
        cert.csr
        metadata.json
    vpn/
      cert-002/
        ...
```

### Storage-Backends

Alle Backends implementieren `CertificateStorageBackend`:

| Backend | Speicherort |
|---------|-----------------|
| **Lokales Dateisystem** | `certificates/{domain}/` (Standard) |
| **Azure Key Vault** | Secrets, native Certificate-Objekte oder beides — siehe unten |
| **AWS Secrets Manager** | AWS Secrets Manager |
| **HashiCorp Vault** | Vault KV v1/v2 |
| **Infisical** | Infisical-Secrets |

#### Azure Key Vault — Speichermodi

Das Azure Key Vault-Backend kann Zertifikate als Secrets (Standard), als native Certificate-Objekte oder als beides persistieren; gesteuert wird dies über `certificate_storage.azure_keyvault.storage_mode` in `settings.json`.

| Modus | Schreibt Secrets | Schreibt Certificate-Objekt | Wann verwenden |
|---|---|---|---|
| `secrets` (Standard) | ja | nein | Rückwärtskompatibles Verhalten. Jedes `cert.pem` / `chain.pem` / `fullchain.pem` / `privkey.pem` sowie die Metadaten werden als separate Key Vault-Secrets gespeichert. |
| `certificate` | nein | ja | Direkte Einbindung über App Service, Application Gateway, Front Door, API Management, AKS Ingress usw. Das Zertifikat + Kette + privater Schlüssel werden als einzelnes PKCS12-`Certificate`-Objekt mit `issuer_name="Unknown"` importiert, damit Key Vault keine Erneuerung versucht. |
| `both` | ja | ja | Übergangs- oder Mischkonsumenten-Setups. Lesezugriffe bevorzugen weiterhin den Secrets-Pfad (kostengünstiger). |

Eine manuelle Aktion **Backfill Certificate objects** im Einstellungsbereich für den Speicher (`POST /api/storage/azure-keyvault/backfill-certificates`) importiert ein Certificate-Objekt für jede Domain, die im Vault bereits als Secret vorhanden ist, aber noch kein solches Objekt besitzt. Bereits vorhandene Certificate-Objekte werden übersprungen. Der Endpoint akzeptiert einen optionalen Abfrageparameter `?limit=N`, um die Anzahl der pro Aufruf verarbeiteten Domains zu begrenzen; bei großen Vaults kann durch wiederholte Aufrufe paginiert werden, bis die Antwort `0` verbleibende Domains meldet.

##### Sicherheitshinweis — Certificate-Objekte legen den privaten Schlüssel über die Secrets-API offen

Wenn Key Vault ein PKCS12-Certificate-Objekt importiert, erstellt es gleichzeitig ein begleitendes **Secret** mit demselben Namen, dessen Wert das vollständige PFX (einschließlich des privaten Schlüssels) enthält. Dies ist in Azure by design: Es ist der dokumentierte Weg, über den VM-Extensions und App Service das Zertifikat abrufen; jeder Principal mit `Secrets/Get` auf dem Vault kann daher den privaten Schlüssel herunterladen — *die Berechtigung `Get` auf Certificates allein reicht nicht aus, um den privaten Schlüssel zu extrahieren, `Secrets/Get` hingegen schon*. Betreiber, die CertMate im Modus `certificate` oder `both` betreiben, sollten `Secrets/Get` sorgfältig einschränken und Azure RBAC gegenüber Vault-Zugriffsrichtlinien für eine feinere Steuerung bevorzugen. Siehe [Microsoft Learn — Zertifikate in Key Vault](https://learn.microsoft.com/azure/key-vault/certificates/about-certificates) für das vollständige Modell.

##### Service-Principal-Berechtigungen

| Modus | Erforderliche Berechtigungen auf dem Vault |
|---|---|
| `secrets` | Secrets `Get/Set/List/Delete` |
| `certificate` / `both` | Fügt Certificates `Get/List/Import/Delete` hinzu und behält Secrets `Get/List` (Key Vault stellt das importierte PFX, einschließlich des privaten Schlüssels, ausschließlich über das Secret mit demselben Namen wie das Certificate-Objekt bereit). |

---

## Konfigurationsstruktur

Alle Einstellungen werden in `data/settings.json` gespeichert:

```json
{
  "email": "admin@example.com",
  "domains": ["example.com", "*.example.com"],
  "auto_renew": true,
  "renewal_threshold_days": 30,
  "api_bearer_token": "secure-token",
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {
      "accounts": {
        "production": {"api_token": "token-prod"},
        "staging": {"api_token": "token-staging"}
      }
    }
  },
  "default_accounts": {
    "cloudflare": "production"
  },
  "ca_providers": {
    "letsencrypt": {
      "accounts": {
        "default": {"email": "admin@example.com"}
      }
    }
  },
  "certificate_storage": {
    "backend": "local_filesystem",
    "cert_dir": "certificates"
  },
  "default_key_type": "rsa",
  "default_key_size": 2048,
  "default_elliptic_curve": "secp256r1"
}
```

### Zertifikat-Schlüsseltyp/-größe

Drei Schlüssel auf der obersten Ebene steuern die Form des öffentlichen Schlüssels neu ausgestellter Zertifikate:

| Schlüssel | Werte | Gilt wenn |
|---|---|---|
| `default_key_type` | `rsa` (Standard) / `ecdsa` | immer |
| `default_key_size` | `2048` (Standard) / `3072` / `4096` | `default_key_type == "rsa"` |
| `default_elliptic_curve` | `secp256r1` (Standard) / `secp384r1` | `default_key_type == "ecdsa"` |

Eine pro-Zertifikat-Überschreibung wird unterstützt: Jeder Eintrag in `domains` kann optional einen `key_type` sowie entweder `key_size` (RSA) oder `elliptic_curve` (ECDSA) tragen. Ist die Überschreibung vorhanden, hat sie Vorrang; andernfalls gilt der globale Standardwert. Die Standardwerte `rsa`/`2048` spiegeln den impliziten certbot-Standard wider, den CertMate vor der Einführung dieser Einstellung verwendete; aktualisierte Installationen sehen daher keine Änderung, sofern der Betreiber nichts anderes wählt.

Erneuerungen behalten stets die Form bei, die zum Zeitpunkt der Erstellung gültig war: certbot schreibt `--key-type`, `--rsa-key-size` und `--elliptic-curve` beim ersten Ausstellen in seine eigene `renewal/<domain>.conf`, und `certbot renew --cert-name <domain>` verwendet diese Werte automatisch wieder.

---

## API-Endpoints

### Server-Zertifikate

| Methode | Endpoint | Zweck |
|--------|----------|---------|
| GET | `/api/health` | Statusprüfung |
| GET | `/api/certificates` | Alle Zertifikate auflisten |
| POST | `/api/certificates` | Neues Zertifikat erstellen |
| GET | `/api/certificates/{domain}` | Zertifikatsinformationen abrufen |
| POST | `/api/certificates/{domain}/renew` | Zertifikat erneuern |
| GET | `/api/certificates/{domain}/download` | Als ZIP herunterladen |
| GET | `/{domain}/tls` | Direkter Fullchain-Download |

### Client-Zertifikate

| Methode | Endpoint | Zweck |
|--------|----------|---------|
| POST | `/api/client-certs/create` | Zertifikat erstellen |
| GET | `/api/client-certs` | Mit Filtern auflisten |
| GET | `/api/client-certs/{id}` | Metadaten abrufen |
| GET | `/api/client-certs/{id}/download/{type}` | Zertifikat/Schlüssel/CSR herunterladen |
| POST | `/api/client-certs/{id}/revoke` | Zertifikat sperren |
| POST | `/api/client-certs/{id}/renew` | Zertifikat erneuern |
| GET | `/api/client-certs/stats` | Statistiken |
| POST | `/api/client-certs/batch` | CSV-Massenimport |
| GET | `/api/ocsp/status/{serial}` | OCSP-Status |
| GET | `/api/crl/download/{format}` | CRL herunterladen |

---

## Technologie-Stack

| Schicht | Technologien |
|-------|-------------|
| **Backend** | Python 3.9+, Flask, Flask-RESTX, APScheduler, Certbot |
| **Frontend** | HTML5, Tailwind CSS, Vanilla JavaScript, Font Awesome |
| **Cloud-SDKs** | Azure SDK, boto3, hvac, infisical-python |
| **Kryptografie** | cryptography (OpenSSL), certbot-Plugins |
| **Deployment** | Docker, Docker Compose, Gunicorn, systemd |

---

## Bekannte Einschränkungen

1. **Nur Certbot für Server-Zertifikate**: Ausschließlich DNS-01-ACME-Challenges
2. **Domain-zentrierter Server-Speicher**: Ein Zertifikat pro Domain-Verzeichnis
3. **Keine Datenbank**: Einzelne JSON-Datei für die Konfiguration
4. **Schlüsselverwendung bei Server-Zertifikaten**: Keine Kontrolle über keyUsage/extendedKeyUsage-Erweiterungen

---

# Architektur der Client-Zertifikate

## Systemüberblick

```

 Web UI Layer 
 (/client-certificates web dashboard) 

 
 API Layer 
 (/api/client-certs, /api/ocsp, /api/crl) 
 (REST endpoints with Flask-RESTX) 

 
 Managers Layer 
 
 ClientCertificateManager (lifecycle + metadata) 
 OCSPResponder (certificate status queries) 
 CRLManager (revocation list generation) 
 AuditLogger (operation tracking) 
 SimpleRateLimiter (request throttling) 
 

 
 Core Modules Layer 
 
 PrivateCAGenerator (CA management) 
 CSRHandler (CSR validation & creation) 
 ClientCertificateManager (cert operations) 
 OCSPResponder (status responses) 
 CRLManager (revocation lists) 
 AuditLogger (logging) 
 RateLimitConfig/SimpleRateLimiter (limiting) 
 

 
 Cryptography & Storage Layer 
 
 Cryptography Library (OpenSSL) 
 File System Storage (data/certs/) 
 Storage Backends (Azure, AWS, Vault, etc) 
 

```

---

## Kernkomponenten

### 1. PrivateCAGenerator (`modules/core/private_ca.py`)

**Zweck**: Die selbst-signierte Zertifizierungsstelle erzeugen und verwalten

**Hauptfunktionen**:
- Erzeugt 4096-Bit-RSA-Schlüssel für die CA
- Gültigkeitsdauer von 10 Jahren
- Selbst-signierte Zertifikate mit korrekten Erweiterungen
- Sicherungs- und Wiederherstellungsfunktion der CA
- CRL-Signierfähigkeit

**Erstellte Dateien**:
- `data/certs/ca/ca.crt` — CA-Zertifikat (PEM)
- `data/certs/ca/ca.key` — Privater CA-Schlüssel (PEM, Berechtigungen 0600)
- `data/certs/ca/ca_metadata.json` — CA-Metadaten
- `data/certs/ca/crl.pem` — Zertifikats-Sperrliste

**Hauptmethoden**:
```python
initialize() # Initialize or load existing CA
sign_certificate_request() # Sign a CSR
generate_crl() # Generate CRL from revoked serials
get_crl_pem() # Get CRL in PEM format
```

---

### 2. CSRHandler (`modules/core/csr_handler.py`)

**Zweck**: Certificate Signing Requests validieren, analysieren und erstellen

**Hauptfunktionen**:
- Neue CSRs mit privaten Schlüsseln erstellen (2048 oder 4096 Bit)
- PEM-kodierte CSRs validieren
- CSR-Informationen extrahieren (CN, Org, E-Mail, SAN usw.)
- Unterstützung für Subject Alternative Names (SANs)
- CSR- und Schlüsselpaare auf Disk speichern

**Hauptmethoden**:
```python
create_csr() # Create new CSR with private key
validate_csr_pem() # Validate and load CSR from PEM
get_csr_info() # Extract information from CSR
save_csr_and_key() # Save CSR and key to files
```

---

### 3. ClientCertificateManager (`modules/core/client_certificates.py`)

**Zweck**: Vollständiges Lebenszyklusmanagement von Client-Zertifikaten

**Hauptfunktionen**:
- Zertifikate erstellen (CA-signiert oder per CSR)
- Zertifikate auflisten/filtern (nach Verwendungszweck, Status, Suche)
- Zertifikate mit Audit-Trail sperren
- Zertifikate erneuern (gleicher CN, neue Seriennummer)
- Automatische Erneuerungsplanung
- Metadatenspeicherung (JSON pro Zertifikat)
- Unterstützung von 30.000+ gleichzeitigen Zertifikaten

**Speicherstruktur**:
```
data/certs/client/
 api-mtls/ # Certificates for API mTLS
 cert-001/
 cert.crt
 cert.key
 cert.csr
 metadata.json
 vpn/ # Certificates for VPN
 cert-002/
 ...
 other/ # Other usage types
 ...
```

**Metadatenstruktur** (JSON):
```json
{
 "type": "client_certificate",
 "identifier": "cert-001",
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "country": "US",
 "state": "California",
 "locality": "San Francisco",
 "serial_number": "12345678901234567890",
 "key_usage": ["digitalSignature", "keyEncipherment"],
 "extended_key_usage": ["serverAuth", "clientAuth"],
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "cert_usage": "api-mtls",
 "notes": "Production certificate",
 "revocation": {
 "revoked": false,
 "revoked_at": null,
 "reason_revoked": null
 },
 "renewal": {
 "renewal_enabled": true,
 "renewal_threshold_days": 30,
 "last_renewed_at": null
 }
}
```

**Hauptmethoden**:
```python
create_client_certificate() # Create new certificate
list_client_certificates() # List with optional filters
get_certificate_metadata() # Get cert metadata
get_certificate_file() # Get cert/key/csr file
revoke_certificate() # Revoke with reason
renew_certificate() # Renew certificate
check_renewals() # Auto-renewal check
get_statistics() # Get usage statistics
```

---

### 4. OCSPResponder (`modules/core/ocsp_crl.py`)

**Zweck**: Antworten gemäß dem Online Certificate Status Protocol (OCSP) bereitstellen

**Hauptfunktionen**:
- Zertifikatsstatus abfragen (good/revoked/unknown)
- OCSP-Antworten erzeugen
- Statusabfragen in Echtzeit
- Unterstützung mehrerer Statustypen

**Status-Werte**:
- `good` — Zertifikat ist gültig
- `revoked` — Zertifikat wurde gesperrt
- `unknown` — Zertifikat nicht gefunden

**Hauptmethoden**:
```python
get_cert_status() # Get certificate status
generate_ocsp_response() # Generate OCSP response
```

**Antwortformat**:
```json
{
 "response_status": "successful",
 "certificate_status": "good|revoked|unknown",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z",
 "next_update": null,
 "responder_name": "CertMate OCSP Responder",
 "revocation_time": null,
 "revocation_reason": null
}
```

---

### 5. CRLManager (`modules/core/ocsp_crl.py`)

**Zweck**: Zertifikats-Sperrlisten erzeugen und verteilen

**Hauptfunktionen**:
- CRL mit allen gesperrten Zertifikaten erzeugen
- Verteilung in PEM- und DER-Format
- CRL-Metadaten und -Informationen speichern
- Automatische CRL-Aktualisierungen

**Hauptmethoden**:
```python
get_revoked_serials() # Get revoked certificate serials
update_crl() # Generate/update CRL
get_crl_pem() # Get CRL in PEM format
get_crl_der() # Get CRL in DER format
get_crl_info() # Get CRL metadata
```

---

### 6. AuditLogger (`modules/core/audit.py`)

**Zweck**: Alle Zertifikatsoperationen zur Compliance und zur Fehleranalyse protokollieren

**Hauptfunktionen**:
- Protokollierung im JSON-Format
- Persistente Audit-Datei
- Verfolgung von Operationen, Benutzern und IP-Adressen
- Abfrage von Einträgen nach Ressource oder Zeitraum

**Protokollformat**:
```json
{
 "timestamp": "2024-10-30T18:00:00Z",
 "operation": "create|revoke|renew|download|batch_import",
 "resource_type": "certificate|endpoint",
 "resource_id": "cert-001",
 "status": "success|failure|denied",
 "user": "admin@example.com",
 "ip_address": "192.168.1.1",
 "details": {},
 "error": null
}
```

**Protokolldatei**: `logs/audit/certificate_audit.log`

**Hauptmethoden**:
```python
log_certificate_created() # Log cert creation
log_certificate_revoked() # Log revocation
log_certificate_renewed() # Log renewal
log_certificate_downloaded() # Log downloads
log_batch_operation() # Log batch operations
log_api_request() # Log API requests
get_recent_entries() # Get latest audit entries
get_entries_by_resource() # Get entries for a resource
```

---

### 7. Rate Limiting (`modules/core/rate_limit.py`)

**Zweck**: API durch Request-Rate-Limiting vor Missbrauch schützen

**Konfiguration**:
- Standard: 100 Req/min
- Zertifikatserstellung: 30 Req/min (aufwendig)
- Batch-Operationen: 10 Req/min (sehr aufwendig)
- OCSP-Status: 200 Req/min (kostengünstig)
- CRL-Download: 60 Req/min

**Hauptklassen**:
```python
RateLimitConfig # Configuration holder
SimpleRateLimiter # In-memory limiter
rate_limit_decorator # Flask endpoint decorator
```

**Antwort bei überschrittenem Limit**:
```json
{
 "error": "Rate limit exceeded",
 "message": "Too many requests. Please try again later.",
 "retry_after": 60
}
```

HTTP-Status: `429 Too Many Requests`

---

## Datenfluss

### Ablauf der Zertifikatserstellung

```
User/API Request
 ↓
ClientCertificateManager.create_client_certificate()
 Generate CSR (or accept provided CSR)
 Sign CSR with private CA
 Create metadata.json
 Store cert/key/csr files
 Log in audit trail
 Return cert data
 ↓
Response to User
```

### Ablauf der Zertifikatssperrung

```
User/API Request (revoke endpoint)
 ↓
ClientCertificateManager.revoke_certificate()
 Load certificate metadata
 Update revocation status
 Save updated metadata
 Log in audit trail
 Trigger CRL update
 Return success
 ↓
Response to User
```

### OCSP-Abfrageablauf

```
Client OCSP Request (serial number)
 ↓
OCSPResponder.get_cert_status()
 Search certificate by serial
 Check revocation status
 Return status (good/revoked/unknown)
 ↓
OCSPResponder.generate_ocsp_response()
 Format OCSP response
 Add timestamps
 Return response
 ↓
Response to Client
```

---

## Speicherarchitektur

### Verzeichnisstruktur

```
data/certs/
 ca/ # Certificate Authority
 ca.crt # CA certificate (public)
 ca.key # CA private key (0600)
 ca_metadata.json # CA metadata
 crl.pem # Certificate Revocation List

 client/ # Client certificates
 api-mtls/ # API mTLS certificates
 cert-001/
 cert.crt
 cert.key
 cert.csr
 metadata.json
 ...
 vpn/ # VPN certificates
 ...
 other/ # Other usage types
 ...

 crl/ # CRL storage
 (generated CRLs)
```

### Metadaten-Dateien

Jedes Zertifikat besitzt eine `metadata.json`-Datei mit folgenden Inhalten:
- Zertifikatsidentifikation (CN, Seriennummer, Fingerabdruck)
- Inhaberinformationen (Organisation, E-Mail, Standort)
- Gültigkeitszeiträume
- Sperrstatus und -verlauf
- Erneuerungskonfiguration
- Benutzerdefinierte Notizen

---

## Sicherheitsmodell

### Schlüsselschutz

- **Dateiberechtigungen**: 0600 (nur Lesen/Schreiben für den Eigentümer)
- **Schlüsselformat**: PEM im traditionellen OpenSSL-Format
- **Keine Schlüsselverschlüsselung**: Schlüssel werden verschlüsselt im Ruhezustand gespeichert, wenn Storage-Backends verwendet werden

### Zertifikatssignierung

- **Signaturalgorithmus**: SHA256withRSA
- **Schlüsselgröße**: 4096-Bit RSA für die CA, 2048/4096 Bit für Clients
- **Gültigkeit**: Konfigurierbar (Standard 1 Jahr für Client-Zertifikate)

### Zugangskontrolle

- **Authentifizierung**: Bearer-Token auf allen API-Endpoints
- **Autorisierung**: Token-basiert (erweiterbar mit Rollen)
- **Rate Limiting**: Schutz pro Endpoint

### Audit-Trail

- Alle Operationen mit Zeitstempel protokolliert
- Benutzer- und IP-Adress-Verfolgung
- Unveränderliche Audit-Protokolldatei
- Für Compliance abfragbar

---

## Skalierbarkeit

### Zertifikatsspeicherung

- **Lineare Skalierbarkeit**: Verzeichnisbasierter Speicher
- **Kapazität**: Getestet mit 30.000+ Zertifikaten
- **Performance**: Effiziente O(n)-Verzeichnis-Scans

### API-Performance

- **Rate Limiting**: Verhindert Ressourcenerschöpfung
- **Zustandsloses Design**: Kann in mehreren Instanzen betrieben werden
- **Batch-Operationen**: Verarbeitet 100–30.000 Zertifikate pro Anfrage

### Automatische Erneuerung

- **Geplant**: Täglich um 3 Uhr (konfigurierbar)
- **Schwellenwert**: 30 Tage vor Ablauf (konfigurierbar)
- **Fehlertolerant**: Setzt bei Fehlern fort und protokolliert zur Überprüfung

---

## Deployment-Überlegungen

### Mindestanforderungen

- Python 3.9+
- 100 MB Speicherplatz für CA und initiale Zertifikate
- 50 MB für Audit-Protokolle pro 1 Mio. Operationen
- Geringer Speicherbedarf

### Empfehlungen für den Produktionsbetrieb

- Storage-Backend (Azure, AWS, Vault) für Hochverfügbarkeit verwenden
- Audit-Protokollierung zur Compliance aktivieren
- Rate Limiting entsprechend der Last konfigurieren
- Regelmäßige CRL-Aktualisierungen (täglich oder bei Sperrungen)
- CA-Schlüssel und Metadaten sichern
- Audit-Protokolle auf verdächtige Aktivitäten überwachen

### Hochverfügbarkeit

Für Multi-Instanz-Deployments:
1. Gemeinsames Storage-Backend für Zertifikate verwenden
2. Audit-Protokolle an einen zentralen Speicherort synchronisieren
3. Load Balancer mit Sticky Sessions einsetzen
4. Rate-Limiting-Zähler instanzübergreifend überwachen

---

## Integrationspunkte

### Mit dem CertMate-Hauptsystem

- Verwendet bestehende CertMate-Storage-Backends
- In die Manager von app.py integriert
- Teil der Flask-RESTX-API-Struktur
- Mit APScheduler geplant

### Externe Systeme

- Kann Zertifikate über die API exportieren
- Kann den Status über OCSP abfragen
- Kann die CRL zur Validierung abrufen
- Unterstützt Webhook/Callback-Integration (zukünftig)

---

## Zukünftige Erweiterbarkeit

### Geplante Verbesserungen

1. **CA-Passwortschutz** — CA-Schlüssel mit Passwort verschlüsseln
2. **Erweitertes Audit** — Rollenbasierte Zugriffskontrolle
3. **Webhook-Benachrichtigungen** — Bei Zertifikatsereignissen
4. **Zertifikatssignierung** — CSRs von externen Quellen akzeptieren
5. **Hardware-Token** — PKCS#11-Unterstützung für HSMs

### Erweiterungspunkte

1. **Storage-Backends** — Unterstützt bereits mehrere Backends
2. **Audit-Ziele** — Kann Audit-Protokolle an externe Systeme senden
3. **API-Middleware** — Benutzerdefinierte Authentifizierung/Autorisierung hinzufügen
4. **Benachrichtigungssystem** — Integration mit Alarmsystemen

---

## Überwachung und Beobachtbarkeit

### Wichtige Metriken

- Zertifikatsanzahl (gesamt, aktiv, gesperrt, demnächst ablaufend)
- Performance der API-Endpoints
- Rate-Limiting-Verstöße
- Volumen der Audit-Protokolle
- Erfolgs-/Fehlerquote bei automatischen Erneuerungen

### Statusprüfungen

- Verfügbarkeit der CA
- Funktionsfähigkeit des Audit-Loggers
- Reaktionsfähigkeit des Rate Limiters
- Status der CRL-Erzeugung

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [Schnellstart →](./guide.md) • [API-Referenz →](./api.md)

</div>
