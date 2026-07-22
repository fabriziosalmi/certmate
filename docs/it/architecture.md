# Architettura di CertMate

Questo documento descrive l'architettura completa di CertMate — sia il sistema principale per i certificati server che il sottosistema per i certificati client.

---

## Indice

- [Architettura del sistema principale](#architettura-del-sistema-principale)
- [Diagramma ad alto livello](#diagramma-ad-alto-livello)
- [Classi di gestione (Manager)](#classi-di-gestione-managers)
- [Flusso di creazione del certificato](#flusso-di-creazione-del-certificato)
- [Architettura di archiviazione](#architettura-di-archiviazione)
- [Struttura di configurazione](#struttura-di-configurazione)
- [Endpoint API](#endpoint-api)
- [Stack tecnologico](#stack-tecnologico)
- [Architettura dei certificati client](#architettura-dei-certificati-client)

---

## Architettura del sistema principale

CertMate è un sistema modulare ed estensibile per la gestione di certificati SSL/TLS costruito con Python/Flask. Supporta molteplici provider CA, oltre due dozzine di provider DNS e backend di archiviazione intercambiabili.

**Informazioni principali:**
- **Linguaggio**: Python 3.9+ (Flask, Flask-RESTX)
- **Archiviazione**: filesystem locale come impostazione predefinita + 4 backend cloud (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical)
- **Provider CA**: Let's Encrypt, DigiCert ACME, CA privata
- **Provider DNS**: oltre due dozzine supportati (Cloudflare, AWS Route53, Azure, Google e altri — vedere [Provider DNS](./dns-providers.md) per l'elenco completo)
- **API**: REST con Swagger/OpenAPI tramite Flask-RESTX
- **Tipi di certificati attuali**: TLS lato server (DV, OV, EV)

---

## Diagramma ad alto livello

```
┌─────────────────────────────────────────────────────┐
│              Applicazione CertMate                  │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │           Livello Web (Flask)                  │  │
│  │  Dashboard    Impostazioni    Aiuto    Cert. Cl│  │
│  └────────────────────┬──────────────────────────┘  │
│                       ↓                             │
│  ┌──────────────────┐   ┌────────────────────────┐  │
│  │  API REST         │   │  Route Web             │  │
│  │  /api/certificates│   │  /api/web/certificates │  │
│  │  /api/client-certs│   │  /client-certificates  │  │
│  └────────┬─────────┘   └────────┬───────────────┘  │
│           └──────────┬───────────┘                   │
│                      ↓                               │
│  ┌───────────────────────────────────────────────┐  │
│  │     Livello Manager (Logica applicativa)       │  │
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
│  │          Livello di esecuzione                 │  │
│  │  Certbot (cert server via DNS-01 ACME)        │  │
│  │  PrivateCA (cert client via firma diretta)    │  │
│  └────────────────────┬──────────────────────────┘  │
│                       ↓                             │
│  ┌───────────────────────────────────────────────┐  │
│  │     Livello di archiviazione (Backend plug.)  │  │
│  │  Local FS │ Azure KV │ AWS SM │ Vault │ Infis │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Classi di gestione (Managers)

```
CertMateApp (applicazione principale)
  ├── FileOperations          # I/O file, backup
  ├── SettingsManager         # Caricamento/salvataggio settings.json
  ├── AuthManager             # Validazione token
  ├── CertificateManager      # Crea/rinnova/info (cert server)
  ├── CAManager               # Configurazione provider CA, costruzione certbot
  ├── DNSManager              # Account provider DNS
  ├── CacheManager            # Cache di deployment
  ├── StorageManager          # Astrazione dei backend
  ├── ClientCertificateManager # Ciclo di vita dei certificati client
  ├── PrivateCAGenerator      # Gestione della CA auto-firmata
  ├── OCSPResponder           # Interrogazioni sullo stato dei certificati
  ├── CRLManager              # Generazione delle liste di revoca
  └── AuditLogger             # Tracciamento delle operazioni
```

---

## Flusso di creazione del certificato

### Certificati server (via Certbot + ACME)

```
1. L'utente invia: dominio, email, provider DNS, provider CA
2. Validazione degli input (formato del dominio, email, esistenza del provider)
3. Recupero della configurazione CA (URL ACME, credenziali EAB se DigiCert)
4. Recupero della configurazione DNS (credenziali account dalle impostazioni)
5. Creazione della directory: certificates/{dominio}/
6. Costruzione del comando certbot:
   certbot certonly --non-interactive --agree-tos
     --server {acme_url}
     --email {email}
     --{dns_plugin} --{dns_plugin}-credentials {cred_file}
     --{dns_plugin}-propagation-seconds {timeout}
     --eab-kid/--eab-hmac-key (se richiesto)
     -d {dominio}
7. Creazione del file temporaneo delle credenziali DNS (permessi 600)
8. Esecuzione di certbot (timeout di 30 minuti)
9. Risoluzione dei symlink, copia dei file del certificato nella directory radice del dominio
10. Archiviazione tramite il backend configurato + creazione di metadata.json
11. Pulizia del file delle credenziali
```

### Certificati client (via CA privata)

```
1. L'utente invia: common_name, email, organizzazione, cert_usage
2. Inizializzazione o caricamento della CA esistente (RSA 4096 bit)
3. Generazione del CSR (o accettazione di un CSR fornito)
4. Firma del CSR con la CA privata
5. Archiviazione dei file cert/chiave/csr + metadata.json
6. Registrazione nella traccia di audit
```

---

## Architettura di archiviazione

### Certificati server

```
certificates/
  example.com/
    cert.pem          # Certificato server
    chain.pem         # Catena CA intermedia
    fullchain.pem     # cert + catena
    privkey.pem       # Chiave privata (permessi 600)
    metadata.json     # Metadati del certificato
```

### Certificati client

```
data/certs/
  ca/
    ca.crt            # Certificato CA
    ca.key            # Chiave privata CA (permessi 600)
    ca_metadata.json  # Metadati CA
    crl.pem           # Lista di revoca dei certificati
  client/
    api-mtls/         # Certificati per tipo di utilizzo
      cert-001/
        cert.crt
        cert.key
        cert.csr
        metadata.json
    vpn/
      cert-002/
        ...
```

### Backend di archiviazione

Tutti i backend implementano `CertificateStorageBackend`:

| Backend | Posizione di archiviazione |
|---------|---------------------------|
| **Filesystem locale** | `certificates/{dominio}/` (predefinito) |
| **Azure Key Vault** | Secret, oggetti Certificate nativi, o entrambi — vedere sotto |
| **AWS Secrets Manager** | AWS Secrets Manager |
| **HashiCorp Vault** | Vault KV v1/v2 |
| **Infisical** | Secret Infisical |

#### Azure Key Vault — modalità di archiviazione

Il backend Azure Key Vault può conservare i certificati come Secret (impostazione predefinita), come oggetti Certificate nativi, o entrambi, controllato da `certificate_storage.azure_keyvault.storage_mode` in `settings.json`.

| Modalità | Scrive Secret | Scrive oggetto Certificate | Quando utilizzarla |
|---|---|---|---|
| `secrets` (predefinita) | sì | no | Comportamento retrocompatibile. Ogni `cert.pem` / `chain.pem` / `fullchain.pem` / `privkey.pem` e i metadati sono archiviati come Secret di Key Vault separati. |
| `certificate` | no | sì | Collegamento diretto da App Service, Application Gateway, Front Door, API Management, AKS Ingress, ecc. Il cert + catena + chiave privata vengono importati come singolo oggetto `Certificate` PKCS12 con `issuer_name="Unknown"` in modo che Key Vault non tenti di rinnovarlo. |
| `both` | sì | sì | Configurazioni transitorie o con consumatori misti. Le letture preferiscono sempre il percorso dei Secret (meno costoso). |

Un'azione manuale **Backfill Certificate objects** nel pannello delle impostazioni di archiviazione (`POST /api/storage/azure-keyvault/backfill-certificates`) importa un oggetto Certificate per ogni dominio che esiste già nel vault come Secret ma non ne ha ancora uno. Gli oggetti Certificate esistenti vengono ignorati. L'endpoint accetta un parametro di query opzionale `?limit=N` per limitare il numero di domini elaborati per chiamata; i vault di grandi dimensioni possono paginare chiamando ripetutamente fino a quando la risposta segnala `0` rimanenti.

##### Nota di sicurezza — gli oggetti Certificate espongono la chiave privata tramite l'API Secrets

Quando Key Vault importa un oggetto Certificate PKCS12, crea anche un **Secret** associato con lo stesso nome il cui valore è il PFX completo (inclusa la chiave privata). Questo è il comportamento previsto in Azure: è il modo documentato con cui le estensioni VM e App Service consumano il certificato, e qualsiasi principal con `Secrets/Get` sul vault può quindi scaricare la chiave privata — *il permesso `Get` sui Certificate da solo non è sufficiente per estrarre la chiave privata, ma `Secrets/Get` lo è*. Gli operatori che eseguono CertMate in modalità `certificate` o `both` devono limitare `Secrets/Get` con attenzione e preferire Azure RBAC rispetto alle policy di accesso al vault per un controllo più granulare. Vedere [Microsoft Learn — Certificati in Key Vault](https://learn.microsoft.com/azure/key-vault/certificates/about-certificates) per il modello completo.

##### Permessi del Service Principal

| Modalità | Permessi richiesti sul vault |
|---|---|
| `secrets` | Secrets `Get/Set/List/Delete` |
| `certificate` / `both` | Aggiunge Certificates `Get/List/Import/Delete` e mantiene Secrets `Get/List` (Key Vault espone il PFX importato, inclusa la chiave privata, solo tramite il Secret con lo stesso nome dell'oggetto Certificate). |

---

## Struttura di configurazione

Tutte le impostazioni sono archiviate in `data/settings.json`:

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

### Tipo/dimensione della chiave del certificato

Tre chiavi di primo livello controllano la forma della chiave pubblica dei certificati di nuova emissione:

| Chiave | Valori | Si applica quando |
|---|---|---|
| `default_key_type` | `rsa` (predefinito) / `ecdsa` | sempre |
| `default_key_size` | `2048` (predefinito) / `3072` / `4096` | `default_key_type == "rsa"` |
| `default_elliptic_curve` | `secp256r1` (predefinito) / `secp384r1` | `default_key_type == "ecdsa"` |

È supportato un override per singolo certificato: ogni voce in `domains` può includere un `key_type` opzionale più `key_size` (RSA) o `elliptic_curve` (ECDSA). Quando l'override è presente, ha la precedenza; altrimenti si applica il valore globale predefinito. I valori predefiniti `rsa`/`2048` rispecchiano il default implicito di certbot che CertMate applicava prima dell'introduzione di questa impostazione, pertanto le installazioni aggiornate non subiscono alcuna variazione a meno che l'operatore non scelga qualcos'altro.

I rinnovi preservano sempre la forma in uso al momento della creazione: certbot persiste `--key-type`, `--rsa-key-size` e `--elliptic-curve` nel proprio `renewal/<dominio>.conf` durante la prima emissione, e `certbot renew --cert-name <dominio>` riutilizza automaticamente quei valori.

---

## Endpoint API

### Certificati server

| Metodo | Endpoint | Scopo |
|--------|----------|-------|
| GET | `/api/health` | Verifica dello stato |
| GET | `/api/certificates` | Elenca tutti i certificati |
| POST | `/api/certificates` | Crea un nuovo certificato |
| GET | `/api/certificates/{domain}` | Ottieni informazioni sul certificato |
| POST | `/api/certificates/{domain}/renew` | Rinnova il certificato |
| GET | `/api/certificates/{domain}/download` | Scarica come ZIP |
| GET | `/{domain}/tls` | Download diretto della fullchain |

### Certificati client

| Metodo | Endpoint | Scopo |
|--------|----------|-------|
| POST | `/api/client-certs/create` | Crea un certificato |
| GET | `/api/client-certs` | Elenca con filtri |
| GET | `/api/client-certs/{id}` | Ottieni i metadati |
| GET | `/api/client-certs/{id}/download/{type}` | Scarica cert/chiave/csr |
| POST | `/api/client-certs/{id}/revoke` | Revoca il certificato |
| POST | `/api/client-certs/{id}/renew` | Rinnova il certificato |
| GET | `/api/client-certs/stats` | Statistiche |
| POST | `/api/client-certs/batch` | Importazione CSV in batch |
| GET | `/api/ocsp/status/{serial}` | Stato OCSP |
| GET | `/api/crl/download/{format}` | Scarica la CRL |

---

## Stack tecnologico

| Livello | Tecnologie |
|---------|-----------|
| **Backend** | Python 3.9+, Flask, Flask-RESTX, APScheduler, Certbot |
| **Frontend** | HTML5, Tailwind CSS, Vanilla JavaScript, Font Awesome |
| **SDK Cloud** | Azure SDK, boto3, hvac, infisical-python |
| **Crittografia** | cryptography (OpenSSL), plugin certbot |
| **Deployment** | Docker, Docker Compose, Gunicorn, systemd |

---

## Limitazioni principali

1. **Solo Certbot per i certificati server**: esclusivamente challenge DNS-01 ACME
2. **Archiviazione server centrata sul dominio**: un certificato per directory di dominio
3. **Nessun database**: un singolo file JSON per la configurazione
4. **Utilizzo delle chiavi nei certificati server**: nessun controllo sulle estensioni keyUsage/extendedKeyUsage

---

# Architettura dei certificati client

## Panoramica del sistema

```

 Livello Interfaccia Web
 (dashboard web /client-certificates)

 

 Livello API
 (/api/client-certs, /api/ocsp, /api/crl)
 (endpoint REST con Flask-RESTX)

 

 Livello Manager

 ClientCertificateManager (ciclo di vita + metadati)
 OCSPResponder (interrogazioni sullo stato dei certificati)
 CRLManager (generazione delle liste di revoca)
 AuditLogger (tracciamento delle operazioni)
 SimpleRateLimiter (limitazione delle richieste)

 

 Livello Moduli principali

 PrivateCAGenerator (gestione CA)
 CSRHandler (validazione e creazione CSR)
 ClientCertificateManager (operazioni sui certificati)
 OCSPResponder (risposte di stato)
 CRLManager (liste di revoca)
 AuditLogger (registrazione)
 RateLimitConfig/SimpleRateLimiter (limitazione)

 

 Livello Crittografia e archiviazione

 Cryptography Library (OpenSSL)
 Archiviazione filesystem (data/certs/)
 Backend di archiviazione (Azure, AWS, Vault, ecc.)

```

---

## Componenti principali

### 1. PrivateCAGenerator (`modules/core/private_ca.py`)

**Scopo**: Generare e gestire la Certificate Authority auto-firmata

**Funzionalità principali**:
- Genera chiavi RSA a 4096 bit per la CA
- Periodo di validità di 10 anni
- Certificati auto-firmati con estensioni appropriate
- Funzionalità di backup e ripristino della CA
- Capacità di firma CRL

**File creati**:
- `data/certs/ca/ca.crt` — Certificato CA (PEM)
- `data/certs/ca/ca.key` — Chiave privata CA (PEM, permessi 0600)
- `data/certs/ca/ca_metadata.json` — Metadati CA
- `data/certs/ca/crl.pem` — Lista di revoca dei certificati

**Metodi principali**:
```python
initialize() # Inizializzare o caricare la CA esistente
sign_certificate_request() # Firmare un CSR
generate_crl() # Generare la CRL dai numeri seriali revocati
get_crl_pem() # Ottenere la CRL in formato PEM
```

---

### 2. CSRHandler (`modules/core/csr_handler.py`)

**Scopo**: Validare, analizzare e creare Certificate Signing Request

**Funzionalità principali**:
- Crea nuovi CSR con chiavi private (2048 o 4096 bit)
- Valida i CSR codificati in PEM
- Estrae le informazioni dal CSR (CN, Org, Email, SAN, ecc.)
- Supporto per i Subject Alternative Name (SAN)
- Salva il CSR e le coppie di chiavi su disco

**Metodi principali**:
```python
create_csr() # Creare un nuovo CSR con chiave privata
validate_csr_pem() # Validare e caricare un CSR da PEM
get_csr_info() # Estrarre informazioni da un CSR
save_csr_and_key() # Salvare CSR e chiave in file
```

---

### 3. ClientCertificateManager (`modules/core/client_certificates.py`)

**Scopo**: Gestione completa del ciclo di vita dei certificati client

**Funzionalità principali**:
- Crea certificati (firmati dalla CA o tramite CSR)
- Elenca/filtra i certificati (per utilizzo, stato, ricerca)
- Revoca certificati con traccia di audit
- Rinnova certificati (stesso CN, nuovo numero seriale)
- Pianificazione del rinnovo automatico
- Archiviazione dei metadati (JSON per certificato)
- Supporto per 30.000+ certificati simultanei

**Struttura di archiviazione**:
```
data/certs/client/
 api-mtls/ # Certificati per API mTLS
 cert-001/
 cert.crt
 cert.key
 cert.csr
 metadata.json
 vpn/ # Certificati per VPN
 cert-002/
 ...
 other/ # Altri tipi di utilizzo
 ...
```

**Struttura dei metadati** (JSON):
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

**Metodi principali**:
```python
create_client_certificate() # Creare un nuovo certificato
list_client_certificates() # Elencare con filtri opzionali
get_certificate_metadata() # Ottenere i metadati del certificato
get_certificate_file() # Ottenere il file cert/chiave/csr
revoke_certificate() # Revocare con motivazione
renew_certificate() # Rinnovare il certificato
check_renewals() # Verifica dei rinnovi automatici
get_statistics() # Ottenere le statistiche di utilizzo
```

---

### 4. OCSPResponder (`modules/core/ocsp_crl.py`)

**Scopo**: Fornire risposte al protocollo Online Certificate Status Protocol (OCSP)

**Funzionalità principali**:
- Interroga lo stato del certificato (good/revoked/unknown)
- Genera risposte OCSP
- Ricerche di stato in tempo reale
- Supporto per più tipi di stato

**Stati**:
- `good` — Il certificato è valido
- `revoked` — Il certificato è stato revocato
- `unknown` — Certificato non trovato

**Metodi principali**:
```python
get_cert_status() # Ottenere lo stato del certificato
generate_ocsp_response() # Generare la risposta OCSP
```

**Formato della risposta**:
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

**Scopo**: Generare e distribuire le Certificate Revocation List

**Funzionalità principali**:
- Genera la CRL con tutti i certificati revocati
- Distribuisce nei formati PEM e DER
- Archivia i metadati e le informazioni della CRL
- Aggiornamenti automatici della CRL

**Metodi principali**:
```python
get_revoked_serials() # Ottenere i numeri seriali dei certificati revocati
update_crl() # Generare/aggiornare la CRL
get_crl_pem() # Ottenere la CRL in formato PEM
get_crl_der() # Ottenere la CRL in formato DER
get_crl_info() # Ottenere i metadati della CRL
```

---

### 6. AuditLogger (`modules/core/audit.py`)

**Scopo**: Tracciare tutte le operazioni sui certificati per la conformità e il debug

**Funzionalità principali**:
- Registrazione in formato JSON
- File di audit persistente
- Tracciamento di operazioni, utenti, indirizzi IP
- Interrogazione delle voci per risorsa o periodo

**Formato del registro**:
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

**File di registro**: `logs/audit/certificate_audit.log`

**Metodi principali**:
```python
log_certificate_created() # Registrare la creazione del certificato
log_certificate_revoked() # Registrare la revoca
log_certificate_renewed() # Registrare il rinnovo
log_certificate_downloaded() # Registrare i download
log_batch_operation() # Registrare le operazioni in batch
log_api_request() # Registrare le richieste API
get_recent_entries() # Ottenere le ultime voci di audit
```

---

### 7. Rate Limiting (`modules/core/rate_limit.py`)

**Scopo**: Proteggere l'API dagli abusi con la limitazione del tasso di richieste

**Configurazione**:
- Predefinito: 100 req/min
- Creazione certificato: 30 req/min (costoso)
- Operazioni in batch: 10 req/min (molto costoso)
- Stato OCSP: 200 req/min (economico)
- Download CRL: 60 req/min

**Classi principali**:
```python
RateLimitConfig # Contenitore di configurazione
SimpleRateLimiter # Limitatore in memoria
rate_limit_decorator # Decoratore per endpoint Flask
```

**Risposta al superamento del limite**:
```json
{
 "error": "Rate limit exceeded",
 "message": "Too many requests. Please try again later.",
 "retry_after": 60
}
```

Stato HTTP: `429 Too Many Requests`

---

## Flusso dei dati

### Flusso di creazione del certificato

```
Richiesta Utente/API
 ↓
ClientCertificateManager.create_client_certificate()
 Generare il CSR (o accettare un CSR fornito)
 Firmare il CSR con la CA privata
 Creare metadata.json
 Archiviare i file cert/chiave/csr
 Registrare nella traccia di audit
 Restituire i dati del certificato
 ↓
Risposta all'Utente
```

### Flusso di revoca del certificato

```
Richiesta Utente/API (endpoint di revoca)
 ↓
ClientCertificateManager.revoke_certificate()
 Caricare i metadati del certificato
 Aggiornare lo stato di revoca
 Salvare i metadati aggiornati
 Registrare nella traccia di audit
 Avviare l'aggiornamento della CRL
 Restituire il successo
 ↓
Risposta all'Utente
```

### Flusso di interrogazione OCSP

```
Richiesta OCSP del client (numero seriale)
 ↓
OCSPResponder.get_cert_status()
 Ricercare il certificato per numero seriale
 Verificare lo stato di revoca
 Restituire lo stato (good/revoked/unknown)
 ↓
OCSPResponder.generate_ocsp_response()
 Formattare la risposta OCSP
 Aggiungere i timestamp
 Restituire la risposta
 ↓
Risposta al Client
```

---

## Architettura di archiviazione

### Struttura delle directory

```
data/certs/
  ca/                      # Certificate Authority
    ca.crt                 # Certificato CA (pubblico)
    ca.key                 # Chiave privata CA (0600)
    ca_metadata.json       # Metadati CA
    crl.pem                # Lista di revoca dei certificati

  client/                  # Certificati client
    api-mtls/              # Certificati API mTLS
      cert-001/
        cert.crt
        cert.key
        cert.csr
        metadata.json
      ...
    vpn/                   # Certificati VPN
      ...
    other/                 # Altri tipi di utilizzo
      ...

  crl/                     # Archiviazione CRL
    (CRL generate)
```

### File di metadati

Ogni certificato ha un file `metadata.json` contenente:
- Identificazione del certificato (CN, numero seriale, impronta digitale)
- Informazioni sul soggetto (Org, email, posizione)
- Date di validità
- Stato e cronologia di revoca
- Configurazione del rinnovo
- Note personalizzate

---

## Modello di sicurezza

### Protezione delle chiavi

- **Permessi dei file**: 0600 (lettura/scrittura solo per il proprietario)
- **Formato delle chiavi**: PEM nel formato tradizionale OpenSSL
- **Cifratura delle chiavi**: chiavi archiviate cifrate a riposo se si utilizzano backend di archiviazione

### Firma dei certificati

- **Algoritmo di firma**: SHA256withRSA
- **Dimensione della chiave**: RSA a 4096 bit per la CA, 2048/4096 bit per i client
- **Validità**: configurabile (predefinito 1 anno per i certificati client)

### Controllo degli accessi

- **Autenticazione**: Bearer token su tutti gli endpoint API
- **Autorizzazione**: basata su token (estendibile con ruoli)
- **Rate Limiting**: protezione per endpoint

### Traccia di audit

- Tutte le operazioni registrate con timestamp
- Tracciamento di utente e indirizzo IP
- File di registro di audit immutabile
- Interrogabile per la conformità

---

## Scalabilità

### Archiviazione dei certificati

- **Scalabilità lineare**: archiviazione basata su directory
- **Capacità**: testato con oltre 30.000 certificati
- **Prestazioni**: scansioni delle directory O(n) efficienti

### Prestazioni dell'API

- **Rate Limiting**: previene l'esaurimento delle risorse
- **Progettazione stateless**: può eseguire più istanze
- **Operazioni in batch**: gestisce da 100 a 30.000 certificati per richiesta

### Rinnovo automatico

- **Pianificato**: ogni giorno alle ore 3:00 (configurabile)
- **Soglia**: 30 giorni prima della scadenza (configurabile)
- **Progressivo**: continua in caso di errori, registra per la revisione

---

## Considerazioni sul deployment

### Requisiti minimi

- Python 3.9+
- 100 MB di spazio su disco per la CA e i certificati iniziali
- 50 MB per i registri di audit per milione di operazioni
- Basso utilizzo di memoria

### Raccomandazioni per la produzione

- Utilizzare un backend di archiviazione (Azure, AWS, Vault) per l'alta disponibilità
- Abilitare la registrazione di audit per la conformità
- Configurare il rate limiting in base al carico
- Aggiornamenti regolari della CRL (giornalieri o alla revoca)
- Effettuare il backup delle chiavi CA e dei metadati
- Monitorare i registri di audit per attività sospette

### Alta disponibilità

Per i deployment multi-istanza:
1. Utilizzare un backend di archiviazione condiviso per i certificati
2. Sincronizzare i registri di audit in una posizione centrale
3. Utilizzare un load balancer con sessioni persistenti
4. Monitorare i contatori di rate limiting tra le istanze

---

## Punti di integrazione

### Con il sistema principale di CertMate

- Utilizza i backend di archiviazione esistenti di CertMate
- Integrato nei manager di app.py
- Integrato nella struttura API Flask-RESTX
- Pianificato con APScheduler

### Sistemi esterni

- Può esportare certificati tramite API
- Può interrogare lo stato tramite OCSP
- Può recuperare la CRL per la validazione
- Supporta l'integrazione webhook/callback (futuro)

---

## Estensibilità futura

### Miglioramenti previsti

1. **Protezione con password della CA** — Cifrare le chiavi CA con password
2. **Audit avanzato** — Controllo degli accessi basato sui ruoli
3. **Notifiche webhook** — Per eventi sui certificati
4. **Firma di certificati** — Accettare CSR da fonti esterne
5. **Token hardware** — Supporto PKCS#11 per HSM

### Punti di estensione

1. **Backend di archiviazione** — Già supporta più backend
2. **Destinazioni di audit** — Può inviare i registri di audit a sistemi esterni
3. **Middleware API** — Aggiungere autenticazione/autorizzazione personalizzata
4. **Sistema di notifica** — Integrazione con sistemi di alerting

---

## Monitoraggio e osservabilità

### Metriche principali

- Conteggio dei certificati (totali, attivi, revocati, in scadenza)
- Prestazioni degli endpoint API
- Violazioni del rate limit
- Volume dei registri di audit
- Tasso di successo/fallimento dei rinnovi automatici

### Controlli di stato

- Disponibilità della CA
- Funzionamento del registro di audit
- Reattività del limitatore di velocità
- Stato di generazione della CRL

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Guida rapida →](./guide.md) • [Riferimento API →](./api.md)

</div>
