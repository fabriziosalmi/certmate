# Provider DNS

CertMate supporta un'ampia gamma di provider DNS per le challenge DNS-01 di Let's Encrypt tramite plugin certbot individuali. La lista completa si trova nella tabella seguente.

---

## Provider supportati

| Provider | Plugin | Credenziali richieste | Categoria |
|----------|--------|-----------------------|-----------|
| **Cloudflare** | `certbot-dns-cloudflare` | API Token | Cloud principale |
| **AWS Route53** | `certbot-dns-route53` | Access Key, Secret Key | Cloud principale |
| **Azure DNS** | `certbot-dns-azure` | Service Principal | Cloud principale |
| **Google Cloud DNS** | `certbot-dns-google` | Service Account JSON | Cloud principale |
| **PowerDNS** | `certbot-dns-powerdns` | URL API, Chiave API | Enterprise |
| **DNS Made Easy** | `certbot-dns-dnsmadeeasy` | Chiave API, Secret Key | Enterprise |
| **NS1** | `certbot-dns-nsone` | Chiave API | Enterprise |
| **DigitalOcean** | `certbot-dns-digitalocean` | API Token | Cloud |
| **Linode** (Akamai Connected Cloud) | `certbot-dns-linode` | Chiave API | Cloud |
| **Akamai Edge DNS** | `certbot-plugin-edgedns` | EdgeGrid `.edgerc` (client_token, client_secret, access_token, host) | Enterprise |
| **Vultr** | `certbot-dns-vultr` | Chiave API | Cloud |
| **Hetzner (DNS legacy)** | `certbot-dns-hetzner` | API Token | Cloud |
| **Hetzner Cloud** | `certbot-dns-hetzner-cloud` | API Token | Cloud |
| **Gandi** | `certbot-dns-gandi` | API Token | Registrar |
| **Namecheap** | `certbot-dns-namecheap` | Nome utente, Chiave API | Registrar |
| **Porkbun** | `certbot-dns-porkbun` | Chiave API, Secret Key | Registrar |
| **GoDaddy** | `certbot-dns-godaddy` | Chiave API, Secret | Registrar |
| **OVH** | `certbot-dns-ovh` | Credenziali API | Regionale |
| **Infomaniak** | `certbot-dns-infomaniak` | API Token | Regionale |
| **ArvanCloud** | `certbot-dns-arvancloud` | Chiave API | Regionale |
| **RFC2136** | `certbot-dns-rfc2136` | Server DNS, Chiave TSIG | Protocollo standard |
| **ACME-DNS** | `certbot-acme-dns` | URL API, Nome utente, Password | Specializzato |
| **Hurricane Electric** | `certbot-dns-he-ddns` | Nome utente, Password | DNS gratuito |
| **Dynu** | `certbot-dns-dynudns` | API Token | DNS dinamico |
| **DuckDNS** | `certbot-dns-duckdns` | Token account | DDNS gratuito (senza dominio) |
| **deSEC** | `certbot-dns-desec` | API Token | Gratuito, UE (DE), DNSSEC — delegare NS a `ns1.desec.io` / `ns2.desec.org` |
| **Scaleway** | `certbot-dns-scaleway` | Chiave segreta API | Cloud sovrano UE (FR) — plugin della community (alpha), installare separatamente: `pip install certbot-dns-scaleway` |
| **Script personalizzato** | nessuno (certbot `--manual`) | Percorso script auth (+ script cleanup opzionale) | Porta il tuo |

---

## Configurazione

### Tramite interfaccia Web

1. Vai su **Impostazioni**
2. Seleziona il provider DNS dall'elenco a discesa
3. Inserisci le credenziali richieste
4. Salva le impostazioni

### Tramite API

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

## Esempi di configurazione per provider

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

Per server DNS BIND o altri compatibili RFC2136 (incluso **Technitium DNS Server**):

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

> **Technitium DNS**: abilita Dynamic Updates in Zone Options, crea una chiave TSIG (ad es. `certmate-key` con HMAC-SHA512), quindi utilizza il segreto generato nella configurazione sopra.

### Hetzner (API DNS legacy)

> **Avviso di deprecazione:** L'API console DNS Hetzner verrà dismessa a maggio 2025. I nuovi utenti devono utilizzare il provider **Hetzner Cloud** indicato di seguito. Gli utenti esistenti devono migrare a `hetzner-cloud` prima della data di dismissione. Consulta la [pagina di stato Hetzner](https://status.hetzner.com/incident/c2146c42-6dd2-4454-916a-19f07e0e5a44) per i dettagli.

```json
{
  "dns_provider": "hetzner",
  "dns_providers": {
    "hetzner": {
      "api_token": "your_hetzner_dns_api_token"
    }
  }
}
```

### Hetzner Cloud

Utilizza la nuova [API Hetzner Cloud](https://docs.hetzner.cloud/reference/cloud) che sostituisce la console DNS Hetzner deprecata. Questo è il provider consigliato per tutti gli utenti Hetzner.

```json
{
  "dns_provider": "hetzner-cloud",
  "dns_providers": {
    "hetzner-cloud": {
      "api_token": "your_hetzner_cloud_api_token"
    }
  }
}
```

> Genera un API token Hetzner Cloud dalla [Console Hetzner Cloud](https://console.hetzner.cloud/) nella sezione token API del tuo progetto. Il token deve avere i permessi di lettura/scrittura DNS.

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

> Ottieni l'API token da Infomaniak Manager (sezione API con scope "Domain").

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

### DuckDNS (senza dominio richiesto)

DuckDNS assegna gratuitamente sottodomini `<nome>.duckdns.org` — il modo più semplice per ottenere un certificato di fiducia pubblica quando non si possiede un dominio. Casi d'uso tipici: homelab, servizi self-hosted, dispositivi IoT, dashboard interni precedentemente vincolati a certificati auto-firmati.

1. Accedi su <https://www.duckdns.org/> (SSO Google / GitHub / Twitter / Reddit).
2. Scegli un sottodominio (ad es. `mybox` → `mybox.duckdns.org`).
3. Copia il token account visualizzato in cima alla pagina.

```json
{
  "dns_provider": "duckdns",
  "domains": ["mybox.duckdns.org"],
  "dns_providers": {
    "duckdns": {
      "api_token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    }
  }
}
```

I wildcard come `*.mybox.duckdns.org` sono supportati con lo stesso token. Poiché DuckDNS memorizza un solo record TXT per dominio alla volta, è necessaria una singola esecuzione certbot per sottodominio DuckDNS — i certificati SAN che coprono più sottodomini DuckDNS non sono supportati.

### Script personalizzato (porta il tuo provider)

Per i provider DNS privi di plugin certbot — Oracle Cloud (OCI), DNS interno, API di appliance — punta CertMate ai tuoi script e li gestirà tramite la modalità `--manual` di certbot. Non è richiesta alcuna installazione di plugin.

```json
{
  "dns_provider": "custom-script",
  "dns_providers": {
    "custom-script": {
      "auth_hook": "/usr/local/bin/certmate-dns-auth.sh",
      "cleanup_hook": "/usr/local/bin/certmate-dns-cleanup.sh"
    }
  }
}
```

certbot invoca l'auth hook una volta per ogni challenge di validazione con l'ambiente standard [manual-hook](https://eff-certbot.readthedocs.io/en/stable/using.html#hooks): `CERTBOT_DOMAIN` (il dominio in fase di validazione) e `CERTBOT_VALIDATION` (il valore TXT). Lo script deve creare il record TXT `_acme-challenge.$CERTBOT_DOMAIN` **e attendere che si propaghi** — certbot valida immediatamente dopo il ritorno dell'hook. Il cleanup hook opzionale viene eseguito dopo la validazione per rimuovere il record.

Esempio per OCI DNS (copre [#285](https://github.com/fabriziosalmi/certmate/issues/285)). Si noti che un certificato che copre sia `example.com` che `*.example.com` produce DUE challenge di validazione sullo stesso nome `_acme-challenge.example.com`, e certbot esegue tutti gli auth hook prima di validare — quindi l'hook deve AGGIUNGERE al rrset TXT, non mai sostituirlo (un semplice `rrset update` sovrascriverebbe il primo token con il secondo):

```bash
#!/bin/sh
# /usr/local/bin/certmate-dns-auth.sh
set -eu
ZONE="example.com"
NAME="_acme-challenge.${CERTBOT_DOMAIN}"
# Unisci il nuovo token di validazione con gli eventuali record già presenti sul nome
# (i certificati apex + wildcard inseriscono due valori TXT sullo stesso nome).
EXISTING=$(oci dns record rrset get --zone-name-or-id "$ZONE" \
  --domain "$NAME" --rtype TXT \
  --query 'data.items[].rdata' --raw-output 2>/dev/null || echo '[]')
ITEMS=$(printf '%s' "$EXISTING" | python3 -c "
import json, os, sys
name = os.environ['NAME']
rdata = [r.strip('\"') for r in json.load(sys.stdin)]
rdata.append(os.environ['CERTBOT_VALIDATION'])
print(json.dumps([
    {'domain': name, 'rdata': v, 'rtype': 'TXT', 'ttl': 60} for v in rdata
]))
")
NAME="$NAME" oci dns record rrset update --force \
  --zone-name-or-id "$ZONE" \
  --domain "$NAME" \
  --rtype TXT \
  --items "$ITEMS"
sleep "${CERTMATE_DNS_PROPAGATION_SECONDS:-60}"
```

Requisiti e modello di fiducia:

- I percorsi devono essere **assoluti**, i file devono esistere, essere **eseguibili**, non scrivibili da tutti gli utenti, e non contenere spazi o metacaratteri della shell (certbot esegue gli hook tramite la shell). Validati all'emissione e dall'endpoint API di test (`POST /api/web/certificates/test-provider`)
- Gli script vengono eseguiti con i privilegi di CertMate — stesso modello di fiducia dei deploy hook: solo gli amministratori possono configurarli, trattali come parte del tuo deployment
- L'impostazione `dns_propagation_seconds` per provider viene esportata agli script come `CERTMATE_DNS_PROPAGATION_SECONDS` (un campo `propagation_seconds` a livello di account lo sovrascrive)
- I rinnovi rieseguono i percorsi degli hook dalla configurazione di rinnovo di certbot: mantieni gli script in un percorso stabile (se li sposti, riemetti il certificato)
- I certificati wildcard funzionano (l'hook riceve ogni record di validazione)

---

## Creazione di certificati

### Utilizzo del provider predefinito

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Utilizzo di un provider specifico

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "vultr"
  }'
```

### Utilizzo di un account specifico

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

## Supporto multi-account

CertMate supporta più account per provider DNS per ambienti enterprise.

### Casi d'uso

- **Separazione degli ambienti**: Account production, staging e DR
- **Multi-regione**: Account diversi per domini US, UE, APAC
- **Isolamento dei permessi**: Account admin, limitato e CI/CD

### Aggiunta di più account

```bash
# Aggiungere un account production
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

# Aggiungere un account staging
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

# Impostare production come account predefinito
curl -X PUT http://localhost:8000/api/settings/dns-providers/cloudflare/default-account \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"account_id": "production"}'
```

### Gestione degli account

```bash
# Elencare tutti gli account di un provider
curl -X GET http://localhost:8000/api/settings/dns-providers/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Aggiornare un account
curl -X PUT http://localhost:8000/api/settings/dns-providers/cloudflare/accounts/staging \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "name": "Staging & Testing",
      "api_token": "new_staging_token"
    }
  }'

# Eliminare un account
curl -X DELETE http://localhost:8000/api/settings/dns-providers/cloudflare/accounts/old-account \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

### Struttura di configurazione multi-account

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

### Retrocompatibilità

Le configurazioni a singolo account esistenti vengono migrate automaticamente al formato multi-account al primo utilizzo. Non sono richiesti tempi di inattività né migrazioni manuali.

---

## DNS multi-master e alias di dominio (delega CNAME)

Quando il tuo dominio è gestito da più provider DNS contemporaneamente (configurazione multi-master), utilizza la **delega CNAME** standard per centralizzare la validazione ACME DNS su un unico provider.

### Il problema

Con il DNS multi-master (ad es. deSEC + gcore), puoi configurare un solo provider DNS per richiesta di certificato, ma la validazione ACME richiede la creazione di record TXT `_acme-challenge`.

### La soluzione

La validazione tramite alias DNS funziona mediante delega CNAME. Let's Encrypt segue le catene CNAME durante la validazione DNS-01; CertMate scrive il record TXT richiesto sul nome di validazione delegato.

1. **Crea un dominio di validazione** su un provider supportato (ad es. `validation.example.org` su Cloudflare, PowerDNS, Route53 o ACME-DNS)
2. **Aggiungi record CNAME** in tutti i tuoi provider DNS che puntano al dominio di validazione:
   ```dns
   _acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
   ```
3. **Richiedi il certificato**, specificando il provider che gestisce il dominio di validazione:
   ```bash
   curl -X POST http://localhost:8000/api/certificates/create \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "domain": "example.com",
       "dns_provider": "cloudflare",
       "domain_alias": "validation.example.org"
     }'
   ```

   Quando `domain_alias` è impostato con un provider supportato, CertMate utilizza un hook DNS manuale di certbot per creare il record TXT su `_acme-challenge.validation.example.org`. Il CNAME garantisce che Let's Encrypt trovi quel valore TXT interrogando `_acme-challenge.example.com`.

### Vantaggi

- Funziona indipendentemente dal provider DNS che risponde alla query
- Non richiede sincronizzazione tra provider
- Funziona con provider non nativamente supportati da CertMate (deSEC, gcore)
- Le credenziali DNS sono limitate al solo dominio di validazione
- Implementato per i provider DNS di prima classe di CertMate; i provider generici vengono rifiutati finché non esistono adapter alias dedicati

### Esempi per provider

Cloudflare, PowerDNS e Route53 utilizzano tutti la stessa forma di richiesta:

```json
{
  "domain": "example.com",
  "dns_provider": "route53",
  "domain_alias": "validation.example.org"
}
```

Per ACME-DNS, `domain_alias` deve corrispondere esattamente al `subdomain`/fulldomain ACME-DNS configurato. CertMate aggiorna direttamente quel record ACME-DNS e non tenta la pulizia perché ACME-DNS memorizza l'ultimo valore di validazione.

### Certificati wildcard con alias di dominio

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "*.example.com",
    "dns_provider": "cloudflare",
    "domain_alias": "validation.example.org"
  }'
```

Assicurati che il CNAME sia in atto prima di richiedere il certificato:

```dns
_acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
```

### Risoluzione dei problemi con alias di dominio

```bash
# Verificare la propagazione del CNAME
dig @8.8.8.8 _acme-challenge.example.com CNAME +short
# Atteso: _acme-challenge.validation.example.org.

# Dopo aver richiesto un certificato, verificare il record TXT sul dominio di validazione
dig _acme-challenge.validation.example.org TXT +short
# Atteso: un token di challenge ACME codificato in base64
```

---

## Variabili d'ambiente

Imposta le credenziali del provider DNS tramite variabili d'ambiente per i workflow CI/CD:

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

### Priorità di configurazione (dalla più alta alla più bassa)

1. Variabili d'ambiente
2. Impostazioni specifiche per dominio
3. Impostazioni dell'account predefinito
4. Impostazione globale del provider
5. Predefinito di sistema (Cloudflare)

---

## Tempi di propagazione DNS

| Velocita | Provider | Secondi |
|----------|----------|---------|
| Molto rapida | ACME-DNS | 30 |
| Rapida | Cloudflare, Route53, PowerDNS, DuckDNS | 60 |
| Media | DigitalOcean, Linode, Google, ArvanCloud | 120 |
| Lenta | Azure, Gandi, OVH | 180 |
| Molto lenta | Namecheap | 300 |

---

## Funzionalita di sicurezza

- **Mascheramento delle credenziali** nell'interfaccia Web e nelle risposte API
- **Permessi file sicuri** (600) per tutti i file di credenziali
- **Validazione del token API** prima della creazione del certificato
- **Supporto variabili d'ambiente** per i workflow CI/CD
- **Audit logging** per tutte le operazioni sui provider DNS
- **Isolamento degli account** — le credenziali di ciascun account sono memorizzate separatamente

---

## Architettura e guida per sviluppatori

### Classi principali

| Classe | File | Scopo |
|--------|------|-------|
| `DNSManager` | `modules/core/dns_providers.py` | Gestione configurazione multi-account |
| `CertificateManager` | `modules/core/certificates.py` | Creazione certificati con provider DNS |
| `SettingsManager` | `modules/core/settings.py` | Persistenza e migrazione delle impostazioni |
| `Utils` | `modules/core/utils.py` | Generazione e validazione dei file di credenziali |

### Metodi di archiviazione delle credenziali

1. **File delle impostazioni** (`data/settings.json`) — il piu comune
2. **Variabili d'ambiente** — per CI/CD
3. **File di configurazione temporanei** (`letsencrypt/config/[provider].ini`) — creati durante le richieste di certificato, eliminati dopo

### Aggiunta di un nuovo provider DNS

1. Aggiungi il plugin a `requirements.txt`: `certbot-dns-newprovider`
2. Crea una funzione di configurazione in `modules/core/utils.py`
3. Aggiungi la definizione delle credenziali in `utils.py`
4. Importa e gestisci in `modules/core/certificates.py`
5. Aggiungi all'elenco dei provider supportati in `modules/core/settings.py`
6. Aggiorna la documentazione

Consulta la [Guida all'architettura](./architecture.md) per i dettagli completi di implementazione.

---

## Risoluzione dei problemi

### Problemi comuni

| Errore | Soluzione |
|--------|-----------|
| "DNS provider not configured" | Verifica che tutte le credenziali richieste siano fornite |
| "Certificate creation failed" | Controlla i permessi DNS e la proprieta del dominio |
| "Plugin not found" | Esegui `pip install -r requirements.txt` o ricostruisci Docker |
| "Provider detection failing" | Controlla il campo `dns_provider` nelle impostazioni del dominio |

### Modalita di debug

```bash
export FLASK_DEBUG=1
python app.py
```

### Test della configurazione del provider

```bash
curl -X GET http://localhost:8000/api/settings/dns-providers \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

---

## Guida alla migrazione

### Da un provider singolo a piu provider

Le configurazioni esistenti rimangono invariate. E sufficiente aggiungere i nuovi provider:

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

### Utilizzo di provider diversi per certificato

```bash
# Cloudflare per un dominio
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "dns_provider": "cloudflare"}'

# Route53 per un altro
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "test.org", "dns_provider": "route53"}'
```

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Installazione →](./installation.md) • [Provider CA →](./ca-providers.md)

</div>
