# Documentazione CertMate

<!-- CERTMATE-TRANSLATED-FROM bc6b854a04bbb77b -->

Benvenuto nella documentazione di CertMate. Questa cartella contiene guide complete per tutte le funzionalità.

---

## Navigazione rapida

### Per iniziare
- **[Guida all'installazione](./installation.md)** — Configurazione, dipendenze, deployment in produzione
- **[Guida Docker](./docker.md)** — Build Docker, multi-piattaforma, Docker Compose
- **[Note Kubernetes](./kubernetes.md)** — Risorse di produzione, dimensionamento OOM, patching runtime
- **[Configurazione](../configuration.md)** — ogni variabile d'ambiente, il suo valore predefinito e cosa cambia *(in inglese)*

### Funzionalità principali
- **[Provider DNS](./dns-providers.md)** — provider supportati, multi-account, alias di dominio
- **[Script DNS personalizzato](../custom-dns-script.md)** — qualsiasi provider senza plugin, guidato dai tuoi hook *(in inglese)*
- **[Provider CA](./ca-providers.md)** — Let's Encrypt, DigiCert, CA privata
- **[Certificati client](./guide.md)** — Ciclo di vita dei certificati client, dashboard web, operazioni batch
- **[Server MCP (Model Context Protocol)](./mcp.md)** — Server Node.js standalone per l'integrazione con agenti IA

### Riferimento
- **[Riferimento API](./api.md)** — Documentazione completa dell'API REST
- **[Architettura](./architecture.md)** — Progettazione del sistema, componenti, flusso dei dati
- **[Guida ai test](./testing.md)** — Framework di test, CI/CD, copertura
- **[Discovery e inventario dei certificati](../discovery-inventory.md)** — discovery via probe/CT-log, inventario, adopt, crypto readiness *(in inglese)*
- **[Deploy hook](./deploy-hooks.md)** — hook post-emissione: configurazione, test, redazione dell'output, finestre di manutenzione
- **[Certificati solo CSR](../csr-only-certificates.md)** — emissione e rinnovo quando la chiave privata resta sul dispositivo *(in inglese)*
- **[Webhook](../webhooks.md)** — webhook generici: template del payload, autenticazione, verifica della firma *(in inglese)*
- **[Conformità](./compliance.md)** — catena di audit, attribuzione delle azioni, postura NIS2/eIDAS
- **[Backup e ripristino](../backup.md)** — i due tipi di archivio, copie fuori dall'host, ripristino, password di amministratore persa *(in inglese)*
- **[Sonde di deployment](./probes.md)** — verificare che il certificato rinnovato sia davvero servito
- **[Single sign-on (OIDC)](../sso.md)** — accesso con OpenID Connect, mappatura dei ruoli, provisioning *(in inglese)*
- **[Storage dei certificati](../storage.md)** — backend di storage, cosa serve a ciascuno, migrazione tra di essi *(in inglese)*
- **[Monitoraggio](../monitoring.md)** — endpoint di salute, metriche Prometheus, log, canali di notifica *(in inglese)*
- **[Risoluzione dei problemi](../troubleshooting.md)** — errori comuni, log di debug, come segnalare un bug *(in inglese)*

---

## Documentazione per pubblico

### Per i nuovi utenti

1. **[Installazione](./installation.md)** — Mettere in funzione CertMate
2. **[Provider DNS](./dns-providers.md)** — Configurare il proprio provider DNS
3. **[Guida ai certificati client](./guide.md)** — Creare il primo certificato

### Per gli sviluppatori

1. **[Riferimento API](./api.md)** — Tutti gli endpoint con esempi
2. **[Architettura](./architecture.md)** — Funzionamento interno e progettazione del sistema
3. **[Guida ai test](./testing.md)** — Come scrivere ed eseguire i test

### Per gli amministratori

1. **[Deployment Docker](./docker.md)** — Configurazione Docker per la produzione
2. **[Note Kubernetes](./kubernetes.md)** — Dimensionamento dei pod in produzione e patching operativo
3. **[Provider CA](./ca-providers.md)** — Configurare le autorità di certificazione
4. **[Provider DNS](./dns-providers.md#supporto-multi-account)** — Configurazione multi-account aziendale

---

## Panoramica delle funzionalità

### Certificati server
- **Tutti i provider DNS supportati** per le challenge DNS-01 di Let's Encrypt (vedere [Provider DNS](./dns-providers.md) per l'elenco completo)
- **Più provider CA**: Let's Encrypt, DigiCert, CA privata
- **Supporto multi-account** per provider DNS
- **Storage backend intercambiabili**: locale, Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical, S3-compatible
- **Rinnovo automatico** con soglie configurabili
- **Supporto Docker** con build multi-piattaforma (ARM64 + AMD64)
- **Log Sanitizer** — Oscura automaticamente token API, chiavi private e credenziali sensibili dai log di CertMate
- **Zombie Certificate Scanner** — Sonda multi-thread che verifica se i nomi dei certificati gestiti risolvono ancora e rispondono
- **Server MCP (Model Context Protocol)** — Server Node.js standalone per l'integrazione con assistenti IA agentici

### Certificati client
- **CA auto-firmata** con chiavi RSA a 4096 bit
- **Gestione completa del ciclo di vita** — creazione, rinnovo, revoca, monitoraggio
- **OCSP & CRL** — stato in tempo reale e liste di revoca
- **Dashboard web** su `/client-certificates`
- **Operazioni batch** — importazione in blocco di certificati client via CSV (fino a 100 righe per richiesta)
- **Audit logging** e **rate limiting**

---

## Riferimento rapido degli endpoint API

| Metodo | Endpoint                                 | Descrizione                   |
| ------ | ---------------------------------------- | ----------------------------- |
| POST   | `/api/client-certs/create`               | Crea un certificato           |
| GET    | `/api/client-certs`                      | Elenca i certificati          |
| GET    | `/api/client-certs/<id>`                 | Ottieni i metadati            |
| GET    | `/api/client-certs/<id>/download/<type>` | Scarica cert/chiave/csr       |
| POST   | `/api/client-certs/<id>/revoke`          | Revoca un certificato         |
| POST   | `/api/client-certs/<id>/renew`           | Rinnova un certificato        |
| GET    | `/api/client-certs/stats`                | Ottieni le statistiche        |
| POST   | `/api/client-certs/batch`                | Importazione batch CSV        |
| GET    | `/api/ocsp/status/<serial>`              | Stato OCSP                    |
| GET    | `/api/crl/download/<format>`             | Scarica la CRL                |

Vedere il [Riferimento API](./api.md#endpoint) per la documentazione completa.

---

## Test

Tutte le funzionalità sono testate in modo approfondito:

```bash
# Esegui i test
# La suite UI pilota Playwright contro un server vivo e non può condividere
# il processo con le altre; e2e richiede un'istanza in esecuzione. È la
# stessa selezione usata da `make test` e scripts/release.sh.
pytest -v --tb=short -m "not ui and not e2e"
```

La copertura dei test include:
- Operazioni CA
- Operazioni CSR
- Ciclo di vita dei certificati
- Filtri e ricerca
- Operazioni batch
- OCSP & CRL
- Audit e rate limiting

---

## Funzionalità di sicurezza

- **RSA 4096 bit** per le chiavi CA
- **Algoritmo di firma** SHA256
- **Autenticazione** tramite Bearer token
- **Rate limiting** su tutti gli endpoint
- **Audit logging** di tutte le operazioni
- **Permessi sui file** 0600 per le chiavi private

---

## Performance

- Supporta **30.000+ certificati simultanei**
- Query **multi-filtro** efficienti
- Pianificazione del **rinnovo automatico**
- **Operazioni batch** con tracciamento degli errori

---

## Serve aiuto?

1. **Problemi di installazione?** → Vedere la [sezione Installazione](./guide.md#installazione)
2. **Domande sull'API?** → Vedere il [Riferimento API](./api.md)
3. **Domande sull'architettura?** → Vedere il [documento di architettura](./architecture.md)
4. **Altro?** → Aprire una [issue](https://github.com/fabriziosalmi/certmate/issues)

---

## Struttura dei file

<!-- Checked by tests/test_docs_navigation.py: this listing must match
     what is actually on disk. It used to omit six pages. -->

```
docs/it/
  README.md           this file — documentation index  <- you are here
  THEME_MIGRATION.md  one-off theme migration record
  api.md              complete REST API reference
  architecture.md     system architecture
  ca-providers.md     certificate authorities
  compliance.md       audit chain, attribution, NIS2/eIDAS
  deploy-hooks.md     post-issuance deploy hooks
  dns-providers.md    DNS providers, multi-account, domain alias
  docker.md           Docker build and deployment
  guide.md            client-certificate user guide
  index.md            client-certificate landing page
  installation.md     installation and setup
  kubernetes.md       Kubernetes production notes and Helm chart
  mcp.md              MCP server for AI agents
  probes.md           deployment probes
  testing.md          test framework and CI/CD
```

---

## Percorso di apprendimento

**Principiante** → [Inizia qui](./guide.md) → [Guida introduttiva](./guide.md)

**Sviluppatore** → [Riferimento API](./api.md) → [Architettura](./architecture.md)

**Avanzato** → [Documentazione API completa](./api.md) → [Dettagli architetturali](./architecture.md)

---

## Link importanti

- **Dashboard web**: `http://localhost:8000/client-certificates`
- **Documentazione API**: `http://localhost:8000/docs/`
- **Controllo di integrità**: `http://localhost:8000/health`
- **Log di audit**: `logs/audit/certificate_audit.log`

---

## Stato dei test

Qui non c'è un prospetto dei test mantenuto a mano. Una tabella con il conteggio dei test è già vecchia il giorno dopo che la si scrive: questa diceva `27/27` mentre la suite aveva superato i duemila test.

Il segnale autorevole è la CI su `main`: i badge in cima al [README del progetto](../../README.md) e la soglia di copertura imposta in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

---

## Esempi rapidi

### Creare un certificato tramite API

```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365
 }'
```

### Elencare i certificati

```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer YOUR_TOKEN"
```

### Scaricare un certificato

```bash
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o certificate.crt
```

Vedere la [Guida API](./api.md) per ulteriori esempi.

---

## Licenza

CertMate è distribuito sotto licenza MIT. Vedere il file LICENSE nel repository.

---

## Domande o problemi?

- Consultare la pagina di documentazione pertinente
- Esaminare i file di test per esempi di utilizzo
- Consultare il [Riferimento API](./api.md) per i dettagli degli endpoint

---

---

**Versione corrente**: 2.50.1

<div align="center">

[Home](../../README.md) • [Documentazione](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
