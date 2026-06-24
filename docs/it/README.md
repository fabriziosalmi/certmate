# Documentazione CertMate

Benvenuto nella documentazione di CertMate. Questa cartella contiene guide complete per tutte le funzionalità.

---

## Navigazione rapida

### Per iniziare
- **[Guida all'installazione](./installation.md)** — Configurazione, dipendenze, deployment in produzione
- **[Guida Docker](./docker.md)** — Build Docker, multi-piattaforma, Docker Compose
- **[Note Kubernetes](./kubernetes.md)** — Risorse di produzione, dimensionamento OOM, patching runtime

### Funzionalità principali
- **[Provider DNS](./dns-providers.md)** — Provider supportati, multi-account, alias di dominio
- **[Provider CA](./ca-providers.md)** — Let's Encrypt, DigiCert, CA privata
- **[Certificati client](./guide.md)** — Ciclo di vita dei certificati client, dashboard web, operazioni batch
- **[Server MCP (Model Context Protocol)](./mcp.md)** — Server Node.js standalone per l'integrazione con agenti IA

### Riferimento
- **[Riferimento API](./api.md)** — Documentazione completa dell'API REST
- **[Architettura](./architecture.md)** — Progettazione del sistema, componenti, flusso dei dati
- **[Guida ai test](./testing.md)** — Framework di test, CI/CD, copertura

---

## Documentazione per pubblico

### Per i nuovi utenti

1. **[Installazione](./installation.md)** — Mettere in funzione CertMate
2. **[Provider DNS](./dns-providers.md)** — Configurare il proprio provider DNS
3. **[Guida ai certificati client](./guide.md)** — Creare il primo certificato

### Per gli sviluppatori

1. **[Riferimento API](./api.md)** — Tutti gli endpoint con esempi
2. **[Architettura](./architecture.md)** — Funzionamento interno e progettazione
3. **[Guida ai test](./testing.md)** — Come scrivere ed eseguire i test

### Per gli amministratori

1. **[Deployment Docker](./docker.md)** — Configurazione Docker per la produzione
2. **[Note Kubernetes](./kubernetes.md)** — Dimensionamento dei pod e patching operativo
3. **[Provider CA](./ca-providers.md)** — Configurare le autorità di certificazione
4. **[Provider DNS](./dns-providers.md#multi-account-support)** — Configurazione multi-account aziendale

---

## Panoramica delle funzionalità

### Certificati server
- **Oltre due dozzine di provider DNS** per le sfide Let's Encrypt DNS-01 (vedere [Provider DNS](./dns-providers.md) per l'elenco completo)
- **Più provider CA**: Let's Encrypt, DigiCert, CA privata
- **Supporto multi-account** per provider DNS
- **Storage backend intercambiabili**: locale, Azure Key Vault, AWS, Vault, Infisical
- **Rinnovo automatico** con soglie configurabili
- **Supporto Docker** con build multi-piattaforma (ARM64 + AMD64)
- **Log Sanitizer** — Oscura automaticamente token API, chiavi private e credenziali sensibili dai log di CertMate
- **Zombie Certificate Scanner** — Scanner multi-thread del filesystem per identificare e rimuovere certificati orfani
- **Server MCP (Model Context Protocol)** — Server Node.js standalone per l'integrazione con assistenti IA agentici

### Certificati client
- **CA auto-firmata** con chiavi RSA a 4096 bit
- **Gestione completa del ciclo di vita** — creazione, rinnovo, revoca, monitoraggio
- **OCSP & CRL** — stato in tempo reale e liste di revoca
- **Dashboard web** su `/client-certificates`
- **Operazioni batch** — importazione di 100-30.000 certificati tramite CSV
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

Vedere il [Riferimento API](./api.md#endpoints) per la documentazione completa.

---

## Test

Tutte le funzionalità sono testate in modo approfondito:

```bash
# Esegui i test
python -m pytest tests/ -v
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

## Struttura dei file

```
docs/
  README.md            ← Sei qui
  index.md             ← Pagina iniziale dei certificati client
  installation.md      ← Installazione e configurazione
  kubernetes.md        ← Note di produzione Kubernetes
  dns-providers.md     ← Provider DNS e multi-account
  ca-providers.md      ← Provider delle autorità di certificazione
  docker.md            ← Build e deployment Docker
  testing.md           ← Framework di test e CI/CD
  guide.md             ← Guida utente dei certificati client
  api.md               ← Riferimento API completo
  architecture.md      ← Architettura del sistema
```

---

## Percorso di apprendimento

**Principiante** → [Inizia qui](./index.md) → [Guida introduttiva](./guide.md)

**Sviluppatore** → [Riferimento API](./api.md) → [Architettura](./architecture.md)

**Avanzato** → [Documentazione API completa](./api.md) → [Dettagli architetturali](./architecture.md)

---

## Link importanti

- **Dashboard web**: `http://localhost:8000/client-certificates`
- **Documentazione API**: `http://localhost:8000/docs/`
- **Controllo di integrità**: `http://localhost:8000/health`
- **Log di audit**: `logs/audit/certificate_audit.log`

---

## Dashboard di stato

| Componente          | Stato     | Test      |
| ------------------- | --------- | --------- |
| Fondazione CA       | Pronto    | 3/3       |
| Gestore CSR         | Pronto    | 3/3       |
| Gestore cert.       | Pronto    | 8/8       |
| Filtri              | Pronto    | 3/3       |
| Operazioni batch    | Pronto    | 2/2       |
| OCSP/CRL            | Pronto    | 5/5       |
| Audit/Rate Limit    | Pronto    | 3/3       |
| **Totale**          | **Pronto**| **27/27** |

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

<div align="center">

[Home](../README.md) • [Documentation](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
