# CertMate - Certificati Client

<div align="center">

![CertMate](https://img.shields.io/badge/CertMate-Certificati%20Client-blue?style=for-the-badge)
![Stato](https://img.shields.io/badge/Stato-Pronto%20per%20la%20produzione-green?style=for-the-badge)

**Gestione completa dei certificati client per CertMate**

[Documentazione](#documentazione) • [Avvio rapido](#avvio-rapido) • [Riferimento API](./api.md) • [Architettura](./architecture.md)

</div>

---

## Panoramica

CertMate Certificati Client è una soluzione completa e pronta per la produzione per la gestione dei certificati client con:

- **CA auto-firmata** — Genera e gestisci la tua Certification Authority
- **Gestione completa del ciclo di vita** — Crea, rinnova, revoca e monitora i certificati client
- **OCSP & CRL** — Stato dei certificati in tempo reale e liste di revoca
- **Dashboard Web** — Interfaccia intuitiva per la gestione dei certificati
- **API REST** — API completa per l'automazione
- **Operazioni batch** — Importa da 100 a 30.000 certificati tramite CSV
- **Log di audit** — Traccia tutte le operazioni per la conformità
- **Rate limiting** — Protezione integrata contro gli abusi

---

## Funzionalità

### Fase 1: Fondamenta CA
- **PrivateCAGenerator**: CA auto-firmata con chiavi RSA a 4096 bit, validità 10 anni
- **CSRHandler**: Valida, crea e analizza le Certificate Signing Request
- **Archiviazione sicura**: Permessi sui file appropriati (0600) per le chiavi private

### Fase 2: Motore dei certificati client
- **Ciclo di vita completo**: Crea, elenca, filtra, revoca e rinnova i certificati
- **Query multi-filtro**: Ricerca per tipo di utilizzo, stato di revoca, nome comune
- **Rinnovo automatico**: Verifiche quotidiane pianificate per i certificati in scadenza
- **Supporto per 30k+ certificati**: Archiviazione basata su directory per scalabilità lineare
- **Gestione dei metadati**: Traccia CN, email, organizzazione, utilizzo, date di scadenza

### Fase 3: Interfaccia utente e funzionalità avanzate
- **Dashboard Web**: Interfaccia di gestione responsive con modalità scura
- **OCSP Responder**: Interroga lo stato dei certificati in tempo reale
- **CRL Manager**: Genera e distribuisce le liste di revoca (PEM/DER)
- **API REST**: 10 endpoint in 3 namespace per un'automazione completa
- **Operazioni batch**: Importa certificati da file CSV

### Fase 4: Miglioramenti rapidi
- **Log di audit**: Traccia tutte le operazioni sui certificati con informazioni su utente/IP
- **Rate limiting**: Limiti configurabili per endpoint con valori predefiniti ragionevoli
- **Pronto per l'integrazione**: Entrambi i manager disponibili nell'applicazione per un utilizzo immediato

---

## Avvio rapido

### Installazione

```bash
pip install -r requirements.txt
python app.py
```

Il server si avvia su `http://localhost:8000`

### Utilizzo di base

#### 1. Accesso alla Dashboard Web
```
Naviga verso: http://localhost:8000/client-certificates
```

#### 2. Creare un certificato tramite API
```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer IL_TUO_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true
 }'
```

#### 3. Elencare i certificati
```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer IL_TUO_TOKEN"
```

#### 4. Scaricare i file del certificato
```bash
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer IL_TUO_TOKEN" \
 -o user.crt

curl http://localhost:8000/api/client-certs/USER_ID/download/key \
 -H "Authorization: Bearer IL_TUO_TOKEN" \
 -o user.key
```

---

## Documentazione

### Documentazione principale

- **[Guida all'installazione](./installation.md)** — Configurazione, dipendenze, deployment
- **[Note Kubernetes](./kubernetes.md)** — Dimensionamento dei pod e risoluzione dei problemi OOM
- **[Provider DNS](./dns-providers.md)** — Provider supportati, multi-account, alias di dominio
- **[Provider CA](./ca-providers.md)** — Let's Encrypt, Actalis, DigiCert, CA privata
- **[Guida Docker](./docker.md)** — Build Docker, multi-piattaforma, Compose
- **[Guida ai test](./testing.md)** — Framework di test, CI/CD, copertura
- **[Riferimento API](./api.md)** — Documentazione completa dell'API REST con esempi
- **[Architettura](./architecture.md)** — Progettazione del sistema, componenti e flusso dei dati
- **[Guida utente](./guide.md)** — Guida passo-passo per le attività comuni

### Link rapidi

- [Endpoint API](./api.md#endpoints) — Tutti gli endpoint disponibili
- [Tipi di certificato](./api.md#certificate-types) — VPN, API mTLS, ecc.
- [Rate limiting](./api.md#rate-limiting) — Limiti predefiniti e configurazione
- [Log di audit](./api.md#audit-logging) — Comprendere le tracce di audit

---

## Test

Tutte le funzionalità sono state testate in modo approfondito:

```bash
python -m pytest tests/ -v
```

### Copertura dei test
- Operazioni CA (3 test)
- Operazioni CSR (3 test)
- Ciclo di vita dei certificati (8 test)
- Filtraggio e ricerca (3 test)
- Operazioni batch (2 test)
- OCSP e CRL (5 test)
- Audit e rate limiting (3 test)

---

## Riepilogo degli endpoint API

| Metodo | Endpoint                                 | Scopo                               |
| ------ | ---------------------------------------- | ----------------------------------- |
| `POST` | `/api/client-certs/create`               | Creare un nuovo certificato         |
| `GET`  | `/api/client-certs`                      | Elencare i certificati con filtri   |
| `GET`  | `/api/client-certs/<id>`                 | Ottenere i metadati di un certificato |
| `GET`  | `/api/client-certs/<id>/download/<type>` | Scaricare cert/key/csr              |
| `POST` | `/api/client-certs/<id>/revoke`          | Revocare un certificato             |
| `POST` | `/api/client-certs/<id>/renew`           | Rinnovare un certificato            |
| `GET`  | `/api/client-certs/stats`                | Ottenere le statistiche             |
| `POST` | `/api/client-certs/batch`                | Import batch CSV                    |
| `GET`  | `/api/ocsp/status/<serial>`              | Query di stato OCSP                 |
| `GET`  | `/api/crl/download/<format>`             | Scaricare la CRL (PEM/DER)          |

---

## Architettura

Il sistema è costruito con un'architettura modulare a livelli:

```

 Interfaccia Web e API REST
 (/client-certificates, /api/*)

 Risorse API e manager
 (OCSP, CRL, Audit, Rate Limiting)

 Moduli principali
 (Gestione certificati, CSR, CA, Archiviazione)

 Crittografia e archiviazione
 (OpenSSL, File System, Backend)

```

Vedere la [Documentazione sull'architettura](./architecture.md) per informazioni dettagliate.

---

## Sicurezza

### Robustezza crittografica
- **CA**: Chiavi RSA a 4096 bit, validità 10 anni
- **Certificati client**: RSA a 2048 o 4096 bit (configurabile)
- **Firme**: SHA256
- **Archiviazione delle chiavi**: Permessi 0600 sui sistemi Unix

### Controllo degli accessi
- **Autenticazione Bearer token** su tutti gli endpoint API
- **Rate limiting**: Limiti configurabili per endpoint
- **Log di audit**: Tutte le operazioni tracciate con informazioni su utente/IP

### Conformità
- Tracciamento dei metadati dei certificati
- Traccia di audit delle revoche
- Log delle operazioni persistenti
- Supporto per le query di conformità

---

## Performance

L'implementazione è ottimizzata per:
- **Scalabilità**: L'archiviazione basata su directory supporta 30k+ certificati simultanei
- **Velocità**: Query multi-filtro efficienti
- **Affidabilità**: Pianificazione automatica del rinnovo
- **Reattività**: JavaScript asincrono nell'interfaccia Web

---

## Supporto

Per domande o problemi:
1. Consulta la [Guida utente](./guide.md)
2. Consulta la [Documentazione API](./api.md)
3. Consulta la sezione [Architettura](./architecture.md)
4. Esamina i casi di test in `test_e2e_complete.py`

---

## Licenza

Vedere il file LICENSE nel repository

---

## Versione

**Versione corrente**: 2.3.0
**Stato**: Pronto per la produzione

---

<div align="center">

[Documentazione](.) • [Licenza](../LICENSE)

</div>
