# CertMate Certificati Client - Riferimento API

## Panoramica

L'API CertMate per la gestione dei certificati client fornisce endpoint REST per una gestione completa dei certificati con autenticazione, rate limiting e journalizzazione dell'audit.

**URL di base**: `http://localhost:5000/api`
**Autenticazione**: Bearer Token (obbligatoria su tutti gli endpoint)
**Content-Type**: `application/json`

---

## Autenticazione

Tutti gli endpoint API richiedono l'autenticazione tramite Bearer token.

### Formato dell'header

```
Authorization: Bearer IL_TUO_TOKEN
```

### Esempio di richiesta

```bash
curl -X GET http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer IL_TUO_TOKEN" \
 -H "Content-Type: application/json"
```

---

## Rate Limiting

Gli endpoint API hanno limiti di frequenza per prevenire gli abusi:

| Endpoint              | Limite | Per     |
| --------------------- | ------ | ------- |
| Generale              | 100    | minuto  |
| Crea certificato      | 30     | minuto  |
| Operazioni batch      | 10     | minuto  |
| Stato OCSP            | 200    | minuto  |
| Download CRL          | 60     | minuto  |

### Risposta in caso di limite raggiunto

Quando il limite viene superato, si riceve:

```
HTTP 429 Too Many Requests

{
 "error": "Rate limit exceeded",
 "message": "Too many requests. Please try again later.",
 "retry_after": 60
}
```

---

## Endpoint

### Gestione dei certificati

#### 1. Crea certificato

**Endpoint**: `POST /client-certs/create`

Crea un nuovo certificato client.

**Richiesta**:
```json
{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true,
 "notes": "Production certificate"
}
```

**Parametri**:
- `common_name` (obbligatorio) — Subject del certificato
- `email` (opzionale) — Indirizzo e-mail
- `organization` (opzionale) — Nome dell'organizzazione
- `organizational_unit` (opzionale) — Nome del reparto
- `cert_usage` (opzionale) — Tipo di utilizzo: `api-mtls`, `vpn`, o personalizzato
- `days_valid` (opzionale) — Validita in giorni (predefinito: 365)
- `generate_key` (opzionale) — Genera chiave privata (predefinito: true)
- `notes` (opzionale) — Note aggiuntive

**Risposta** (201 Created):
```json
{
 "identifier": "cert-abc123",
 "common_name": "user@example.com",
 "serial_number": "12345678901234567890",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "cert_usage": "api-mtls",
 "status": "active"
}
```

**Esempio**:
```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365
 }'
```

---

#### 2. Elenca certificati

**Endpoint**: `GET /client-certs`

Elenca tutti i certificati client con filtro opzionale.

**Parametri di query**:
- `usage` (opzionale) — Filtra per tipo di utilizzo (es. `api-mtls`)
- `revoked` (opzionale) — Filtra per stato (`true` o `false`)
- `search` (opzionale) — Cerca nel common name

**Risposta** (200 OK):
```json
{
 "certificates": [{
 "identifier": "cert-001",
 "common_name": "user1@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "revoked": false,
 "status": "active"
 },
 {
 "identifier": "cert-002",
 "common_name": "user2@example.com",
 "organization": "ACME Corp",
 "cert_usage": "vpn",
 "created_at": "2024-10-29T18:00:00Z",
 "expires_at": "2025-10-29T18:00:00Z",
 "revoked": true,
 "status": "revoked"
 }
 ],
 "total": 2
}
```

**Esempi**:
```bash
# Elenca tutti i certificati
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtra per tipo di utilizzo
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Elenca solo i revocati
curl "http://localhost:5000/api/client-certs?revoked=true" \
 -H "Authorization: Bearer TOKEN"

# Cerca per common name
curl "http://localhost:5000/api/client-certs?search=user1" \
 -H "Authorization: Bearer TOKEN"
```

---

#### 3. Ottieni dettagli certificato

**Endpoint**: `GET /client-certs/<identifier>`

Recupera i metadati completi di un certificato.

**Risposta** (200 OK):
```json
{
 "type": "client_certificate",
 "identifier": "cert-001",
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "serial_number": "12345678901234567890",
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
 "renewal_threshold_days": 30
 }
}
```

**Esempio**:
```bash
curl http://localhost:5000/api/client-certs/cert-001 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 4. Scarica file del certificato

**Endpoint**: `GET /client-certs/<identifier>/download/<type>`

Scarica il certificato, la chiave privata o il file CSR.

**Parametri**:
- `identifier` — ID del certificato
- `type` — Tipo di file: `crt`, `key`, o `csr`

**Risposta** (200 OK):
- Content-Type: `application/octet-stream`
- Allegato con nome appropriato

**Esempi**:
```bash
# Scarica il certificato
curl http://localhost:5000/api/client-certs/cert-001/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o certificate.crt

# Scarica la chiave privata
curl http://localhost:5000/api/client-certs/cert-001/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o private.key

# Scarica il CSR
curl http://localhost:5000/api/client-certs/cert-001/download/csr \
 -H "Authorization: Bearer TOKEN" \
 -o request.csr
```

---

#### 5. Revoca certificato

**Endpoint**: `POST /client-certs/<identifier>/revoke`

Revoca un certificato con motivo opzionale.

**Richiesta** (opzionale):
```json
{
 "reason": "compromised"
}
```

**Risposta** (200 OK):
```json
{
 "message": "Certificate revoked: cert-001",
 "revoked_at": "2024-10-30T18:15:00Z",
 "reason": "compromised"
}
```

**Esempio**:
```bash
curl -X POST http://localhost:5000/api/client-certs/cert-001/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "reason": "compromised"
 }'
```

---

#### 6. Rinnova certificato

**Endpoint**: `POST /client-certs/<identifier>/renew`

Rinnova un certificato (stesso CN, nuovo numero seriale).

**Risposta** (201 Created):
```json
{
 "identifier": "cert-001-renewed",
 "common_name": "user@example.com",
 "serial_number": "98765432109876543210",
 "created_at": "2024-10-30T18:20:00Z",
 "expires_at": "2025-10-30T18:20:00Z",
 "status": "active"
}
```

**Esempio**:
```bash
curl -X POST http://localhost:5000/api/client-certs/cert-001/renew \
 -H "Authorization: Bearer TOKEN"
```

---

#### 7. Ottieni statistiche

**Endpoint**: `GET /client-certs/stats`

Recupera le statistiche di utilizzo dei certificati.

**Risposta** (200 OK):
```json
{
 "total": 100,
 "active": 85,
 "revoked": 15,
 "expiring_soon": 8,
 "by_usage": {
 "api-mtls": 60,
 "vpn": 35,
 "other": 5
 },
 "created_count": 100,
 "renewal_enabled": 92
}
```

**Esempio**:
```bash
curl http://localhost:5000/api/client-certs/stats \
 -H "Authorization: Bearer TOKEN"
```

---

#### 8. Importazione batch di certificati

**Endpoint**: `POST /client-certs/batch`

Crea piu certificati da dati CSV in un'unica richiesta.

**Richiesta**:
```json
{
 "headers": ["common_name", "email", "organization", "cert_usage", "days_valid"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp", "api-mtls", "365"],
 ["user2@example.com", "user2@example.com", "ACME Corp", "vpn", "365"],
 ["user3@example.com", "user3@example.com", "ACME Corp", "api-mtls", "365"]
 ]
}
```

**Risposta** (201 Created):
```json
{
 "total": 3,
 "successful": 3,
 "failed": 0,
 "errors": [],
 "certificates": [{
 "identifier": "cert-batch-001",
 "common_name": "user1@example.com"
 },
 {
 "identifier": "cert-batch-002",
 "common_name": "user2@example.com"
 },
 {
 "identifier": "cert-batch-003",
 "common_name": "user3@example.com"
 }
 ]
}
```

**Esempio**:
```bash
curl -X POST http://localhost:5000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "headers": ["common_name", "email", "organization"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
 ["user2@example.com", "user2@example.com", "ACME Corp"]
 ]
 }'
```

---

### OCSP & CRL

#### 9. Query di stato OCSP

**Endpoint**: `GET /ocsp/status/<serial_number>`

Interroga lo stato di un certificato tramite OCSP.

**Risposta** (200 OK):
```json
{
 "response_status": "successful",
 "certificate_status": "good|revoked|unknown",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z",
 "next_update": null,
 "responder_name": "CertMate OCSP Responder"
}
```

**Esempio**:
```bash
curl http://localhost:5000/api/ocsp/status/12345678 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 10. Distribuzione della CRL

**Endpoint**: `GET /crl/download/<format_type>`

Scarica la Certificate Revocation List.

**Parametri**:
- `format_type` — `pem`, `der`, o `info`

**Risposta**:
- Per `pem` e `der`: allegato file
- Per `info`: JSON con metadati CRL

**Esempi**:
```bash
# Scarica la CRL in formato PEM
curl http://localhost:5000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Scarica la CRL in formato DER
curl http://localhost:5000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Ottieni le informazioni sulla CRL
curl http://localhost:5000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

**Risposta informazioni CRL**:
```json
{
 "status": "available",
 "issuer": "CN=CertMate CA, O=CertMate",
 "last_update": "2024-10-30T18:00:00Z",
 "next_update": "2024-10-31T18:00:00Z",
 "revoked_count": 5,
 "revoked_serials": [12345678,
 87654321
 ]
}
```

---

#### 11. Scarica file del certificato di dominio

**Endpoint**: `GET /certificates/<domain>/download`

Scarica i file del certificato per un dominio specifico. Per impostazione predefinita, questo endpoint restituisce un archivio ZIP contenente tutti i componenti del certificato. E possibile richiedere un file specifico tramite il parametro di query `file`. E disponibile anche una modalita JSON per l'automazione che desidera ottenere tutti i PEM in un'unica risposta.

**Parametri**:
- `domain` (Path) — Il nome di dominio associato al certificato.
- `file` (Query, opzionale) — Specifica un singolo file da scaricare.
  - Valori supportati: `fullchain.pem`, `privkey.pem`, `combined.pem`
- `format` (Query, opzionale) — Impostare a `json` per restituire tutti i file del certificato in un oggetto JSON.

**Risposta** (200 OK):
- **Predefinito**: `application/zip` (un file ZIP contenente tutti i file PEM)
- **Con parametro `file`**: `application/x-pem-file` (il contenuto grezzo del file richiesto)
- **Con `format=json`**: `application/json` con `domain`, `cert_pem`, `chain_pem`, `fullchain_pem` e `private_key_pem`

La forma JSON e il formato di automazione preferito per Ansible, Salt o qualsiasi altro client che desideri scrivere direttamente i file PEM.

**Esempi**:

```bash
# Scarica tutti i file come archivio ZIP
curl http://localhost:5000/api/certificates/example.com/download \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.zip

# Scarica solo il file fullchain.pem
curl "http://localhost:5000/api/certificates/example.com/download?file=fullchain.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o fullchain.pem

# Scarica solo la chiave privata
curl "http://localhost:5000/api/certificates/example.com/download?file=privkey.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o privkey.pem

# Scarica il bundle completo in JSON
curl "http://localhost:5000/api/certificates/example.com/download?format=json" \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.json

```

---

#### 12. Riemetti un certificato di dominio (modifica la configurazione)

**Endpoint**: `POST /certificates/<domain>/reissue`

Modifica la configurazione di un certificato e lo riemette sul posto — estende o rimuove le voci SAN senza cancellare e ricreare. I campi omessi mantengono i valori con cui il certificato e stato emesso (letti dai suoi metadati), evitando cosi di dover reinserire la configurazione DNS/alias/CA. Il certificato attuale continua ad essere servito fino al completamento della riemissione. La forma della chiave e preservata salvo modifica esplicita (nessun flag di chiave viene inviato e certbot mantiene la chiave della lineage).

**Corpo della richiesta** (tutti i campi sono opzionali):
```json
{
  "san_domains": ["www.example.com", "api.example.com"],
  "domain_alias": "",
  "async": true
}
```

- `san_domains`: set di sostituzione dei SAN — omettere per mantenere, `[]` per rimuovere tutti i SAN
- `domain_alias`: omettere per mantenere, `""` per cancellare
- `dns_provider`, `account_id`, `ca_provider`, `challenge_type`: omettere per mantenere
- `key_type`/`key_size`/`elliptic_curve`: omettere per mantenere la forma di chiave esistente
- `async`: rinvia l'emissione a un job in background (202 + ID del job, interrogare `GET /certificates/jobs/<job_id>`)

**Risposta** (200 OK, o 202 Accepted con `async`): message, domain, dns_provider, ca_provider, duration.

**Errori**: 404 quando non esiste alcun certificato per il dominio (usare create), 403 scope, 400 validazione, 409 operazione in corso, 422 errore certbot (il certificato precedente e ancora in uso).

**Esempio**:
```bash
curl -X POST http://localhost:5000/api/certificates/example.com/reissue \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"san_domains": ["www.example.com", "api.example.com"]}'
```

---

## Gestione degli errori

### Formato della risposta di errore

```json
{
 "error": "Error message",
 "code": "ERROR_CODE",
 "status": 400
}
```

### Codici di stato HTTP comuni

| Codice | Significato          | Esempio                          |
| ------ | -------------------- | -------------------------------- |
| 200    | Successo             | Certificato elencato             |
| 201    | Creato               | Certificato creato               |
| 400    | Richiesta errata     | Campo obbligatorio mancante      |
| 401    | Non autorizzato      | Token non valido/mancante        |
| 404    | Non trovato          | Il certificato non esiste        |
| 429    | Troppe richieste     | Rate limit superato              |
| 500    | Errore del server    | Errore interno                   |
| 503    | Servizio non disponibile | OCSP/CRL non disponibile    |

### Esempio di errore

```bash
curl http://localhost:5000/api/client-certs/invalid-id \
 -H "Authorization: Bearer TOKEN"

# Risposta
{
 "error": "Certificate not found: invalid-id",
 "code": 404,
 "status": 404
}
```

---

## Journalizzazione dell'audit

Le operazioni del ciclo di vita dei certificati e le modifiche alla configurazione e al controllo degli accessi vengono registrate in un log di audit. Questo include i percorsi critici del ciclo di vita — creazioni, rinnovi, riemissioni, deploy e attivazioni/disattivazioni del rinnovo automatico riusciti e falliti, nonche i **rinnovi non presidiati (pianificati)** — ciascuno attribuito all'attore che lo ha eseguito e al trigger che ne e stata la causa.

### Formato del log

Il log di audit viene scritto in `logs/audit/certificate_audit.log`. Ogni riga e una riga di log Python standard il cui messaggio e la voce di audit JSON:

```
2026-06-15 18:00:00 - certmate.audit - INFO - {"timestamp": "...", ...}
```

Per recuperare il JSON, dividere ogni riga sul letterale ` - INFO - ` e analizzare il resto. Si notino le due basi temporali: il prefisso temporale della riga e l'ora **locale** del server, mentre il campo `timestamp` del JSON e in **UTC** (ISO-8601). Leggerlo in tempo reale con:

```bash
tail -f logs/audit/certificate_audit.log
```

### Struttura della voce

```json
{
  "timestamp": "2026-06-15T18:00:00.000000+00:00",
  "operation": "renew",
  "resource_type": "certificate",
  "resource_id": "api.example.com",
  "status": "success",
  "user": "api_key:renew-bot",
  "ip_address": "10.0.0.9",
  "details": {"force": false},
  "error": null,
  "actor": {
    "kind": "agent",
    "id": "9f2c…",
    "label": "api_key:renew-bot",
    "token_prefix": "cm_1a2b",
    "agent_session": "sess-9f2"
  },
  "trigger": {"cause": "agent"}
}
```

- **`actor.kind`** — `user` (una sessione umana / login OIDC), `api_token` (una chiave API o il token Bearer globale legacy), `agent` (una chiave API esplicitamente contrassegnata come agente IA/MCP — vedi sotto), `scheduler` (un job di rinnovo non presidiato), o `system`. Viene derivato **esclusivamente dall'identita autenticata**.
- **`actor.id` / `token_prefix`** — l'ID stabile della chiave API e il prefisso del token associato all'azione (assente per il token Bearer globale legacy, che non puo essere distinto per chiamante — preferire le chiavi con scope).
- **`actor.agent_session` / `agent_id`** — i valori degli header `X-CertMate-Agent-Session` / `X-CertMate-Agent-Id` forniti dal client (il server MCP li invia). Sono una **dichiarazione puramente informativa**: vengono registrati per correlazione ma non modificano mai `actor.kind`, quindi un chiamante non-agent non puo falsificare un'attribuzione `agent`.
- **`trigger.cause`** — `manual`, `api`, `agent`, `scheduled_renewal`, o `event`; per i rinnovi pianificati, `trigger.job_id` indica il nome del job.

Affinche le azioni di un agent vengano registrate come `actor.kind="agent"`, creare una chiave API con scope e `is_agent: true` (una casella di controllo in Impostazioni → Chiavi API, o `is_agent` in `POST /api/keys`) e puntare il server MCP verso di essa. Vedere la [guida MCP](./mcp.md).

### Lettura del log di audit tramite l'API

`GET /api/activity?limit=N` restituisce le voci piu recenti (admin/viewer, limitato a 500).

### Prova di integrita (hash chain)

Parallelamente al log leggibile dall'utente, ogni voce viene aggiunta a una **hash chain** SHA-256 a prova di manomissione in `data/audit/certificate_audit.chain.jsonl`. Ogni record e `{seq, entry, prev_hash, hash}` dove `hash` si impegna sulla voce e sull'hash del record precedente, e `seq` e un contatore senza lacune — pertanto qualsiasi modifica, cancellazione o riordinamento da parte di chiunque non possa ricalcolare l'intera chain e rilevabile e localizzabile. E attiva per impostazione predefinita; disabilitare con `CERTMATE_AUDIT_CHAIN=0`.

**Verifica tramite API:** `GET /api/audit/verify` (admin) restituisce il risultato del verificatore e HTTP `200` quando integra o `409` quando corrotta:

```json
{"ok": true, "count": 128, "first_seq": 0, "last_seq": 127, "head_hash": "5ee1…", "reason": "intact"}
```

**Verifica off-box:** il verificatore autonomo dipende solo dalla libreria standard Python, quindi un revisore puo eseguirlo senza installare ne fidarsi di CertMate:

```bash
python -m modules.core.audit_verify data/audit/certificate_audit.chain.jsonl
# OK: audit chain intact (128 entries, seq 0..127)
# or: FAIL: audit chain broken at seq 42: hash mismatch at seq 42: entry was modified
```

Codice di uscita `0` integra, `1` corrotta (con il `seq` incriminato e il motivo), `2` file mancante/illeggibile.

### Bundle di esportazione firmato (verificabile da terzi)

L'istanza detiene una chiave di firma Ed25519, persistita in `data/.audit_signing_key` (generata al primo avvio, `0600`; sovrascrivere con `AUDIT_SIGNING_KEY_FILE` per conservarla fuori dalla macchina). La sua identita pubblica e esposta tramite `GET /api/audit/public-key` (admin): `{algorithm, public_key_pem, fingerprint}`. La testa della chain viene firmata in checkpoint periodici (`certificate_audit.checkpoints.jsonl`).

`GET /api/audit/export` (admin, opzionale `?from_seq`/`?to_seq`) restituisce un bundle firmato e auto-verificabile — `{manifest, entries, bundle_signature}`. Il manifest fissa il fingerprint dell'istanza, la chiave pubblica, l'intervallo di `seq` e il `head_hash`; la firma e sul manifest canonico, che (tramite `head_hash`) si impegna transitivamente su ogni voce. Un revisore lo verifica **fuori dalla macchina** senza eseguire ne fidarsi di CertMate, con la possibilita di fissare la chiave esternamente:

```bash
python -m modules.core.audit_verify --bundle bundle.json --pubkey instance.pem
# OK: audit bundle intact and signed (128 entries, seq 0..127; signed by 0m2V5lDmnkPWOUHX)
```

Il verificatore controlla la struttura della chain, che il manifest corrisponda alle voci, la firma Ed25519 e che il fingerprint corrisponda alla chiave pubblica (opzionalmente fissata).

> **Onesta sul modello di minaccia.** La chain e la firma rilevano qualsiasi modifica interna, cancellazione o riordinamento, e collegano un'esportazione alla chiave pubblica di questa istanza — per chiunque non detenga la chiave di firma. Non **vincolano** l'operatore, che detiene la chiave e potrebbe ri-firmare una chain riscritta, e il troncamento finale viene rilevato solo confrontando le esportazioni nel tempo (un'esportazione successiva con meno voci) o rispetto a un checkpoint conservato esternamente. Vincolare completamente l'operatore richiede l'invio dei checkpoint firmati a un sink esterno append-only — un ancoraggio esterno opzionale, una funzionalita pianificata ma non ancora disponibile. Vedere [compliance.md](./compliance.md).

---

## Tipi di certificati

### API mTLS

Per l'autenticazione dei client API tramite TLS mutuale.

```
cert_usage: "api-mtls"
```

### VPN

Per l'autenticazione dei client VPN.

```
cert_usage: "vpn"
```

### Tipi di utilizzo personalizzati

E possibile utilizzare qualsiasi stringa di tipo di utilizzo personalizzato:

```
cert_usage: "custom-application"
```

---

## Buone pratiche

### Sicurezza

1. **Proteggi il tuo token**
 - Mantieni i token segreti
 - Ruota i token regolarmente
 - Usa HTTPS in produzione

2. **Gestione dei certificati**
 - Abilita il rinnovo automatico
 - Monitora le date di scadenza
 - Esamina regolarmente i log di audit
 - Revoca immediatamente i certificati compromessi

3. **Rate Limiting**
 - Rispetta i limiti di frequenza
 - Implementa un backoff esponenziale
 - Usa le operazioni batch quando possibile

### Performance

1. **Usa le operazioni batch**
 - Importa piu certificati contemporaneamente
 - Riduce le chiamate API
 - Migliore gestione degli errori

2. **Filtra i risultati**
 - Usa i parametri di query
 - Filtra per utilizzo o stato
 - Riduce il trasferimento di dati

3. **Utilizza la cache quando appropriato**
 - Memorizza in cache i metadati dei certificati
 - Aggiorna periodicamente
 - Verifica la scadenza localmente

---


---

<div align="center">

[← Torna alla documentazione](./README.md) • [Guida rapida →](./guide.md) • [Architettura →](./architecture.md)

</div>
