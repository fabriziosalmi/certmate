# CertMate Certificati Client - Guida all'utilizzo

## Per iniziare

### Installazione

```bash
# 1. Installa le dipendenze
pip install -r requirements.txt

# 2. Avvia CertMate
python app.py

# 3. Apri il dashboard
# Naviga su: http://localhost:5000/client-certificates
```

### Primi passi

1. **Genera la CA** — Creata automaticamente al primo avvio
2. **Accedi al dashboard** — Vai su `/client-certificates`
3. **Crea un certificato** — Usa il modulo Web o l'API
4. **Scarica i file** — Ottieni il certificato, la chiave e il CSR

---

## Dashboard Web

### Funzionalità del dashboard

**URL**: `http://localhost:5000/client-certificates`

#### Pannello statistiche
- Totale certificati
- Numero attivi
- Numero revocati
- Ripartizione per tipo di utilizzo

#### Tabella certificati
- Elenco di tutti i certificati
- Ricerca per nome comune
- Filtro per tipo di utilizzo
- Filtro per stato
- Ordinamento per data di creazione

#### Modulo di creazione certificato

**Campi del modulo**:
- Nome comune (obbligatorio)
- Indirizzo email
- Organizzazione
- Unità organizzativa
- Tipo di utilizzo (VPN, API-mTLS, ecc.)
- Giorni di validità (predefinito: 365)
- Genera chiave (casella di spunta)
- Note

**Esempio**:
```
Common Name: user@example.com
Email: user@example.com
Organization: ACME Corp
Usage Type: api-mtls
Days Valid: 365
```

#### Importazione CSV in blocco

1. Clicca sulla scheda "Importazione in blocco"
2. Prepara un file CSV con le intestazioni:
 ```
 common_name,email,organization,cert_usage,days_valid
 user1@example.com,user1@example.com,ACME Corp,api-mtls,365
 user2@example.com,user2@example.com,ACME Corp,vpn,365
 ```
3. Trascina e rilascia oppure clicca per caricare
4. Rivedi l'anteprima
5. Clicca su "Importa"

---

## Operazioni comuni

### Creare un singolo certificato

#### Tramite il dashboard Web

1. Vai su `/client-certificates`
2. Compila il modulo "Crea certificato"
3. Clicca su "Crea"
4. Il certificato appare nella tabella

#### Tramite API

```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
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

---

### Scaricare i file di un certificato

#### Tramite il dashboard Web

1. Trova il certificato nella tabella
2. Clicca sull'icona "Scarica"
3. Seleziona il tipo di file:
   - **CRT** — Certificato (pubblico)
   - **KEY** — Chiave privata (da tenere segreta)
   - **CSR** — Richiesta di firma del certificato

#### Tramite API

```bash
# Scarica il certificato
curl http://localhost:5000/api/client-certs/CERT_ID/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o my-cert.crt

# Scarica la chiave
curl http://localhost:5000/api/client-certs/CERT_ID/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o my-key.key
```

---

### Revocare un certificato

#### Tramite il dashboard Web

1. Trova il certificato nella tabella
2. Clicca sul pulsante "Revoca"
3. Inserisci il motivo della revoca (facoltativo)
4. Conferma

#### Tramite API

```bash
curl -X POST http://localhost:5000/api/client-certs/CERT_ID/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "reason": "compromised"
 }'
```

**Motivi di revoca**:
- `compromised` — La chiave è stata compromessa
- `superseded` — Sostituito da un nuovo certificato
- `unspecified` — Revoca generica
- Qualsiasi motivo personalizzato

---

### Rinnovare un certificato

#### Tramite il dashboard Web

1. Trova il certificato nella tabella
2. Clicca sul pulsante "Rinnova"
3. Conferma il rinnovo

#### Tramite API

```bash
curl -X POST http://localhost:5000/api/client-certs/CERT_ID/renew \
 -H "Authorization: Bearer TOKEN"
```

**Nota**: Il rinnovo crea un nuovo certificato con:
- Stesso nome comune
- Nuovo numero seriale
- Nuova data di scadenza
- ID originale aggiornato

---

### Elencare e filtrare i certificati

#### Tramite il dashboard Web

1. Vai alla tabella dei certificati
2. Usa la casella "Cerca" per il nome comune
3. Usa il menu a tendina "Tipo di utilizzo" per filtrare
4. Usa il menu a tendina "Stato" (Attivo/Revocato)
5. Clicca su "Applica filtri"

#### Tramite API

```bash
# Elenca tutti
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtra per utilizzo
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Filtra per stato
curl "http://localhost:5000/api/client-certs?revoked=false" \
 -H "Authorization: Bearer TOKEN"

# Cerca
curl "http://localhost:5000/api/client-certs?search=user@" \
 -H "Authorization: Bearer TOKEN"
```

---

### Verificare lo stato di un certificato (OCSP)

#### Tramite API

```bash
curl http://localhost:5000/api/ocsp/status/SERIAL_NUMBER \
 -H "Authorization: Bearer TOKEN"
```

**Risposta**:
```json
{
 "certificate_status": "good",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z"
}
```

---

### Ottenere la lista di revoca (CRL)

#### Scarica la CRL

```bash
# Formato PEM
curl http://localhost:5000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Formato DER
curl http://localhost:5000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl
```

#### Ottieni le informazioni CRL

```bash
curl http://localhost:5000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

---

## Operazioni in blocco

### Formato CSV

```csv
common_name,email,organization,cert_usage,days_valid
user1@example.com,user1@example.com,ACME Corp,api-mtls,365
user2@example.com,user2@example.com,ACME Corp,vpn,365
user3@example.com,user3@example.com,ACME Corp,api-mtls,730
```

### Colonne obbligatorie

- `common_name` — Soggetto del certificato (obbligatorio)

### Colonne facoltative

- `email` — Indirizzo email
- `organization` — Nome dell'organizzazione
- `organizational_unit` — Nome del reparto
- `cert_usage` — Tipo di utilizzo
- `days_valid` — Validità in giorni

### Tramite il dashboard Web

1. Vai alla scheda "Importazione in blocco"
2. Carica il file CSV
3. Rivedi l'anteprima
4. Clicca su "Importa tutto"

### Tramite API

```bash
curl -X POST http://localhost:5000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "headers": ["common_name", "email", "organization"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
 ["user2@example.com", "user2@example.com", "ACME Corp"],
 ["user3@example.com", "user3@example.com", "ACME Corp"]
 ]
 }'
```

### Risultati dell'importazione

Restituisce i contatori di successo/fallimento:
```json
{
 "total": 3,
 "successful": 3,
 "failed": 0,
 "errors": [],
 "certificates": [{"identifier": "cert-batch-001", "common_name": "user1@example.com"},
 {"identifier": "cert-batch-002", "common_name": "user2@example.com"},
 {"identifier": "cert-batch-003", "common_name": "user3@example.com"}
 ]
}
```

---

## Tipi di utilizzo dei certificati

### API mTLS

Per l'autenticazione mutual TLS dei client API.

```
Usage Type: api-mtls
Typical Validity: 1 year (365 days)
```

### VPN

Per l'autenticazione dei client VPN.

```
Usage Type: vpn
Typical Validity: 1-2 years (365-730 days)
```

### Tipi personalizzati

Puoi creare certificati per qualsiasi utilizzo personalizzato:

```
Usage Type: custom-application
Usage Type: internal-service
Usage Type: mobile-app
```

---

## Rinnovo automatico

### Configurazione

- **Orario di verifica**: Ogni giorno alle 3:00
- **Soglia**: 30 giorni prima della scadenza
- **Azione**: Rinnovo automatico se abilitato

### Abilitazione del rinnovo automatico

Il rinnovo automatico è abilitato per impostazione predefinita. Per verificare lo stato:

```bash
curl http://localhost:5000/api/client-certs/CERT_ID \
 -H "Authorization: Bearer TOKEN"
```

Cerca:
```json
{
 "renewal": {
 "renewal_enabled": true,
 "renewal_threshold_days": 30
 }
}
```

### Comportamento del rinnovo

In caso di rinnovo automatico:
- Nuovo certificato creato
- Stesso CN (nome comune)
- Nuovo numero seriale
- Nuova data di scadenza
- L'ID originale rimane invariato
- Il vecchio certificato viene sostituito

---

## Risoluzione dei problemi

### Problemi comuni

#### Creazione del certificato non riuscita

**Errore**: `Failed to create certificate`

**Soluzioni**:
1. Verifica che il nome comune sia valido
2. Controlla che tutti i campi obbligatori siano compilati
3. Verifica che la CA sia inizializzata
4. Consulta i log per ulteriori dettagli

#### Download del file non riuscito

**Errore**: `File not found`

**Soluzioni**:
1. Verifica che l'ID del certificato esista
2. Controlla il tipo di file (crt, key, csr)
3. Assicurati che il certificato non sia stato eliminato
4. Controlla lo spazio su disco

#### Limite di richieste superato

**Errore**: `HTTP 429 Too Many Requests`

**Soluzioni**:
1. Attendi prima di riprovare
2. Usa le operazioni in blocco
3. Implementa un backoff esponenziale
4. Controlla il limite per il tuo endpoint

### Consultazione dei log

Visualizza i log dell'applicazione:
```bash
tail -f logs/certmate.log
```

Visualizza i log di audit:
```bash
tail -f logs/audit/certificate_audit.log
```

---

## Buone pratiche di sicurezza

### Chiavi private

- **NON** condividere mai le tue chiavi private
- **NON** includere mai le chiavi in git
- Conserva le chiavi in modo sicuro
- Usa i permessi 0600 sui file

### Certificati

- Monitora le date di scadenza
- Rinnova prima della scadenza
- Revoca immediatamente i certificati compromessi
- Conserva i log di audit per la conformità

### Token API

- Ruota i token regolarmente
- Usa HTTPS in produzione
- Non includere i token nel codice sorgente
- Usa le variabili d'ambiente

### Revoca

Revoca sempre quando:
- La chiave è compromessa
- Il certificato viene sostituito
- Un utente lascia l'organizzazione
- Il servizio viene dismesso

---

## Suggerimenti per le prestazioni

### Per grandi volumi

Usa le operazioni in blocco invece delle creazioni individuali:
```bash
# Corretto: una richiesta per 1000 certificati
POST /api/client-certs/batch

# Scorretto: 1000 richieste per 1000 certificati
POST /api/client-certs/create × 1000
```

### Per il filtraggio

Filtra lato server:
```bash
# Corretto: il server filtra
GET /api/client-certs?usage=api-mtls

# Scorretto: il client filtra tutto
GET /api/client-certs
```

### Per il monitoraggio

Usa l'endpoint delle statistiche:
```bash
GET /api/client-certs/stats
```

---

## Supporto

### Documentazione

- [Riferimento API](./api.md) — Tutti gli endpoint
- [Architettura](./architecture.md) — Progettazione del sistema
- [Note di rilascio](../RELEASE_NOTES.md) — Cronologia delle versioni

### Test

Vedi `test_e2e_complete.py` per esempi di utilizzo.

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Riferimento API →](./api.md) • [Architettura →](./architecture.md)

</div>
