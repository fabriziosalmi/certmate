# CertMate Certificati Client - Guida all'utilizzo

<!-- CERTMATE-TRANSLATED-FROM 88bb16eb976577c4 -->

## Panoramica

CertMate Certificati Client e una soluzione completa e pronta per la produzione per la gestione dei certificati client con:

- **CA auto-firmata** — Genera e gestisci la tua Certification Authority
- **Gestione completa del ciclo di vita** — Crea, rinnova, revoca e monitora i certificati client
- **OCSP & CRL** — Stato dei certificati in tempo reale e liste di revoca
- **Dashboard Web** — Interfaccia intuitiva per la gestione dei certificati
- **API REST** — API completa per l'automazione
- **Operazioni batch** — Importa certificati client in blocco via CSV (massimo 100 righe per richiesta)
- **Log di audit** — Traccia tutte le operazioni per la conformità
- **Rate limiting** — Protezione integrata contro gli abusi

---


## Per iniziare

### Installazione

```bash
# 1. Installa le dipendenze
pip install -r requirements.txt

# 2. Avvia CertMate
python app.py

# 3. Apri il dashboard
# Naviga su: http://localhost:8000/client-certificates
```

### Primi passi

1. **Genera la CA** — Creata automaticamente al primo avvio
2. **Accedi al dashboard** — Vai su `/client-certificates`
3. **Crea un certificato** — Usa il modulo Web o l'API
4. **Scarica i file** — Ottieni il certificato, la chiave e il CSR

---

## Dashboard Web

### Funzionalità del dashboard

**URL**: `http://localhost:8000/client-certificates`

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
curl -X POST http://localhost:8000/api/client-certs/create \
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
curl http://localhost:8000/api/client-certs/CERT_ID/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o my-cert.crt

# Scarica la chiave
curl http://localhost:8000/api/client-certs/CERT_ID/download/key \
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
curl -X POST http://localhost:8000/api/client-certs/CERT_ID/revoke \
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
curl -X POST http://localhost:8000/api/client-certs/CERT_ID/renew \
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
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtra per utilizzo
curl "http://localhost:8000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Filtra per stato
curl "http://localhost:8000/api/client-certs?revoked=false" \
 -H "Authorization: Bearer TOKEN"

# Cerca
curl "http://localhost:8000/api/client-certs?search=user@" \
 -H "Authorization: Bearer TOKEN"
```

---

### Verificare lo stato di un certificato (OCSP)

#### Tramite API

```bash
curl http://localhost:8000/api/ocsp/status/SERIAL_NUMBER \
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
curl http://localhost:8000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Formato DER
curl http://localhost:8000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl
```

#### Ottieni le informazioni CRL

```bash
curl http://localhost:8000/api/crl/download/info \
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
curl -X POST http://localhost:8000/api/client-certs/batch \
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

- **Orario di verifica**: Ogni giorno. I certificati client fra le 02:00 e le
  04:00; i certificati server, di cui il resto di questa sezione descrive la
  regola, fra le 01:00 e le 03:00 (ogni giro parte alla sua ora con fino a
  un'ora di scarto casuale, prima o dopo)
- **Soglia**: 30 giorni prima della scadenza (`renewal_threshold_days`), quando
  non supera meta della durata del certificato; vedi sotto
- **Azione**: Rinnovo automatico se abilitato

### Quando si rinnova un certificato

Decide una sola regola, e la risposta del certificato la riporta:
`needs_renewal` diventa vero a `renews_at`, l'istante in cui la scansione lo
rinnova (`GET /api/certificates/<domain>`, dal contratto API 2.40). La
decisione la prende CertMate, che dice a certbot di rinnovare; il cancello di
certbot non conta piu, quindi un aggiornamento di certbot non puo cambiare
quando CertMate rinnova.

- **La soglia**, quando non supera meta della durata: 30 giorni di un
  certificato da 90, come sempre, oppure 45 se imposti 45.
- **Altrimenti la durata**: un terzo, o la meta per un certificato che vive
  meno di 10 giorni. 30 giorni non hanno senso per un certificato da 45, che
  quindi si rinnova quando ne mancano 15; uno da 160 ore quando ne mancano
  circa 3.
- **La finestra della CA**, quando ne ha pubblicata una per questo certificato
  (sotto): prima o dopo la soglia.

Per un certificato da 90 giorni con i 30 predefiniti, i rinnovi avvengono
quando sono sempre avvenuti.

### Quando la CA non e d'accordo con la soglia (ARI)

La soglia e l'opinione di CertMate, ed e la stessa per ogni
certificato e per ogni CA. Dalla [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html)
una CA puo pubblicare la propria, per singolo certificato: un endpoint
`renewalInfo` che risponde con una finestra entro cui desidera che quel
certificato venga sostituito. Let's Encrypt ne espone uno, in produzione e in
staging. step-ca non ancora (0.30.2, misurato; vedi smallstep/certificates#2162),
quindi su una step-ca privata decide solo la soglia e il pannello del
certificato dice che la CA non pubblica una finestra.

La scansione di rinnovo TLS lo chiede, per ogni certificato, e la finestra
decide in entrambe le direzioni. **Anticipa** un rinnovo: e cosi che
un'istanza viene a sapere di una sostituzione in blocco — una emissione
errata, un intermedio compromesso, una decisione del CA/Browser Forum — giorni
prima che arrivi la revoca, invece che quando il certificato smette di
funzionare. E **posticipa** un rinnovo che la soglia avrebbe fatto, fino al
punto della finestra che la CA ha chiesto.

**Un rinvio ha un pavimento.** Una finestra non trattiene mai un certificato
quando resta un sesto della sua durata (15 giorni su 90, 7,5 su 45, circa uno
su 160 ore), ne oltre la fine della finestra stessa, quindi una CA che sbaglia,
o una finestra vecchia, non puo spingere un certificato verso la scadenza. Ogni
assenza — una CA che non pubblica `renewalInfo`, un endpoint irraggiungibile,
una risposta malformata, un certificato autofirmato senza Authority Key
Identifier con cui nominarlo — non lascia alcuna finestra, e decide la soglia.
La finestra resta su disco, quindi un rinvio dura da una scansione alla
successiva.

Dentro la finestra CertMate sceglie un punto, derivato dall'identificatore del
certificato stesso, cosi la scelta e la stessa a ogni scansione e due
certificati non finiscono sullo stesso istante. E esattamente a questo che
serve la finestra: una CA non vuole che tutti i suoi client rinnovino insieme.

Il riepilogo della scansione li conta come `ari_advanced` e `ari_postponed`,
cosi un rinnovo che la tua configurazione non spiega, o uno che non fa, resta
attribuibile.

Il pannello di dettaglio del certificato mostra cosa ha detto la CA
all'ultima scansione, alla voce **CA renewal window**: la finestra, l'istante
al suo interno in cui CertMate rinnova, e il link di spiegazione della CA
quando lo fornisce. Quando non c'e una finestra dice quale assenza e: la CA
non ne pubblica, la CA non ha risposto all'ultimo controllo, oppure il
certificato non puo essere nominato in ARI. Lo stesso record e restituito come
`renewal_info` da `GET /api/certificates/<domain>`. Viene letto da cio che la
scansione ha salvato, quindi aprire la dashboard non manda mai una richiesta
alla CA. Subito dopo un rinnovo mostra "Not checked yet" finche la scansione
successiva non chiede del nuovo certificato.

Imposta `"ari_enabled": false` in `settings.json` per disattivarlo; e attivo
per impostazione predefinita e costa una GET non autenticata per certificato
per scansione, piu una per CA all'ora per la directory.

### Una soglia oltre i 30 giorni

Prima della release 2.40.0 CertMate chiedeva a certbot di rinnovare senza
forzarlo, e il cancello di certbot rinnovava solo negli ultimi 30 giorni prima
della scadenza, quindi un `renewal_threshold_days` di 45 si comportava come 30.
La release 2.40.0 ha forzato i rinnovi che una soglia oltre i 30 giorni dava
da fare, e dal contratto API 2.40 ogni rinnovo deciso da CertMate e forzato:
una soglia di 45 rinnova un certificato da 90 giorni 45 giorni prima della
scadenza. Un rinnovo che la soglia anticipa rispetto alla regola della durata
arriva con due protezioni:

- **Al massimo `early_renewals_per_sweep` per scansione** (predefinito 10, tra
  1 e 50). Alzare la soglia su molti certificati distribuisce i rinnovi
  anticipati su piu notti invece di mandare tutti gli ordini alla CA in una
  sola. Il riepilogo della scansione li conta come `early_forced`, e quelli
  lasciati alla scansione successiva come `early_deferred`.
- **Un certificato piu giovane di una settimana, o di un terzo della sua
  durata, non viene mai rinnovato in anticipo.** Una soglia oltre meta della
  durata non conta piu (decide la durata), quindi questa protezione e l'ultima
  difesa contro un certificato le cui date non tornano.

Un certificato che richiede attenzione per un altro motivo, una chiave servita
che manca o non corrisponde, non viene forzato: viene riparato dalla sua
lineage senza una chiave nuova.

### Abilitazione del rinnovo automatico

Il rinnovo automatico è abilitato per impostazione predefinita. Per verificare lo stato:

```bash
curl http://localhost:8000/api/client-certs/CERT_ID \
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

Il corpo della risposta dice quale limite è scattato. `"code": "ISSUANCE_QUEUE_FULL"`
significa che ci sono troppi job di certificato in coda o in esecuzione: riprova
quando alcuni terminano, oppure aumenta `CERTMATE_ISSUANCE_QUEUE_LIMIT` /
`CERTMATE_ISSUANCE_WORKERS`. Il limite di frequenza dell'API e quello sui
tentativi di login restituiscono entrambi `retry_after` in secondi.

### Consultazione dei log

Visualizza i log dell'applicazione (CertMate scrive su stdout):
```bash
docker logs -f certmate
```

Un file di log esiste solo se imposti `CERTMATE_LOG_FILE` (ad es.
`CERTMATE_LOG_FILE=/app/logs/certmate.log`); in quel caso fai `tail -f` su quel percorso.

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
- [Note di rilascio](../../RELEASE_NOTES.md) — Cronologia delle versioni

### Test

Vedi `test_e2e_complete.py` per esempi di utilizzo.

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Riferimento API →](./api.md) • [Architettura →](./architecture.md)

</div>
