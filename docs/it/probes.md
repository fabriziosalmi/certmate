# Probe di Deployment

Le probe verificano che i tuoi certificati siano raggiungibili sulla rete eseguendo un TLS handshake in tempo reale con il server deployato.

## Configurazione

Configura le probe per dominio in **Impostazioni → Probe di deployment**.

| Campo | Descrizione |
|---|---|
| Dominio | Il dominio del certificato da sondare |
| Host | Nome host a cui connettersi e da inviare come SNI. Opzionale — di default il dominio. **Obbligatorio per i wildcard** (vedi sotto) |
| Porta | Porta TCP (default: 443 per HTTPS/TLS, 587 per SMTP STARTTLS) |
| Protocollo | `HTTPS/TLS` — handshake HTTPS standard, `TLS` — TLS grezzo senza HTTP, `SMTP STARTTLS` — SMTP semplice con upgrade a TLS |

Host, porta e protocollo sono memorizzati nel `metadata.json` del certificato
sotto le chiavi `deployment_host`, `deployment_port` e `deployment_protocol`.

### Certificati wildcard

Un certificato wildcard **non può essere sondato senza un host**, perché un
wildcard non copre il proprio apex: `*.example.com` non è valido per
`example.com`, quindi connettersi all'apex confronterebbe il nome sbagliato.
Invece di segnalare un rosso «Certificato errato» per ogni wildcard, CertMate
riporta uno stato neutro **Non verificabile** finché non viene impostato un host.

Imposta **Host** su un nome che il certificato copre davvero — `www.example.com`
per `*.example.com` — e la verifica funziona normalmente. Il campo ne suggerisce
uno.

Svuotare il campo Host lo rimuove, così un host impostato per errore si corregge
senza cancellare e ricreare la probe.

## Funzionamento

### Probe backend

1. Il backend legge la porta e il protocollo configurati nei metadati del certificato.
2. Viene aperta una connessione socket ed eseguito un TLS handshake.
3. L'impronta digitale del certificato servito viene confrontata con quella del certificato locale.
4. Il risultato (raggiungibile, deployato, corrispondenza certificato) viene messo in cache per 5 minuti (configurabile).

### Probe browser (fallback)

Quando la probe backend indica che il server non è raggiungibile **e** il protocollo è `HTTPS/TLS`, viene attivata una probe di riserva lato browser tramite `fetch(..., { mode: 'no-cors' })`. Questo permette di verificare la raggiungibilità anche quando il backend non riesce a connettersi (es. segmentazione di rete).

Per i protocolli `TLS` e `SMTP STARTTLS`, la probe browser viene **ignorata** perché i browser non sono in grado di eseguire connessioni TLS grezze o SMTP. Lo stato browser mostra "Non verificato".

### Cache

| Livello | Durata | Bypass |
|---|---|---|
| Backend (memoria) | 300 s (default) | Parametro `?refresh=1` |
| Frontend (memoria) | 300 s | `forceRefresh=true` (pulsante Verifica probe) |

## API

### Verificare lo stato di deployment

```
GET /api/certificates/<domain>/deployment-status
GET /api/certificates/<domain>/deployment-status?refresh=1
```

Restituisce:

| Campo | Tipo | Descrizione |
|---|---|---|
| domain | string | Il dominio sondato |
| deployed | boolean | Se un certificato è stato servito |
| reachable | boolean | Se il server ha risposto |
| certificate_match | boolean/null | Se il certificato servito corrisponde a quello locale |
| method | string | Protocollo utilizzato (`https-tls`, `tls`, `smtp-starttls`) |
| port | integer | Porta TCP sondara |
| protocol | string | Uguale a method |
| error | string | Messaggio di errore se la probe ha fallito |
| browser | object | Risultato della probe browser (solo HTTPS) |

### Configurare una probe

```
PATCH /api/certificates/<domain>
```

```json
{ "deployment_port": 444, "deployment_protocol": "https-tls" }
```

Impostare a `null` per rimuovere la configurazione:

```json
{ "deployment_port": null, "deployment_protocol": null }
```
