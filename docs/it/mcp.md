# Server MCP (Model Context Protocol) CertMate

<!-- CERTMATE-TRANSLATED-FROM a14882fc878f55e6 -->

CertMate include un server MCP (Model Context Protocol) integrato scritto in Node.js. Questo consente agli assistenti IA agentici (come Claude o Gemini) di ispezionare lo stato dei certificati, attivare rinnovi, richiedere diagnostiche e interagire direttamente con l'API CertMate.

## Funzionalità e strumenti

Il server MCP CertMate espone i seguenti strumenti agli assistenti IA:

**Inventario e stato**
1. **`certmate_list_certificates`** — Elenca tutti i certificati gestiti dall'istanza CertMate attiva (con scadenza, stato, domini).
2. **`certmate_get_certificate`** — Dettaglio completo per un dominio: stato, giorni alla scadenza, SAN, provider DNS/CA, flag di rinnovo automatico. Usalo per decidere se un certificato deve essere rinnovato.
3. **`certmate_get_activity`** — Attività recente/registro di audit, per diagnosticare cosa è cambiato o ha fallito.
4. **`certmate_diagnostics`** — Istantanea diagnostica completa e sanificata.
5. **`certmate_get_settings`** — Impostazioni globali e configurazione, con i valori segreti mascherati.

**Operazioni sul ciclo di vita**
6. **`certmate_create_certificate`** — Richiede un nuovo certificato TLS per un dominio (provider DNS, account, CA opzionali). Il server chiede sempre l'emissione asincrona, quindi restituisce un `job_id` (HTTP 202) da interrogare.
7. **`certmate_renew_certificate`** — Forza il rinnovo di un certificato esistente. Anch'esso asincrono: restituisce un `job_id`.
8. **`certmate_get_job`** — Interroga un job asincrono di creazione/rinnovo/modifica tramite `job_id` finché il suo stato non è `succeeded` o `failed` (`queued` e `running` non sono stati finali).
9. **`certmate_set_auto_renew`** — Abilita o disabilita il rinnovo automatico per un singolo dominio.
10. **`certmate_deploy_certificate`** — Esegue manualmente tutti i deploy hook configurati per un dominio.
11. **`certmate_download_certificate`** — Restituisce il materiale del certificato di un dominio come JSON (fullchain, key, chain) affinché un agente possa distribuirlo altrove.

**Provider**
12. **`certmate_list_dns_providers`** — Provider DNS supportati e configurati su questa istanza.
13. **`certmate_list_dns_accounts`** — Account provider DNS configurati (credenziali mascherate); usa un id account restituito come `account_id` durante la creazione di un certificato. **Richiede `admin`.**

**Modifica e rimozione**
14. **`certmate_update_certificate`** — Modifica sul posto la copertura di un certificato esistente riemettendolo: sostituisce l'insieme dei SAN e/o l'alias DNS-01. Il dominio principale è l'identità del certificato e qui non si può cambiare. Restituisce un `job_id`.
15. **`certmate_delete_certificate`** — **Distruttivo e irreversibile.** Rimuove i file del certificato dal disco e il dominio dalle impostazioni. **Richiede `admin`.**
16. **`certmate_get_certificate_file`** — Restituisce un singolo file del certificato come PEM grezzo, pronto da incollare, anziché incapsulato in JSON. `cert.pem`, `chain.pem` e `fullchain.pem` sono leggibili da un `viewer`; `privkey.pem`, `combined.pem` e `cert.pfx` contengono materiale di chiave e richiedono `operator`.

## Ruoli

Assegna all'agente il token più ristretto che gli basta, e tieni presente che
alcuni strumenti richiedono più degli altri:

| Strumento | Ruolo minimo |
|---|---|
| tutto ciò che è in Inventario e stato tranne la diagnostica (`certmate_get_settings` restituisce i segreti mascherati), `certmate_list_dns_providers`, `certmate_get_certificate_file` per `cert.pem` / `chain.pem` / `fullchain.pem` | `viewer` |
| `certmate_create_certificate`, `certmate_renew_certificate`, `certmate_get_job`, `certmate_set_auto_renew`, `certmate_update_certificate`, `certmate_download_certificate`, `certmate_get_certificate_file` per `privkey.pem` / `combined.pem` / `cert.pfx` | `operator` |
| `certmate_diagnostics` | `admin` |
| **`certmate_deploy_certificate`** | **`admin`** |
| **`certmate_list_dns_accounts`** | **`admin`** |
| **`certmate_delete_certificate`** | **`admin`** |

Deploy ed elenco degli account sono quelli che sorprendono: entrambi leggono o
usano credenziali memorizzate, quindi lato server sono `admin` anche se un agente
che si limita a rinnovare si accontenterebbe di `operator`. Un agente con ruolo
operator a cui si chiede di "scegliere un account ed emettere" riceverà un 403
sulla ricerca dell'account: passa l'`account_id` nel prompt, oppure dagli
deliberatamente un token admin.

## Configurazione

### Prerequisiti
- Node.js (>= 20 — `mcp/package.json` dichiara `engines.node: ">=20.0.0"`)
- npm

### Installazione
Naviga nella directory `mcp/` del repository CertMate e installa le dipendenze:
```bash
cd mcp
npm install
```

### Variabili d'ambiente
Il server MCP comunica con l'API REST CertMate e richiede due variabili d'ambiente:
- `CERTMATE_URL` — L'URL della tua istanza CertMate (predefinito: `http://localhost:8000`).
- `CERTMATE_TOKEN` — Un token Bearer API valido con le opportune autorizzazioni di ruolo (solitamente `operator` o `admin`). Per un agente verificabile, usa una chiave contrassegnata come chiave agente (vedi [Attribuzione audit](#attribuzione-audit)).

Opzionale:
- `CERTMATE_AGENT_SESSION` — Sovrascrive l'id di sessione per processo che il server invia a ogni chiamata (`X-CertMate-Agent-Session`), in modo che un'esecuzione possa essere correlata con l'id di un orchestratore esterno. Se non impostato, viene generato un UUID nuovo per ogni processo.
- `CERTMATE_AGENT_ID` — Un'etichetta per questo deployment dell'agente (`X-CertMate-Agent-Id`, predefinito `certmate-mcp-server`).

### Esempio di integrazione (configurazione Claude Desktop)
Per aggiungere il server MCP CertMate a Claude Desktop, aggiungi quanto segue al tuo file di configurazione (solitamente in `~/Library/Application Support/Claude/claude_desktop_config.json` su macOS o `%APPDATA%\Claude\claude_desktop_config.json` su Windows):

```json
{
  "mcpServers": {
    "certmate": {
      "command": "node",
      "args": ["/percorso/assoluto/verso/certmate/mcp/index.js"],
      "env": {
        "CERTMATE_URL": "http://localhost:8000",
        "CERTMATE_TOKEN": "your_secure_bearer_token"
      }
    }
  }
}
```

### Altri client MCP (Gemini, ecc.)

Il server comunica tramite MCP standard su stdio, quindi qualsiasi client che supporta MCP funziona allo stesso modo: puntalo su `node /percorso/assoluto/verso/certmate/mcp/index.js` e imposta le due variabili d'ambiente. Nulla nel server è specifico per Claude.

## Utilizzo di CertMate con un agente IA (job pianificati)

La maggior parte degli assistenti di punta supporta ora i **task pianificati** (Claude, Gemini e altri). Combinando questo con il server MCP si ottiene un "custode dei certificati" autonomo: descrivi la policy in linguaggio naturale con condizioni esplicite, il modello si pianifica da solo e a ogni esecuzione usa gli strumenti sopra per applicare la policy. Il pattern è agnostico rispetto al modello — qualsiasi sistema in grado di eseguire un prompt salvato su un calendario e chiamare strumenti MCP funzionerà.

### Il ciclo eseguito dall'agente

1. `certmate_list_certificates` (o `certmate_get_certificate` per dominio) per leggere `days_left` / stato.
2. Decisione in base alla tua condizione, ad es. *rinnova quando `days_left < 14`*.
3. `certmate_renew_certificate` per ogni dominio interessato.
4. Ogni rinnovo restituisce un `job_id`; chiama `certmate_get_job` finché non segnala `succeeded` / `failed`.
5. In caso di fallimento, segnalalo. Un job di rinnovo o di riemissione fallito emette anche `certificate_failed`, così i canali di notifica di CertMate (email, Slack, Discord, Telegram, ntfy, Gotify) inviano comunque una notifica. Due eccezioni: un job fallito perché un'altra operazione teneva già il dominio (`error_code: DOMAIN_OPERATION_IN_PROGRESS`) non lo emette, e nemmeno una creazione asincrona fallita, quindi in quei casi il segnale è il resoconto dell'agente.

### Esempi di prompt pianificati

> **Giornaliero, 08:00** — "Usando gli strumenti MCP CertMate, elenca tutti i certificati. Per quelli con `days_left < 14`, chiama `certmate_renew_certificate`, poi interroga `certmate_get_job` fino al termine. Rispondi con un riepilogo di una riga per dominio e segnala eventuali fallimenti."

> **Settimanale** — "Chiama `certmate_get_activity` e `certmate_diagnostics`. Riassumi eventuali anomalie (rinnovi falliti, certificati scaduti, scheduler non in esecuzione) in tre punti. Se non c'è nulla di anomalo, indicalo."

> **Su richiesta** — "Emetti un certificato per `shop.example.com` usando `certmate_list_dns_providers` per scegliere un provider configurato e `certmate_list_dns_accounts` per l'id dell'account, poi monitora il job fino al completamento."

Poiché le condizioni vivono nel prompt, puoi modificare la policy (soglia, domini, azione in caso di fallimento) senza toccare alcun codice. Assegna all'agente un token con scope limitato esattamente a ciò che deve fare — `operator` per il rinnovo, `admin` solo se deve eseguire i deploy hook, elencare gli account DNS, eliminare certificati o leggere la diagnostica.

## Sicurezza

1. **Protezione del token** — Il server MCP richiede un `CERTMATE_TOKEN` valido. Invia questo token nell'header `Authorization` di ogni richiesta all'API CertMate. Il `CERTMATE_URL` predefinito è `http://localhost:8000` in chiaro; quando CertMate gira su un altro host, usa un URL `https://`, altrimenti il token attraversa la rete in chiaro.
2. **Privilegio minimo** — Limita il token a ciò di cui l'agente ha bisogno. Un custode di rinnovi pianificato ha bisogno di `operator`; riserva i token `admin` agli agenti che devono eseguire i deploy hook, elencare gli account DNS, eliminare certificati o estrarre la diagnostica. Revoca il token per disconnettere immediatamente l'agente.
3. **Compatibilità con la sanificazione dei log** — Strumenti come `certmate_diagnostics` recuperano i dati dopo che il Log Sanitizer ha rimosso le credenziali sensibili, proteggendo chiavi e token da fughe nei contesti LLM.

## Attribuzione audit

Affinché la traccia di audit possa distinguere le azioni di un agente da quelle di un operatore umano, assegna al server MCP una **chiave API dedicata contrassegnata come agente** anziché il token Bearer globale legacy:

1. In CertMate, vai in **Impostazioni → Chiavi API**, crea una chiave e spunta **Chiave agente IA** (oppure invia `"is_agent": true` a `POST /api/keys`). Assegnale il ruolo minimo necessario e, per una chiave `viewer` o `operator`, limitala con `allowed_domains`. Una chiave `admin` non può essere limitata per dominio: il server la rifiuta con un 400.
2. Imposta quella chiave come `CERTMATE_TOKEN` per il server MCP.

Ogni azione sui certificati eseguita dall'agente viene registrata con `actor.kind="agent"`, l'id stabile della chiave e il `X-CertMate-Agent-Session` per processo inviato dal server — così puoi mostrare esattamente quali modifiche ai certificati ha effettuato un agente IA, sotto quale identità e raggruppate per esecuzione. Il token Bearer globale legacy riduce ogni chiamante a `api_user` senza id di chiave ed è registrato come `api_token`, non `agent`. L'header di sessione agente è un'informazione dichiarativa e non promuove mai autonomamente un chiamante a `agent`.

I record risultanti fanno parte della catena di audit a prova di manomissione; vedi [Registro audit](./api.md#audit-logging) e [compliance.md](./compliance.md).

---

<div align="center">

[← Torna alla documentazione](./README.md)

</div>
