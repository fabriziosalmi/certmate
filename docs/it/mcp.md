# Server MCP (Model Context Protocol) CertMate

CertMate include un server MCP (Model Context Protocol) integrato scritto in Node.js. Questo consente agli assistenti IA agentici (come Claude o Gemini) di ispezionare in modo sicuro lo stato dei certificati, attivare rinnovi, richiedere diagnostiche e interagire direttamente con l'API CertMate.

## Funzionalità e strumenti

Il server MCP CertMate espone i seguenti strumenti agli assistenti IA:

**Inventario e stato**
1. **`certmate_list_certificates`** — Elenca tutti i certificati gestiti dall'istanza CertMate attiva (con scadenza, stato, domini).
2. **`certmate_get_certificate`** — Dettaglio completo per un dominio: stato, giorni alla scadenza, SAN, provider DNS/CA, flag di rinnovo automatico. Usalo per decidere se un certificato deve essere rinnovato.
3. **`certmate_get_activity`** — Attività recente/registro di audit, per diagnosticare cosa è cambiato o ha fallito.
4. **`certmate_diagnostics`** — Istantanea diagnostica completa e sanificata.
5. **`certmate_get_settings`** — Impostazioni globali e configurazione.

**Operazioni sul ciclo di vita**
6. **`certmate_create_certificate`** — Richiede un nuovo certificato TLS per un dominio (provider DNS, account, CA opzionali). Può restituire un `job_id` (HTTP 202) per l'emissione asincrona.
7. **`certmate_renew_certificate`** — Forza il rinnovo di un certificato esistente (può restituire anch'esso un `job_id`).
8. **`certmate_get_job`** — Interroga un job asincrono di creazione/rinnovo tramite `job_id` finché non segnala completato o fallito.
9. **`certmate_set_auto_renew`** — Abilita o disabilita il rinnovo automatico per un singolo dominio.
10. **`certmate_deploy_certificate`** — Esegue manualmente tutti i deploy hook configurati per un dominio.
11. **`certmate_download_certificate`** — Restituisce il materiale del certificato di un dominio come JSON (fullchain, key, chain) affinché un agente possa distribuirlo altrove.

**Provider**
12. **`certmate_list_dns_providers`** — Provider DNS supportati e configurati su questa istanza.
13. **`certmate_list_dns_accounts`** — Account provider DNS configurati (credenziali mascherate); usa un id account restituito come `account_id` durante la creazione di un certificato.

## Configurazione

### Prerequisiti
- Node.js (v18 o superiore)
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
4. Se un rinnovo restituisce un `job_id`, `certmate_get_job` finché non segnala `completed` / `failed`.
5. In caso di fallimento, segnalalo — e i canali di notifica di CertMate (email, Slack, Discord, Telegram, ntfy, Gotify) si attiveranno anch'essi su `certificate_failed`, così ricevi una notifica in ogni caso.

### Esempi di prompt pianificati

> **Giornaliero, 08:00** — "Usando gli strumenti MCP CertMate, elenca tutti i certificati. Per quelli con `days_left < 14`, chiama `certmate_renew_certificate`, poi interroga `certmate_get_job` fino al termine. Rispondi con un riepilogo di una riga per dominio e segnala eventuali fallimenti."

> **Settimanale** — "Chiama `certmate_get_activity` e `certmate_diagnostics`. Riassumi eventuali anomalie (rinnovi falliti, certificati scaduti, scheduler non in esecuzione) in tre punti. Se non c'è nulla di anomalo, indicalo."

> **Su richiesta** — "Emetti un certificato per `shop.example.com` usando `certmate_list_dns_providers` per scegliere un provider configurato e `certmate_list_dns_accounts` per l'id dell'account, poi monitora il job fino al completamento."

Poiché le condizioni vivono nel prompt, puoi modificare la policy (soglia, domini, azione in caso di fallimento) senza toccare alcun codice. Assegna all'agente un token con scope limitato esattamente a ciò che deve fare — `operator` per rinnovo/deploy, `admin` solo se deve modificare impostazioni o leggere diagnostiche.

## Sicurezza

1. **Protezione del token** — Il server MCP richiede un `CERTMATE_TOKEN` valido. Trasmette questo token in modo sicuro nell'header `Authorization` per tutte le richieste all'API CertMate.
2. **Privilegio minimo** — Limita il token a ciò di cui l'agente ha bisogno. Un custode di rinnovi pianificato ha bisogno di `operator`; riserva i token `admin` agli agenti che devono modificare impostazioni o estrarre diagnostiche. Revoca il token per disconnettere immediatamente l'agente.
3. **Compatibilità con la sanificazione dei log** — Strumenti come `certmate_diagnostics` recuperano i dati dopo che il Log Sanitizer ha rimosso le credenziali sensibili, proteggendo chiavi e token da fughe nei contesti LLM.

## Attribuzione audit

Affinché la traccia di audit possa distinguere le azioni di un agente da quelle di un operatore umano, assegna al server MCP una **chiave API dedicata contrassegnata come agente** anziché il token Bearer globale legacy:

1. In CertMate, vai in **Impostazioni → Chiavi API**, crea una chiave e spunta **Chiave agente IA** (oppure invia `"is_agent": true` a `POST /api/keys`). Limitala con `allowed_domains` e il ruolo minimo necessario.
2. Imposta quella chiave come `CERTMATE_TOKEN` per il server MCP.

Ogni azione sui certificati eseguita dall'agente viene registrata con `actor.kind="agent"`, l'id stabile della chiave e il `X-CertMate-Agent-Session` per processo inviato dal server — così puoi mostrare esattamente quali modifiche ai certificati ha effettuato un agente IA, sotto quale identità e raggruppate per esecuzione. Il token Bearer globale legacy riduce ogni chiamante a `api_user` senza id di chiave ed è registrato come `api_token`, non `agent`. L'header di sessione agente è un'informazione dichiarativa e non promuove mai autonomamente un chiamante a `agent`.

I record risultanti fanno parte della catena di audit a prova di manomissione; vedi [Registro audit](./api.md#audit-logging) e [compliance.md](./compliance.md).

---

<div align="center">

[← Torna alla documentazione](./README.md)

</div>
