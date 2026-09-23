# Deploy Hook

<!-- CERTMATE-TRANSLATED-FROM 380a402d93da0cfb -->
<!-- CERTMATE-STALE-TRANSLATION -->
> **Questa traduzione non è aggiornata.** La versione inglese ([`docs/deploy-hooks.md`](../deploy-hooks.md)) è stata modificata da allora ed è quella che fa fede. In caso di discordanza vale il documento inglese.

Chiude [#117](https://github.com/fabriziosalmi/certmate/issues/117).

I deploy hook sono brevi comandi shell che CertMate esegue **dopo** il rilascio, il rinnovo o la revoca di un certificato. Usali per ricaricare servizi, inviare il nuovo certificato a un load balancer, inviare una notifica, o qualsiasi altra azione necessaria a seguito di una esecuzione riuscita di certbot.

Questa guida illustra:

1. [Cos'è un hook](#cosè-un-hook)
2. [Configurazione degli hook (UI + JSON)](#configurazione-degli-hook)
3. [Variabili d'ambiente passate al comando](#variabili-dambiente-passate-al-comando)
4. [Attivazione manuale](#attivazione-manuale)
5. [Modello di sicurezza: perché alcuni comandi vengono rifiutati](#modello-di-sicurezza)
6. [Ricette comuni](#ricette-comuni)
7. [Audit, cronologia e debug](#audit-cronologia-e-debug)

---

## Cos'è un hook

Un hook è un oggetto JSON con cinque campi:

| Campo | Tipo | Obbligatorio | Note |
|---|---|---|---|
| `id` | string | sì | Identificatore stabile (un UUID va bene; l'UI ne genera uno automaticamente). Usato da `/api/deploy/test/<id>`. |
| `name` | string | sì | Etichetta leggibile mostrata nell'UI e nel log di audit. |
| `command` | string | sì | Un singolo comando shell (`sh -c`). Max 1024 caratteri. Vedi [sicurezza](#modello-di-sicurezza). |
| `enabled` | boolean | no | Predefinito `true`. Gli hook disabilitati vengono ignorati durante l'attivazione automatica ma possono ancora essere testati manualmente. |
| `timeout` | integer | no | Secondi. Predefinito 30, limitato al `MAX_TIMEOUT` di sistema (attualmente 300). |
| `on_events` | string array | no | Sottoinsieme di `["created", "renewed", "revoked"]`. Se assente al salvataggio della configurazione, viene impostato a `["created", "renewed"]`. Un hook scritto a mano in `settings.json` senza `on_events` non parte mai su un evento del certificato; parte comunque da un'attivazione manuale. |

Gli hook si trovano sotto due chiavi in `deploy_hooks`:

- **`global_hooks`** — si attivano per ogni dominio. Ideale per "ricaricare nginx dopo qualsiasi modifica al certificato".
- **`domain_hooks`** — indicizzati per nome di dominio esatto. Ideale per "inviare il certificato LB di `api.example.com` su S3 dopo il rinnovo di quel certificato specifico".

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "global_hooks": [
      {
        "id": "5f8...",
        "name": "Ricarica nginx",
        "command": "curl -fsS -X POST https://lb.internal/api/reload",
        "enabled": true,
        "timeout": 30,
        "on_events": ["created", "renewed"]
      }
    ],
    "domain_hooks": {
      "api.example.com": [
        {
          "id": "9b1...",
          "name": "Invia al LB",
          "command": "/opt/scripts/push-cert-to-lb.sh",
          "enabled": true,
          "timeout": 120,
          "on_events": ["renewed"]
        }
      ]
    }
  }
}
```

Se `enabled` al livello superiore è `false`, nessun hook viene eseguito durante gli eventi del certificato. I test dei singoli hook (`POST /api/deploy/test/<id>`) continuano a funzionare — utile per iterare su un hook prima di attivare l'interruttore principale. L'esecuzione di tutti gli hook di un dominio (`POST /api/certificates/<domain>/deploy`) invece no: viene rifiutata finché l'interruttore è spento.

---

## Configurazione degli hook

### Tramite UI

`Impostazioni → Deploy Hook`. Attiva/disattiva l'interruttore **Abilitato**, quindi aggiungi hook globali o per dominio. Ogni riga ha:

- nome + comando + timeout + caselle di controllo degli eventi
- un pulsante **Test** (esegue l'hook su un dominio sintetico `test.example.com` con `CERTMATE_EVENT=test` e `CERTMATE_DRY_RUN=1`)
- interruttore di abilitazione/disabilitazione
- eliminazione

Salva le impostazioni per rendere le modifiche persistenti.

### Tramite API

```bash
# Leggere la configurazione attuale
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Scrivere la configurazione (le chiavi di primo livello inviate sostituiscono quelle salvate)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

Il POST fa un merge al primo livello di `deploy_hooks`: ogni chiave inviata (`enabled`, `global_hooks`, `domain_hooks`, `targets`) sostituisce per intero il valore salvato, e una chiave omessa resta com'era. Quindi inviare `global_hooks` sostituisce l'intera lista; per aggiungere un hook, leggi la lista, aggiungi la voce e rimandala. Una lista vuota esplicita svuota quella chiave.

---

## Variabili d'ambiente passate al comando

Ogni invocazione imposta queste variabili nell'ambiente del processo dell'hook:

| Variabile | Valore di esempio |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (solo intermediari, senza il certificato foglia — per i target che richiedono la chain come file separato) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` (Deploy Now) / `test` (test del singolo hook) |
| `CERTMATE_DRY_RUN` | Impostato a `1` solo nel test di un singolo hook (`/api/deploy/test/<id>`, il pulsante **Test**); assente altrimenti, anche per Deploy Now. Il comando viene eseguito comunque: è solo un segnale che lo script può controllare. |

I percorsi sono nella directory dei certificati di CertMate: `/app/certificates` nell'immagine Docker, oppure dove punta `CERTMATE_CERT_DIR`.

Il tuo comando può fare riferimento a queste variabili come `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"`, ecc. I valori vengono passati tramite l'ambiente, non per interpolazione di stringa, quindi il quoting funziona come in qualsiasi shell normale.

L'hook viene eseguito come utente del processo CertMate (nell'immagine Docker: `certmate`, UID/GID 1000:1000) all'interno del container. Tutto ciò che esegui con `cp`, `curl`, `ssh`, ecc. deve essere raggiungibile da lì.

---

## Attivazione manuale

Due modi per attivare un hook al di fuori del normale ciclo di vita del certificato:

### Test per singolo hook (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Esegue solo l'hook con quell'`id`, sul dominio sintetico `test.example.com` (o sul `domain` indicato in un body JSON), con `CERTMATE_EVENT=test` e `CERTMATE_DRY_RUN=1`. Il comando viene eseguito davvero. Bypassa il filtro `on_events`, il flag `enabled` dell'hook e l'interruttore principale — utile per "questo comando funziona davvero?".

### Eseguire tutti gli hook per un dominio (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Attiva tutti gli hook globali + specifici per il dominio abilitati (e ogni deploy target tipizzato applicabile) per `api.example.com` con `CERTMATE_EVENT=manual`, ignorando `on_events`. Viene rifiutato finché l'interruttore principale è spento. Restituisce un riepilogo strutturato:

```jsonc
{
  "ok": true,
  "total": 3,
  "succeeded": 2,
  "failed": 1,
  "results": [
    {"hook_name": "Ricarica nginx", "exit_code": 0, "duration_ms": 142, ...},
    ...
  ]
}
```

Questo è ciò che richiama il pulsante **Run deploy hooks now** (icona play, sezione Deployment del pannello di dettaglio del certificato).

---

## Modello di sicurezza

Gli hook sono esecuzione di codice arbitrario per definizione — questa è la funzionalità. Per limitare il raggio d'azione, il campo command viene validato **al momento del salvataggio e nuovamente a runtime** (difesa in profondità) e rifiutato se contiene:

### Pattern shell bloccati

| Pattern | Motivo |
|---|---|
| `` ` `` (backtick) | sostituzione di comando |
| `$(...)` | sostituzione di comando |
| `${...}` | espansione di parametro. `$VAR` è consentito, e anche `${CERTMATE_NOME}` con la graffa chiusa subito dopo il nome; ogni altra forma `${...}`, compresa `${CERTMATE_DOMAIN:-x}`, è bloccata |
| `&&` / `\|\|` | concatenazione logica |
| `;` | separatore di istruzione |
| `\r` / `\n` | newline (impedisce a `sh -c` di interpretarli come `;`) |
| `> /` (redirect verso percorso assoluto) | impedisce la sovrascrittura di file di sistema |
| `<<` | here-doc |
| `eval`, `source`, `.` (la forma breve di source, con qualunque argomento) | builtin shell che caricano codice arbitrario |

Due cose che sembrerebbero da elenco sono consentite di proposito (#115): una pipe semplice, per l'elaborazione a valle come `curl ... | grep -q ok` (entrambi i lati devono essere un comando presente nell'immagine — `jq` non lo è), e un redirect verso un percorso relativo (`> out.txt`). È bloccato solo il redirect verso un percorso assoluto.

Se hai bisogno di uno di questi, inserisci la logica in un file script all'interno del container e richiama lo script direttamente:

```sh
/opt/scripts/deploy.sh
```

### Riferimenti a file bloccati

I riferimenti ai file sensibili di CertMate vengono rifiutati (senza distinzione tra maiuscole e minuscole):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`

I file del certificato non sono nella lista: installare il certificato e la sua chiave (`privkey.pem`, `$CERTMATE_KEY_PATH`) è il compito normale di un hook. `cat /app/data/settings.json` verrebbe rifiutato al salvataggio.

### Cosa è consentito

- **Comandi semplici**: `curl -fsS https://lb.internal/api/reload`, `openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates`
- **Richieste curl (webhook)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Espansione di variabili negli argomenti**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **Payload JSON con `$VAR`**: `curl -H "Content-Type: application/json" -d "{\"domain\":\"$CERTMATE_DOMAIN\"}" ...`. Il corpo va tra virgolette doppie: tra apici singoli la shell non espande `$CERTMATE_DOMAIN` e il ricevente riceve il testo letterale.
- **Invocazione di script singolo**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Se un comando che prima potevi salvare ora genera `Command blocked at runtime: contains dangerous shell metacharacters`, consulta le note di versione — il validatore è stato rafforzato nella v2.4.0 e leggermente allentato nella v2.4.1+.

---

**Dentro il container di CertMate**, come il processo che ha emesso il certificato — non sull'host Docker, e non sulla macchina che vuoi ricaricare.

È la cosa da capire prima di scrivere un hook, e gli esempi di questa pagina la sbagliavano. Un comando come `systemctl reload haproxy` sembra ricaricare il tuo load balancer. Non lo fa: gira in un container che non ha systemd, né haproxy, né nginx, ed esce con 127 — *not found* — che è quanto [#856](https://github.com/fabriziosalmi/certmate/issues/856) ha segnalato per `scp`.

Cosa contiene davvero l'immagine pubblicata, per un hook:

| | |
|---|---|
| **presenti** | `sh`, `bash`, `curl`, `openssl` |
| **assenti** | `ssh`, `scp`, `sftp`, `rsync`, `jq`, `nginx`, `systemctl`, `haproxy`, e tutto il resto |

L'elenco è corto di proposito: lo stage di runtime installa tre pacchetti, e il Dockerfile spiega perché — ogni pacchetto aggiunto è superficie da aggiornare e scansionare ([#403](https://github.com/fabriziosalmi/certmate/issues/403)). Non è una dimenticanza, quindi un hook deve lavorare con quello che c'è, oppure raggiungere qualcosa che ha di più.

### Tre modi per agire su una macchina che non è questa

**Chiederglielo via rete.** Quasi tutto ciò che vale la pena ricaricare ha un'API, e `curl` c'è. È lo schema che funziona senza cambiare nulla.

**Costruire una propria immagine.** Quella di CertMate è una base come un'altra:

```
FROM fabriziosalmi/certmate:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
USER certmate
```

Così `scp` c'è, insieme a ciò che hai aggiunto, e la superficie è tua da aggiornare invece che di tutti.

**Montare uno script.** Un hook può chiamare qualunque percorso nel container, quindi uno script montato funziona — ma gira comunque nel container, quindi anche ciò che invoca deve stare lì dentro.

---

## Ricette comuni

Girano nell'immagine così com'è pubblicata. Ognuna è verificata contro di essa.

### Inviare a un webhook Slack

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Dire a qualcos'altro che il certificato è cambiato

Qualunque cosa abbia un'API HTTP — un load balancer, un endpoint di gestione della configurazione, un piccolo agente accanto al servizio:

```sh
curl -fsS -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" --data-binary "@$CERTMATE_FULLCHAIN_PATH" https://lb.internal/api/certs/$CERTMATE_DOMAIN
```

`-f` conta: senza, `curl` esce con 0 anche su un errore HTTP, e l'hook riporta successo per un deploy che non è avvenuto.

### Controllare cosa è stato emesso prima di spedirlo

```sh
openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -subject -dates
```

### Eseguire uno script proprio

```sh
/opt/scripts/deploy.sh
```

Montato nel container e scritto per ciò che il container ha. Usa uno script ogni volta che ti servono `;` o `&&`: il campo del comando li rifiuta, ed è comunque lì che quella logica appartiene.
---

## Audit, cronologia e debug

### Feed di attività

`GET /api/deploy/history?limit=50` e la scheda **Attività** nell'UI mostrano le ultime N esecuzioni di hook con: nome dell'hook, dominio, evento, codice di uscita, durata, stdout/stderr (troncati a 4096 byte ciascuno) e timestamp.

### Console di debug

Impostazioni → Deploy Hook dispone di una console di debug (pulsante di attivazione in basso a destra) che trasmette gli eventi `loadConfig` / `saveConfig` / `testHook` lato client. Utile quando si itera sull'UI.

### Log di audit

Ogni esecuzione di hook scrive una voce `operation: deploy_hook` nel log di audit con stato `success`/`failure` più il nome dell'hook, il codice di uscita e la durata. Visibile tramite la scheda Attività e `/api/audit`.

### Errori comuni

| Sintomo | Causa probabile |
|---|---|
| `Hook <id> is no longer in settings...` | L'ID dell'hook nella richiesta di test non corrisponde a nessun hook nella configurazione salvata: la pagina è obsoleta, l'hook è stato appena eliminato, oppure il suo comando è stato rifiutato al salvataggio. Aggiorna la pagina. |
| `Command blocked at runtime` | Uno dei [pattern bloccati](#pattern-shell-bloccati) ha superato il salvataggio. Sposta la logica problematica in un file script. |
| `exit code 127` | Comando non trovato all'interno del container (es. `nginx` non è nel `$PATH`). Usa percorsi assoluti o installa il binario nell'immagine. |
| `timeout after 30s` | L'hook ha superato il suo `timeout`. Aumentalo (max 300s) o sposta il lavoro in uno script in background. |
| `Deploy hooks are disabled. Enable them in Settings → Deploy.` | `deploy_hooks.enabled` è `false` e hai eseguito tutti gli hook di un dominio. Attiva l'interruttore principale in Impostazioni. |
| `No enabled hooks or deploy targets configured for <domain>...` | Si tenta di eseguire hook per un dominio senza hook globali abilitati, senza voci abilitate sotto `domain_hooks[<domain>]` e senza target tipizzati applicabili. Aggiungi un hook (o chiama `/api/deploy/test/<id>` per uno specifico). |

---

## Vedi anche

- [`modules/core/deployer.py`](../../modules/core/deployer.py) — implementazione
- [`modules/web/settings_routes.py`](../../modules/web/settings_routes.py) — endpoint `/api/deploy/*`
- [`templates/partials/settings_deploy.html`](../../templates/partials/settings_deploy.html) — partial UI
- [`static/js/settings-deploy.js`](../../static/js/settings-deploy.js) — componente Alpine

---

<div align="center">

[← Torna alla documentazione](./README.md)

</div>
