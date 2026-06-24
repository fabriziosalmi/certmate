# Deploy Hook

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
| `on_events` | string array | no | Sottoinsieme di `["created", "renewed", "revoked"]`. Se assente, l'hook viene eseguito per tutti e tre. |

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
        "command": "/usr/sbin/nginx -s reload",
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

Se `enabled` al livello superiore è `false`, nessun hook viene eseguito durante gli eventi del certificato. I test manuali (`POST /api/deploy/test/<id>`) continuano a funzionare — utile per iterare su un hook prima di attivare l'interruttore principale.

---

## Configurazione degli hook

### Tramite UI

`Impostazioni → Deploy Hook`. Attiva/disattiva l'interruttore **Abilitato**, quindi aggiungi hook globali o per dominio. Ogni riga ha:

- nome + comando + timeout + caselle di controllo degli eventi
- un pulsante **Test** (esegue l'hook su un dominio sintetico `test.example.com` con `CERTMATE_EVENT=manual`)
- interruttore di abilitazione/disabilitazione
- eliminazione

Salva le impostazioni per rendere le modifiche persistenti.

### Tramite API

```bash
# Leggere la configurazione attuale
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Sostituire la configurazione (scrittura completa del documento — passa l'intero dizionario deploy_hooks)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

Il POST sostituisce l'intero blocco `deploy_hooks`; esegui il merge lato client se vuoi preservare le voci esistenti.

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
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` |
| `CERTMATE_DRY_RUN` | Impostato a `1` solo durante il dry-run; assente altrimenti. |

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

Esegue solo l'hook con quell'`id`, sul dominio sintetico `test.example.com`, con `CERTMATE_EVENT=manual`. Bypassa il filtro `on_events` — utile per "questo comando funziona davvero?".

### Eseguire tutti gli hook per un dominio (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Attiva tutti gli hook globali + specifici per il dominio abilitati per `api.example.com` con `CERTMATE_EVENT=manual`, ignorando `on_events`. Restituisce un riepilogo strutturato:

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

Questo è ciò che il pulsante **Esegui Deploy Hook ora** nel pannello di dettaglio del certificato richiama.

---

## Modello di sicurezza

Gli hook sono esecuzione di codice arbitrario per definizione — questa è la funzionalità. Per limitare il raggio d'azione, il campo command viene validato **al momento del salvataggio e nuovamente a runtime** (difesa in profondità) e rifiutato se contiene:

### Pattern shell bloccati

| Pattern | Motivo |
|---|---|
| `` ` `` (backtick) | sostituzione di comando |
| `$(...)` | sostituzione di comando |
| `${...}` | espansione di parametro (l'espansione delle variabili d'ambiente è consentita — solo la forma `${...}` è bloccata) |
| `&&` / `\|\|` | concatenazione logica |
| `;` | separatore di istruzione |
| `\|` | pipe |
| `\r` / `\n` | newline (impedisce a `sh -c` di interpretarli come `;`) |
| `> /` (redirect verso percorso assoluto) | impedisce la sovrascrittura di file di sistema |
| `<<` | here-doc |
| `eval`, `source`, `. /` | builtin shell che caricano codice arbitrario |

Se hai bisogno di uno di questi, inserisci la logica in un file script all'interno del container e richiama lo script direttamente:

```sh
/opt/scripts/deploy.sh
```

### Riferimenti a file bloccati

I riferimenti ai file sensibili di CertMate vengono rifiutati (senza distinzione tra maiuscole e minuscole):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`, `private*key`, `.pem`

Quindi `cat $CERTMATE_FULLCHAIN_PATH` è accettabile (la variabile viene espansa dalla shell, la stringa letterale `.pem` non compare in `command`), ma `cat /app/data/settings.json` verrebbe rifiutato al salvataggio.

### Cosa è consentito

- **Comandi semplici**: `/usr/sbin/nginx -s reload`, `systemctl reload haproxy`
- **Richieste curl (webhook)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Espansione di variabili negli argomenti**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **Payload JSON con `$VAR` (senza `${}`)**: `curl -d '{"domain":"$CERTMATE_DOMAIN"}' ...`
- **Invocazione di script singolo**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Se un comando che prima potevi salvare ora genera `Command blocked at runtime: contains dangerous shell metacharacters`, consulta le note di versione — il validatore è stato rafforzato nella v2.4.0 e leggermente allentato nella v2.4.1+.

---

## Ricette comuni

### Ricaricare nginx (globale, tutti gli eventi)

```sh
/usr/sbin/nginx -t && /usr/sbin/nginx -s reload
```

(Nota: `&&` è bloccato. Racchiudi questo in uno script: `/opt/scripts/reload-nginx.sh`.)

### Ricaricare haproxy

```sh
systemctl reload haproxy
```

### Inviare a un webhook Slack

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Sincronizzare il certificato su un host remoto

(Da racchiudere in uno script — `;` e `&&` non sono consentiti inline.)

```sh
/opt/scripts/sync-cert.sh
```

Dove `sync-cert.sh` è:

```sh
#!/bin/sh
set -eu
scp "$CERTMATE_FULLCHAIN_PATH" "$CERTMATE_KEY_PATH" deploy@lb:/etc/ssl/$CERTMATE_DOMAIN/
ssh deploy@lb 'systemctl reload haproxy'
```

### Ignorare gli hook durante il dry-run

Nel tuo script:

```sh
[ -n "${CERTMATE_DRY_RUN:-}" ] && { echo "dry run, skipping"; exit 0; }
```

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
| `Hook not found` | L'ID dell'hook nella richiesta di test non corrisponde a nessun hook nella configurazione salvata (l'UI era obsoleta o l'hook è stato appena eliminato). Aggiorna la pagina. |
| `Command blocked at runtime` | Uno dei [pattern bloccati](#pattern-shell-bloccati) ha superato il salvataggio. Sposta la logica problematica in un file script. |
| `exit code 127` | Comando non trovato all'interno del container (es. `nginx` non è nel `$PATH`). Usa percorsi assoluti o installa il binario nell'immagine. |
| `timeout after 30s` | L'hook ha superato il suo `timeout`. Aumentalo (max 300s) o sposta il lavoro in uno script in background. |
| `Deploy hooks disabled` | `deploy_hooks.enabled` è `false`. Attiva l'interruttore principale in Impostazioni. |
| `No hooks configured for <domain>` | Si tenta di eseguire hook per un dominio senza hook globali E senza voce sotto `domain_hooks[<domain>]`. Aggiungi un hook (o chiama `/api/deploy/test/<id>` per uno specifico). |

---

## Vedi anche

- [`modules/core/deployer.py`](../modules/core/deployer.py) — implementazione
- [`modules/web/settings_routes.py`](../modules/web/settings_routes.py) — endpoint `/api/deploy/*`
- [`templates/partials/settings_deploy.html`](../templates/partials/settings_deploy.html) — partial UI
- [`static/js/settings-deploy.js`](../static/js/settings-deploy.js) — componente Alpine

---

<div align="center">

[← Torna alla documentazione](./README.md)

</div>
