# Deploy Hook

<!-- CERTMATE-TRANSLATED-FROM 0d31dc7a82589489 -->

Chiude [#117](https://github.com/fabriziosalmi/certmate/issues/117).

I deploy hook sono brevi comandi shell che CertMate esegue **dopo** il rilascio, il rinnovo o la revoca di un certificato. Usali per ricaricare servizi, inviare il nuovo certificato a un load balancer, inviare una notifica, o qualsiasi altra azione necessaria a seguito di una esecuzione riuscita di certbot.

> **Su `revoked`.** Tramite CertMate si possono revocare solo i certificati client — `POST /api/client-certs/<id>/revoke` — ed è quindi in quel momento che parte un hook `revoked`, con `CERTMATE_DOMAIN` impostato all'identificatore del certificato client. Per un certificato server non esiste un'operazione di revoca, quindi per esso non parte alcun hook.

Questa guida illustra:

1. [Cos'è un hook](#cosè-un-hook)
2. [Configurazione degli hook (UI + JSON)](#configurazione-degli-hook)
3. [Variabili d'ambiente passate al comando](#variabili-dambiente-passate-al-comando)
4. [Finestre di manutenzione](#finestre-di-manutenzione)
5. [Attivazione manuale](#attivazione-manuale)
6. [Modello di sicurezza: perché alcuni comandi vengono rifiutati](#modello-di-sicurezza)
7. [Dove gira un hook](#dove-gira-un-hook)
8. [Ricette comuni](#ricette-comuni)
9. [Audit, cronologia e debug](#audit-cronologia-e-debug)
10. [Deploy target tipizzati](#deploy-target-tipizzati)

---

## Cos'è un hook

Un hook è un oggetto JSON con questi campi:

| Campo | Tipo | Obbligatorio | Note |
|---|---|---|---|
| `id` | string | sì | Identificatore stabile (un UUID va bene; l'UI ne genera uno automaticamente). Usato da `/api/deploy/test/<id>`. |
| `name` | string | sì | Etichetta leggibile mostrata nell'UI e nel log di audit. |
| `command` | string | sì | Un singolo comando shell (`sh -c`). Max 1024 caratteri. Vedi [sicurezza](#modello-di-sicurezza). |
| `enabled` | boolean | no | Predefinito `true`. Gli hook disabilitati vengono ignorati durante l'attivazione automatica ma possono ancora essere testati manualmente. |
| `timeout` | integer | no | Secondi. Predefinito 30, limitato al `MAX_TIMEOUT` di sistema (attualmente 300). |
| `on_events` | string array | no | Sottoinsieme di `["created", "renewed", "revoked"]`. Se assente al salvataggio della configurazione, viene impostato a `["created", "renewed"]` — `revoked` va scelto esplicitamente, così che aggiungere un hook non inizi a eseguire comandi su revoche per cui nessuno l'ha scritto. Un hook scritto a mano in `settings.json` non viene mai normalizzato, quindi senza `on_events` non parte su nessun evento del certificato; parte comunque da un'attivazione manuale. |
| `window` | object | no | Una [finestra di manutenzione](#finestre-di-manutenzione). Se assente, l'hook viene eseguito non appena il certificato viene emesso o rinnovato — il comportamento che ogni hook ha avuto finora. |

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
        "name": "Tell the load balancer",
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
          "name": "Push to LB",
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

`Settings → Deploy Hooks`. Attiva/disattiva l'interruttore **Abilitato**, quindi aggiungi hook globali o per dominio. Ogni riga ha:

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
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` — **non impostata** per un [certificato solo CSR](../csr-only-certificates.md), la cui chiave resta sul dispositivo |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (solo intermediari, senza il certificato foglia — per i target che richiedono la chain come file separato) |
| `CERTMATE_TAGS` | `loadbalancer,env:prod` — i [tag](./api.md) del certificato, separati da virgole e in minuscolo; **vuota** quando non ne ha, e sempre impostata, così che un hook possa farvi affidamento (dal contratto API 2.33) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` (Deploy Now) / `test` (test del singolo hook). `renewed` segue anche la [sostituzione di un certificato esterno](../api.md#replace-an-external-certificate) tramite upload. |
| `CERTMATE_DRY_RUN` | Impostato a `1` solo nel test di un singolo hook (`/api/deploy/test/<id>`, il pulsante **Test**); assente altrimenti, anche per Deploy Now. Il comando viene eseguito comunque: è solo un segnale che lo script può controllare. |

I percorsi sono nella directory dei certificati di CertMate: `/app/certificates` nell'immagine Docker, oppure dove punta `CERTMATE_CERT_DIR`.

Il tuo comando può fare riferimento a queste variabili come `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"`, ecc. I valori vengono passati tramite l'ambiente, non per interpolazione di stringa, quindi il quoting funziona come in qualsiasi shell normale.

L'hook viene eseguito come utente del processo CertMate (nell'immagine Docker: `certmate`, UID/GID 1000:1000) all'interno del container. Tutto ciò che esegui con `cp`, `curl`, `ssh`, ecc. deve essere raggiungibile da lì.

---

## Finestre di manutenzione

Chiude [#632](https://github.com/fabriziosalmi/certmate/issues/632).

Un certificato si rinnova quando è in scadenza, cioè in un momento che nessuno ha scelto: il ciclo di rinnovo pianificato gira alle 02:00 con un'ora di jitter, e solo per i certificati che quella notte rientrano nella soglia. L'hook veniva poi eseguito immediatamente. Per un hook che riavvia un database o ricarica un load balancer, questo significa un disservizio a un'ora imprevedibile.

Una `window` separa le due cose. Il certificato si rinnova comunque quando è in scadenza — questo è determinato dalla scadenza e non è negoziabile — ma il **deploy** viene trattenuto fino alla successiva apertura della finestra.

```jsonc
"window": {
  "start": "02:00",          // obbligatorio, formato 24 ore HH:MM
  "end": "04:00",            // obbligatorio, escluso
  "days": ["sat", "sun"],    // facoltativo; omettilo o lascialo vuoto per tutti i giorni
  "timezone": "Europe/Rome"  // nome IANA facoltativo, predefinito UTC
}
```

Lo stesso campo funziona sui deploy target tipizzati, ed è di solito lì che lo vuoi: il rollout di un secret Kubernetes è esattamente il tipo di deploy che appartiene a una finestra di manutenzione.

### Quali sono le regole

- **`end` è escluso.** `02:00`–`04:00` e `04:00`–`06:00` sono adiacenti, non sovrapposte.
- **Una finestra può attraversare la mezzanotte**, e appartiene al giorno in cui **inizia**. Una finestra `22:00`–`04:00` su `["fri"]` è aperta alle 02:00 di sabato mattina. Leggerla nell'altro modo ti costringerebbe, senza dirlo, a spuntare anche il sabato.
- **`start` e `end` non possono essere uguali.** Si leggerebbe ugualmente bene come "sempre aperta" e come "mai aperta", quindi viene rifiutato anziché indovinato. Usa `00:00`–`23:59` per un giorno intero.
- **Il fuso orario è un nome IANA** (`Europe/Rome`, `America/New_York`), validato al salvataggio. Un errore di battitura viene rifiutato in quel momento, anziché trattenere in silenzio ogni deploy per una finestra che non si apre mai.
- **L'ora legale è gestita dal fuso, non dall'aritmetica.** Nel giorno del passaggio primaverile all'ora legale, una finestra `02:00`–`04:00` su Roma si apre alle 03:00 locali, perché l'intervallo 02:00–02:59 non esiste; nel giorno autunnale è aperta durante entrambi i passaggi di 02:00–02:59.

### Cosa succede mentre un deploy è trattenuto

La coda si trova in `data/pending_deploys.json` e sopravvive a un riavvio — la finestra è tipicamente a ore di distanza.

- Un secondo rinnovo prima che la finestra si apra **non** accoda un secondo deploy. L'hook legge il certificato dal disco quando viene eseguito, quindi un'unica esecuzione differita pubblica sempre il più recente.
- Se l'hook viene eliminato o disabilitato, o se i deploy hook vengono spenti del tutto, il deploy in coda viene **scartato** al successivo svuotamento della coda. La tua configurazione attuale dice di non eseguirlo.
- Se rimuovi la finestra, il deploy viene rilasciato al successivo svuotamento della coda anziché attendere ancora una volta.
- **Deploy Now consuma il deploy che era in attesa.** Se l'hook (o il target tipizzato) che esegui a mano riesce, la sua voce in coda per quel dominio viene rimossa: il certificato è stato consegnato, ed eseguirlo di nuovo all'apertura della finestra sarebbe un secondo deploy non annunciato. Se l'esecuzione manuale **fallisce**, la voce resta, quindi il deploy nella finestra fa da nuovo tentativo. Un rinnovo che avviene *mentre* Deploy Now è in esecuzione mantiene la propria voce, perché quel certificato è più recente di quello letto dall'esecuzione manuale. I due non eseguono mai lo stesso deploy nello stesso momento: se la finestra si apre mentre Deploy Now sta eseguendo un hook, l'esecuzione pianificata lo salta e il tick successivo lo trova consegnato oppure ancora dovuto; se invece l'esecuzione pianificata è già dentro l'hook quando premi il pulsante, Deploy Now attende che finisca e poi viene eseguito. Un deploy in coda che non vuoi può comunque essere rimosso solo disabilitando o eliminando l'hook (viene poi scartato al successivo svuotamento della coda).
- Un hook che fallisce dentro la sua finestra **non** viene riaccodato. Viene registrato nella cronologia come qualsiasi altro fallimento; riaccodarlo significherebbe ritentare ogni minuto per tutto il tempo in cui la finestra resta aperta.
- Un deploy ancora in attesa dopo sette giorni viene registrato nel log come warning. Non è un limite — l'attesa è la funzionalità — ma una settimana significa che la finestra non si è aperta affatto, il che di solito vuol dire che i giorni o il fuso orario non sono quelli che intendevi.

I deploy trattenuti per una finestra sono invisibili ovunque altrove: il certificato si è rinnovato, la cronologia non mostra nulla e nulla è fallito. `GET /api/deploy/pending` li elenca insieme alla finestra che stanno aspettando e al momento in cui si aprirà la prossima volta.

```bash
curl -H "Authorization: Bearer $TOKEN" https://certmate.local/api/deploy/pending
```

```json
[
  {
    "kind": "hook", "id": "6f0…", "domain": "api.example.com",
    "event": "renewed", "queued_at": "2026-09-08T13:12:04+00:00",
    "window": "02:00-04:00 Europe/Rome (sat, sun)",
    "next_run": "2026-09-12T00:00:00+00:00", "orphaned": false
  }
]
```

### Cosa ignora la finestra

**Deploy Now** la ignora. Premerlo significa scegliere questo momento; trattenere il deploy fino alle 02:00 farebbe sì che il pulsante non producesse alcun effetto visibile. Ciò che consegna non viene consegnato di nuovo: vedi *Cosa succede mentre un deploy è trattenuto*. Ignora la finestra allo stesso modo anche `POST /api/deploy/test/<id>`, che non tocca mai la coda.

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
    {"hook_name": "Reload nginx", "exit_code": 0, "duration_ms": 142, ...},
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
| `${...}` | espansione di parametro. `$VAR` è consentito, e anche `${CERTMATE_NAME}` con la graffa chiusa subito dopo il nome; ogni altra forma `${...}`, compresa `${CERTMATE_DOMAIN:-x}`, è bloccata |
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

Un comando che nomina uno dei file sensibili di CertMate viene rifiutato (senza distinzione tra maiuscole e minuscole):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`

I file del certificato non sono nella lista: installare il certificato e la sua chiave (`privkey.pem`, `$CERTMATE_KEY_PATH`) è il compito normale di un hook. `cat /app/data/settings.json` viene rifiutato al salvataggio.

Il controllo riconosce quei nomi **così come sono scritti**. Ferma un hook che nomina uno di quei file per errore. Non ferma un comando che raggiunge lo stesso file senza scriverne il nome: un glob (`settings*`), un carattere jolly `?` o un nome spezzato dalle virgolette (`settings"."json`) passano. È una protezione dagli incidenti, non un confine di sicurezza. Solo un admin può salvare o eseguire un hook, e un admin che può salvare un hook può già eseguire qualsiasi comando come CertMate. Lo stesso vale per i pattern di shell elencati sopra.

### Inviare la chiave privata da un hook

Un hook può inviare la chiave a un URL: `CERTMATE_KEY_PATH` non è nella lista dei file bloccati e `curl` è presente nell'immagine, quindi `curl --data-binary @"$CERTMATE_KEY_PATH" …` viene salvato. CertMate non guarda cosa fa un comando del genere con la chiave. I controlli spettano a te:

- usa `https://`, mai `http://`: la chiave attraverserebbe la rete in chiaro;
- non aggiungere `-k`/`--insecure`, che disattiva il controllo che il server sia quello che intendevi;
- non aggiungere `-L`/`--location`, che ripete la richiesta, chiave inclusa, a qualunque indirizzo indicato dalla risposta;
- non lasciare che il comando stampi nell'output ciò che il server risponde: l'output dell'hook viene conservato nella cronologia, e il log di audit non può essere modificato.

Per Kubernetes usa invece il [target tipizzato](#deploy-target-tipizzati), che rispetta per te i primi tre punti.

### Cosa è consentito

- **Comandi semplici**: `curl -fsS https://lb.internal/api/reload`, `openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates`
- **Richieste curl POST (webhook)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Espansione di variabili negli argomenti**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **Payload JSON con `$VAR`**: `curl -H "Content-Type: application/json" -d "{\"domain\":\"$CERTMATE_DOMAIN\"}" ...`. Il corpo va tra virgolette doppie: tra apici singoli la shell non espande `$CERTMATE_DOMAIN` e il ricevente riceve il testo letterale.
- **Invocazione di script singolo**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Se un comando che prima potevi salvare ora genera `Command blocked at runtime: contains dangerous shell metacharacters`, consulta le note di versione — il validatore è stato rafforzato nella v2.4.0 e leggermente allentato nella v2.4.1+.

---

## Dove gira un hook

**Dentro il container di CertMate**, come il processo che ha emesso il certificato — non sull'host Docker, e non sulla macchina che vuoi ricaricare.

È l'unica cosa da fare giusta prima di scrivere un hook, e gli esempi di questa pagina la sbagliavano. Un comando come `systemctl reload haproxy` sembra ricaricare il tuo load balancer. Non lo fa: gira in un container che non ha systemd, né haproxy, né nginx, ed esce con 127 — `not found` — che è quanto [#856](https://github.com/fabriziosalmi/certmate/issues/856) ha segnalato per `scp`.

Cosa contiene davvero l'immagine pubblicata, a disposizione di un hook:

| | |
|---|---|
| **presenti** | `sh`, `bash`, `curl`, `openssl` |
| **assenti** | `ssh`, `scp`, `sftp`, `rsync`, `jq`, `nginx`, `systemctl`, `haproxy`, e tutto il resto |

L'elenco è corto di proposito. Lo stage di runtime installa tre pacchetti, e il Dockerfile spiega perché: ogni pacchetto aggiunto è superficie da aggiornare e scansionare ([#403](https://github.com/fabriziosalmi/certmate/issues/403)). Non è una dimenticanza, quindi un hook deve lavorare con quello che c'è — oppure raggiungere qualcosa che ha di più.

`tests/test_a_hook_runs_where_certmate_runs.py` verifica gli esempi qui sotto contro l'immagine, così questa tabella non può più discostarsene.

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

**Montare uno script e le sue dipendenze.** Un hook può chiamare qualunque percorso nel container, quindi uno script montato con un bind mount funziona — ma gira comunque nel container, quindi anche tutto ciò che invoca deve stare lì dentro.

---

## Ricette comuni

Girano nell'immagine così com'è pubblicata. Ognuna è verificata contro di essa.

### Inviare a un webhook Slack

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Dire a qualcos'altro che il certificato è cambiato

Qualunque cosa abbia un'API HTTP — un load balancer, un endpoint di gestione della configurazione, un tuo piccolo agente accanto al servizio:

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

Montato nel container e scritto per ciò che il container ha. Usa uno script ogni volta che ti servono `;` o `&&`: il campo del comando li rifiuta entrambi, ed è comunque nello script che quella logica deve stare.

### Agire solo su alcuni certificati

Assegna dei tag a un certificato (`PATCH /api/certificates/<domain>` con `tags`, oppure **Edit** nel suo pannello di dettaglio) e un solo hook globale può decidere, certificato per certificato, se agire. `CERTMATE_TAGS` è sempre impostata, separata da virgole e in minuscolo, e un tag contiene solo lettere, cifre e `. _ - : /`, quindi è sicuro usarla senza virgolette. Nel tuo script:

```sh
echo ",$CERTMATE_TAGS," | grep -q ',loadbalancer,' || exit 0
```

Sono le virgole attorno a rendere esatta la corrispondenza: senza di esse `loadbalancer` corrisponderebbe anche a un tag chiamato `loadbalancer-old`.

### Saltare il lavoro reale durante un'esecuzione di Test

Nel tuo script (la variabile è impostata solo dal **Test** del singolo hook):

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
| `Hook <id> is no longer in settings...` | L'ID dell'hook nella richiesta di test non corrisponde a nessun hook nella configurazione salvata: la pagina è obsoleta, l'hook è stato appena eliminato, oppure il suo comando è stato rifiutato al salvataggio. Aggiorna la pagina. |
| `Command blocked at runtime` | Uno dei [pattern bloccati](#pattern-shell-bloccati) ha superato il salvataggio. Sposta la logica problematica in un file script. |
| `exit code 127` | Comando non trovato all'interno del container (es. `nginx` non è nel `$PATH`). Usa percorsi assoluti o installa il binario nell'immagine. |
| `timeout after 30s` | L'hook ha superato il suo `timeout`. Aumentalo (max 300s) o sposta il lavoro in uno script in background. |
| `Deploy hooks are disabled. Enable them in Settings → Deploy.` | `deploy_hooks.enabled` è `false` e hai eseguito tutti gli hook di un dominio. Attiva l'interruttore principale in Impostazioni. |
| `No enabled hooks or deploy targets configured for <domain>...` | Si tenta di eseguire hook per un dominio senza hook globali abilitati, senza voci abilitate sotto `domain_hooks[<domain>]` e senza alcun target tipizzato per esso. Aggiungi un hook (o chiama `/api/deploy/test/<id>` per uno specifico). |

---

## Deploy target tipizzati

Un **deploy target tipizzato** è un'alternativa dichiarativa a un hook shell per una destinazione comune, così non devi scriverti a mano `kubectl` + credenziali. I target si trovano sotto `deploy_hooks.targets` e partono dagli stessi punti del ciclo di vita degli hook (emissione + ogni rinnovo, e deploy manuale), con lo stesso isolamento dei fallimenti — un target che fallisce scrive nel log, nell'audit e solleva l'avviso `deploy_hook_failed`, ma non blocca mai l'operazione sul certificato.

Il primo target tipizzato è **Kubernetes Secret**: scrive i `fullchain.pem` / `privkey.pem` rinnovati in un Secret `kubernetes.io/tls` tramite Server-Side Apply (un'unica create-or-update idempotente).

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "targets": [
      {
        "id": "prod-web-tls",
        "name": "Publish to prod web Secret",
        "type": "kubernetes-secret",
        "enabled": true,
        "on_events": ["created", "renewed"],
        "domains": ["example.com"],          // vuoto/omesso = tutti i domini gestiti
        "config": {
          "secret_name": "example-tls",
          "namespace": "web",
          // Opzione A — parlare direttamente con l'API server:
          "api_server": "https://10.0.0.1:6443",
          "token": "<service-account bearer token>",
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",  // facoltativo; altrimenti le CA di sistema
          "verify_ssl": true
          // Opzione B — in esecuzione dentro il cluster: imposta invece "in_cluster": true,
          // e API server, token, CA e namespace predefinito vengono letti dal
          // service account montato.
        }
      }
    ]
  }
}
```

Configuralo tramite `POST /api/deploy/config` (lo stesso endpoint riservato agli admin usato per gli hook shell). Il token del service account usato dovrebbe essere limitato a `patch`/`create` sui Secret nel namespace di destinazione.

> **Sicurezza:** la configurazione dei deploy è riservata agli admin e — come un secret incorporato in un hook shell — il `token` Kubernetes è salvato nelle impostazioni e restituito agli admin su `GET /api/deploy/config`. Mantieni il token con i permessi minimi.

Un target invia la chiave privata all'indirizzo con cui è configurato, quindi vengono garantite due cose:

- **I redirect non vengono seguiti.** Un redirect ripeterebbe la richiesta, chiave inclusa, a qualunque indirizzo indicato dalla risposta. Un `3xx` dall'API server viene riportato come un fallimento che lo dice esplicitamente (senza l'indirizzo indicato); punta `api_server` all'indirizzo che risponde direttamente.
- **Ciò che torna indietro non viene mai copiato nei registri.** La risposta a una richiesta fallita viene mostrata all'operatore, e finisce anche nel log di audit, nella cronologia dei deploy e nell'avviso di fallimento. Il log di audit è una hash chain e non può essere modificato in seguito, quindi dalla risposta vengono tolti il bearer token e la chiave (come PEM, con escape JSON, in base64, URL-encoded, o una sua singola riga) prima che venga accorciata e conservata.

`verify_ssl: false` è ancora accettato per un cluster con un certificato che non puoi verificare. Disattiva il controllo che il server sia quello che hai configurato, quindi usalo solo su una rete che controlli.

### Target webhook: consegnare il certificato e, facoltativamente, la chiave

Un **webhook di notifica** (Impostazioni → Notifiche) *annuncia* un rinnovo, e ciò che riporta raggiunge avvisi, mail e log. Non trasporta mai la chiave privata ([webhooks.md](../webhooks.md)). Il **target webhook** *consegna*: invia il certificato e la chain e, se il template lo richiede, la chiave privata, a un endpoint HTTPS scelto da te, tipicamente un'appliance o un servizio con un'API di upload. Sono cose diverse con regole diverse, quindi questo è un deploy target e non un ulteriore placeholder del webhook di notifica.

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "targets": [
      {
        "id": "lb-cert",
        "name": "Upload to the load balancer",
        "type": "webhook",
        "enabled": true,
        "domains": ["shop.example.com"],      // obbligatorio: mai "tutti i domini" per impostazione predefinita
        "on_events": ["created", "renewed"],
        "config": {
          "url": "https://lb.internal:8443/api/certificate",
          "method": "POST",                   // POST, PUT o PATCH
          "payload_template": "{\"name\": \"{{domain}}\", \"cert\": \"{{fullchain}}\", \"key\": \"{{privkey_pkcs8}}\"}",
          "auth_type": "bearer", "auth_token": "<token>",   // none | bearer | basic | header
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",     // oppure "pin_sha256": "<fingerprint>"
          "allow_internal": true,             // la destinazione è su una rete privata
          "acknowledge_key_delivery_to": "lb.internal"      // necessario perché il template nomina la chiave
        }
      }
    ]
  }
}
```

**Nell'UI.** Impostazioni → Deploy → **Deploy Targets** elenca ogni target e permette di modificare quelli webhook: nome, domini (obbligatori), eventi, URL, metodo, autenticazione, signing secret, come viene verificato il server, un interruttore per la rete privata, timeout e tentativi, e il payload con le variabili come pulsanti. Le variabili della chiave sono rosse, e aggiungerne una è ciò che fa scattare la conferma descritta più sotto. **Preview what would be sent** chiama l'endpoint di anteprima descritto più sotto e mostra la destinazione con la sua porta, come viene verificato il server, i file che una consegna legge, gli header (con le credenziali mascherate) e il body renderizzato con un certificato e una chiave di esempio. Un'anteprima scompare non appena il modulo cambia, quindi ciò che è sullo schermo è sempre ciò che verrebbe salvato.

Se il payload nomina una variabile della chiave privata, il modulo mostra un riquadro rosso con l'host di destinazione e tiene **Save target** disabilitato finché non hai digitato quell'host. Per un target già confermato per il suo host la conferma non viene richiesta di nuovo quando lo rinomini o ne cambi i domini; un host diverso la richiede di nuovo e indica per quale host era stata data. Il salvataggio scrive solo `targets`, a partire dalla lista che il server ha in quel momento con questo solo target modificato, quindi non può sovrascrivere una modifica fatta nel frattempo tramite l'API, e lascia gli altri tipi di target (secret Kubernetes) esattamente come sono. Quelli sono elencati lì e si modificano tramite l'API. La pagina non invia mai un consenso: lo scrive il server.

**Variabili del template.** Il payload è JSON scritto da te. Un placeholder dentro una stringa viene inserito con escape, quindi un PEM (che contiene newline) non può rompere il JSON.

| Variabile | Cos'è |
|---|---|
| `{{cert}}`, `{{fullchain}}`, `{{chain}}` | il certificato, il certificato con la sua chain, la sola chain (PEM) |
| `{{privkey_pkcs8}}` | la chiave privata come PKCS#8 (`BEGIN PRIVATE KEY`) |
| `{{privkey_traditional}}` | la chiave privata come PKCS#1 per RSA (`BEGIN RSA PRIVATE KEY`) o SEC1 per EC (`BEGIN EC PRIVATE KEY`). Un tipo di chiave che non ha una forma del genere, come Ed25519, viene rifiutato con un messaggio, non sostituito in silenzio |
| `{{event}}`, `{{domain}}`, `{{timestamp}}`, `{{certificate_sha256}}` | l'evento, il nome del certificato, l'ora e lo SHA-256 del certificato foglia |

Non esiste un `privkey` semplice: le due grafie rendono visibile la scelta, e un errore di battitura in un nome viene rifiutato al salvataggio invece di non inviare nulla in silenzio. Un nome che non è in questa tabella viene rifiutato.

**Inviare la chiave è una decisione su una destinazione.** Se il template nomina una variabile della chiave privata, il salvataggio deve contenere `config.acknowledge_key_delivery_to` impostato all'host presente in `url`. Il server registra allora chi l'ha confermato e quando (`delivery_consent`, restituito da `GET /api/deploy/config`); questo dato non viene mai letto da ciò che invii. Se in seguito cambi l'host, la conferma non vale più: il target si rifiuta di inviare finché non viene data di nuovo, e un salvataggio senza di essa viene rifiutato. Ogni conferma è nel log di audit.

**Come viene verificato il server.** Sempre. Per impostazione predefinita contro lo store di sistema. Con `ca_cert`, solo contro quella CA (che sostituisce lo store di sistema). Con `pin_sha256`, contro l'esatta impronta SHA-256 del certificato del server stesso, per un'appliance che si firma da sola: indica l'impronta (i due punti sono ammessi), non il certificato. Non esiste un'impostazione che disattivi la verifica, e l'URL deve essere `https://`.

**Dove può inviare.** L'host viene risolto una sola volta, ogni indirizzo viene controllato, e la connessione va a quell'indirizzo. Un indirizzo loopback, link-local o di metadati cloud non è mai una destinazione. Una destinazione su una rete privata richiede `allow_internal: true` **su questo target**, il che è voluto ed è più ristretto di un interruttore per l'intera istanza. I redirect non vengono seguiti: un `3xx` è un fallimento che lo dice esplicitamente.

**Cosa fa quando qualcosa va storto.** Un errore di rete, o uno status `408`, `425`, `429`, `500`, `502`, `503` o `504`, viene ritentato con backoff fino a `attempts` tentativi (predefinito 3, al massimo 5). Qualsiasi altro status no: un `4xx` dice che la richiesta è sbagliata, e inviare di nuovo una chiave per sentirselo dire di nuovo non aiuta nessuno. Ogni consegna porta un `Idempotency-Key` che è lo stesso per i nuovi tentativi di una consegna e per lo stesso certificato inviato di nuovo, e diverso per il certificato successivo, così un ricevente può distinguere una ripetizione da una consegna nuova. Con `signing_secret` il body viene firmato in `X-CertMate-Signature`, come per il webhook di notifica.

**Cosa viene registrato, e cosa no.** Un risultato è uno status e una frase che nomina l'host: mai l'indirizzo, la query, gli header, il body che hai inviato o il body con cui ha risposto il ricevente, che può ripetere ciò che gli è stato inviato. Una consegna che ha trasportato la chiave privata viene segnata nel log di audit: dove è andata (`key_sent_to`), per quale dominio, l'impronta del certificato, lo status e i tentativi, e mai la chiave. Un reset dopo l'handshake TLS viene registrato come possibilmente inviato, perché non si può distinguere da uno avvenuto prima.

**Non esiste un "invia un test" per un target che invia la chiave**, di proposito. Un test che consegnasse una chiave a un'appliance che accetta upload la installerebbe al posto di quella reale. Usa invece l'**anteprima** ([`POST /api/deploy/targets/preview`](./api.md)): esegue il rendering della richiesta con un certificato e una chiave di esempio, non legge alcun file e non invia nulla. Per consegnare davvero una volta, usa [*Eseguire tutti gli hook per un dominio*](#eseguire-tutti-gli-hook-per-un-dominio-admin) (admin), che è un'azione esplicita.

**Da cosa protegge, e da cosa no.**

| Protegge da | Non protegge da |
|---|---|
| La chiave che va a un host che non hai confermato, anche dopo una modifica dell'URL | Un ricevente compromesso o che registra ciò che gli viene inviato: una volta ricevuta, la chiave ce l'ha. Alcune piattaforme di automazione conservano ogni body di richiesta in una cronologia delle esecuzioni; non puntare a una di esse un target che trasporta la chiave |
| Un redirect, una risposta DNS ricollegata (rebinding) o un indirizzo di metadati che portano la richiesta altrove | Un amministratore: chiunque possa salvare questa configurazione può già scrivere un [hook shell](#inviare-la-chiave-privata-da-un-hook) che invia la chiave, senza nessuno dei controlli sopra |
| L'invio su HTTP in chiaro, o a un server che nessuno ha verificato | Tenere la chiave fuori dai backup e dai log del ricevente stesso |
| La risposta del ricevente che porta la chiave nel log di audit | |
| | Le credenziali del target stesso: `auth_token`, `auth_password` e `signing_secret` sono conservati in `settings.json` (modalità `0600`) e restituiti a un amministratore da `GET /api/deploy/config`, esattamente come il token di un target Kubernetes. Il modulo li mostra come campi password. Dai al ricevente un token che possa fare solo questa cosa |

Non in questa versione: un bundle come upload di file o come PKCS#12, e header di richiesta personalizzati diversi da quello di autenticazione. Di' cosa serve a un ricevente.

#### Riceverlo in n8n

Verificato con n8n 2.41.4 usando un certificato reale, un nodo Webhook e il payload qui sotto; i tre passaggi sono ciò che è stato necessario fare, non ciò che vale in generale per n8n.

```json
{"domain": "{{domain}}", "event": "{{event}}",
 "certificates": {"cert": "{{cert}}", "key": "{{privkey_pkcs8}}", "rsa_key": "{{privkey_traditional}}",
                  "fullchain": "{{fullchain}}", "intermediate": "{{chain}}"}}
```

1. **n8n deve rispondere su HTTPS.** Un n8n predefinito ascolta su HTTP in chiaro, e un target lo rifiuta (`url must be https://`). Metti davanti un terminatore TLS, oppure dai a n8n un proprio certificato con `N8N_PROTOCOL=https`, `N8N_SSL_KEY=/path/key.pem` e `N8N_SSL_CERT=/path/cert.pem`. Per un certificato che n8n si è firmato da solo, imposta `pin_sha256` sul target alla sua impronta: solo le cifre, non l'etichetta. Il comando `openssl x509 -in cert.pem -noout -fingerprint -sha256` stampa `SHA256 Fingerprint=AA:BB:...`; incolla ciò che segue `=`, perché il campo rifiuta l'etichetta. Se n8n si trova a un indirizzo privato, imposta anche `allow_internal: true` sul target.
2. **Il nodo Webhook:** HTTP Method `POST`, un Path come `certmate`, Respond *Immediately*, e pubblica il workflow. Il target deve chiamare l'URL di **produzione** (`https://host:5678/webhook/certmate`), non quello di test.
3. **Cosa riceve il nodo.** `$json.body` è il payload che hai scritto, quindi l'esempio sopra dà `{{ $json.body.certificates.fullchain }}` e così via, come normale stringa PEM su più righe. Gli header sono in `$json.headers`: `x-certmate-event`, `idempotency-key` (lo stesso per un nuovo tentativo di una consegna, così un workflow può ignorare una ripetizione) e `user-agent: CertMate-Deploy/1`. Nella verifica, ogni certificato è arrivato identico al file, la chiave PKCS#8 identica a `privkey.pem`, e la chiave nella forma tradizionale (`RSA PRIVATE KEY` o `EC PRIVATE KEY`) era la chiave del certificato, sia per un certificato RSA sia per uno EC.

**n8n conserva ciò che riceve.** Con le impostazioni predefinite n8n ha salvato ogni body di richiesta nel proprio database, e nella verifica la chiave privata poteva essere letta da quei dati di esecuzione. Considera il database di n8n e i suoi backup come contenitori della chiave, oppure lascia fuori le variabili della chiave da un target n8n e recupera la chiave in altro modo. Impostare il workflow in modo che non salvi le esecuzioni **non** si è comportato come previsto nella stessa verifica (le esecuzioni sono rimaste nello stato `running` con i loro dati), quindi non fare affidamento su quell'impostazione senza guardare cosa memorizza la tua istanza. È questo il caso che la tabella sopra intende con "alcune piattaforme di automazione conservano ogni body di richiesta in una cronologia delle esecuzioni".

---

## Vedi anche

- [`modules/core/deployer.py`](../../modules/core/deployer.py) — implementazione
- [`modules/core/deploy_targets.py`](../../modules/core/deploy_targets.py) — deploy target tipizzati
- [`modules/web/settings_routes.py`](../../modules/web/settings_routes.py) — endpoint `/api/deploy/*`
- [`templates/partials/settings_deploy.html`](../../templates/partials/settings_deploy.html) — partial UI
- [`static/js/settings-deploy.js`](../../static/js/settings-deploy.js) — componente Alpine
