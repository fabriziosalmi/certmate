# Deploy Hooks

Schliesst [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Deploy Hooks sind kurze Shell-Befehle, die CertMate **nach** der Ausstellung, Erneuerung oder dem Widerruf eines Zertifikats ausführt. Verwenden Sie sie, um Dienste neu zu laden, das neue Zertifikat an einen Load Balancer zu übermitteln, eine Benachrichtigung zu versenden oder alles andere, was nach einem erfolgreichen certbot-Lauf erledigt werden muss.

Diese Anleitung behandelt:

1. [Was ein Hook ist](#was-ein-hook-ist)
2. [Hooks konfigurieren (UI + JSON)](#hooks-konfigurieren)
3. [Umgebungsvariablen, die an Ihren Befehl übergeben werden](#umgebungsvariablen-die-an-ihren-befehl-übergeben-werden)
4. [Manuelles Auslösen](#manuelles-auslösen)
5. [Sicherheitsmodell: warum bestimmte Befehle abgelehnt werden](#sicherheitsmodell)
6. [Häufige Rezepte](#häufige-rezepte)
7. [Audit, Verlauf und Debugging](#audit-verlauf-und-debugging)

---

## Was ein Hook ist

Ein Hook ist ein JSON-Objekt mit fünf Feldern:

| Feld | Typ | Erforderlich | Hinweise |
|---|---|---|---|
| `id` | string | ja | Stabiler Bezeichner (eine UUID ist geeignet; die UI generiert automatisch eine). Wird von `/api/deploy/test/<id>` verwendet. |
| `name` | string | ja | Lesbares Label, das in der UI und im Audit-Log angezeigt wird. |
| `command` | string | ja | Ein einzelner Shell-Befehl (`sh -c`). Max. 1024 Zeichen. Siehe [Sicherheitsmodell](#sicherheitsmodell). |
| `enabled` | boolean | nein | Standard: `true`. Deaktivierte Hooks werden beim automatischen Auslösen übersprungen, können aber weiterhin manuell getestet werden. |
| `timeout` | integer | nein | Sekunden. Standard 30, begrenzt auf den systemweiten `MAX_TIMEOUT` (aktuell 300). |
| `on_events` | string array | nein | Teilmenge von `["created", "renewed", "revoked"]`. Fehlt dieses Feld, läuft der Hook bei allen drei Ereignissen. |

Hooks werden unter zwei Schlüsseln in `deploy_hooks` gespeichert:

- **`global_hooks`** — werden für jede Domain ausgeführt. Gut geeignet für „nginx nach jeder Zertifikatsänderung neu laden".
- **`domain_hooks`** — nach exaktem Domainnamen indiziert. Gut geeignet für „das LB-Zertifikat für `api.example.com` nach der Erneuerung dieses spezifischen Zertifikats zu S3 übertragen".

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "global_hooks": [
      {
        "id": "5f8...",
        "name": "Reload nginx",
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

Wenn `enabled` auf der obersten Ebene `false` ist, werden bei Zertifikatsereignissen keine Hooks ausgeführt. Manuelle Testläufe (`POST /api/deploy/test/<id>`) funktionieren weiterhin — nützlich, wenn Sie einen Hook iterativ entwickeln, bevor Sie den Hauptschalter umlegen.

---

## Hooks konfigurieren

### Über die UI

`Einstellungen → Deploy Hooks`. Schalten Sie den **Aktiviert**-Schalter um, und fügen Sie dann globale oder domainspezifische Hooks hinzu. Jede Zeile enthält:

- Name + Befehl + Timeout + Ereignis-Checkboxen
- eine **Test**-Schaltfläche (führt den Hook gegen die synthetische Domain `test.example.com` mit `CERTMATE_EVENT=manual` aus)
- Aktivieren/Deaktivieren-Schalter
- Löschen

Einstellungen speichern, um die Änderungen beizubehalten.

### Über die API

```bash
# Aktuelle Konfiguration lesen
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Konfiguration ersetzen (vollständiges Dokument schreiben — gesamtes deploy_hooks-Dict übergeben)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

Der POST ersetzt den gesamten `deploy_hooks`-Block; führen Sie die Zusammenführung clientseitig durch, wenn Sie bestehende Einträge beibehalten möchten.

---

## Umgebungsvariablen, die an Ihren Befehl übergeben werden

Jeder Aufruf setzt diese Variablen in der Prozessumgebung des Hooks:

| Variable | Beispielwert |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (nur Zwischenzertifikate, kein Blattzertifikat — für Ziele, die die Chain als separate Datei benötigen) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` |
| `CERTMATE_DRY_RUN` | Nur während eines Dry-Run auf `1` gesetzt; andernfalls nicht vorhanden. |

Ihr Befehl kann diese Variablen als `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"` usw. referenzieren. Die Werte werden über die Umgebung übergeben, nicht durch String-Interpolation, sodass das Quoting wie in jeder normalen Shell funktioniert.

Der Hook wird als Prozessbenutzer von CertMate ausgeführt (im Docker-Image: `certmate`, UID/GID 1000:1000), innerhalb des Containers. Alles, was Sie per `cp`, `curl`, `ssh` usw. ausführen, muss von dort erreichbar sein.

---

## Manuelles Auslösen

Zwei Möglichkeiten, einen Hook ausserhalb des normalen Zertifikatslebenszyklus auszuführen:

### Hook-Test pro Hook (Admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Führt nur den Hook mit dieser `id` gegen die synthetische Domain `test.example.com` aus, mit `CERTMATE_EVENT=manual`. Umgeht den `on_events`-Filter — nützlich für „funktioniert dieser Befehl tatsächlich?".

### Alle Hooks für eine Domain ausführen (Admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Löst alle aktivierten globalen und domainspezifischen Hooks für `api.example.com` mit `CERTMATE_EVENT=manual` aus und ignoriert dabei `on_events`. Gibt eine strukturierte Zusammenfassung zurück:

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

Dies ist das, was die Schaltfläche **Deploy Hooks jetzt ausführen** im Zertifikat-Detailbereich aufruft.

---

## Sicherheitsmodell

Hooks sind konzeptbedingt beliebige Code-Ausführung — das ist das Feature. Um den möglichen Schaden zu begrenzen, wird das Befehlsfeld **beim Speichern und erneut zur Laufzeit** validiert (Defense in Depth) und abgelehnt, wenn es Folgendes enthält:

### Blockierte Shell-Muster

| Muster | Grund |
|---|---|
| `` ` `` (Backticks) | Befehlssubstitution |
| `$(...)` | Befehlssubstitution |
| `${...}` | Parameterexpansion (Env-Variablen-Expansion ist erlaubt — nur die `${...}`-Form ist blockiert) |
| `&&` / `\|\|` | Logische Verknüpfung |
| `;` | Anweisungstrenner |
| `\|` | Pipe |
| `\r` / `\n` | Zeilenumbrüche (damit `sh -c` sie nicht als `;` interpretiert) |
| `> /` (Umleitung auf absoluten Pfad) | Verhindert das Überschreiben von Systemdateien |
| `<<` | Here-Doc |
| `eval`, `source`, `. /` | Shell-Builtins, die beliebigen Code laden |

Wenn Sie eines dieser Muster benötigen, legen Sie die Logik in eine Skriptdatei innerhalb des Containers und rufen Sie das Skript direkt auf:

```sh
/opt/scripts/deploy.sh
```

### Blockierte Dateireferenzen

Referenzen auf CertMates eigene sensible Dateien werden grundsätzlich abgelehnt (Gross-/Kleinschreibung wird ignoriert):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`, `private*key`, `.pem`

`cat $CERTMATE_FULLCHAIN_PATH` ist also zulässig (die Variable wird von der Shell aufgelöst, die literale Zeichenkette `.pem` erscheint nicht in `command`), aber `cat /app/data/settings.json` würde beim Speichern abgelehnt.

### Was erlaubt ist

- **Einfache Befehle**: `/usr/sbin/nginx -s reload`, `systemctl reload haproxy`
- **Curl-POSTs (Webhooks)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Variablenexpansion in Argumenten**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **JSON-Payloads mit `$VAR` (kein `${}`)**: `curl -d '{"domain":"$CERTMATE_DOMAIN"}' ...`
- **Einzelne Skriptaufrufe**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Wenn ein Befehl, den Sie früher speichern konnten, jetzt `Command blocked at runtime: contains dangerous shell metacharacters` auslöst, lesen Sie die Versionshinweise — der Validator wurde in v2.4.0 verschärft und in v2.4.1+ leicht gelockert.

---

## Häufige Rezepte

### nginx neu laden (global, alle Ereignisse)

```sh
/usr/sbin/nginx -t && /usr/sbin/nginx -s reload
```

(Hinweis: `&&` ist blockiert. Verpacken Sie dies in ein Skript: `/opt/scripts/reload-nginx.sh`.)

### haproxy neu laden

```sh
systemctl reload haproxy
```

### An einen Slack-Webhook senden

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Zertifikat auf einen Remote-Host synchronisieren

(In ein Skript verpacken — kein `;`, `&&` inline erlaubt.)

```sh
/opt/scripts/sync-cert.sh
```

Wobei `sync-cert.sh` folgenden Inhalt hat:

```sh
#!/bin/sh
set -eu
scp "$CERTMATE_FULLCHAIN_PATH" "$CERTMATE_KEY_PATH" deploy@lb:/etc/ssl/$CERTMATE_DOMAIN/
ssh deploy@lb 'systemctl reload haproxy'
```

### Hooks während eines Dry-Run überspringen

In Ihrem Skript:

```sh
[ -n "${CERTMATE_DRY_RUN:-}" ] && { echo "dry run, skipping"; exit 0; }
```

---

## Audit, Verlauf und Debugging

### Aktivitätsfeed

`GET /api/deploy/history?limit=50` und der **Aktivität**-Tab der UI zeigen die letzten N Hook-Ausführungen mit: Hook-Name, Domain, Ereignis, Exit-Code, Dauer, stdout/stderr (jeweils auf 4096 Byte gekürzt) und Zeitstempel.

### Debug-Konsole

Einstellungen → Deploy Hooks verfügt über eine Debug-Konsole (Umschalter-Schaltfläche unten rechts), die `loadConfig` / `saveConfig` / `testHook`-Ereignisse clientseitig streamt. Nützlich, wenn Sie iterativ an der UI arbeiten.

### Audit-Log

Jede Hook-Ausführung schreibt einen `operation: deploy_hook`-Eintrag in das Audit-Log mit dem Status `success`/`failure` sowie Hook-Name, Exit-Code und Dauer. Sichtbar über den Aktivität-Tab und `/api/audit`.

### Häufige Fehler

| Symptom | Wahrscheinliche Ursache |
|---|---|
| `Hook not found` | Die Hook-ID in der Testanfrage stimmt mit keinem Hook in der gespeicherten Konfiguration überein (UI war veraltet oder der Hook wurde gerade gelöscht). Seite neu laden. |
| `Command blocked at runtime` | Eines der [blockierten Muster](#blockierte-shell-muster) hat die Speicherprüfung umgangen. Verschieben Sie die problematische Logik in eine Skriptdatei. |
| `exit code 127` | Befehl im Container nicht gefunden (z. B. `nginx` ist nicht in `$PATH`). Absolute Pfade verwenden oder die Binärdatei im Image installieren. |
| `timeout after 30s` | Der Hook hat seinen `timeout` überschritten. Erhöhen Sie ihn (max. 300s) oder verlagern Sie die Arbeit in ein im Hintergrund laufendes Skript. |
| `Deploy hooks disabled` | `deploy_hooks.enabled` ist `false`. Den Hauptschalter in den Einstellungen aktivieren. |
| `No hooks configured for <domain>` | Versuch, Hooks für eine Domain ohne globale Hooks UND ohne Eintrag unter `domain_hooks[<domain>]` auszuführen. Einen Hook hinzufügen (oder `/api/deploy/test/<id>` für einen bestimmten Hook aufrufen). |

---

## Siehe auch

- [`modules/core/deployer.py`](../modules/core/deployer.py) — Implementierung
- [`modules/web/settings_routes.py`](../modules/web/settings_routes.py) — `/api/deploy/*`-Endpoints
- [`templates/partials/settings_deploy.html`](../templates/partials/settings_deploy.html) — UI-Partial
- [`static/js/settings-deploy.js`](../static/js/settings-deploy.js) — Alpine-Komponente

---

<div align="center">

[← Zurück zur Dokumentation](./README.md)

</div>
