# Deploy Hooks

<!-- CERTMATE-TRANSLATED-FROM 0d31dc7a82589489 -->

Schließt [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Deploy Hooks sind kurze Shell-Befehle, die CertMate **nach** der Ausstellung, Erneuerung oder dem Widerruf eines Zertifikats ausführt. Verwenden Sie sie, um Dienste neu zu laden, das neue Zertifikat an einen Load Balancer zu übermitteln, eine Benachrichtigung zu versenden oder alles andere, was nach einem erfolgreichen certbot-Lauf erledigt werden muss.

> **Zu `revoked`.** Über CertMate lassen sich nur Client-Zertifikate widerrufen — `POST /api/client-certs/<id>/revoke` —, und genau dann läuft ein `revoked`-Hook, wobei `CERTMATE_DOMAIN` auf den Bezeichner des Client-Zertifikats gesetzt ist. Für ein Server-Zertifikat gibt es keinen Widerruf, also läuft dafür auch kein Hook.

Diese Anleitung behandelt:

1. [Was ein Hook ist](#was-ein-hook-ist)
2. [Hooks konfigurieren (UI + JSON)](#hooks-konfigurieren)
3. [Umgebungsvariablen, die an Ihren Befehl übergeben werden](#umgebungsvariablen-die-an-ihren-befehl-übergeben-werden)
4. [Wartungsfenster](#wartungsfenster)
5. [Manuelles Auslösen](#manuelles-auslösen)
6. [Sicherheitsmodell: warum bestimmte Befehle abgelehnt werden](#sicherheitsmodell)
7. [Wo ein Hook läuft](#wo-ein-hook-läuft)
8. [Häufige Rezepte](#häufige-rezepte)
9. [Audit, Verlauf und Debugging](#audit-verlauf-und-debugging)
10. [Typisierte Deploy-Ziele](#typisierte-deploy-ziele)

---

## Was ein Hook ist

Ein Hook ist ein JSON-Objekt mit diesen Feldern:

| Feld | Typ | Erforderlich | Hinweise |
|---|---|---|---|
| `id` | string | ja | Stabiler Bezeichner (eine UUID ist geeignet; die UI generiert automatisch eine). Wird von `/api/deploy/test/<id>` verwendet. |
| `name` | string | ja | Lesbares Label, das in der UI und im Audit-Log angezeigt wird. |
| `command` | string | ja | Ein einzelner Shell-Befehl (`sh -c`). Max. 1024 Zeichen. Siehe [Sicherheitsmodell](#sicherheitsmodell). |
| `enabled` | boolean | nein | Standard: `true`. Deaktivierte Hooks werden beim automatischen Auslösen übersprungen, können aber weiterhin manuell getestet werden. |
| `timeout` | integer | nein | Sekunden. Standard 30, begrenzt auf den systemweiten `MAX_TIMEOUT` (aktuell 300). |
| `on_events` | string array | nein | Teilmenge von `["created", "renewed", "revoked"]`. Fehlt das Feld beim Speichern der Konfiguration, wird es auf `["created", "renewed"]` gesetzt — `revoked` muss ausdrücklich gewählt werden, damit ein neuer Hook nicht anfängt, bei Widerrufen Befehle auszuführen, für die ihn niemand geschrieben hat. Ein von Hand in `settings.json` eingetragener Hook wird nie normalisiert: ohne `on_events` läuft er bei keinem Zertifikatsereignis, wohl aber bei manueller Auslösung. |
| `window` | object | nein | Ein [Wartungsfenster](#wartungsfenster). Fehlt es, läuft der Hook, sobald das Zertifikat ausgestellt oder erneuert ist — so, wie sich bisher jeder Hook verhalten hat. |

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

Wenn `enabled` auf der obersten Ebene `false` ist, werden bei Zertifikatsereignissen keine Hooks ausgeführt. Testläufe einzelner Hooks (`POST /api/deploy/test/<id>`) funktionieren weiterhin — nützlich, wenn Sie einen Hook iterativ entwickeln, bevor Sie den Hauptschalter umlegen. Das Ausführen aller Hooks für eine Domain (`POST /api/certificates/<domain>/deploy`) dagegen nicht: Es wird abgelehnt, solange der Schalter aus ist.

---

## Hooks konfigurieren

### Über die UI

`Settings → Deploy Hooks`. Schalten Sie den **Aktiviert**-Schalter um, und fügen Sie dann globale oder domainspezifische Hooks hinzu. Jede Zeile enthält:

- Name + Befehl + Timeout + Ereignis-Checkboxen
- eine **Test**-Schaltfläche (führt den Hook gegen die synthetische Domain `test.example.com` mit `CERTMATE_EVENT=test` und `CERTMATE_DRY_RUN=1` aus)
- Aktivieren/Deaktivieren-Schalter
- Löschen

Einstellungen speichern, um die Änderungen beizubehalten.

### Über die API

```bash
# Aktuelle Konfiguration lesen
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Konfiguration schreiben (die gesendeten Schlüssel der obersten Ebene ersetzen die gespeicherten)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

Der POST führt auf der obersten Ebene von `deploy_hooks` zusammen: Jeder Schlüssel, den Sie senden (`enabled`, `global_hooks`, `domain_hooks`, `targets`), ersetzt den gespeicherten Wert vollständig, und ein Schlüssel, den Sie weglassen, bleibt, wie er war. Wer `global_hooks` sendet, ersetzt also die gesamte Liste; um einen Hook hinzuzufügen, lesen Sie die Liste, hängen den Hook an und senden sie zurück. Eine ausdrücklich leere Liste leert diesen Schlüssel.

---

## Umgebungsvariablen, die an Ihren Befehl übergeben werden

Jeder Aufruf setzt diese Variablen in der Prozessumgebung des Hooks:

| Variable | Beispielwert |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` — **nicht gesetzt** bei einem [CSR-only-Zertifikat](../csr-only-certificates.md), dessen Schlüssel auf dem Gerät bleibt |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (nur Zwischenzertifikate, kein Blattzertifikat — für Ziele, die die Chain als separate Datei benötigen) |
| `CERTMATE_TAGS` | `loadbalancer,env:prod` — die [Tags](./api.md) des Zertifikats, kommagetrennt und in Kleinbuchstaben; **leer**, wenn es keine hat, und immer gesetzt, sodass ein Hook sich darauf verlassen kann (seit API-Vertrag 2.33) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` (Deploy Now) / `test` (Test eines einzelnen Hooks). `renewed` folgt auch auf das [Ersetzen eines externen Zertifikats](../api.md#replace-an-external-certificate) per Upload. |
| `CERTMATE_DRY_RUN` | Nur beim Test eines einzelnen Hooks auf `1` gesetzt (`/api/deploy/test/<id>`, die **Test**-Schaltfläche); andernfalls nicht vorhanden, auch bei Deploy Now. Der Befehl wird trotzdem ausgeführt; dies ist nur ein Signal, das Ihr Skript prüfen kann. |

Die Pfade liegen unter dem Zertifikatsverzeichnis von CertMate: `/app/certificates` im Docker-Image, oder wohin auch immer `CERTMATE_CERT_DIR` zeigt.

Ihr Befehl kann diese Variablen als `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"` usw. referenzieren. Die Werte werden über die Umgebung übergeben, nicht durch String-Interpolation, sodass das Quoting wie in jeder normalen Shell funktioniert.

Der Hook wird als Prozessbenutzer von CertMate ausgeführt (im Docker-Image: `certmate`, UID/GID 1000:1000), innerhalb des Containers. Alles, was Sie per `cp`, `curl`, `ssh` usw. ausführen, muss von dort erreichbar sein.

---

## Wartungsfenster

Schließt [#632](https://github.com/fabriziosalmi/certmate/issues/632).

Ein Zertifikat wird erneuert, wenn es fällig ist, und diesen Zeitpunkt hat niemand gewählt: Der Erneuerungslauf startet um 02:00 mit einer Stunde Jitter, und nur für die Zertifikate, die in dieser Nacht innerhalb des Schwellenwerts liegen. Der Hook lief dann sofort. Für einen Hook, der eine Datenbank neu startet oder einen Load Balancer neu lädt, ist das ein Ausfall zu einer unvorhersehbaren Stunde.

Ein `window` trennt beides. Das Zertifikat wird weiterhin erneuert, sobald es fällig ist — das richtet sich nach dem Ablauf und ist nicht verhandelbar —, aber das **Deployment** wird zurückgehalten, bis sich das Fenster das nächste Mal öffnet.

```jsonc
"window": {
  "start": "02:00",          // Pflicht, 24-Stunden-Format HH:MM
  "end": "04:00",            // Pflicht, exklusiv
  "days": ["sat", "sun"],    // optional; weglassen oder leer lassen für jeden Tag
  "timezone": "Europe/Rome"  // optionaler IANA-Name, Standard ist UTC
}
```

Dasselbe Feld funktioniert bei typisierten Deploy-Zielen, und dort will man es meistens haben: Der Rollout eines Kubernetes-Secrets ist genau die Art von Deployment, die in ein Wartungsfenster gehört.

### Welche Regeln gelten

- **`end` ist exklusiv.** `02:00`–`04:00` und `04:00`–`06:00` grenzen aneinander, sie überlappen nicht.
- **Ein Fenster darf über Mitternacht gehen** und gehört zu dem Tag, an dem es **beginnt**. Ein Fenster `22:00`–`04:00` mit `["fri"]` ist am Samstagmorgen um 02:00 offen. Die umgekehrte Lesart würde stillschweigend verlangen, dass Sie auch den Samstag ankreuzen.
- **`start` und `end` dürfen nicht gleich sein.** Das lässt sich ebenso gut als „immer offen" wie als „nie offen" lesen, deshalb wird es abgelehnt statt erraten. Verwenden Sie `00:00`–`23:59` für einen ganzen Tag.
- **Die Zeitzone ist ein IANA-Name** (`Europe/Rome`, `America/New_York`) und wird beim Speichern geprüft. Ein Tippfehler wird in diesem Moment abgelehnt, statt stillschweigend jedes Deployment für ein Fenster zurückzuhalten, das sich nie öffnet.
- **Die Sommerzeit wird von der Zone behandelt, nicht durch Arithmetik.** Am Tag der Umstellung im Frühjahr öffnet ein Fenster `02:00`–`04:00` in Rom um 03:00 Ortszeit, weil es 02:00–02:59 nicht gibt; am Tag der Umstellung im Herbst ist es während beider Durchgänge von 02:00–02:59 offen.

### Was geschieht, während ein Deployment zurückgehalten wird

Die Warteschlange liegt unter `data/pending_deploys.json` und übersteht einen Neustart — das Fenster ist typischerweise Stunden entfernt.

- Eine zweite Erneuerung vor dem Öffnen des Fensters reiht **kein** zweites Deployment ein. Der Hook liest das Zertifikat von der Festplatte, wenn er läuft, also veröffentlicht ein einziger aufgeschobener Lauf immer das neueste.
- Wird der Hook gelöscht oder deaktiviert oder werden Deploy Hooks ganz abgeschaltet, wird das eingereihte Deployment beim nächsten Abarbeiten der Warteschlange **verworfen**. Ihre aktuelle Konfiguration sagt, dass es nicht laufen soll.
- Entfernen Sie das Fenster, wird das Deployment beim nächsten Abarbeiten freigegeben, statt noch ein weiteres Mal zu warten.
- **Deploy Now verbraucht das wartende Deployment.** Ist der Hook (oder das typisierte Ziel), den Sie von Hand ausführen, erfolgreich, wird sein eingereihter Eintrag für diese Domain entfernt: Das Zertifikat wurde ausgeliefert, und es beim Öffnen des Fensters erneut auszuführen, wäre ein unangekündigtes zweites Deployment. **Schlägt** der manuelle Lauf **fehl**, bleibt der Eintrag bestehen, sodass das Deployment im Fenster der erneute Versuch ist. Eine Erneuerung, die *während* Deploy Now läuft, behält ihren Eintrag, weil dieses Zertifikat neuer ist als das, welches der manuelle Lauf gelesen hat. Die beiden führen nie gleichzeitig dasselbe Deployment aus: Öffnet sich das Fenster, während Deploy Now einen Hook ausführt, überspringt der geplante Lauf ihn, und der nächste Tick findet ihn entweder ausgeliefert oder noch ausstehend; und steckt der geplante Lauf bereits in dem Hook, wenn Sie die Schaltfläche drücken, wartet Deploy Now, bis er fertig ist, und läuft dann. Ein eingereihtes Deployment, das Sie nicht wollen, lässt sich weiterhin nur entfernen, indem Sie den Hook deaktivieren oder löschen (es wird dann beim nächsten Abarbeiten verworfen).
- Ein Hook, der innerhalb seines Fensters fehlschlägt, wird **nicht** erneut eingereiht. Er wird wie jeder andere Fehlschlag im Verlauf festgehalten; ein erneutes Einreihen würde jede Minute wiederholen, solange das Fenster offen bleibt.
- Ein Deployment, das nach sieben Tagen immer noch wartet, wird als Warnung protokolliert. Das ist keine Grenze — das Warten ist die Funktion —, aber eine Woche bedeutet, dass sich das Fenster überhaupt nicht geöffnet hat, was meist heißt, dass die Tage oder die Zeitzone nicht das sind, was Sie gemeint haben.

Für ein Fenster zurückgehaltene Deployments sind überall sonst unsichtbar: Das Zertifikat wurde erneuert, der Verlauf zeigt nichts, und nichts ist fehlgeschlagen. `GET /api/deploy/pending` listet sie mit dem Fenster auf, auf das sie warten, und dem Zeitpunkt, zu dem es sich als Nächstes öffnet.

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

### Was das Fenster ignoriert

**Deploy Now** ignoriert es. Wer die Schaltfläche drückt, wählt diesen Moment; das Deployment bis 02:00 zurückzuhalten, würde die Schaltfläche nichts Sichtbares tun lassen. Was sie ausliefert, wird nicht noch einmal ausgeliefert: siehe *Was geschieht, während ein Deployment zurückgehalten wird*. Ebenso ignoriert `POST /api/deploy/test/<id>` das Fenster; es berührt die Warteschlange nie.

---

## Manuelles Auslösen

Zwei Möglichkeiten, einen Hook außerhalb des normalen Zertifikatslebenszyklus auszuführen:

### Hook-Test pro Hook (Admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Führt nur den Hook mit dieser `id` aus, gegen die synthetische Domain `test.example.com` (oder die in einem JSON-Body angegebene `domain`), mit `CERTMATE_EVENT=test` und `CERTMATE_DRY_RUN=1`. Der Befehl wird wirklich ausgeführt. Umgeht den `on_events`-Filter, das eigene `enabled`-Flag des Hooks und den Hauptschalter — nützlich für „funktioniert dieser Befehl tatsächlich?".

### Alle Hooks für eine Domain ausführen (Admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Löst jeden aktivierten globalen und domainspezifischen Hook (und jedes passende typisierte Deploy-Ziel) für `api.example.com` mit `CERTMATE_EVENT=manual` aus und ignoriert dabei `on_events`. Wird abgelehnt, solange der Hauptschalter aus ist. Gibt eine strukturierte Zusammenfassung zurück:

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

Dies ist das, was die Schaltfläche **Deploy Hooks jetzt ausführen** (Play-Symbol, Abschnitt Deployment im Detailbereich des Zertifikats) aufruft.

---

## Sicherheitsmodell

Hooks sind konzeptbedingt beliebige Code-Ausführung — das ist das Feature. Um den möglichen Schaden zu begrenzen, wird das Befehlsfeld **beim Speichern und erneut zur Laufzeit** validiert (Defense in Depth) und abgelehnt, wenn es Folgendes enthält:

### Blockierte Shell-Muster

| Muster | Grund |
|---|---|
| `` ` `` (Backticks) | Befehlssubstitution |
| `$(...)` | Befehlssubstitution |
| `${...}` | Parameterexpansion. `$VAR` ist erlaubt, ebenso `${CERTMATE_NAME}` mit der schließenden Klammer direkt nach dem Namen; jede andere `${...}`-Form, einschließlich `${CERTMATE_DOMAIN:-x}`, ist blockiert |
| `&&` / `\|\|` | Logische Verknüpfung |
| `;` | Anweisungstrenner |
| `\r` / `\n` | Zeilenumbrüche (damit `sh -c` sie nicht als `;` interpretiert) |
| `> /` (Umleitung auf absoluten Pfad) | Verhindert das Überschreiben von Systemdateien |
| `<<` | Here-Doc |
| `eval`, `source`, `.` (die Source-Kurzform, mit beliebigem Argument) | Shell-Builtins, die beliebigen Code laden |

Zwei Dinge, die so aussehen, als gehörten sie auf diese Liste, sind absichtlich erlaubt (#115): eine einfache Pipe für die Nachbearbeitung, etwa `curl ... | grep -q ok` (beide Seiten müssen ein Befehl sein, den das Image mitbringt — `jq` gehört nicht dazu), und eine Umleitung auf einen relativen Pfad (`> out.txt`). Nur eine Umleitung auf einen absoluten Pfad ist blockiert.

Wenn Sie eines dieser Muster benötigen, legen Sie die Logik in eine Skriptdatei innerhalb des Containers und rufen Sie das Skript direkt auf:

```sh
/opt/scripts/deploy.sh
```

### Blockierte Dateireferenzen

Ein Befehl, der eine von CertMates eigenen sensiblen Dateien nennt, wird abgelehnt (Groß-/Kleinschreibung wird ignoriert):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`

Zertifikatsdateien stehen nicht auf der Liste: das Zertifikat und seinen Schlüssel zu installieren (`privkey.pem`, `$CERTMATE_KEY_PATH`) ist die normale Aufgabe eines Hooks. `cat /app/data/settings.json` wird beim Speichern abgelehnt.

Die Prüfung erkennt diese Namen **so, wie sie geschrieben sind**. Sie fängt einen Hook ab, der eine dieser Dateien versehentlich nennt. Sie hält keinen Befehl auf, der dieselbe Datei erreicht, ohne ihren Namen auszuschreiben: ein Glob (`settings*`), ein `?`-Platzhalter oder ein durch Anführungszeichen geteilter Name (`settings"."json`) kommen durch. Sie schützt vor Versehen, sie ist keine Sicherheitsgrenze. Nur ein Admin kann einen Hook speichern oder ausführen, und ein Admin, der einen Hook speichern kann, kann bereits jeden Befehl als CertMate ausführen. Dasselbe gilt für die Shell-Muster oben.

### Den privaten Schlüssel aus einem Hook senden

Ein Hook kann den Schlüssel an eine URL senden: `CERTMATE_KEY_PATH` steht nicht auf der Sperrliste,
und `curl` ist im Image, also lässt sich `curl --data-binary @"$CERTMATE_KEY_PATH" …`
speichern. CertMate prüft nicht, was ein solcher Befehl mit dem Schlüssel macht. Die
Prüfungen liegen bei Ihnen:

- verwenden Sie `https://`, nie `http://`: Der Schlüssel würde das Netz im Klartext durchqueren;
- fügen Sie nicht `-k`/`--insecure` hinzu, das die Prüfung abschaltet, ob der Server
  derjenige ist, den Sie gemeint haben;
- fügen Sie nicht `-L`/`--location` hinzu, das die Anfrage samt Schlüssel an jeder
  Adresse wiederholt, die die Antwort nennt;
- lassen Sie den Befehl nicht in die Ausgabe schreiben, was der Server antwortet: Die
  Ausgabe eines Hooks wird im Verlauf aufbewahrt, und das Audit-Log lässt sich nicht bearbeiten.

Für Kubernetes verwenden Sie stattdessen das [typisierte Ziel](#typisierte-deploy-ziele), das
die ersten drei Punkte für Sie einhält.

### Was erlaubt ist

- **Einfache Befehle**: `curl -fsS https://lb.internal/api/reload`, `openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates`
- **Curl-POSTs (Webhooks)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Variablenexpansion in Argumenten**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **JSON-Payloads mit `$VAR`**: `curl -H "Content-Type: application/json" -d "{\"domain\":\"$CERTMATE_DOMAIN\"}" ...`. Der Body muss in doppelten Anführungszeichen stehen: Innerhalb einfacher Anführungszeichen expandiert die Shell `$CERTMATE_DOMAIN` nie, und der Empfänger erhält den wörtlichen Text.
- **Einzelne Skriptaufrufe**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Wenn ein Befehl, den Sie früher speichern konnten, jetzt `Command blocked at runtime: contains dangerous shell metacharacters` auslöst, lesen Sie die Versionshinweise — der Validator wurde in v2.4.0 verschärft und in v2.4.1+ leicht gelockert.

---

## Wo ein Hook läuft

**Im CertMate-Container**, als der Prozess, der das Zertifikat ausgestellt hat —
nicht auf dem Docker-Host und nicht auf der Maschine, die Sie neu laden wollen.

Das ist das Entscheidende, das man richtig haben muss, bevor man einen Hook schreibt, und
die Beispiele auf dieser Seite hatten es früher falsch. Ein Befehl wie `systemctl reload haproxy`
liest sich, als lade er Ihren Load Balancer neu. Das tut er nicht: Er läuft in einem Container
ohne systemd, ohne haproxy und ohne nginx und endet mit 127 — `not found` —,
was [#856](https://github.com/fabriziosalmi/certmate/issues/856)
für `scp` gemeldet hat.

Was das veröffentlichte Image für einen Hook tatsächlich enthält:

| | |
|---|---|
| **vorhanden** | `sh`, `bash`, `curl`, `openssl` |
| **nicht vorhanden** | `ssh`, `scp`, `sftp`, `rsync`, `jq`, `nginx`, `systemctl`, `haproxy` und alles Übrige |

Die Liste ist absichtlich kurz. Die Runtime-Stage installiert drei Pakete, und
das Dockerfile erklärt, warum: Jedes zusätzliche Paket ist Fläche, die
gepatcht und gescannt werden muss ([#403](https://github.com/fabriziosalmi/certmate/issues/403)).
Es ist kein Versehen, also muss ein Hook mit dem auskommen, was da ist — oder
etwas erreichen, das mehr hat.

`tests/test_a_hook_runs_where_certmate_runs.py` prüft die Beispiele unten
gegen das Image, sodass diese Tabelle nicht wieder davon abweichen kann.

### Drei Wege, auf eine Maschine zu wirken, die nicht diese ist

**Über das Netz fragen.** Fast alles, was sich neu zu laden lohnt, hat eine API, und
`curl` ist vorhanden. Das ist das Muster, das ganz ohne Änderungen funktioniert.

**Ein eigenes Image bauen.** Das Image von CertMate ist eine Basis wie jede andere:

```
FROM fabriziosalmi/certmate:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
USER certmate
```

Jetzt ist `scp` vorhanden, zusammen mit allem anderen, was Sie hinzugefügt haben, und die
Fläche zu patchen ist Ihre Sache statt die aller.

**Ein Skript und seine Abhängigkeiten einhängen.** Ein Hook darf jeden Pfad im
Container aufrufen, also funktioniert ein per Bind-Mount eingehängtes Skript — es läuft aber weiterhin im
Container, also muss auch alles, was es aufruft, dort vorhanden sein.

---

## Häufige Rezepte

Diese laufen im Image, so wie es veröffentlicht ist. Jedes wird dagegen geprüft.

### An einen Slack-Webhook senden

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Etwas anderem mitteilen, dass sich das Zertifikat geändert hat

Alles mit einer HTTP-API — ein Load Balancer, ein Endpoint für Konfigurationsmanagement, Ihr
eigener kleiner Agent neben dem Dienst:

```sh
curl -fsS -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" --data-binary "@$CERTMATE_FULLCHAIN_PATH" https://lb.internal/api/certs/$CERTMATE_DOMAIN
```

`-f` ist wichtig: Ohne es endet `curl` auch bei einem HTTP-Fehler mit 0, und der Hook meldet
Erfolg für ein Deployment, das nicht stattgefunden hat.

### Prüfen, was ausgestellt wurde, bevor es ausgeliefert wird

```sh
openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -subject -dates
```

### Ein eigenes Skript ausführen

```sh
/opt/scripts/deploy.sh
```

In den Container eingehängt und für das geschrieben, was der Container hat. Verwenden Sie ein
Skript immer dann, wenn Sie `;` oder `&&` brauchen — das Befehlsfeld lehnt beides ab, und das
Skript ist ohnehin der Ort, an den diese Logik gehört.

### Nur bei bestimmten Zertifikaten handeln

Versehen Sie ein Zertifikat mit Tags (`PATCH /api/certificates/<domain>` mit `tags`, oder **Edit** in
seinem Detailbereich), und ein einziger globaler Hook kann pro Zertifikat entscheiden, ob er
handelt. `CERTMATE_TAGS` ist immer gesetzt, kommagetrennt und in Kleinbuchstaben, und ein Tag
enthält nur Buchstaben, Ziffern und `. _ - : /`, daher kann man es ohne Anführungszeichen verwenden. In
Ihrem Skript:

```sh
echo ",$CERTMATE_TAGS," | grep -q ',loadbalancer,' || exit 0
```

Die umgebenden Kommas machen den Vergleich exakt: Ohne sie würde `loadbalancer`
auch auf einen Tag namens `loadbalancer-old` passen.

### Echte Arbeit bei einem Testlauf überspringen

In Ihrem Skript (die Variable wird nur vom **Test** eines einzelnen Hooks gesetzt):

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
| `Hook <id> is no longer in settings...` | Die Hook-ID in der Testanfrage stimmt mit keinem Hook in der gespeicherten Konfiguration überein: Die Seite ist veraltet, der Hook wurde gerade gelöscht, oder sein Befehl wurde beim Speichern abgelehnt. Seite neu laden. |
| `Command blocked at runtime` | Eines der [blockierten Muster](#blockierte-shell-muster) hat die Speicherprüfung umgangen. Verschieben Sie die problematische Logik in eine Skriptdatei. |
| `exit code 127` | Befehl im Container nicht gefunden (z. B. `nginx` ist nicht in `$PATH`). Absolute Pfade verwenden oder die Binärdatei im Image installieren. |
| `timeout after 30s` | Der Hook hat seinen `timeout` überschritten. Erhöhen Sie ihn (max. 300s) oder verlagern Sie die Arbeit in ein im Hintergrund laufendes Skript. |
| `Deploy hooks are disabled. Enable them in Settings → Deploy.` | `deploy_hooks.enabled` ist `false`, und Sie haben alle Hooks für eine Domain ausgeführt. Den Hauptschalter in den Einstellungen aktivieren. |
| `No enabled hooks or deploy targets configured for <domain>...` | Versuch, Hooks für eine Domain auszuführen, die keinen aktivierten globalen Hook, keinen aktivierten Eintrag unter `domain_hooks[<domain>]` und kein typisiertes Ziel dafür hat. Einen Hook hinzufügen (oder `/api/deploy/test/<id>` für einen bestimmten Hook aufrufen). |

---

## Typisierte Deploy-Ziele

Ein **typisiertes Deploy-Ziel** ist eine deklarative Alternative zu einem Shell-Hook für ein
gängiges Zielsystem, damit Sie `kubectl` + Zugangsdaten nicht selbst zusammenbauen müssen. Ziele liegen
unter `deploy_hooks.targets` und werden an denselben Stellen im Lebenszyklus ausgelöst wie Hooks
(Ausstellung + jede Erneuerung sowie manuelles Deployment), mit derselben Fehlerisolierung —
ein Ziel, das fehlschlägt, protokolliert, schreibt ins Audit-Log und löst den Alarm `deploy_hook_failed` aus, blockiert aber
nie den Zertifikatsvorgang.

Das erste typisierte Ziel ist **Kubernetes Secret**: Es schreibt die erneuerten
`fullchain.pem` / `privkey.pem` per Server-Side Apply in ein Secret vom Typ `kubernetes.io/tls`
(ein idempotentes Anlegen-oder-Aktualisieren).

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
        "domains": ["example.com"],          // leer/weggelassen = alle verwalteten Domains
        "config": {
          "secret_name": "example-tls",
          "namespace": "web",
          // Option A — direkt mit dem API-Server sprechen:
          "api_server": "https://10.0.0.1:6443",
          "token": "<service-account bearer token>",
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",  // optional; sonst die System-CAs
          "verify_ssl": true
          // Option B — Betrieb im Cluster: stattdessen "in_cluster": true setzen,
          // dann werden API-Server, Token, CA und Standard-Namespace aus dem
          // eingehängten Service Account gelesen.
        }
      }
    ]
  }
}
```

Konfigurieren Sie es über `POST /api/deploy/config` (derselbe nur für Admins zugängliche Endpoint wie
für Shell-Hooks). Das verwendete Service-Account-Token sollte auf
`patch`/`create` für Secrets im Ziel-Namespace beschränkt sein.

> **Sicherheit:** Die Deploy-Konfiguration ist nur für Admins zugänglich, und — wie ein in
> einen Shell-Hook eingebettetes Secret — wird das Kubernetes-`token` in den Einstellungen gespeichert und
> Admins bei `GET /api/deploy/config` zurückgegeben. Halten Sie den Geltungsbereich des Tokens minimal.

Ein Ziel sendet den privaten Schlüssel an die Adresse, mit der es konfiguriert ist, daher
gelten zwei Dinge:

- **Weiterleitungen werden nicht verfolgt.** Eine Weiterleitung würde die Anfrage samt
  Schlüssel an jeder Adresse wiederholen, die die Antwort nennt. Ein `3xx` vom API-Server wird
  als Fehlschlag gemeldet, der das sagt (ohne die genannte Adresse); richten Sie
  `api_server` auf die Adresse, die direkt antwortet.
- **Was zurückkommt, wird nie in die Aufzeichnungen kopiert.** Die Antwort auf eine fehlgeschlagene
  Anfrage wird dem Betreiber angezeigt und landet außerdem im Audit-Log, im Deploy-Verlauf
  und im Fehleralarm. Das Audit-Log ist eine Hash-Kette und kann nachträglich nicht
  bearbeitet werden, daher wird die Antwort vom Bearer-Token und vom Schlüssel bereinigt
  (als PEM, JSON-escaped, base64, URL-kodiert oder als eine Zeile davon), bevor sie
  gekürzt und aufbewahrt wird.

`verify_ssl: false` wird für einen Cluster mit einem Zertifikat, das Sie nicht verifizieren können,
weiterhin akzeptiert. Es schaltet die Prüfung ab, ob der Server derjenige ist, den Sie konfiguriert haben;
verwenden Sie es also nur in einem Netz, das Sie kontrollieren.

### Webhook-Ziel: das Zertifikat ausliefern, optional auch den Schlüssel

Ein **Benachrichtigungs-Webhook** (Settings → Notifications) *kündigt* eine Erneuerung *an*, und
was er meldet, erreicht Alarme, E-Mail und Logs. Er trägt nie den privaten Schlüssel
([webhooks.md](../webhooks.md)). Das **Webhook-Ziel** *liefert aus*: Es sendet das
Zertifikat und die Chain und, wenn die Vorlage danach fragt, den privaten Schlüssel an einen
von Ihnen gewählten HTTPS-Endpoint, typischerweise eine Appliance oder einen Dienst mit einer Upload-API.
Das sind verschiedene Dinge mit verschiedenen Regeln, daher ist dies ein Deploy-Ziel
und kein weiterer Platzhalter des Benachrichtigungs-Webhooks.

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
        "domains": ["shop.example.com"],      // Pflicht: nie standardmäßig "alle Domains"
        "on_events": ["created", "renewed"],
        "config": {
          "url": "https://lb.internal:8443/api/certificate",
          "method": "POST",                   // POST, PUT oder PATCH
          "payload_template": "{\"name\": \"{{domain}}\", \"cert\": \"{{fullchain}}\", \"key\": \"{{privkey_pkcs8}}\"}",
          "auth_type": "bearer", "auth_token": "<token>",   // none | bearer | basic | header
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",     // oder "pin_sha256": "<fingerprint>"
          "allow_internal": true,             // das Ziel liegt in einem privaten Netz
          "acknowledge_key_delivery_to": "lb.internal"      // nötig, weil die Vorlage den Schlüssel nennt
        }
      }
    ]
  }
}
```

**In der UI.** Settings → Deploy → **Deploy Targets** listet jedes Ziel auf und
bearbeitet die Webhook-Ziele: Name, Domains (Pflicht), Ereignisse, URL, Methode,
Authentifizierung, Signier-Secret, wie der Server verifiziert wird, einen Schalter für private Netze,
Timeout und Versuche sowie die Payload mit den Variablen als Schaltflächen. Die
Schlüsselvariablen sind rot, und das Hinzufügen einer davon löst die unten beschriebene Bestätigung aus. **Preview what would be sent**
ruft den unten beschriebenen Preview-Endpoint auf und zeigt das Ziel mit seinem Port,
wie der Server verifiziert wird, die Dateien, die eine Auslieferung liest, die Header (Zugangsdaten
maskiert) und den Body, gerendert mit einem Beispielzertifikat und -schlüssel. Eine Vorschau
verschwindet, sobald sich das Formular ändert, sodass das, was auf dem Bildschirm steht, immer das ist,
was gespeichert würde.

Nennt die Payload eine Variable für den privaten Schlüssel, zeigt das Formular einen roten Kasten mit dem
Ziel-Host und hält **Save target** deaktiviert, bis Sie diesen Host eingetippt haben.
Ein Ziel, das für seinen Host bereits bestätigt ist, wird nicht erneut gefragt, wenn Sie es umbenennen oder
seine Domains ändern; ein anderer Host fragt erneut und sagt, für welchen Host es
bestätigt war. Das Speichern schreibt nur `targets`, aus der Liste, die der Server in diesem
Moment hält, mit nur diesem einen geänderten Ziel, sodass es eine zwischenzeitlich über
die API vorgenommene Änderung nicht überschreiben kann, und es lässt die anderen Zieltypen (Kubernetes-Secrets)
genau so, wie sie sind. Sie werden dort aufgelistet und über die API bearbeitet. Die Seite
sendet nie eine Zustimmung: Der Server schreibt sie.

**Vorlagenvariablen.** Die Payload ist JSON, das Sie schreiben. Ein Platzhalter innerhalb eines
Strings wird escaped eingefügt, sodass ein PEM (das Zeilenumbrüche enthält) das JSON nicht zerbrechen kann.

| Variable | Was sie ist |
|---|---|
| `{{cert}}`, `{{fullchain}}`, `{{chain}}` | das Zertifikat, das Zertifikat mit seiner Chain, die Chain allein (PEM) |
| `{{privkey_pkcs8}}` | der private Schlüssel als PKCS#8 (`BEGIN PRIVATE KEY`) |
| `{{privkey_traditional}}` | der private Schlüssel als PKCS#1 für RSA (`BEGIN RSA PRIVATE KEY`) oder SEC1 für EC (`BEGIN EC PRIVATE KEY`). Ein Schlüsseltyp ohne eine solche Form, etwa Ed25519, wird mit einer Meldung abgelehnt, nicht stillschweigend ersetzt |
| `{{event}}`, `{{domain}}`, `{{timestamp}}`, `{{certificate_sha256}}` | das Ereignis, der Name des Zertifikats, die Uhrzeit und der SHA-256 des Blattzertifikats |

Es gibt kein bloßes `privkey`: Die zwei Schreibweisen machen die Wahl sichtbar, und ein
Tippfehler in einem Namen wird beim Speichern abgelehnt, statt stillschweigend nichts zu senden. Ein
Name, der nicht in dieser Tabelle steht, wird abgelehnt.

**Den Schlüssel zu senden ist eine Entscheidung über ein Ziel.** Nennt die Vorlage eine
Variable für den privaten Schlüssel, muss das Speichern `config.acknowledge_key_delivery_to`
mit dem Host aus `url` als Wert mitführen. Der Server hält dann fest, wer es bestätigt hat und wann
(`delivery_consent`, zurückgegeben von `GET /api/deploy/config`); das wird nie aus dem gelesen,
was Sie senden. Ändern Sie später den Host, gilt die Bestätigung nicht mehr:
Das Ziel verweigert das Senden, bis sie erneut gegeben wird, und ein Speichern ohne sie wird
abgelehnt. Jede Bestätigung steht im Audit-Log.

**Wie der Server verifiziert wird.** Immer. Standardmäßig gegen den Zertifikatsspeicher des Systems. Mit
`ca_cert` nur gegen diese CA (sie ersetzt den Systemspeicher). Mit
`pin_sha256` gegen den exakten SHA-256-Fingerprint des eigenen Zertifikats des Servers,
für eine Appliance, die sich selbst signiert: Geben Sie den Fingerprint an (Doppelpunkte
erlaubt), nicht das Zertifikat. Es gibt keine Einstellung, die die Verifizierung abschaltet,
und die URL muss `https://` sein.

**Wohin es senden darf.** Der Host wird einmal aufgelöst, jede Adresse wird geprüft, und
die Verbindung geht an diese Adresse. Eine Loopback-, Link-Local- oder Cloud-Metadaten-Adresse
ist nie ein Ziel. Ein Ziel in einem privaten Netz braucht
`allow_internal: true` **auf diesem Ziel**, was bewusst so gewählt und enger ist als
ein Schalter für die ganze Instanz. Weiterleitungen werden nicht verfolgt: Ein `3xx` ist ein
Fehlschlag, der das sagt.

**Was es tut, wenn etwas schiefgeht.** Ein Netzwerkfehler oder ein
Status `408`, `425`, `429`, `500`, `502`, `503` oder `504` wird mit Backoff
bis zu `attempts` Mal wiederholt (Standard 3, höchstens 5). Jeder andere Status nicht: Ein `4xx` sagt, dass die
Anfrage falsch ist, und einen Schlüssel noch einmal zu senden, um das noch einmal gesagt zu bekommen, hilft niemandem. Jede Auslieferung trägt einen `Idempotency-Key`,
der für die Wiederholungen einer Auslieferung und für dasselbe erneut gesendete Zertifikat gleich ist
und für das nächste Zertifikat ein anderer, sodass ein Empfänger eine
Wiederholung von einer neuen Auslieferung unterscheiden kann. Mit `signing_secret` wird der Body in
`X-CertMate-Signature` signiert, wie beim Benachrichtigungs-Webhook.

**Was festgehalten wird und was nicht.** Ein Ergebnis ist ein Status und ein Satz, der
den Host nennt: nie die Adresse, die Query, die Header, der von Ihnen gesendete Body oder
der Body, mit dem der Empfänger geantwortet hat, der zurückgeben kann, was ihm gesendet wurde. Eine Auslieferung, die
den privaten Schlüssel enthielt, wird im Audit-Log markiert: wohin sie ging (`key_sent_to`),
für welche Domain, der Fingerprint des Zertifikats, der Status und die Versuche, und
nie der Schlüssel. Ein Reset nach dem TLS-Handshake wird als möglicherweise gesendet festgehalten,
weil er sich nicht von einem Reset davor unterscheiden lässt.

**Es gibt kein „Test senden" für ein Ziel, das den Schlüssel sendet**, mit Absicht. Ein Test,
der einen Schlüssel an eine Appliance auslieferte, die Uploads annimmt, würde ihn anstelle
des echten installieren. Verwenden Sie stattdessen die **Vorschau**
([`POST /api/deploy/targets/preview`](./api.md)): Sie rendert die Anfrage gegen ein
Beispielzertifikat und einen Beispielschlüssel, liest keine Datei und sendet nichts. Um einmal wirklich
auszuliefern, verwenden Sie [*Alle Hooks für eine Domain ausführen*](#alle-hooks-für-eine-domain-ausführen-admin) (Admin), was eine ausdrückliche Aktion ist.

**Wovor das schützt und wovor nicht.**

| Es schützt davor | Es schützt nicht davor |
|---|---|
| Dass der Schlüssel an einen Host geht, den Sie nicht bestätigt haben, auch nachdem die URL bearbeitet wurde | Dass ein Empfänger kompromittiert ist oder protokolliert, was ihm gesendet wird: Er hält den Schlüssel, sobald er ihn hat. Manche Automatisierungsplattformen bewahren jeden Request-Body in einem Ausführungsverlauf auf; richten Sie kein Ziel, das den Schlüssel trägt, auf eine solche |
| Dass eine Weiterleitung, eine per Rebinding umgelenkte DNS-Antwort oder eine Metadaten-Adresse die Anfrage woandershin lenkt | Vor einem Administrator: Wer diese Konfiguration speichern kann, kann bereits einen [Shell-Hook](#den-privaten-schlüssel-aus-einem-hook-senden) schreiben, der den Schlüssel sendet, ohne irgendeine der obigen Prüfungen |
| Dass über einfaches HTTP gesendet wird oder an einen Server, den niemand verifiziert hat | Dass der Schlüssel in den eigenen Backups und Logs des Empfängers landet |
| Dass die Antwort des Empfängers den Schlüssel ins Audit-Log trägt | |
| | Vor dem Abgreifen der eigenen Zugangsdaten des Ziels: `auth_token`, `auth_password` und `signing_secret` werden in `settings.json` (Modus `0600`) aufbewahrt und einem Administrator von `GET /api/deploy/config` zurückgegeben, genau wie das Token eines Kubernetes-Ziels. Das Formular zeigt sie als Passwortfelder. Geben Sie dem Empfänger ein Token, das genau diese eine Sache kann |

In dieser Version nicht enthalten: ein Bundle als Datei-Upload oder PKCS#12 sowie eigene Request-Header
außer dem für die Authentifizierung. Sagen Sie, was ein Empfänger braucht.

#### Empfang in n8n

Geprüft mit n8n 2.41.4, einem echten Zertifikat, einem Webhook-Node und der Payload
unten; die drei Schritte sind das, was getan werden musste, nicht das, was allgemein für n8n gilt.

```json
{"domain": "{{domain}}", "event": "{{event}}",
 "certificates": {"cert": "{{cert}}", "key": "{{privkey_pkcs8}}", "rsa_key": "{{privkey_traditional}}",
                  "fullchain": "{{fullchain}}", "intermediate": "{{chain}}"}}
```

1. **n8n muss über HTTPS antworten.** Ein n8n mit Standardeinstellungen lauscht auf einfachem HTTP, und ein Ziel
   lehnt das ab (`url must be https://`). Stellen Sie einen TLS-Terminator davor, oder geben Sie n8n
   selbst ein Zertifikat mit `N8N_PROTOCOL=https`, `N8N_SSL_KEY=/path/key.pem` und
   `N8N_SSL_CERT=/path/cert.pem`. Für ein Zertifikat, das n8n selbst signiert hat, setzen Sie `pin_sha256` auf
   dem Ziel auf dessen Fingerprint: nur die Ziffern, nicht die Bezeichnung. Der Befehl
   `openssl x509 -in cert.pem -noout -fingerprint -sha256` gibt
   `SHA256 Fingerprint=AA:BB:...` aus; fügen Sie ein, was nach dem `=` folgt, weil das Feld die
   Bezeichnung ablehnt. Liegt n8n an einer privaten Adresse, setzen Sie auf dem Ziel außerdem `allow_internal: true`.
2. **Der Webhook-Node:** HTTP Method `POST`, ein Path wie `certmate`, Respond
   *Immediately*, und veröffentlichen Sie den Workflow. Das Ziel muss die **Produktions**-URL aufrufen
   (`https://host:5678/webhook/certmate`), nicht die Test-URL.
3. **Was der Node empfängt.** `$json.body` ist die Payload, die Sie geschrieben haben, das Beispiel oben
   ergibt also `{{ $json.body.certificates.fullchain }}` und so weiter, als gewöhnlichen mehrzeiligen
   PEM-String. Die Header stehen in `$json.headers`: `x-certmate-event`, `idempotency-key`
   (gleich bei einer Wiederholung einer Auslieferung, sodass ein Workflow eine Wiederholung ignorieren kann) und
   `user-agent: CertMate-Deploy/1`. In der Prüfung kam jedes Zertifikat identisch mit
   der Datei an, der PKCS#8-Schlüssel identisch mit `privkey.pem`, und der Schlüssel in der traditionellen
   Form (`RSA PRIVATE KEY` oder `EC PRIVATE KEY`) war der Schlüssel des Zertifikats, für ein RSA-
   und ein EC-Zertifikat.

**n8n bewahrt auf, was es empfängt.** Mit seinen Standardeinstellungen speicherte n8n jeden Request-Body
in seiner eigenen Datenbank, und in der Prüfung ließ sich der private Schlüssel aus diesen
Ausführungsdaten auslesen. Behandeln Sie die Datenbank von n8n und ihre Backups so, als enthielten sie den Schlüssel, oder lassen Sie die
Schlüsselvariablen aus einem n8n-Ziel weg und holen Sie den Schlüssel auf anderem Weg. Den Workflow so einzustellen, dass er
keine Ausführungen speichert, verhielt sich in derselben Prüfung **nicht** wie erwartet (die Ausführungen blieben
mit ihren Daten im Zustand `running`), verlassen Sie sich also nicht auf diese Einstellung, ohne nachzusehen,
was Ihre eigene Instanz speichert. Das ist der Fall, den die Tabelle oben mit „Manche Automatisierungsplattformen
bewahren jeden Request-Body in einem Ausführungsverlauf auf" meint.

---

## Siehe auch

- [`modules/core/deployer.py`](../../modules/core/deployer.py) — Implementierung
- [`modules/core/deploy_targets.py`](../../modules/core/deploy_targets.py) — typisierte Deploy-Ziele
- [`modules/web/settings_routes.py`](../../modules/web/settings_routes.py) — `/api/deploy/*`-Endpoints
- [`templates/partials/settings_deploy.html`](../../templates/partials/settings_deploy.html) — UI-Partial
- [`static/js/settings-deploy.js`](../../static/js/settings-deploy.js) — Alpine-Komponente
