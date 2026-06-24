# CertMate Model Context Protocol (MCP) Server

CertMate enthält einen integrierten Model Context Protocol (MCP) Server, der in Node.js geschrieben ist. Dadurch können agentische KI-Assistenten (wie Claude oder Gemini) Zertifikatsstatus sicher prüfen, Erneuerungen auslösen, Diagnosen anfordern und direkt mit der CertMate API interagieren.

## Funktionen und Tools

Der CertMate MCP Server stellt folgenden KI-Assistenten diese Tools zur Verfügung:

**Inventar und Status**
1. **`certmate_list_certificates`** — Listet alle vom aktiven CertMate-Instanz verwalteten Zertifikate auf (mit Ablaufdatum, Status, Domains).
2. **`certmate_get_certificate`** — Vollständige Details für eine Domain: Status, verbleibende Tage bis zum Ablauf, SANs, DNS/CA-Anbieter, Auto-Renew-Flag. Verwenden Sie es, um zu entscheiden, ob ein Zertifikat erneuert werden muss.
3. **`certmate_get_activity`** — Aktuelle Aktivitäten/Auditprotokoll, um nachzuvollziehen, was sich geändert hat oder fehlgeschlagen ist.
4. **`certmate_diagnostics`** — Umfassender, bereinigter Diagnose-Snapshot.
5. **`certmate_get_settings`** — Globale Einstellungen und Konfiguration.

**Lebenszyklus-Operationen**
6. **`certmate_create_certificate`** — Fordert ein neues TLS-Zertifikat für eine Domain an (optionaler DNS-Anbieter, Account, CA). Kann bei asynchroner Ausstellung eine `job_id` (HTTP 202) zurückgeben.
7. **`certmate_renew_certificate`** — Erzwingt die Erneuerung eines vorhandenen Zertifikats (kann ebenfalls eine `job_id` zurückgeben).
8. **`certmate_get_job`** — Fragt einen asynchronen Erstellungs-/Erneuerungsauftrag per `job_id` ab, bis dieser als abgeschlossen oder fehlgeschlagen gemeldet wird.
9. **`certmate_set_auto_renew`** — Aktiviert oder deaktiviert die automatische Erneuerung für eine einzelne Domain.
10. **`certmate_deploy_certificate`** — Führt alle konfigurierten deploy hooks für eine Domain manuell aus.
11. **`certmate_download_certificate`** — Gibt das Zertifikatsmaterial einer Domain als JSON zurück (fullchain, key, chain), damit ein Agent es anderswo einsetzen kann.

**Anbieter**
12. **`certmate_list_dns_providers`** — Auf dieser Instanz unterstützte und konfigurierte DNS-Anbieter.
13. **`certmate_list_dns_accounts`** — Konfigurierte DNS-Anbieter-Accounts (Zugangsdaten maskiert); verwenden Sie eine zurückgegebene Account-ID als `account_id` beim Erstellen eines Zertifikats.

## Einrichtung und Konfiguration

### Voraussetzungen
- Node.js (v18 oder höher)
- npm

### Installation
Wechseln Sie in das Verzeichnis `mcp/` im CertMate-Repository und installieren Sie die Abhängigkeiten:
```bash
cd mcp
npm install
```

### Umgebungsvariablen
Der MCP Server kommuniziert mit der CertMate REST API und benötigt zwei Umgebungsvariablen:
- `CERTMATE_URL` — Die URL Ihrer CertMate-Instanz (Standard: `http://localhost:8000`).
- `CERTMATE_TOKEN` — Ein gültiger API-Bearer-Token mit den entsprechenden Rollenberechtigungen (in der Regel `operator` oder `admin`). Für einen auditierbaren Agenten verwenden Sie einen als Agent-Key markierten Schlüssel (siehe [Audit-Zuordnung](#audit-zuordnung)).

Optional:
- `CERTMATE_AGENT_SESSION` — Überschreibt die prozessgebundene Session-ID, die der Server bei jedem Aufruf sendet (`X-CertMate-Agent-Session`), damit ein Lauf mit der ID eines externen Orchestrators korreliert werden kann. Wenn nicht gesetzt, wird pro Prozess eine neue UUID generiert.
- `CERTMATE_AGENT_ID` — Eine Bezeichnung für dieses Agent-Deployment (`X-CertMate-Agent-Id`, Standard `certmate-mcp-server`).

### Integrationsbeispiel (Claude Desktop Konfiguration)
Um den CertMate MCP Server zu Claude Desktop hinzuzufügen, fügen Sie Folgendes zu Ihrer Konfigurationsdatei hinzu (in der Regel unter `~/Library/Application Support/Claude/claude_desktop_config.json` auf macOS oder `%APPDATA%\Claude\claude_desktop_config.json` unter Windows):

```json
{
  "mcpServers": {
    "certmate": {
      "command": "node",
      "args": ["/absolute/path/to/certmate/mcp/index.js"],
      "env": {
        "CERTMATE_URL": "http://localhost:8000",
        "CERTMATE_TOKEN": "your_secure_bearer_token"
      }
    }
  }
}
```

### Andere MCP-Clients (Gemini usw.)

Der Server spricht Standard-MCP über stdio, sodass jeder Client, der MCP unterstützt, auf dieselbe Weise funktioniert: Verweisen Sie ihn auf `node /absolute/path/to/certmate/mcp/index.js` und setzen Sie die zwei Umgebungsvariablen. Nichts im Server ist Claude-spezifisch.

## CertMate mit einem KI-Agenten betreiben (geplante Aufgaben)

Die meisten erstklassigen Assistenten unterstützen inzwischen **geplante Aufgaben** (Claude, Gemini und andere). Kombiniert mit diesem MCP Server ergibt sich ein autonomer „Zertifikatswächter": Sie beschreiben die Richtlinie in natürlicher Sprache mit expliziten Bedingungen, das Modell plant sich selbst, und bei jeder Ausführung setzt es die Richtlinie mithilfe der oben genannten Tools durch. Das Muster ist modellunabhängig — alles, was einen gespeicherten Prompt nach Zeitplan ausführen und MCP-Tools aufrufen kann, wird funktionieren.

### Die Schleife, die der Agent durchläuft

1. `certmate_list_certificates` (oder `certmate_get_certificate` pro Domain), um `days_left` / Status zu lesen.
2. Entscheidung gemäß Ihrer Bedingung, z. B. *erneuern, wenn `days_left < 14`*.
3. `certmate_renew_certificate` für jede fällige Domain.
4. Wenn eine Erneuerung eine `job_id` zurückgibt, `certmate_get_job` so lange aufrufen, bis `completed` / `failed` gemeldet wird.
5. Bei einem Fehler diesen melden — und die eigenen Benachrichtigungskanäle von CertMate (E-Mail, Slack, Discord, Telegram, ntfy, Gotify) werden bei `certificate_failed` ebenfalls ausgelöst, sodass Sie unabhängig davon eine Push-Benachrichtigung erhalten.

### Beispiele für geplante Prompts

> **Täglich, 08:00** — „Verwende die CertMate MCP Tools und liste alle Zertifikate auf. Rufe für alle mit `days_left < 14` `certmate_renew_certificate` auf und frage dann `certmate_get_job` ab, bis der Vorgang abgeschlossen ist. Antworte mit einer einzeiligen Zusammenfassung pro Domain und hebe Fehler hervor."

> **Wöchentlich** — „Rufe `certmate_get_activity` und `certmate_diagnostics` auf. Fasse Auffälligkeiten (fehlgeschlagene Erneuerungen, abgelaufene Zertifikate, nicht laufender Scheduler) in drei Punkten zusammen. Wenn alles in Ordnung ist, sage es."

> **Bei Bedarf** — „Stelle ein Zertifikat für `shop.example.com` aus, indem du `certmate_list_dns_providers` verwendest, um einen konfigurierten Anbieter auszuwählen, und `certmate_list_dns_accounts` für die Account-ID, und verfolge dann den Auftrag bis zum Abschluss."

Da die Bedingungen im Prompt liegen, können Sie die Richtlinie (Schwellenwert, welche Domains, Verhalten bei Fehler) anpassen, ohne Code zu ändern. Geben Sie dem Agenten einen Token, der genau auf das beschränkt ist, was er tun soll — `operator` für Erneuerung/Deployment, `admin` nur wenn er Einstellungen ändern oder Diagnosen lesen muss.

## Sicherheit

1. **Token-Schutz** — Der MCP Server erfordert einen gültigen `CERTMATE_TOKEN`. Er überträgt diesen Token sicher im `Authorization`-Header für alle Anfragen an die CertMate API.
2. **Minimale Berechtigungen** — Beschränken Sie den Token auf das, was der Agent benötigt. Ein geplanter Erneuerungswächter benötigt `operator`; reservieren Sie `admin`-Tokens für Agenten, die Einstellungen ändern oder Diagnosen abrufen müssen. Widerrufen Sie den Token, um dem Agenten sofort den Zugang zu entziehen.
3. **Kompatibilität mit Log-Bereinigung** — Tools wie `certmate_diagnostics` rufen Daten ab, nachdem der Log Sanitizer sensible Zugangsdaten entfernt hat, und schützen so Schlüssel und Tokens vor dem Durchsickern in LLM-Kontexte.

## Audit-Zuordnung

Damit das Auditprotokoll die Aktionen eines Agenten von denen eines menschlichen Operators unterscheiden kann, geben Sie dem MCP Server einen **dedizierten, als Agent markierten API-Schlüssel** anstelle des veralteten globalen Bearer-Tokens:

1. Gehen Sie in CertMate zu **Einstellungen → API-Schlüssel**, erstellen Sie einen Schlüssel und aktivieren Sie **KI-Agent-Schlüssel** (oder senden Sie `"is_agent": true` an `POST /api/keys`). Schränken Sie ihn mit `allowed_domains` und der minimal benötigten Rolle ein.
2. Setzen Sie diesen Schlüssel als `CERTMATE_TOKEN` für den MCP Server.

Jede Zertifikatsaktion, die der Agent daraufhin durchführt, wird mit `actor.kind="agent"`, der stabilen ID des Schlüssels und der prozessgebundenen `X-CertMate-Agent-Session`, die der Server sendet, aufgezeichnet — sodass Sie später genau nachvollziehen können, welche Zertifikatsänderungen ein KI-Agent vorgenommen hat, unter welcher Identität und gruppiert nach Lauf. Der veraltete globale Bearer-Token fasst jeden Aufrufer als `api_user` ohne Schlüssel-ID zusammen und wird als `api_token`, nicht als `agent`, erfasst. Der Agent-Session-Header ist eine informative Angabe und befördert einen Aufrufer niemals allein in den Status `agent`.

Die resultierenden Einträge sind Teil der manipulationssicheren Audit-Kette; siehe [Audit Logging](./api.md#audit-logging) und [compliance.md](./compliance.md).

---

<div align="center">

[← Zurück zur Dokumentation](./README.md)

</div>
