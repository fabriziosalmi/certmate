# CertMate Client-Zertifikate - API-Referenz

## Übersicht

Die CertMate-API für Client-Zertifikate stellt REST-Endpoints für eine vollständige Zertifikatsverwaltung mit Authentifizierung, Rate Limiting und Audit-Protokollierung bereit.

**Basis-URL**: `http://localhost:5000/api`
**Authentifizierung**: Bearer Token (auf allen Endpoints erforderlich)
**Content-Type**: `application/json`

---

## Authentifizierung

Alle API-Endpoints erfordern eine Authentifizierung per Bearer Token.

### Header-Format

```
Authorization: Bearer IHR_TOKEN
```

### Beispielanfrage

```bash
curl -X GET http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer IHR_TOKEN" \
 -H "Content-Type: application/json"
```

---

## Rate Limiting

API-Endpoints unterliegen Rate Limits, um Missbrauch zu verhindern:

| Endpoint              | Limit | Pro    |
| --------------------- | ----- | ------ |
| Allgemein             | 100   | Minute |
| Zertifikat erstellen  | 30    | Minute |
| Batch-Operationen     | 10    | Minute |
| OCSP-Status           | 200   | Minute |
| CRL-Download          | 60    | Minute |

### Antwort bei überschrittenem Limit

Wird das Limit überschritten, erhalten Sie:

```
HTTP 429 Too Many Requests

{
 "error": "Rate limit exceeded",
 "message": "Too many requests. Please try again later.",
 "retry_after": 60
}
```

---

## Endpoints

### Zertifikatsverwaltung

#### 1. Zertifikat erstellen

**Endpoint**: `POST /client-certs/create`

Erstellt ein neues Client-Zertifikat.

**Anfrage**:
```json
{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true,
 "notes": "Production certificate"
}
```

**Parameter**:
- `common_name` (erforderlich) — Subject des Zertifikats
- `email` (optional) — E-Mail-Adresse
- `organization` (optional) — Name der Organisation
- `organizational_unit` (optional) — Abteilungsname
- `cert_usage` (optional) — Verwendungstyp: `api-mtls`, `vpn` oder benutzerdefiniert
- `days_valid` (optional) — Gültigkeitsdauer in Tagen (Standard: 365)
- `generate_key` (optional) — Privaten Schlüssel erzeugen (Standard: true)
- `notes` (optional) — Zusätzliche Anmerkungen

**Antwort** (201 Created):
```json
{
 "identifier": "cert-abc123",
 "common_name": "user@example.com",
 "serial_number": "12345678901234567890",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "cert_usage": "api-mtls",
 "status": "active"
}
```

**Beispiel**:
```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365
 }'
```

---

#### 2. Zertifikate auflisten

**Endpoint**: `GET /client-certs`

Listet alle Client-Zertifikate mit optionaler Filterung auf.

**Query-Parameter**:
- `usage` (optional) — Nach Verwendungstyp filtern (z. B. `api-mtls`)
- `revoked` (optional) — Nach Status filtern (`true` oder `false`)
- `search` (optional) — Im Common Name suchen

**Antwort** (200 OK):
```json
{
 "certificates": [{
 "identifier": "cert-001",
 "common_name": "user1@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "revoked": false,
 "status": "active"
 },
 {
 "identifier": "cert-002",
 "common_name": "user2@example.com",
 "organization": "ACME Corp",
 "cert_usage": "vpn",
 "created_at": "2024-10-29T18:00:00Z",
 "expires_at": "2025-10-29T18:00:00Z",
 "revoked": true,
 "status": "revoked"
 }
 ],
 "total": 2
}
```

**Beispiele**:
```bash
# Alle Zertifikate auflisten
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Nach Verwendungstyp filtern
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Nur widerrufene auflisten
curl "http://localhost:5000/api/client-certs?revoked=true" \
 -H "Authorization: Bearer TOKEN"

# Nach Common Name suchen
curl "http://localhost:5000/api/client-certs?search=user1" \
 -H "Authorization: Bearer TOKEN"
```

---

#### 3. Zertifikatsdetails abrufen

**Endpoint**: `GET /client-certs/<identifier>`

Ruft die vollständigen Metadaten eines Zertifikats ab.

**Antwort** (200 OK):
```json
{
 "type": "client_certificate",
 "identifier": "cert-001",
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "serial_number": "12345678901234567890",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "cert_usage": "api-mtls",
 "notes": "Production certificate",
 "revocation": {
 "revoked": false,
 "revoked_at": null,
 "reason_revoked": null
 },
 "renewal": {
 "renewal_enabled": true,
 "renewal_threshold_days": 30
 }
}
```

**Beispiel**:
```bash
curl http://localhost:5000/api/client-certs/cert-001 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 4. Zertifikatsdateien herunterladen

**Endpoint**: `GET /client-certs/<identifier>/download/<type>`

Lädt das Zertifikat, den privaten Schlüssel oder die CSR-Datei herunter.

**Parameter**:
- `identifier` — Zertifikats-ID
- `type` — Dateityp: `crt`, `key` oder `csr`

**Antwort** (200 OK):
- Content-Type: `application/octet-stream`
- Dateianhang mit korrekter Benennung

**Beispiele**:
```bash
# Zertifikat herunterladen
curl http://localhost:5000/api/client-certs/cert-001/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o certificate.crt

# Privaten Schlüssel herunterladen
curl http://localhost:5000/api/client-certs/cert-001/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o private.key

# CSR herunterladen
curl http://localhost:5000/api/client-certs/cert-001/download/csr \
 -H "Authorization: Bearer TOKEN" \
 -o request.csr
```

---

#### 5. Zertifikat widerrufen

**Endpoint**: `POST /client-certs/<identifier>/revoke`

Widerruft ein Zertifikat mit optionalem Grund.

**Anfrage** (optional):
```json
{
 "reason": "compromised"
}
```

**Antwort** (200 OK):
```json
{
 "message": "Certificate revoked: cert-001",
 "revoked_at": "2024-10-30T18:15:00Z",
 "reason": "compromised"
}
```

**Beispiel**:
```bash
curl -X POST http://localhost:5000/api/client-certs/cert-001/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "reason": "compromised"
 }'
```

---

#### 6. Zertifikat erneuern

**Endpoint**: `POST /client-certs/<identifier>/renew`

Erneuert ein Zertifikat (gleicher CN, neue Seriennummer).

**Antwort** (201 Created):
```json
{
 "identifier": "cert-001-renewed",
 "common_name": "user@example.com",
 "serial_number": "98765432109876543210",
 "created_at": "2024-10-30T18:20:00Z",
 "expires_at": "2025-10-30T18:20:00Z",
 "status": "active"
}
```

**Beispiel**:
```bash
curl -X POST http://localhost:5000/api/client-certs/cert-001/renew \
 -H "Authorization: Bearer TOKEN"
```

---

#### 7. Statistiken abrufen

**Endpoint**: `GET /client-certs/stats`

Ruft Nutzungsstatistiken zu Zertifikaten ab.

**Antwort** (200 OK):
```json
{
 "total": 100,
 "active": 85,
 "revoked": 15,
 "expiring_soon": 8,
 "by_usage": {
 "api-mtls": 60,
 "vpn": 35,
 "other": 5
 },
 "created_count": 100,
 "renewal_enabled": 92
}
```

**Beispiel**:
```bash
curl http://localhost:5000/api/client-certs/stats \
 -H "Authorization: Bearer TOKEN"
```

---

#### 8. Zertifikate im Batch importieren

**Endpoint**: `POST /client-certs/batch`

Erstellt mehrere Zertifikate aus CSV-Daten in einer einzigen Anfrage.

**Anfrage**:
```json
{
 "headers": ["common_name", "email", "organization", "cert_usage", "days_valid"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp", "api-mtls", "365"],
 ["user2@example.com", "user2@example.com", "ACME Corp", "vpn", "365"],
 ["user3@example.com", "user3@example.com", "ACME Corp", "api-mtls", "365"]
 ]
}
```

**Antwort** (201 Created):
```json
{
 "total": 3,
 "successful": 3,
 "failed": 0,
 "errors": [],
 "certificates": [{
 "identifier": "cert-batch-001",
 "common_name": "user1@example.com"
 },
 {
 "identifier": "cert-batch-002",
 "common_name": "user2@example.com"
 },
 {
 "identifier": "cert-batch-003",
 "common_name": "user3@example.com"
 }
 ]
}
```

**Beispiel**:
```bash
curl -X POST http://localhost:5000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "headers": ["common_name", "email", "organization"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
 ["user2@example.com", "user2@example.com", "ACME Corp"]
 ]
 }'
```

---

### OCSP & CRL

#### 9. OCSP-Statusabfrage

**Endpoint**: `GET /ocsp/status/<serial_number>`

Fragt den Zertifikatsstatus per OCSP ab.

**Antwort** (200 OK):
```json
{
 "response_status": "successful",
 "certificate_status": "good|revoked|unknown",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z",
 "next_update": null,
 "responder_name": "CertMate OCSP Responder"
}
```

**Beispiel**:
```bash
curl http://localhost:5000/api/ocsp/status/12345678 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 10. CRL-Distribution

**Endpoint**: `GET /crl/download/<format_type>`

Lädt die Zertifikatssperrliste (CRL) herunter.

**Parameter**:
- `format_type` — `pem`, `der` oder `info`

**Antwort**:
- Für `pem` und `der`: Dateianhang
- Für `info`: JSON mit CRL-Metadaten

**Beispiele**:
```bash
# CRL im PEM-Format herunterladen
curl http://localhost:5000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# CRL im DER-Format herunterladen
curl http://localhost:5000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# CRL-Informationen abrufen
curl http://localhost:5000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

**CRL-Info-Antwort**:
```json
{
 "status": "available",
 "issuer": "CN=CertMate CA, O=CertMate",
 "last_update": "2024-10-30T18:00:00Z",
 "next_update": "2024-10-31T18:00:00Z",
 "revoked_count": 5,
 "revoked_serials": [12345678,
 87654321
 ]
}
```

---

#### 11. Domain-Zertifikatsdateien herunterladen

**Endpoint**: `GET /certificates/<domain>/download`

Lädt Zertifikatsdateien für eine bestimmte Domain herunter. Standardmäßig gibt dieser Endpoint ein ZIP-Archiv zurück, das alle Zertifikatskomponenten enthält. Eine einzelne Datei kann über den Query-Parameter `file` angefordert werden. Ein JSON-Modus ist ebenfalls verfügbar für Automatisierung, die alle PEMs in einer einzigen Antwort erhalten möchte.

**Parameter**:
- `domain` (Pfad) — Der mit dem Zertifikat verknüpfte Domainname.
- `file` (Query, optional) — Gibt eine einzelne herunterzuladende Datei an.
  - Unterstützte Werte: `fullchain.pem`, `privkey.pem`, `combined.pem`
- `format` (Query, optional) — Auf `json` setzen, um alle Zertifikatsdateien in einem JSON-Objekt zurückzugeben.

**Antwort** (200 OK):
- **Standard**: `application/zip` (ein ZIP-Archiv mit allen PEM-Dateien)
- **Mit `file`-Parameter**: `application/x-pem-file` (der rohe Inhalt der angeforderten Datei)
- **Mit `format=json`**: `application/json` mit `domain`, `cert_pem`, `chain_pem`, `fullchain_pem` und `private_key_pem`

Die JSON-Form ist das bevorzugte Automatisierungsformat für Ansible, Salt oder jeden anderen Client, der PEM-Dateien direkt schreiben möchte.

**Beispiele**:

```bash
# Alle Dateien als ZIP-Archiv herunterladen
curl http://localhost:5000/api/certificates/example.com/download \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.zip

# Nur die Datei fullchain.pem herunterladen
curl "http://localhost:5000/api/certificates/example.com/download?file=fullchain.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o fullchain.pem

# Nur den privaten Schlüssel herunterladen
curl "http://localhost:5000/api/certificates/example.com/download?file=privkey.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o privkey.pem

# Das vollständige Zertifikats-Bundle als JSON herunterladen
curl "http://localhost:5000/api/certificates/example.com/download?format=json" \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.json

```

---

#### 12. Domain-Zertifikat neu ausstellen (Konfiguration bearbeiten)

**Endpoint**: `POST /certificates/<domain>/reissue`

Bearbeitet die Konfiguration eines Zertifikats und stellt es an Ort und Stelle neu aus — SAN-Einträge erweitern oder entfernen, ohne löschen + neu erstellen zu müssen. Ausgelassene Felder behalten die Werte, mit denen das Zertifikat ausgestellt wurde (aus den Metadaten gelesen), sodass die DNS/Alias/CA-Konfiguration nie erneut eingegeben werden muss. Das aktuelle Zertifikat wird weiterhin ausgeliefert, bis die Neuausstellung erfolgreich ist. Die Schlüsselform bleibt erhalten, sofern nicht explizit geändert (es werden keine Schlüssel-Flags gesendet und certbot behält den Lineage-Schlüssel).

**Request Body** (alle Felder optional):
```json
{
  "san_domains": ["www.example.com", "api.example.com"],
  "domain_alias": "",
  "async": true
}
```

- `san_domains`: Ersatz-SAN-Menge — weglassen zum Beibehalten, `[]` um alle SANs zu entfernen
- `domain_alias`: weglassen zum Beibehalten, `""` zum Löschen
- `dns_provider`, `account_id`, `ca_provider`, `challenge_type`: weglassen zum Beibehalten
- `key_type`/`key_size`/`elliptic_curve`: weglassen, um die vorhandene Schlüsselform beizubehalten
- `async`: Ausstellung an einen Hintergrund-Job verschieben (202 + Job-ID, `GET /certificates/jobs/<job_id>` abfragen)

**Antwort** (200 OK oder 202 Accepted mit `async`): message, domain, dns_provider, ca_provider, duration.

**Fehler**: 404 wenn kein Zertifikat für die Domain vorhanden ist (create verwenden), 403 Scope, 400 Validierung, 409 Operation läuft bereits, 422 certbot-Fehler (das vorherige Zertifikat ist weiterhin aktiv).

**Beispiel**:
```bash
curl -X POST http://localhost:5000/api/certificates/example.com/reissue \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"san_domains": ["www.example.com", "api.example.com"]}'
```

---

## Fehlerbehandlung

### Format der Fehlerantwort

```json
{
 "error": "Error message",
 "code": "ERROR_CODE",
 "status": 400
}
```

### Häufige HTTP-Statuscodes

| Code | Bedeutung           | Beispiel                          |
| ---- | ------------------- | --------------------------------- |
| 200  | Erfolg              | Zertifikat aufgelistet            |
| 201  | Erstellt            | Zertifikat erstellt               |
| 400  | Ungültige Anfrage   | Pflichtfeld fehlt                 |
| 401  | Nicht autorisiert   | Token ungültig/fehlend            |
| 404  | Nicht gefunden      | Zertifikat existiert nicht        |
| 429  | Zu viele Anfragen   | Rate Limit überschritten          |
| 500  | Serverfehler        | Interner Fehler                   |
| 503  | Dienst nicht verfügbar | OCSP/CRL nicht verfügbar       |

### Fehlerbeispiel

```bash
curl http://localhost:5000/api/client-certs/invalid-id \
 -H "Authorization: Bearer TOKEN"

# Antwort
{
 "error": "Certificate not found: invalid-id",
 "code": 404,
 "status": 404
}
```

---

## Audit-Protokollierung

Zertifikats-Lebenszyklusoperationen sowie Konfigurationsänderungen und Zugangskontrolländerungen werden in einem Audit-Log aufgezeichnet. Dies umfasst die sicherheitsrelevanten Lebenszykluspfade — erfolgreiche und fehlgeschlagene Erstellungen, Erneuerungen, Neuausstellungen, Deployments und Auto-Erneuerungs-Umschalter sowie **unbeaufsichtigte (scheduler-gesteuerte) Erneuerungen** — jeweils dem Akteur zugeordnet, der die Aktion durchgeführt hat, und dem Auslöser, der sie verursacht hat.

### Protokollformat

Das Audit-Log wird in `logs/audit/certificate_audit.log` geschrieben. Jede Zeile ist eine Standard-Python-Logzeile, deren Nachricht der JSON-Audit-Eintrag ist:

```
2026-06-15 18:00:00 - certmate.audit - INFO - {"timestamp": "...", ...}
```

Um das JSON zu extrahieren, teilen Sie jede Zeile am Literal ` - INFO - ` auf und parsen den Rest. Beachten Sie die zwei Zeitbasen: der Zeilenpräfix-Zeitstempel ist die **lokale** Serverzeit, während das Feld `timestamp` im JSON **UTC** (ISO-8601) ist. Live lesen mit:

```bash
tail -f logs/audit/certificate_audit.log
```

### Eintragsstruktur

```json
{
  "timestamp": "2026-06-15T18:00:00.000000+00:00",
  "operation": "renew",
  "resource_type": "certificate",
  "resource_id": "api.example.com",
  "status": "success",
  "user": "api_key:renew-bot",
  "ip_address": "10.0.0.9",
  "details": {"force": false},
  "error": null,
  "actor": {
    "kind": "agent",
    "id": "9f2c…",
    "label": "api_key:renew-bot",
    "token_prefix": "cm_1a2b",
    "agent_session": "sess-9f2"
  },
  "trigger": {"cause": "agent"}
}
```

- **`actor.kind`** — `user` (eine menschliche Sitzung / OIDC-Login), `api_token` (ein API-Schlüssel oder der veraltete globale Bearer Token), `agent` (ein API-Schlüssel, der explizit als KI/MCP-Agent markiert ist — siehe unten), `scheduler` (ein unbeaufsichtigter Erneuerungsjob) oder `system`. Wird **ausschließlich aus der authentifizierten Identität** abgeleitet.
- **`actor.id` / `token_prefix`** — die stabile API-Schlüssel-ID und das Token-Präfix hinter der Aktion (fehlt beim veralteten globalen Bearer Token, der nicht pro Aufrufer unterschieden werden kann — bevorzugen Sie Scoped Keys).
- **`actor.agent_session` / `agent_id`** — die Werte der vom Client gelieferten Header `X-CertMate-Agent-Session` / `X-CertMate-Agent-Id` (der MCP-Server sendet sie). Dies sind **rein informative Angaben**: Sie werden zur Korrelation aufgezeichnet, ändern aber niemals `actor.kind`, sodass ein Nicht-Agent-Aufrufer keine `agent`-Attribution fälschen kann.
- **`trigger.cause`** — `manual`, `api`, `agent`, `scheduled_renewal` oder `event`; bei geplanten Erneuerungen benennt `trigger.job_id` den Job.

Damit die Aktionen eines Agents als `actor.kind="agent"` aufgezeichnet werden, erstellen Sie einen Scoped API-Schlüssel mit `is_agent: true` (ein Kontrollkästchen unter Einstellungen → API-Schlüssel oder `is_agent` in `POST /api/keys`) und verweisen Sie den MCP-Server darauf. Siehe den [MCP-Leitfaden](./mcp.md).

### Audit-Log über die API lesen

`GET /api/activity?limit=N` gibt die neuesten Einträge zurück (Admin/Betrachter, begrenzt auf 500).

### Manipulationssicherheit (Hash-Kette)

Neben dem menschenlesbaren Log wird jeder Eintrag an eine manipulationssichere SHA-256-**Hash-Kette** in `data/audit/certificate_audit.chain.jsonl` angehängt. Jeder Datensatz hat die Form `{seq, entry, prev_hash, hash}`, wobei `hash` sich auf den Eintrag und den Hash des vorherigen Datensatzes festlegt und `seq` ein lückenloser Zähler ist — jede Änderung, Löschung oder Neuordnung durch jemanden, der die gesamte Kette nicht neu berechnen kann, ist erkennbar und lokalisierbar. Standardmäßig aktiviert; deaktivieren mit `CERTMATE_AUDIT_CHAIN=0`.

**Verifikation über die API:** `GET /api/audit/verify` (Admin) gibt das Verifikationsergebnis zurück und liefert HTTP `200` bei Integrität oder `409` bei Beschädigung:

```json
{"ok": true, "count": 128, "first_seq": 0, "last_seq": 127, "head_hash": "5ee1…", "reason": "intact"}
```

**Offline-Verifikation:** Der eigenständige Verifizierer hängt nur von der Python-Standardbibliothek ab, sodass ein Prüfer ihn ohne Installation oder Vertrauen in CertMate ausführen kann:

```bash
python -m modules.core.audit_verify data/audit/certificate_audit.chain.jsonl
# OK: audit chain intact (128 entries, seq 0..127)
# or: FAIL: audit chain broken at seq 42: hash mismatch at seq 42: entry was modified
```

Exit-Code `0` intakt, `1` beschädigt (mit dem betroffenen `seq` und Grund), `2` fehlend/nicht lesbar.

### Signiertes Export-Bundle (durch Dritte verifizierbar)

Die Instanz hält einen Ed25519-Signaturschlüssel, gespeichert unter `data/.audit_signing_key` (beim ersten Start generiert, `0600`; mit `AUDIT_SIGNING_KEY_FILE` überschreiben, um ihn extern vorzuhalten). Die öffentliche Identität ist über `GET /api/audit/public-key` (Admin) zugänglich: `{algorithm, public_key_pem, fingerprint}`. Der Kettenstand wird in periodische Checkpoints signiert (`certificate_audit.checkpoints.jsonl`).

`GET /api/audit/export` (Admin, optional `?from_seq`/`?to_seq`) gibt ein signiertes, selbst-verifizierendes Bundle zurück — `{manifest, entries, bundle_signature}`. Das Manifest pinnt den Instanz-Fingerprint, den öffentlichen Schlüssel, den seq-Bereich und den `head_hash`; die Signatur gilt für das kanonische Manifest, das (über `head_hash`) transitiv jeden Eintrag einschließt. Ein Prüfer verifiziert es **außerhalb der Instanz**, ohne CertMate zu installieren oder ihm zu vertrauen, und kann den Schlüssel optional extern pinnen:

```bash
python -m modules.core.audit_verify --bundle bundle.json --pubkey instance.pem
# OK: audit bundle intact and signed (128 entries, seq 0..127; signed by 0m2V5lDmnkPWOUHX)
```

Der Verifizierer prüft die Kettenstruktur, die Übereinstimmung des Manifests mit den Einträgen, die Ed25519-Signatur und ob der Fingerprint mit dem (optional gepinnten) öffentlichen Schlüssel übereinstimmt.

> **Ehrlichkeit zum Bedrohungsmodell.** Die Kette + Signatur erkennen jede interne Änderung, Löschung oder Neuordnung und binden einen Export an den öffentlichen Schlüssel dieser Instanz — für jeden, der nicht im Besitz des Signaturschlüssels ist. Sie **binden nicht** den Betreiber, der den Schlüssel hält und eine umgeschriebene Kette neu signieren könnte, und eine Kürzung am Ende wird nur durch Vergleich von Exporten über die Zeit (ein späterer Export mit weniger Einträgen) oder gegen einen extern gehaltenen Checkpoint erkannt. Eine vollständige Einschränkung des Betreibers erfordert das Versenden signierter Checkpoints an eine externe Append-Only-Senke — optionales externes Anchoring, eine geplante Folgefunktion, die noch nicht ausgeliefert wurde. Siehe [compliance.md](./compliance.md).

---

## Zertifikatstypen

### API mTLS

Für die API-Client-Authentifizierung via mutual TLS.

```
cert_usage: "api-mtls"
```

### VPN

Für die VPN-Client-Authentifizierung.

```
cert_usage: "vpn"
```

### Benutzerdefinierte Verwendungstypen

Sie können eine beliebige benutzerdefinierte Verwendungstyp-Zeichenkette verwenden:

```
cert_usage: "custom-application"
```

---

## Best Practices

### Sicherheit

1. **Token schützen**
 - Tokens geheim halten
 - Tokens regelmäßig rotieren
 - HTTPS in der Produktion verwenden

2. **Zertifikatsverwaltung**
 - Auto-Erneuerung aktivieren
 - Ablaufdaten überwachen
 - Audit-Logs regelmäßig prüfen
 - Kompromittierte Zertifikate sofort widerrufen

3. **Rate Limiting**
 - Rate Limits einhalten
 - Exponentielles Backoff implementieren
 - Batch-Operationen wenn möglich nutzen

### Performance

1. **Batch-Operationen nutzen**
 - Mehrere Zertifikate auf einmal importieren
 - Reduziert API-Aufrufe
 - Bessere Fehlerberichterstattung

2. **Ergebnisse filtern**
 - Query-Parameter verwenden
 - Nach Verwendungstyp oder Status filtern
 - Reduziert den Datentransfer

3. **Caching wo sinnvoll**
 - Zertifikats-Metadaten cachen
 - Regelmäßig aktualisieren
 - Ablauf lokal prüfen

---


---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [Schnellstart →](./guide.md) • [Architektur →](./architecture.md)

</div>
