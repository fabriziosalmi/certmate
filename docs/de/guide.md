# CertMate Client-Zertifikate - Benutzerhandbuch

## Erste Schritte

### Installation

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run CertMate
python app.py

# 3. Open dashboard
# Navigate to: http://localhost:5000/client-certificates
```

### Erste Schritte

1. **CA generieren** — Wird beim ersten Start automatisch erstellt
2. **Dashboard aufrufen** — Gehen Sie zu `/client-certificates`
3. **Zertifikat erstellen** — Verwenden Sie das Webformular oder die API
4. **Dateien herunterladen** — Laden Sie Zertifikat, Schlüssel und CSR herunter

---

## Web-Dashboard

### Dashboard-Funktionen

**URL**: `http://localhost:5000/client-certificates`

#### Statistikbereich
- Gesamtanzahl der Zertifikate
- Anzahl aktiver Zertifikate
- Anzahl widerrufener Zertifikate
- Aufschlüsselung nach Verwendungstyp

#### Zertifikattabelle
- Alle Zertifikate auflisten
- Suche nach Common Name
- Filter nach Verwendungstyp
- Filter nach Status
- Sortierung nach Erstellungsdatum

#### Formular zum Erstellen von Zertifikaten

**Formularfelder**:
- Common Name (erforderlich)
- E-Mail-Adresse
- Organisation
- Organisationseinheit
- Verwendungstyp (VPN, API-mTLS usw.)
- Gültigkeitsdauer in Tagen (Standard: 365)
- Schlüssel generieren (Kontrollkästchen)
- Notizen

**Beispiel**:
```
Common Name: user@example.com
Email: user@example.com
Organization: ACME Corp
Usage Type: api-mtls
Days Valid: 365
```

#### CSV-Massenimport

1. Klicken Sie auf den Tab "Bulk Import"
2. Bereiten Sie eine CSV-Datei mit folgenden Spaltenköpfen vor:
 ```
 common_name,email,organization,cert_usage,days_valid
 user1@example.com,user1@example.com,ACME Corp,api-mtls,365
 user2@example.com,user2@example.com,ACME Corp,vpn,365
 ```
3. Drag-and-drop oder klicken zum Hochladen
4. Vorschau prüfen
5. Auf "Import" klicken

---

## Häufige Aufgaben

### Ein einzelnes Zertifikat erstellen

#### Über das Web-Dashboard

1. Gehen Sie zu `/client-certificates`
2. Füllen Sie das Formular "Zertifikat erstellen" aus
3. Klicken Sie auf "Erstellen"
4. Das Zertifikat erscheint in der Tabelle

#### Über die API

```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true
 }'
```

---

### Zertifikatdateien herunterladen

#### Über das Web-Dashboard

1. Zertifikat in der Tabelle suchen
2. Auf das Download-Symbol klicken ()
3. Dateityp auswählen:
 - **CRT** — Zertifikat (öffentlich)
 - **KEY** — Privater Schlüssel (geheim halten)
 - **CSR** — Certificate Signing Request

#### Über die API

```bash
# Download certificate
curl http://localhost:5000/api/client-certs/CERT_ID/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o my-cert.crt

# Download key
curl http://localhost:5000/api/client-certs/CERT_ID/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o my-key.key
```

---

### Ein Zertifikat widerrufen

#### Über das Web-Dashboard

1. Zertifikat in der Tabelle suchen
2. Auf die Schaltfläche "Widerrufen" klicken ()
3. Widerrufsgrund eingeben (optional)
4. Bestätigen

#### Über die API

```bash
curl -X POST http://localhost:5000/api/client-certs/CERT_ID/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "reason": "compromised"
 }'
```

**Widerrufsgründe**:
- `compromised` — Schlüssel wurde kompromittiert
- `superseded` — Durch ein neues Zertifikat ersetzt
- `unspecified` — Allgemeiner Widerruf
- Beliebiger benutzerdefinierter Grund

---

### Ein Zertifikat erneuern

#### Über das Web-Dashboard

1. Zertifikat in der Tabelle suchen
2. Auf die Schaltfläche "Erneuern" klicken ()
3. Erneuerung bestätigen

#### Über die API

```bash
curl -X POST http://localhost:5000/api/client-certs/CERT_ID/renew \
 -H "Authorization: Bearer TOKEN"
```

**Hinweis**: Bei der Erneuerung wird ein neues Zertifikat erstellt mit:
- Demselben Common Name
- Neuer Seriennummer
- Neuem Ablaufdatum
- Aktualisierter ursprünglicher ID

---

### Zertifikate auflisten und filtern

#### Über das Web-Dashboard

1. Zur Zertifikattabelle wechseln
2. Suchfeld für den Common Name verwenden
3. Dropdown "Verwendungstyp" zum Filtern verwenden
4. Dropdown "Status" verwenden (Aktiv/Widerrufen)
5. Auf "Filter anwenden" klicken

#### Über die API

```bash
# List all
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filter by usage
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Filter by status
curl "http://localhost:5000/api/client-certs?revoked=false" \
 -H "Authorization: Bearer TOKEN"

# Search
curl "http://localhost:5000/api/client-certs?search=user@" \
 -H "Authorization: Bearer TOKEN"
```

---

### Zertifikatstatus prüfen (OCSP)

#### Über die API

```bash
curl http://localhost:5000/api/ocsp/status/SERIAL_NUMBER \
 -H "Authorization: Bearer TOKEN"
```

**Antwort**:
```json
{
 "certificate_status": "good",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z"
}
```

---

### Sperrliste abrufen (CRL)

#### CRL herunterladen

```bash
# PEM format
curl http://localhost:5000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# DER format
curl http://localhost:5000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl
```

#### CRL-Informationen abrufen

```bash
curl http://localhost:5000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

---

## Massenoperationen

### CSV-Format

```csv
common_name,email,organization,cert_usage,days_valid
user1@example.com,user1@example.com,ACME Corp,api-mtls,365
user2@example.com,user2@example.com,ACME Corp,vpn,365
user3@example.com,user3@example.com,ACME Corp,api-mtls,730
```

### Erforderliche Spalten

- `common_name` — Subject des Zertifikats (erforderlich)

### Optionale Spalten

- `email` — E-Mail-Adresse
- `organization` — Organisationsname
- `organizational_unit` — Abteilungsname
- `cert_usage` — Verwendungstyp
- `days_valid` — Gültigkeitsdauer in Tagen

### Über das Web-Dashboard

1. Tab "Bulk Import" aufrufen
2. CSV-Datei hochladen
3. Vorschau prüfen
4. Auf "Alle importieren" klicken

### Über die API

```bash
curl -X POST http://localhost:5000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "headers": ["common_name", "email", "organization"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
 ["user2@example.com", "user2@example.com", "ACME Corp"],
 ["user3@example.com", "user3@example.com", "ACME Corp"]
 ]
 }'
```

### Importergebnisse

Gibt Erfolgs- und Fehlerzähler zurück:
```json
{
 "total": 3,
 "successful": 3,
 "failed": 0,
 "errors": [],
 "certificates": [{"identifier": "cert-batch-001", "common_name": "user1@example.com"},
 {"identifier": "cert-batch-002", "common_name": "user2@example.com"},
 {"identifier": "cert-batch-003", "common_name": "user3@example.com"}
 ]
}
```

---

## Zertifikat-Verwendungstypen

### API mTLS

Für die gegenseitige TLS-Authentifizierung von API-Clients.

```
Usage Type: api-mtls
Typical Validity: 1 year (365 days)
```

### VPN

Für die Authentifizierung von VPN-Clients.

```
Usage Type: vpn
Typical Validity: 1-2 years (365-730 days)
```

### Benutzerdefinierte Typen

Sie können Zertifikate für jeden benutzerdefinierten Verwendungszweck erstellen:

```
Usage Type: custom-application
Usage Type: internal-service
Usage Type: mobile-app
```

---

## Automatische Erneuerung

### Konfiguration

- **Prüfzeitpunkt**: Täglich um 3:00 Uhr
- **Schwellenwert**: 30 Tage vor Ablauf
- **Aktion**: Automatische Erneuerung, sofern aktiviert

### Automatische Erneuerung aktivieren

Die automatische Erneuerung ist standardmäßig aktiviert. So prüfen Sie den Status:

```bash
curl http://localhost:5000/api/client-certs/CERT_ID \
 -H "Authorization: Bearer TOKEN"
```

Achten Sie auf:
```json
{
 "renewal": {
 "renewal_enabled": true,
 "renewal_threshold_days": 30
 }
}
```

### Erneuerungsverhalten

Bei automatischer Erneuerung:
- Neues Zertifikat wird erstellt
- Gleicher CN (Common Name)
- Neue Seriennummer
- Neues Ablaufdatum
- Ursprüngliche ID bleibt unverändert
- Altes Zertifikat wird ersetzt

---

## Fehlerbehebung

### Häufige Probleme

#### Zertifikaterstellung fehlgeschlagen

**Fehler**: `Failed to create certificate`

**Lösungen**:
1. Prüfen Sie, ob der Common Name gültig ist
2. Überprüfen Sie alle erforderlichen Felder
3. Stellen Sie sicher, dass die CA initialisiert ist
4. Überprüfen Sie die Logs für Details

#### Dateidownload fehlgeschlagen

**Fehler**: `File not found`

**Lösungen**:
1. Überprüfen Sie, ob die Zertifikat-ID existiert
2. Prüfen Sie den Dateityp (crt, key, csr)
3. Stellen Sie sicher, dass das Zertifikat nicht gelöscht wurde
4. Prüfen Sie den verfügbaren Speicherplatz

#### Ratenlimit überschritten

**Fehler**: `HTTP 429 Too Many Requests`

**Lösungen**:
1. Warten Sie vor einem erneuten Versuch
2. Verwenden Sie Massenoperationen
3. Implementieren Sie exponentielles Backoff
4. Prüfen Sie das Limit für Ihren Endpoint

### Logs prüfen

Anwendungslogs anzeigen:
```bash
tail -f logs/certmate.log
```

Audit-Logs anzeigen:
```bash
tail -f logs/audit/certificate_audit.log
```

---

## Best Practices für die Sicherheit

### Private Schlüssel

- **NIEMALS** private Schlüssel weitergeben
- **NIEMALS** Schlüssel in git committen
- Schlüssel sicher aufbewahren
- Dateiberechtigungen 0600 verwenden

### Zertifikate

- Ablaufdaten überwachen
- Vor Ablauf erneuern
- Kompromittierte Zertifikate sofort widerrufen
- Audit-Logs für Compliance aufbewahren

### API-Token

- Token regelmäßig rotieren
- In der Produktion HTTPS verwenden
- Token nicht hartcodieren
- Umgebungsvariablen verwenden

### Widerruf

Widerrufen Sie immer, wenn:
- Der Schlüssel kompromittiert wurde
- Das Zertifikat ersetzt wird
- Ein Benutzer die Organisation verlässt
- Ein Dienst außer Betrieb genommen wird

---

## Performance-Tipps

### Bei großen Mengen

Verwenden Sie Massenoperationen statt einzelner Erstellungsaufrufe:
```bash
# Gut: Eine Anfrage für 1000 Zertifikate
POST /api/client-certs/batch

# Schlecht: 1000 Anfragen für 1000 Zertifikate
POST /api/client-certs/create × 1000
```

### Beim Filtern

Serverseitig filtern:
```bash
# Gut: Server filtert
GET /api/client-certs?usage=api-mtls

# Schlecht: Client filtert alles
GET /api/client-certs
```

### Beim Monitoring

Statistik-Endpoint verwenden:
```bash
GET /api/client-certs/stats
```

---

## Support

### Dokumentation

- [API-Referenz](./api.md) — Alle Endpoints
- [Architektur](./architecture.md) — Systemdesign
- [Release-Hinweise](../RELEASE_NOTES.md) — Versionshistorie

### Tests

Verwendungsbeispiele finden Sie in `test_e2e_complete.py`.

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [API-Referenz →](./api.md) • [Architektur →](./architecture.md)

</div>
