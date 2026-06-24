# CertMate Dokumentation

Willkommen in der CertMate-Dokumentation. Dieser Ordner enthält umfassende Anleitungen zu allen Funktionen.

---

## Schnellnavigation

### Erste Schritte
- **[Installationsanleitung](./installation.md)** — Einrichtung, Abhängigkeiten, Produktions-Deployment
- **[Docker-Anleitung](./docker.md)** — Docker-Builds, Multi-Plattform, Docker Compose
- **[Kubernetes-Hinweise](./kubernetes.md)** — Produktionsressourcen, OOM-Dimensionierung, Runtime-Patching

### Kernfunktionen
- **[DNS-Provider](./dns-providers.md)** — Unterstützte Provider, Multi-Account, Domain-Alias
- **[CA-Provider](./ca-providers.md)** — Let's Encrypt, DigiCert, Private CA
- **[Client-Zertifikate](./guide.md)** — Lebenszyklus von Client-Zertifikaten, Web-Dashboard, Batch-Operationen
- **[Model Context Protocol (MCP) Server](./mcp.md)** — Eigenständiger Node.js-Server für KI-Agenten-Integrationen

### Referenz
- **[API-Referenz](./api.md)** — Vollständige REST-API-Dokumentation
- **[Architektur](./architecture.md)** — Systemdesign, Komponenten, Datenfluss
- **[Test-Anleitung](./testing.md)** — Test-Framework, CI/CD, Abdeckung

---

## Dokumentation nach Zielgruppe

### Für neue Benutzer

1. **[Installation](./installation.md)** — CertMate in Betrieb nehmen
2. **[DNS-Provider](./dns-providers.md)** — Ihren DNS-Provider konfigurieren
3. **[Anleitung zu Client-Zertifikaten](./guide.md)** — Ihr erstes Zertifikat erstellen

### Für Entwickler

1. **[API-Referenz](./api.md)** — Alle Endpoints mit Beispielen
2. **[Architektur](./architecture.md)** — Interne Systemstruktur und Design
3. **[Test-Anleitung](./testing.md)** — Wie man Tests schreibt und ausführt

### Für Administratoren

1. **[Docker-Deployment](./docker.md)** — Docker-Einrichtung für die Produktion
2. **[Kubernetes-Hinweise](./kubernetes.md)** — Pod-Dimensionierung und operatives Patching in der Produktion
3. **[CA-Provider](./ca-providers.md)** — Zertifizierungsstellen konfigurieren
4. **[DNS-Provider](./dns-providers.md#multi-account-support)** — Unternehmensweite Multi-Account-Einrichtung

---

## Funktionsübersicht

### Server-Zertifikate
- **Über zwei Dutzend DNS-Provider** für Let's Encrypt DNS-01-Challenges (vollständige Liste unter [DNS-Provider](./dns-providers.md))
- **Mehrere CA-Provider**: Let's Encrypt, DigiCert, Private CA
- **Multi-Account-Unterstützung** pro DNS-Provider
- **Austauschbare Storage-Backends**: Lokal, Azure Key Vault, AWS, Vault, Infisical
- **Auto-Renewal** mit konfigurierbaren Schwellenwerten
- **Docker-Unterstützung** mit Multi-Plattform-Builds (ARM64 + AMD64)
- **Log Sanitizer** — Bereinigt automatisch API-Tokens, private Schlüssel und sensible Zugangsdaten aus den CertMate-Logs
- **Zombie Certificate Scanner** — Multi-Threaded-Dateisystem-Scanner zur Identifikation und Bereinigung verwaister Zertifikate
- **Model Context Protocol (MCP) Server** — Eigenständiger Node.js-Server zur Integration mit agentischen KI-Assistenten

### Client-Zertifikate
- **Self-signed CA** mit 4096-Bit-RSA-Schlüsseln
- **Vollständiges Lifecycle-Management** — erstellen, erneuern, widerrufen, überwachen
- **OCSP & CRL** — Echtzeit-Status und Sperrlisten
- **Web-Dashboard** unter `/client-certificates`
- **Batch-Operationen** — Import von 100 bis 30.000 Zertifikaten per CSV
- **Audit-Logging** und **Rate Limiting**

---

## API-Endpoints Kurzreferenz

| Methode | Endpoint                                 | Beschreibung              |
| ------- | ---------------------------------------- | ------------------------- |
| POST    | `/api/client-certs/create`               | Zertifikat erstellen      |
| GET     | `/api/client-certs`                      | Zertifikate auflisten     |
| GET     | `/api/client-certs/<id>`                 | Metadaten abrufen         |
| GET     | `/api/client-certs/<id>/download/<type>` | Zert/Schlüssel/CSR laden  |
| POST    | `/api/client-certs/<id>/revoke`          | Zertifikat widerrufen     |
| POST    | `/api/client-certs/<id>/renew`           | Zertifikat erneuern       |
| GET     | `/api/client-certs/stats`                | Statistiken abrufen       |
| POST    | `/api/client-certs/batch`                | CSV-Batch-Import          |
| GET     | `/api/ocsp/status/<serial>`              | OCSP-Status               |
| GET     | `/api/crl/download/<format>`             | CRL herunterladen         |

Vollständige Dokumentation unter [API-Referenz](./api.md#endpoints).

---

## Tests

Alle Funktionen sind umfassend getestet:

```bash
# Tests ausführen
python -m pytest tests/ -v
```

Die Testabdeckung umfasst:
- CA-Operationen
- CSR-Operationen
- Zertifikat-Lebenszyklus
- Filterung & Suche
- Batch-Operationen
- OCSP & CRL
- Audit & Rate Limiting

---

## Sicherheitsfunktionen

- **4096-Bit RSA** für CA-Schlüssel
- **SHA256**-Signaturalgorithmus
- **Bearer-Token**-Authentifizierung
- **Rate Limiting** auf allen Endpoints
- **Audit-Logging** aller Operationen
- **Dateiberechtigungen** 0600 für private Schlüssel

---

## Performance

- Unterstützt **30.000+ gleichzeitige Zertifikate**
- Effiziente **Multi-Filter-Abfragen**
- **Auto-Renewal**-Planung
- **Batch-Operationen** mit Fehlerverfolgung

---

## Dateistruktur

```
docs/
  README.md            ← Sie sind hier
  index.md             ← Einstiegsseite für Client-Zertifikate
  installation.md      ← Installation & Einrichtung
  kubernetes.md        ← Kubernetes-Produktionshinweise
  dns-providers.md     ← DNS-Provider & Multi-Account
  ca-providers.md      ← Zertifizierungsstellen-Provider
  docker.md            ← Docker-Build & Deployment
  testing.md           ← Test-Framework & CI/CD
  guide.md             ← Benutzeranleitung Client-Zertifikate
  api.md               ← Vollständige API-Referenz
  architecture.md      ← Systemarchitektur
```

---

## Lernpfad

**Einsteiger** → [Hier starten](./index.md) → [Erste Schritte](./guide.md)

**Entwickler** → [API-Referenz](./api.md) → [Architektur](./architecture.md)

**Fortgeschritten** → [Vollständige API-Dokumentation](./api.md) → [Architekturdetails](./architecture.md)

---

## Wichtige Links

- **Web-Dashboard**: `http://localhost:8000/client-certificates`
- **API-Dokumentation**: `http://localhost:8000/docs/`
- **Statusprüfung**: `http://localhost:8000/health`
- **Audit-Logs**: `logs/audit/certificate_audit.log`

---

## Status-Dashboard

| Komponente       | Status    | Tests     |
| ---------------- | --------- | --------- |
| CA-Grundlage     | Bereit    | 3/3       |
| CSR-Handler      | Bereit    | 3/3       |
| Zert.-Manager    | Bereit    | 8/8       |
| Filterung        | Bereit    | 3/3       |
| Batch-Operationen| Bereit    | 2/2       |
| OCSP/CRL         | Bereit    | 5/5       |
| Audit/Rate Limit | Bereit    | 3/3       |
| **Gesamt**       | **Bereit**| **27/27** |

---

## Schnellbeispiele

### Zertifikat per API erstellen

```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365
 }'
```

### Zertifikate auflisten

```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer YOUR_TOKEN"
```

### Zertifikat herunterladen

```bash
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o certificate.crt
```

Weitere Beispiele im [API-Leitfaden](./api.md).

---

## Lizenz

CertMate steht unter der MIT-Lizenz. Siehe die LICENSE-Datei im Repository.

---

## Fragen oder Probleme?

- Konsultieren Sie die entsprechende Dokumentationsseite
- Schauen Sie in die Testdateien für Verwendungsbeispiele
- Prüfen Sie die [API-Referenz](./api.md) für Details zu den Endpoints

---

<div align="center">

[Startseite](../README.md) • [Dokumentation](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
