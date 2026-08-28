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
- **[Discovery & Inventar](../discovery-inventory.md)** — Probe-/CT-Log-Discovery, Inventar, Adopt, Krypto-Readiness *(auf Englisch)*
- **[Deploy-Hooks](./deploy-hooks.md)** — Hooks nach der Ausstellung: Konfiguration, Test, Redaktion der Ausgabe
- **[Compliance](./compliance.md)** — Audit-Kette, Akteur-Attribution, NIS2-/eIDAS-Posture
- **[Deployment-Probes](./probes.md)** — Prüfen, ob ein erneuertes Zertifikat ausgeliefert wird

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
- **Austauschbare Storage-Backends**: Lokal, Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical, S3-compatible
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
- **Batch-Operationen** — CSV-Import, höchstens 100 Zeilen pro Anfrage
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
# Die UI-Suite steuert Playwright gegen einen laufenden Server und kann
# sich den Prozess nicht mit dem Rest teilen; e2e braucht eine laufende
# Instanz. Dieselbe Auswahl, die `make test` und scripts/release.sh nutzen.
pytest -v --tb=short -m "not ui and not e2e"
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

<!-- Checked by tests/test_docs_navigation.py: this listing must match
     what is actually on disk. It used to omit six pages. -->

```
docs/de/
  README.md           this file — documentation index  <- you are here
  THEME_MIGRATION.md  one-off theme migration record
  api.md              complete REST API reference
  architecture.md     system architecture
  ca-providers.md     certificate authorities
  compliance.md       audit chain, attribution, NIS2/eIDAS
  deploy-hooks.md     post-issuance deploy hooks
  dns-providers.md    DNS providers, multi-account, domain alias
  docker.md           Docker build and deployment
  guide.md            client-certificate user guide
  index.md            client-certificate landing page
  installation.md     installation and setup
  kubernetes.md       Kubernetes production notes and Helm chart
  mcp.md              MCP server for AI agents
  probes.md           deployment probes
  testing.md          test framework and CI/CD
```

---

## Lernpfad

**Einsteiger** → [Hier starten](./guide.md) → [Erste Schritte](./guide.md)

**Entwickler** → [API-Referenz](./api.md) → [Architektur](./architecture.md)

**Fortgeschritten** → [Vollständige API-Dokumentation](./api.md) → [Architekturdetails](./architecture.md)

---

## Wichtige Links

- **Web-Dashboard**: `http://localhost:8000/client-certificates`
- **API-Dokumentation**: `http://localhost:8000/docs/`
- **Statusprüfung**: `http://localhost:8000/health`
- **Audit-Logs**: `logs/audit/certificate_audit.log`

---

## Teststatus

Hier steht keine handgepflegte Punktetabelle. Eine Tabelle mit Testzahlen ist am Tag nach dem Schreiben veraltet — diese sagte `27/27`, wahrend die Suite die zweitausend uberschritten hatte.

Das massgebliche Signal ist die CI auf `main`: die Badges oben im [Projekt-README](../../README.md) und die Coverage-Untergrenze in [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

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

---

**Aktuelle Version**: 2.26.1

<div align="center">

[Startseite](../README.md) • [Dokumentation](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
