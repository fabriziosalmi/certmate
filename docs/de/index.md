# CertMate - Client-Zertifikate

<div align="center">

![CertMate](https://img.shields.io/badge/CertMate-Client%20Certificates-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Production%20Ready-green?style=for-the-badge)

**Vollständige Client-Zertifikatsverwaltung für CertMate**

[Dokumentation](#dokumentation) • [Schnellstart](#schnellstart) • [API-Referenz](./api.md) • [Architektur](./architecture.md)

</div>

---

## Übersicht

CertMate Client-Zertifikate ist eine umfassende, produktionsreife Lösung für die Verwaltung von Client-Zertifikaten mit:

- **Selbstsignierte CA** — Generieren und verwalten Sie Ihre eigene Zertifizierungsstelle
- **Vollständiges Lifecycle-Management** — Erstellen, erneuern, widerrufen und überwachen Sie Client-Zertifikate
- **OCSP & CRL** — Echtzeit-Zertifikatsstatus und Sperrlisten
- **Web-Dashboard** — Intuitive Benutzeroberfläche für die Zertifikatsverwaltung
- **REST API** — Vollständige API für die Automatisierung
- **Batch-Operationen** — Importieren Sie 100 bis 30.000 Zertifikate per CSV
- **Audit-Protokoll** — Verfolgen Sie alle Vorgänge für die Compliance
- **Rate Limiting** — Integrierter Schutz gegen Missbrauch

---

## Funktionen

### Phase 1: CA-Grundlage
- **PrivateCAGenerator**: Selbstsignierte CA mit 4096-Bit-RSA-Schlüsseln, 10 Jahre Gültigkeit
- **CSRHandler**: Zertifikatsignierungsanfragen validieren, erstellen und analysieren
- **Sichere Speicherung**: Korrekte Dateiberechtigungen (0600) für private Schlüssel

### Phase 2: Client-Zertifikats-Engine
- **Vollständiger Lebenszyklus**: Zertifikate erstellen, auflisten, filtern, widerrufen und erneuern
- **Multi-Filter-Abfragen**: Suche nach Verwendungstyp, Widerrufsstatus, Common Name
- **Automatische Erneuerung**: Täglich geplante Prüfungen für ablaufende Zertifikate
- **Unterstützung für 30k+ Zertifikate**: Verzeichnisbasierte Speicherung für lineare Skalierbarkeit
- **Metadatenverwaltung**: Verfolgung von CN, E-Mail, Organisation, Verwendung, Ablaufdaten

### Phase 3: Benutzeroberfläche und erweiterte Funktionen
- **Web-Dashboard**: Responsive Verwaltungsoberfläche mit Dark-Mode-Unterstützung
- **OCSP-Responder**: Zertifikatsstatus in Echtzeit abfragen
- **CRL-Manager**: Sperrlisten generieren und verteilen (PEM/DER)
- **REST API**: 10 Endpoints in 3 Namespaces für vollständige Automatisierung
- **Batch-Operationen**: Zertifikate aus CSV-Dateien importieren

### Phase 4: Quick Wins
- **Audit-Protokoll**: Alle Zertifikatsvorgänge mit Benutzer-/IP-Informationen verfolgen
- **Rate Limiting**: Konfigurierbare Limits pro Endpoint mit sinnvollen Standardwerten
- **Integrationsbereit**: Beide Manager in der Anwendung für den sofortigen Einsatz verfügbar

---

## Schnellstart

### Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

Der Server startet auf `http://localhost:8000`

### Grundlegende Verwendung

#### 1. Web-Dashboard aufrufen
```
Navigate to: http://localhost:8000/client-certificates
```

#### 2. Zertifikat per API erstellen
```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
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

#### 3. Zertifikate auflisten
```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer YOUR_TOKEN"
```

#### 4. Zertifikatsdateien herunterladen
```bash
# Download certificate
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o user.crt

# Download private key
curl http://localhost:8000/api/client-certs/USER_ID/download/key \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o user.key
```

---

## Dokumentation

### Hauptdokumentation

- **[Installationsanleitung](./installation.md)** — Einrichtung, Abhängigkeiten, Deployment
- **[Kubernetes-Hinweise](./kubernetes.md)** — Pod-Dimensionierung und OOM-Fehlerbehebung in der Produktion
- **[DNS-Anbieter](./dns-providers.md)** — Unterstützte Anbieter, Multi-Account, Domain-Alias
- **[CA-Anbieter](./ca-providers.md)** — Let's Encrypt, Actalis, DigiCert, Private CA
- **[Docker-Anleitung](./docker.md)** — Docker-Builds, Multi-Plattform, Compose
- **[Test-Anleitung](./testing.md)** — Test-Framework, CI/CD, Abdeckung
- **[API-Referenz](./api.md)** — Vollständige REST-API-Dokumentation mit Beispielen
- **[Architektur](./architecture.md)** — Systemdesign, Komponenten und Datenfluss
- **[Benutzerhandbuch](./guide.md)** — Schritt-für-Schritt-Anleitung für häufige Aufgaben

### Schnellzugriff

- [API-Endpoints](./api.md#endpoints) — Alle verfügbaren Endpoints
- [Zertifikatstypen](./api.md#certificate-types) — VPN, API mTLS usw.
- [Rate Limiting](./api.md#rate-limiting) — Standardlimits und Konfiguration
- [Audit-Protokoll](./api.md#audit-logging) — Audit-Trails verstehen

---

## Tests

Alle Funktionen wurden umfassend getestet:

```bash
# Run test suite
python -m pytest tests/ -v
```

### Testabdeckung
- CA-Operationen (3 Tests)
- CSR-Operationen (3 Tests)
- Zertifikats-Lebenszyklus (8 Tests)
- Filterung und Suche (3 Tests)
- Batch-Operationen (2 Tests)
- OCSP & CRL (5 Tests)
- Audit & Rate Limiting (3 Tests)

---

## Übersicht der API-Endpoints

| Methode | Endpoint                                 | Zweck                               |
| ------- | ---------------------------------------- | ----------------------------------- |
| `POST`  | `/api/client-certs/create`               | Neues Zertifikat erstellen          |
| `GET`   | `/api/client-certs`                      | Zertifikate mit Filtern auflisten   |
| `GET`   | `/api/client-certs/<id>`                 | Zertifikats-Metadaten abrufen       |
| `GET`   | `/api/client-certs/<id>/download/<type>` | Zertifikat/Schlüssel/CSR herunterladen |
| `POST`  | `/api/client-certs/<id>/revoke`          | Zertifikat widerrufen               |
| `POST`  | `/api/client-certs/<id>/renew`           | Zertifikat erneuern                 |
| `GET`   | `/api/client-certs/stats`                | Statistiken abrufen                 |
| `POST`  | `/api/client-certs/batch`                | CSV-Batch-Import                    |
| `GET`   | `/api/ocsp/status/<serial>`              | OCSP-Statusabfrage                  |
| `GET`   | `/api/crl/download/<format>`             | CRL herunterladen (PEM/DER)         |

---

## Architektur

Das System ist mit einer modularen, mehrschichtigen Architektur aufgebaut:

```

 Web UI & REST API 
 (/client-certificates, /api/*) 

 API Resources & Managers 
 (OCSP, CRL, Audit, Rate Limiting) 

 Core Modules 
 (Certificate Mgmt, CSR, CA, Storage) 

 Cryptography & Storage 
 (OpenSSL, File System, Backends) 

```

Weitere Informationen finden Sie in der [Architekturdokumentation](./architecture.md).

---

## Sicherheit

### Kryptografische Stärke
- **CA**: 4096-Bit-RSA-Schlüssel, 10 Jahre Gültigkeit
- **Client-Zertifikate**: 2048 oder 4096 Bit RSA (konfigurierbar)
- **Signaturen**: SHA256
- **Schlüsselspeicherung**: Dateiberechtigungen 0600 auf Unix-Systemen

### Zugriffskontrolle
- **Bearer-Token-Authentifizierung** auf allen API-Endpoints
- **Rate Limiting**: Konfigurierbare Limits pro Endpoint
- **Audit-Protokoll**: Alle Vorgänge werden mit Benutzer-/IP-Informationen erfasst

### Compliance
- Verfolgung von Zertifikats-Metadaten
- Audit-Trail für Widerrufe
- Persistente Betriebsprotokolle
- Unterstützung für Compliance-Abfragen

---

## Performance

Die Implementierung ist optimiert für:
- **Skalierbarkeit**: Verzeichnisbasierte Speicherung unterstützt 30k+ gleichzeitige Zertifikate
- **Geschwindigkeit**: Effiziente Multi-Filter-Abfragen
- **Zuverlässigkeit**: Automatische Erneuerungsplanung
- **Reaktionsfähigkeit**: Asynchrones JavaScript in der Web-Benutzeroberfläche

---

## Support

Bei Fragen oder Problemen:
1. Lesen Sie das [Benutzerhandbuch](./guide.md)
2. Lesen Sie die [API-Dokumentation](./api.md)
3. Lesen Sie den Abschnitt [Architektur](./architecture.md)
4. Prüfen Sie die Testfälle in `test_e2e_complete.py`

---

## Lizenz

Siehe LICENSE-Datei im Repository

---

## Version

**Aktuelle Version**: 2.3.0
**Status**: Produktionsbereit

---

<div align="center">

[Dokumentation](.) • [Lizenz](../LICENSE)

</div>
