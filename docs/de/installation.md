# Installationsanleitung

Diese Anleitung beschreibt alle Methoden zur Installation und zum Deployment von CertMate.

---

## Voraussetzungen

- Python 3.9 oder höher
- pip (Python-Paketverwaltung)
- Docker (optional, für containerisiertes Deployment)

---

## Methode 1: Direkte Installation

### 1. Repository klonen

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
```

### 2. Virtuelle Umgebung erstellen

```bash
python3 -m venv venv
source venv/bin/activate  # Unter Windows: venv\Scripts\activate
```

### 3. Abhängigkeiten installieren

```bash
pip install -r requirements.txt
```

### 4. Umgebung konfigurieren

Erstellen Sie eine `.env`-Datei:

```bash
cp .env.example .env
# .env mit Ihren Einstellungen bearbeiten
```

### 5. Anwendung starten

```bash
python app.py
```

---

## Methode 2: Docker-Installation

### Mit Docker Compose (empfohlen)

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker-compose up -d
```

### Mit Docker Build

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker build -t certmate .
docker run -p 8000:8000 --env-file .env -v ./certificates:/app/certificates certmate
```

> Für erweitertes Docker-Deployment einschließlich Multi-Plattform-Builds siehe den [Docker-Leitfaden](./docker.md).

---

## Systemabhängigkeiten

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install python3-dev python3-venv build-essential libssl-dev libffi-dev
```

### CentOS / RHEL / Rocky

```bash
sudo yum install python3-devel gcc openssl-devel libffi-devel
```

### macOS

```bash
brew install python3 openssl libffi
```

---

## DNS-Provider-Einrichtung

Konfigurieren Sie nach der Installation die Zugangsdaten Ihres DNS-Providers. Detaillierte Einrichtungsanweisungen für jeden unterstützten Provider finden Sie im [DNS-Provider-Leitfaden](./dns-providers.md).

Schnelleinrichtung für gängige Provider:

### Cloudflare

1. Öffnen Sie das [Cloudflare-Dashboard](https://dash.cloudflare.com/profile/api-tokens)
2. Erstellen Sie einen neuen API-Token mit den Berechtigungen `Zone:DNS:Edit`
3. Fügen Sie den Token in den CertMate-Einstellungen hinzu

### AWS Route53

1. Erstellen Sie einen IAM-Benutzer mit Route53-Berechtigungen
2. Generieren Sie Zugriffsschlüssel
3. Fügen Sie die Zugangsdaten in den CertMate-Einstellungen hinzu

### Azure DNS

1. Erstellen Sie einen Service Principal
2. Weisen Sie die Rolle DNS Zone Contributor zu
3. Konfigurieren Sie die Abonnementdetails in den CertMate-Einstellungen

### Google Cloud DNS

1. Erstellen Sie einen Service Account mit der Rolle DNS Administrator
2. Laden Sie die JSON-Schlüsseldatei herunter
3. Laden Sie diese in den CertMate-Einstellungen hoch

---

## Umgebungsvariablen

```bash
# API-Authentifizierung (automatisch generiert, wenn keine gesetzt ist)
# Option A: direkter Wert
API_BEARER_TOKEN=your_secure_token_here
# Option B: Pfad zu einer Datei mit dem Token (hat Vorrang vor API_BEARER_TOKEN)
API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token

# Geheimer Flask-Sitzungsschlüssel (automatisch generiert, wenn keiner gesetzt ist)
# Option A: direkter Wert
SECRET_KEY=your_flask_secret_key
# Option B: Pfad zu einer Datei mit dem Schlüssel (hat Vorrang vor SECRET_KEY)
SECRET_KEY_FILE=/run/secrets/secret_key

# Reverse Proxy — auf 'true' setzen, wenn CertMate hinter Nginx,
# HAProxy, Traefik, Cloudflare usw. betrieben wird. Ohne diese Einstellung
# löst request.remote_addr für jede Anfrage die IP des Proxys auf, was
# das Rate-Limiting pro Client in einen einzelnen Bucket zusammenführt.
# Siehe den Abschnitt "Hinter einem Reverse Proxy" unter Produktions-Deployment.
BEHIND_PROXY=true

# Backup-Verschlüsselung im Ruhezustand (optional, empfohlen).
# Wenn gesetzt, werden einheitliche Backups als verschlüsselte .zip.enc-Dateien
# geschrieben (PBKDF2-SHA256-Schlüsselableitung + Fernet/AES) statt als
# Klartext-ZIP. Backups enthalten jeden privaten Zertifikatsschlüssel; ohne
# diese Einstellung stellt eine exfiltrierte Backup-Datei einen vollständigen
# Schlüssel-Kompromiss dar. Dieselbe Passphrase muss für die Wiederherstellung
# vorhanden sein. Bewusst nur per Umgebungsvariable: eine in settings.json
# gespeicherte Passphrase würde selbst in Klartext-Backups landen.
CERTMATE_BACKUP_PASSPHRASE=choose-a-long-random-passphrase

# DNS-Provider (einen oder mehrere auswählen)
CLOUDFLARE_TOKEN=your_cloudflare_token
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AZURE_SUBSCRIPTION_ID=your_azure_subscription
AZURE_TENANT_ID=your_azure_tenant
AZURE_CLIENT_ID=your_azure_client
AZURE_CLIENT_SECRET=your_azure_secret
GOOGLE_PROJECT_ID=your_gcp_project
POWERDNS_API_URL=https://your-powerdns:8081
POWERDNS_API_KEY=your_powerdns_key
```

### Auflösungsreihenfolge

| Variable | Priorität |
|----------|-----------|
| `API_BEARER_TOKEN_FILE` | Höchste — wenn gesetzt, wird `API_BEARER_TOKEN` nie gelesen |
| `API_BEARER_TOKEN` | Wird nur verwendet, wenn `API_BEARER_TOKEN_FILE` fehlt |
| *(generiert)* | Fallback, wenn keines gesetzt ist oder der Wert die Validierung nicht besteht |
| `SECRET_KEY_FILE` | Höchste — wenn gesetzt, wird `SECRET_KEY` nie gelesen |
| `SECRET_KEY` | Wird nur verwendet, wenn `SECRET_KEY_FILE` fehlt |
| *(generiert + gespeichert)* | In `data/.secret_key` geschrieben, damit Sitzungen Neustarts überleben |

> **Docker-Secrets-Hinweis**: Verwenden Sie `API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token` und `SECRET_KEY_FILE=/run/secrets/secret_key` mit Docker Swarm oder Kubernetes Secrets, um zu vermeiden, dass sensible Werte in Umgebungsvariablen stehen.

---

## Produktions-Deployment

### Hinter einem Reverse Proxy

Wenn CertMate hinter einem Reverse Proxy betrieben wird (Nginx, HAProxy, Traefik,
Cloudflare, Kubernetes Ingress) — was die empfohlene Betriebsweise für die
TLS-Terminierung ist — setzen Sie `BEHIND_PROXY=true` in der Container-Umgebung.
Dies aktiviert die `ProxyFix`-Middleware von Werkzeug, sodass die folgenden
Komponenten den `X-Forwarded-*`-Headern Ihres Proxys vertrauen:

- `request.remote_addr` löst auf die ursprüngliche Client-IP auf statt auf die
  IP des Proxys. Rate-Limiting, Audit-Log-Einträge und die Warnungen
  "ungültiger API-Token-Versuch von X" werden dadurch pro Client statt pro Proxy
  ausgegeben.
- Schema / Host / Präfix-Header des Proxys werden berücksichtigt, wodurch
  generierte URLs und Cookie-Scopes korrekt bleiben.

```yaml
# docker-compose.yml-Ausschnitt
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    environment:
      BEHIND_PROXY: "true"
    volumes:
      - ./data:/app/data
```

**Wann diese Option NICHT aktiviert werden sollte.** Wenn Sie CertMate ohne
vorgelagerten Proxy direkt ins Netzwerk exponieren, lassen Sie `BEHIND_PROXY`
ungesetzt. Mit dieser Einstellung könnte jeder, der den Listener erreicht,
`X-Forwarded-For` fälschen und das per-Client-Rate-Limiting umgehen. Der Proxy
ist die Vertrauensgrenze.

Ihr Proxy muss die Header natürlich weiterleiten. Nginx-Beispiel:

```nginx
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

#### Beispiel: Zion (Rust-TLS-Gateway + WAF)

[Zion](https://github.com/fabriziosalmi/zion) ist ein hochperformanter Rust-TLS-
Reverse Proxy mit integriertem WAF — eine gute Wahl vor CertMate, wenn Sie
TLS-1.3-Terminierung und Request-Filterung am Edge wünschen. CertMate bleibt
im internen Netzwerk auf einfachem HTTP; Zion terminiert TLS und leitet weiter.

`zion.toml`:

```toml
[server]
listen_http  = "0.0.0.0:8080"
listen_https = "0.0.0.0:8443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"   # your cert, or use Zion's ACME (--features acme)
key_path  = "/etc/ssl/zion/tls.key"
min_version = "1.3"
alpn = ["h2", "http/1.1"]

[upstream.backend]
url = "http://certmate:8000"

# Catch-all to the backend. The explicit "/" route is harmless and documents
# intent; recent Zion also auto-registers "/" for a root catch-all.
[[route]]
path = "/"
upstream = "backend"

[[route]]
path = "/{*rest}"
upstream = "backend"
```

`docker-compose.yml`:

```yaml
services:
  certmate:
    image: certmate:latest          # the published image, or your local build
    environment:
      BEHIND_PROXY: "true"          # trust Zion's X-Forwarded-* headers
    expose:
      - "8000"                       # internal only; not published to the host
    volumes:
      - ./data:/app/data

  zion:
    image: zion:latest              # the published image, or your local build
    depends_on:
      - certmate
    environment:
      ZION_CONFIG: /etc/zion/zion.toml
    volumes:
      - ./zion.toml:/etc/zion/zion.toml:ro
      - ./certs:/etc/ssl/zion:ro
    ports:
      - "443:8443"                   # host 443 -> Zion's HTTPS listener
      - "80:8080"                    # host 80  -> Zion's HTTP listener
```

Behalten Sie `BEHIND_PROXY=true` auf dem CertMate-Service: Zion hängt
`X-Forwarded-For` an, sodass per-Client-Rate-Limiting, Audit-Einträge und
Authentifizierungsfehlerwarnungen auf die echte Client-IP statt auf die Zion-IP
zeigen.

> **`/metrics` wird von Zion bedient, nicht weitergeleitet.** Zion exponiert seinen
> eigenen Prometheus-Endpunkt unter `/metrics` (`zion_*`-Serien für den Proxy),
> der CertMates `/metrics` überlagert. Scrapen Sie diese getrennt: Zions `/metrics`
> aus dem Host-/Cluster-Netzwerk (Zion schränkt es auf private Quell-IPs ein und
> gibt öffentlichen Clients 403 zurück), und CertMates `certmate_*` direkt gegen
> das interne `certmate:8000` mit einem Admin-Bearer-Token (siehe
> [`monitoring/`](../monitoring/) für das Dashboard und die Scrape-Konfiguration).

### Ausgehenden Datenverkehr einschränken (Egress-Hardening)

CertMate stellt ausgehende Verbindungen zu ACME-Zertifizierungsstellen,
DNS-Provider-APIs, Objektspeicher und Benachrichtigungs-Webhooks über HTTP(S)
her, sowie SMTP für E-Mail-Benachrichtigungen. Sie können den **HTTP(S)**-Datenverkehr
einschränken und prüfen, indem Sie ihn über einen **Forward Proxy** leiten und
CertMate jeden anderen Weg ins Internet verweigern.

CertMates HTTP(S)-Clients (`requests`, `certbot`, Webhook-Zustellung via
`urllib`, `boto3`) berücksichtigen die Standard-Umgebungsvariablen
`HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, sodass keine Code-Änderungen
erforderlich sind. **SMTP ist die Ausnahme:** E-Mail-Benachrichtigungen
verwenden `smtplib`, das eine direkte TCP-Verbindung öffnet und die
HTTP-Proxy-Variablen **nicht** berücksichtigt. In einem abgeschotteten
Egress-Netzwerk erlauben Sie direkt `host:port` Ihres SMTP-Relays (per
Firewall-/NetworkPolicy-Regel), oder verwenden Sie einen Webhook-Benachrichtigungskanal
statt E-Mail.

Beispiel mit [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager),
einem selbst gehosteten Squid-basierten Forward Proxy mit WAF, DNS-Sinkhole und —
seit v3.9.0 — einer erstklassigen **Default-deny-Egress-Allowlist** (nur explizit
freigegebene Ziele sind erreichbar; alles andere wird abgewiesen):

```yaml
services:
  certmate:
    image: certmate:latest
    environment:
      HTTP_PROXY:  "http://proxy:3128"
      HTTPS_PROXY: "http://proxy:3128"
      NO_PROXY:    "localhost,127.0.0.1"
    networks:
      - egress            # CertMate kann NUR den Proxy in diesem Netzwerk erreichen
  # Der Secure Proxy Manager Stack stellt den `proxy`-Service auf :3128 bereit.
  # Binden Sie diesen Proxy SOWOHL an das `egress`-Netzwerk (damit CertMate ihn
  # erreicht) ALS AUCH an ein zweites, nicht-internes Netzwerk (damit der Proxy
  # selbst das Internet erreicht). Der Proxy ist dann CertMates einziger Ausgang.
networks:
  egress:
    internal: true        # kein Gateway: CertMate hat keinen direkten Internetzugang
```

CertMate in einem `internal`-Netzwerk (ohne Gateway) zusammen mit dem Proxy zu
betreiben, macht den Proxy zu seinem **einzigen** Ausgang. Ausgehender Datenverkehr
wird zu einem einzelnen, prüfbaren Engpass: Erlauben Sie die Ziele, die CertMate
tatsächlich benötigt (Ihre Zertifizierungsstelle, DNS-Provider, Objektspeicher,
Benachrichtigungs-Endpunkte), verweigern Sie den Rest; reine IP-Adressen als
Ziele werden am Proxy blockiert statt blind vertraut. Wenn Sie DNS-Alias-/
CNAME-Delegation verwenden, erlauben Sie auch `cloudflare-dns.com` — CertMate
löst diese CNAMEs über DoH auf.

Mit Secure Proxy Manager v3.9.0+ ist dies ein eingebauter Modus statt einer
manuellen ACL-Übung: Aktivieren Sie **Default-deny egress** in den Einstellungen
und füllen Sie die **Egress-Allowlist** mit den Zielen, die CertMate benötigt.
Jeder Eintrag ist eine Domain oder eine IP/CIDR (automatisch klassifiziert), und
der Endpunkt `/api/egress-allowlist` ermöglicht die Verwaltung der Liste über IaC.
Eine repräsentative Starter-Allowlist:

- der API-Host Ihrer ACME-Zertifizierungsstelle — z.B. `acme-v02.api.letsencrypt.org`
  (plus `acme-staging-v02.api.letsencrypt.org`, wenn Sie gegen Staging ausstellen),
  oder der Endpunkt der von Ihnen konfigurierten Zertifizierungsstelle;
- der API-Host Ihres DNS-Providers — je nach Provider (z.B. `api.cloudflare.com`);
- Ihr Objektspeicher-Endpunkt, sofern Off-Site-Backup aktiviert ist;
- Ihr Benachrichtigungs-Host — der Webhook-, Gotify-, ntfy- oder Telegram-Endpunkt,
  falls verwendet;
- `cloudflare-dns.com`, wenn Sie DNS-Alias-/CNAME-Delegation nutzen (wird über
  DoH aufgelöst, wie oben beschrieben).

Alles andere wird am Proxy abgewiesen, sodass eine Fehlkonfiguration oder eine
kompromittierte Abhängigkeit nicht unbemerkt zu einem beliebigen Host exfiltrieren
kann. Für HTTPS gleicht die Allowlist den Host des `CONNECT`-Requests ab, sodass
sie ohne TLS-Interception funktioniert.

- **Kubernetes:** eine Egress-Default-deny-`NetworkPolicy`, die Datenverkehr
  nur zum Proxy-Service erlaubt, plus die `HTTP(S)_PROXY`-Umgebungsvariablen
  auf dem Deployment.
- **systemd:** `Environment=HTTPS_PROXY=...` in der Unit, plus Host-Firewall-Regeln,
  die Egress auf den Proxy einschränken.

**HTTPS-Inhaltsinspektion (optional, fortgeschritten).** Ein Forward Proxy sieht
bei einer HTTPS-Verbindung nur SNI / Host / IP — Ziel-Allow/Deny funktioniert
darauf ohne Entschlüsselung. Wenn Sie zusätzlich TLS-Interception (SSL-Bump) auf
dem Proxy aktivieren, um ausgehende *Inhalte* zu inspizieren, muss CertMate der
**Interceptions-CA des Proxys vertrauen**: Setzen Sie `REQUESTS_CA_BUNDLE`
(und `SSL_CERT_FILE`) auf ein Bundle, das diese einschließt, oder fügen Sie sie
dem System-Truststore des Containers hinzu. **Schließen Sie die ACME-Endpunkte
von der Interception aus (`splice`)** — Sie wollen die Verbindung zu Ihrer
Zertifizierungsstelle nicht per MITM abfangen, und einige Endpunkte pinnen
Zertifikate. Dies ist kein mutual TLS; es handelt sich um einseitiges Vertrauen
in eine private CA.

### Speicherort des Datenverzeichnisses

CertMate verwendet standardmäßiges blockierendes Python-Datei-I/O für alles
unter `data/` (Einstellungen, Zertifikate, Audit-Log, SQLite-Speicher des
Schedulers). Lokaler Speicher wird dringend empfohlen.

Wenn Sie `data/` auf einem Netzwerk-Dateisystem (NFS, SMB) einhängen, beachten
Sie Folgendes:

- Ein eingefrorener NFS-Server kann Python-Datei-Lesevorgänge unbegrenzt
  blockieren, ohne eingebauten Timeout. Der Erneuerungsworker, der Audit-Log-
  Schreiber und die /health-Probe blockieren alle auf demselben zugrunde
  liegenden Einhängepunkt.
- SQLites WAL-Journal-Modus erfordert Sperrsemantiken, die NFS nicht immer
  bereitstellt. CertMate protokolliert eine Warnung, wenn es auf einen schwächeren
  Journal-Modus zurückfallen musste; die Korrektheit bleibt erhalten, aber die
  Nebenläufigkeit sinkt.

Falls NFS unvermeidbar ist, hängen Sie mit `soft,timeo=30,retrans=3` ein (oder dem
Äquivalent Ihrer Distribution), damit I/O bei einem blockierten Server schnell
fehlschlägt statt zu hängen, und prüfen Sie `data/logs/certmate.log` nach dem
ersten Start auf die WAL-Fallback-Zeile.

### Gunicorn verwenden

```bash
gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
```

### systemd verwenden

Erstellen Sie `/etc/systemd/system/certmate.service`:

```ini
[Unit]
Description=CertMate SSL Certificate Manager
After=network.target

[Service]
Type=simple
User=certmate
WorkingDirectory=/opt/certmate
Environment=PATH=/opt/certmate/venv/bin
ExecStart=/opt/certmate/venv/bin/gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Aktivieren und starten:

```bash
sudo systemctl enable certmate
sudo systemctl start certmate
```

### Docker im Produktionsbetrieb verwenden

```yaml
version: '3.8'
services:
  certmate:
    build: .
    ports:
      - "8000:8000"
    environment:
      - API_BEARER_TOKEN=${API_BEARER_TOKEN}
      - CLOUDFLARE_TOKEN=${CLOUDFLARE_TOKEN}
    volumes:
      - ./certificates:/app/certificates
      - ./data:/app/data
    restart: unless-stopped
```

---

## Fehlerbehebung

### Versionskonflikte bei DNS-Plugins

Bei Versionskonflikten verwenden Sie diese spezifischen Versionen:

```txt
certbot==4.1.1
certbot-dns-cloudflare==4.1.1
certbot-dns-route53==4.1.1
certbot-dns-azure==2.6.1
certbot-dns-google==4.1.1
certbot-dns-powerdns==0.2.1
```

> Die meisten DNS-Plugins erfordern Certbot 4.1.1. Das Azure-Plugin hat eine eigenständige Versionierung (2.6.1), und PowerDNS ist ein neueres Plugin (0.2.1).

### Manuelle Installation von Abhängigkeiten

Falls die automatische Installation fehlschlägt, installieren Sie DNS-Provider einzeln:

```bash
# Kern-certbot
pip install certbot==4.1.1

# Cloudflare
pip install certbot-dns-cloudflare==4.1.1

# AWS Route53
pip install certbot-dns-route53==4.1.1 boto3==1.35.76

# Azure DNS
pip install certbot-dns-azure==2.6.1 azure-identity==1.19.0 azure-mgmt-dns==8.1.0

# Google Cloud DNS
pip install certbot-dns-google==4.1.1 google-cloud-dns==0.35.0

# PowerDNS
pip install certbot-dns-powerdns==0.2.1
```

### Validierungsbefehle

```bash
# Certbot-Plugins prüfen
certbot plugins --text

# Prüfen, ob der Service läuft
curl -X GET http://localhost:8000/api/health
```

---

## Support

Bei Problemen:

1. Prüfen Sie die Logs auf spezifische Fehler
2. Überprüfen Sie Ihre DNS-Provider-Zugangsdaten
3. Siehe [DNS-Provider-Leitfaden](./dns-providers.md) für anbieterspezifische Fehlerbehebung
4. Siehe [Test-Leitfaden](./testing.md) für die Ausführung von Diagnosen

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [DNS-Provider →](./dns-providers.md) • [Docker →](./docker.md)

</div>
