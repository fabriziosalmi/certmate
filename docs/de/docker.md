# Docker Build & Deployment

<!-- CERTMATE-TRANSLATED-FROM 2fbf24622135f998 -->

Diese Anleitung beschreibt das Erstellen, Deployen und Ausführen von CertMate in Docker — einschließlich Multi-Plattform-Unterstützung für ARM und AMD64.

---

## Produktion mit Docker Compose

Der kürzeste Weg, CertMate produktiv zu betreiben: eine Datei, das veröffentlichte Image, nichts zu bauen und kein Repository zu klonen.

```bash
mkdir certmate && cd certmate
curl -fsSLO https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/docker-compose.yml
printf 'API_BEARER_TOKEN=%s\nSECRET_KEY=%s\nCERTMATE_BACKUP_PASSPHRASE=%s\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
```

Öffnen Sie `http://127.0.0.1:8000`. Die erste Seite legt das Administratorkonto an und verlangt zur Autorisierung das `API_BEARER_TOKEN` aus `.env`. Bewahren Sie `.env` auf: Sie enthält das Token für API-Clients, den Schlüssel, der Sitzungen signiert, und die Passphrase, ohne die ein Backup diese Instanz nicht wiederherstellen kann.

Was die Datei tut:

- **Pinnt das Image** des neuesten Releases. Die Kopie auf `main` wird mit jedem Release aktualisiert. Um auf einer Version zu bleiben, setzen Sie `CERTMATE_VERSION=X.Y.Z` in `.env`.
- **Legt alles in benannten Volumes ab** (`certificates`, `data`, `logs`, `backups`). Docker erstellt sie mit den Besitzrechten, die CertMate braucht, daher ist kein `chown` nötig. `docker compose down` behält sie; `down -v` löscht sie.
- **Lauscht nur auf 127.0.0.1.** Für Fernzugriff einen Reverse Proxy vorschalten und `BEHIND_PROXY=true` setzen. `CERTMATE_BIND=0.0.0.0` veröffentlicht den Dienst auf allen Schnittstellen. `CERTMATE_PORT` ändert den Host-Port.
- **Startet nicht ohne `API_BEARER_TOKEN` und `SECRET_KEY`**, statt Werte zu erzeugen, die sich bei jedem Neuerstellen des Containers ändern würden.

Optionale Variablen für `.env`: `CLOUDFLARE_TOKEN` (legt beim ersten Start ein Cloudflare-DNS-Konto an), `LETSENCRYPT_EMAIL`, `BEHIND_PROXY`.

**Aktualisieren:** Laden Sie die Datei erneut herunter (oder ändern Sie `CERTMATE_VERSION`) und führen Sie dann `docker compose pull && docker compose up -d` aus.

Die `docker-compose.yml` im Wurzelverzeichnis des Repositorys baut das Image aus dem Quellcode und ist für die Entwicklung gedacht.

---

## Schnellstart

### Pull und Ausführen

Die Images werden auf Docker Hub als `fabriziosalmi/certmate` veröffentlicht. Releases nach v2.42.0 werden mit denselben Tags zusätzlich auf GHCR als `ghcr.io/fabriziosalmi/certmate` veröffentlicht, was die anonymen Pull-Limits von Docker Hub vermeidet: Verwenden Sie unten einen der beiden Namen.

```bash
# Docker wählt automatisch die richtige Architektur
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_data:/app/data \
  -v certmate_certificates:/app/certificates \
  fabriziosalmi/certmate:latest
```

### Lokal bauen und ausführen

```bash
docker build -t certmate:latest .
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  -v certmate_logs:/app/logs \
  certmate:latest
```

---

## Sicherheit

Der Build-Prozess stellt sicher, dass keine Secrets im Image enthalten sind:

- `.dockerignore` schließt alle `.env`-Dateien und sensible Daten aus
- Umgebungsvariablen werden **zur Laufzeit** bereitgestellt, nicht beim Build
- Es werden nur die wesentlichen Anwendungsdateien eingebunden
- Images können sicher in öffentliche Registries gepusht werden

### Keine Secrets im Image prüfen

```bash
docker history certmate:latest
docker inspect certmate:latest | grep -i env
docker run --rm certmate:latest find / -name "*.env" 2>/dev/null
```

---

## Laufzeitkonfiguration

### Option 1: Environment-Datei

Erstellen Sie eine `.env`-Datei auf Ihrem Host (nicht im Docker-Image):

```bash
SECRET_KEY=your-super-secret-key-here
# SECRET_KEY_FILE=/run/secrets/secret_key  # Alternative: takes precedence over SECRET_KEY
API_BEARER_TOKEN=your-api-bearer-token-here
# API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token  # Alternative: takes precedence over API_BEARER_TOKEN
CLOUDFLARE_TOKEN=your-cloudflare-api-token
CERTMATE_LOG_LEVEL=INFO
```

```bash
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  -v certmate_logs:/app/logs \
  certmate:latest
```

### Option 2: Direkte Umgebungsvariablen

```bash
docker run -d --name certmate \
  -e SECRET_KEY="your-secret-key" \
  # -e SECRET_KEY_FILE="/run/secrets/secret_key" \  # Alternative: takes precedence over SECRET_KEY
  -e API_BEARER_TOKEN="your-api-bearer-token" \
  # -e API_BEARER_TOKEN_FILE="/run/secrets/api_bearer_token" \  # Alternative: takes precedence over API_BEARER_TOKEN
  -e CLOUDFLARE_TOKEN="your-api-token" \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  certmate:latest
```

### Referenz der Umgebungsvariablen

| Variable | Erforderlich | Beschreibung |
|----------|--------------|--------------|
| `SECRET_KEY` | Nein | Flask-Secret-Key für Sessions (wird automatisch generiert, wenn nicht gesetzt) |
| `SECRET_KEY_FILE` | Nein | Pfad zu einer Datei mit dem Flask-Secret-Key (hat Vorrang vor `SECRET_KEY`) |
| `API_BEARER_TOKEN` | Nein (automatisch generiert) | API-Authentifizierungs-Token. Wird automatisch generiert, wenn nicht gesetzt, aber setzen Sie es, bevor Sie eine noch nicht eingerichtete Instanz im Netzwerk verfügbar machen; wenn gesetzt, fügen Sie es einmal im Erststart-Bildschirm ein, um den Admin zu erstellen |
| `API_BEARER_TOKEN_FILE` | Nein | Pfad zu einer Datei mit dem API-Bearer-Token (hat Vorrang vor `API_BEARER_TOKEN`) |
| `CERTMATE_LOG_LEVEL` | Nein | `INFO` (Standard), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | Nein | Wenn gesetzt, werden einheitliche Backups im Ruhezustand verschlüsselt (`.zip.enc`, PBKDF2-SHA256 + Fernet). Dieselbe Passphrase wird zur Wiederherstellung benötigt. Nicht gesetzt = ältere unverschlüsselte `.zip`-Backups |
| `CLOUDFLARE_TOKEN` | Nein | API-Token für das Standard-Cloudflare-DNS-Konto. Cloudflare ist der einzige DNS-Provider, der aus der Umgebung gelesen wird: Route53 und die übrigen werden unter Einstellungen → DNS-Provider oder über die API konfiguriert, und `AWS_ACCESS_KEY_ID` im Container zu setzen bewirkt nichts |

Siehe den [Installationsleitfaden](./installation.md#environment-variables) für die vollständige Liste.

### DNS-Token aus `settings.json` heraushalten

Über die Oberfläche konfigurierte DNS-Provider-Token liegen in `settings.json`
— genau der Datei, die gesichert, kopiert und eingebunden wird. Jedes
Zugangsdatenfeld kann stattdessen **angeben**, wo sein Wert liegt:
`api_token_file` mit einem Pfad oder `api_token_env` mit einem Variablennamen,
so wie es `API_BEARER_TOKEN_FILE` bereits tut. Der Wert wird gelesen, wenn
certbot läuft, und nie zurückgeschrieben. Für das OIDC-`client_secret` gilt
dasselbe. Siehe
[SECURITY.md](https://github.com/fabriziosalmi/certmate/blob/main/SECURITY.md#keeping-credentials-out-of-settingsjson).

---

## Docker Compose

### Grundkonfiguration

```yaml
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    container_name: certmate
    ports:
      - "127.0.0.1:8000:8000"  # nur localhost; für externen Zugriff einen Reverse Proxy davorschalten
    environment:
      - SECRET_KEY=${SECRET_KEY:-}
      # - SECRET_KEY_FILE=${SECRET_KEY_FILE:-}  # Alternative: path to a file containing the secret key
      - API_BEARER_TOKEN=${API_BEARER_TOKEN:-}
      # - API_BEARER_TOKEN_FILE=${API_BEARER_TOKEN_FILE:-}  # Alternative: path to a file containing the bearer token
      - CERTMATE_LOG_LEVEL=${CERTMATE_LOG_LEVEL:-INFO}
    volumes:
      - certmate_certificates:/app/certificates
      - certmate_data:/app/data
      - certmate_logs:/app/logs
      - certmate_backups:/app/backups
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  certmate_certificates:
  certmate_data:
  certmate_logs:
  certmate_backups:
```

```bash
# Mit .env-Datei im selben Verzeichnis starten
docker-compose up -d

# Oder eine andere .env-Datei angeben
docker-compose --env-file /path/to/.env up -d
```

---

## Podman (Quadlet, rootless) und OpenShift

[`deploy/podman/certmate.container`](../../deploy/podman/certmate.container) ist eine Quadlet-Unit: Podman macht daraus einen systemd-Dienst. Sie führt das veröffentlichte Image mit benannten Volumes aus, den Port nur auf Loopback, die Geheimnisse als Podman-Secrets, mit Healthcheck und `podman auto-update`-Unterstützung.

Rootless, als Ihr eigener Benutzer (die drei Secrets werden einmal angelegt und stehen in keiner Datei; `enable-linger` hält den Dienst ohne Sitzung am Laufen und startet ihn beim Booten):

```bash
for s in certmate-api-token certmate-secret-key certmate-backup-passphrase; do
  openssl rand -hex 32 | tr -d '\n' | podman secret create "$s" -
done

mkdir -p ~/.config/containers/systemd
curl -fsSL -o ~/.config/containers/systemd/certmate.container \
  https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/podman/certmate.container
systemctl --user daemon-reload
systemctl --user start certmate

sudo loginctl enable-linger "$USER"
```

Rootful: Legen Sie die Datei nach `/etc/containers/systemd/`, erstellen Sie die Secrets als root, dann `sudo systemctl daemon-reload && sudo systemctl start certmate`.

Öffnen Sie `http://127.0.0.1:8000`. Die erste Seite legt das Administratorkonto an und verlangt das API-Token: `podman secret inspect --showsecret certmate-api-token --format '{{.SecretData}}'`.

Verifiziert auf Fedora 44 mit Podman 5.8, rootful und rootless: Der Dienst startet gesund, das Token autorisiert die API, und er kommt nach einem Neustart zurück (rootless über Lingering). Die Volumes verwenden `:U`: Rootless ließ Podman die Wurzel des Volumes `backups` im Besitz von root, und CertMate startete nicht. Beliebige UIDs, Bind-Mounts und podman-compose stehen auf der [englischen Seite](../docker.md#podman-quadlet-rootless-and-openshift).

---

## Multi-Plattform-Builds

CertMate unterstützt Multi-Plattform-Docker-Images für ARM- und AMD64-Architekturen.

### Unterstützte Architekturen

| Plattform | Beschreibung | Typische Anwendungsfälle |
|-----------|--------------|--------------------------|
| `linux/amd64` | Intel/AMD 64-Bit | Die meisten Cloud-Server, Desktops |
| `linux/arm64` | ARM 64-Bit | Apple Silicon, ARM-Cloud-Instanzen |
| `linux/arm/v7` | ARM 32-Bit v7 | Raspberry Pi 3+ |
| `linux/arm/v6` | ARM 32-Bit v6 | Raspberry Pi 1, Zero |

### Build-Skripte

```bash
# Nur für die aktuelle Plattform bauen
./build-docker.sh

# Für mehrere Plattformen bauen (ARM64 + AMD64)
./build-docker.sh -m

# Bauen und zu Docker Hub pushen
./build-docker.sh -m -p -r YOUR_DOCKERHUB_USERNAME

# Dediziertes Multi-Plattform-Skript
./build-multiplatform.sh -r USERNAME -v v1.0.0 -p

# Für Raspberry Pi bauen
./build-multiplatform.sh --platforms linux/arm/v7 -r USERNAME -p
```

### Manuelles Docker Buildx

```bash
# Buildx-Builder erstellen und verwenden
docker buildx create --name certmate-builder --use

# Für mehrere Plattformen bauen
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest .

# Bauen und pushen
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest --push .
```

### Voraussetzungen für Multi-Plattform

```bash
# Buildx-Unterstützung prüfen
docker buildx version
docker buildx inspect --bootstrap

# QEMU-Emulation aktivieren (falls erforderlich)
docker run --privileged --rm tonistiigi/binfmt --install all
```

### Bestimmte Plattform erzwingen

```bash
# AMD64 erzwingen (z. B. auf Apple Silicon zum Testen)
docker run --platform linux/amd64 --rm \
  --env-file .env -p 8000:8000 certmate:latest

# Automatische Erkennung (empfohlen)
docker run --rm --env-file .env -p 8000:8000 certmate:latest
```

---

## Zu Docker Hub pushen

```bash
# Anmelden
docker login

# Taggen und pushen
docker build -t USERNAME/certmate:latest .
docker push USERNAME/certmate:latest

# Mit Versions-Tag
docker build -t USERNAME/certmate:v1.0.0 .
docker push USERNAME/certmate:v1.0.0
```

---

## CI/CD-Integration

### GitHub Actions

Erforderliche Secrets:
- `DOCKERHUB_USER`
- `DOCKERHUB_TOKEN`

```bash
# Manueller Trigger mit benutzerdefinierten Plattformen
gh workflow run docker-multiplatform.yml \
  -f platforms="linux/amd64,linux/arm64,linux/arm/v7" \
  -f push_to_registry=true
```

---

## Tipps für den Produktionsbetrieb

1. **Secrets-Verwaltung nutzen**: Docker Secrets, Kubernetes Secrets oder einen Secrets Manager
2. **TLS aktivieren**: Hinter einem Reverse Proxy mit TLS-Terminierung betreiben
3. **Ressourcen überwachen**: CPU- und Speicherlimits setzen
4. **Volumes sichern**: Zertifikats- und Daten-Volumes regelmäßig sichern
5. **Regelmäßig aktualisieren**: Image mit Sicherheits-Patches aktuell halten
6. **Layer-Caching verwenden** für schnellere Builds:
   ```bash
   docker buildx build --cache-from type=registry,ref=USERNAME/certmate:cache .
   ```

---

## Fehlerbehebung

### Container startet nicht

```bash
docker logs certmate
docker exec certmate env
```

### Health Check schlägt fehl

```bash
docker logs certmate
docker exec certmate curl -v http://localhost:8000/health
```

### Berechtigungsprobleme

```bash
docker exec certmate ls -la /app/certificates
docker exec certmate ls -la /app/data
```

### Probleme bei Multi-Plattform-Builds

| Fehler | Lösung |
|--------|--------|
| "multiple platforms not supported for docker driver" | `docker buildx create --name multiplatform --use` |
| "exec format error" | `docker run --privileged --rm tonistiigi/binfmt --install all` |
| Langsame nicht-native Builds | Normal aufgrund der Emulation; GitHub Actions für den Produktionsbetrieb verwenden |
| Multi-Plattform-Image kann nicht in lokales Docker geladen werden | `--load` mit einer einzelnen Plattform für lokale Tests verwenden |

---

## Image-Größen

Typische Größen je Architektur:
- **AMD64**: ~200-300 MB
- **ARM64**: ~200-300 MB
- **ARM v7**: ~180-250 MB

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [Installation →](./installation.md) • [Architektur →](./architecture.md)

</div>
