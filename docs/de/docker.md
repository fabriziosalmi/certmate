# Docker Build & Deployment

Diese Anleitung beschreibt das Erstellen, Deployen und Ausführen von CertMate in Docker — einschließlich Multi-Plattform-Unterstützung für ARM und AMD64.

---

## Schnellstart

### Pull und Ausführen

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
CLOUDFLARE_API_TOKEN=your-cloudflare-api-token
LOG_LEVEL=INFO
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
  -e CLOUDFLARE_API_TOKEN="your-api-token" \
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
| `API_BEARER_TOKEN` | Nein | Authentifizierungs-Token für den API-Zugriff (wird automatisch generiert, wenn nicht gesetzt) |
| `API_BEARER_TOKEN_FILE` | Nein | Pfad zu einer Datei mit dem API-Bearer-Token (hat Vorrang vor `API_BEARER_TOKEN`) |
| `LOG_LEVEL` | Nein | `INFO` (Standard), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | Nein | Wenn gesetzt, werden einheitliche Backups im Ruhezustand verschlüsselt (`.zip.enc`, PBKDF2-SHA256 + Fernet). Dieselbe Passphrase wird zur Wiederherstellung benötigt. Nicht gesetzt = ältere unverschlüsselte `.zip`-Backups |
| `CLOUDFLARE_API_TOKEN` | Nein | Cloudflare-DNS-Provider-Token |
| `AWS_ACCESS_KEY_ID` | Nein | AWS-Route53-Zugriffsschlüssel |
| `AWS_SECRET_ACCESS_KEY` | Nein | AWS-Route53-Secret-Key |

Siehe den [Installationsleitfaden](./installation.md#environment-variables) für die vollständige Liste.

---

## Docker Compose

### Grundkonfiguration

```yaml
version: '3.8'

services:
  certmate:
    image: fabriziosalmi/certmate:latest
    container_name: certmate
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY:-}
      # - SECRET_KEY_FILE=${SECRET_KEY_FILE:-}  # Alternative: path to a file containing the secret key
      - API_BEARER_TOKEN=${API_BEARER_TOKEN:-}
      # - API_BEARER_TOKEN_FILE=${API_BEARER_TOKEN_FILE:-}  # Alternative: path to a file containing the bearer token
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    volumes:
      - certmate_certificates:/app/certificates
      - certmate_data:/app/data
      - certmate_logs:/app/logs
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
```

```bash
# Mit .env-Datei im selben Verzeichnis starten
docker-compose up -d

# Oder eine andere .env-Datei angeben
docker-compose --env-file /path/to/.env up -d
```

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
- `DOCKERHUB_USERNAME`
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
