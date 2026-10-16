# Docker Build & Deployment

<!-- CERTMATE-TRANSLATED-FROM b3c7a928998dc93e -->

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

## Portainer

Stellen Sie in Portainer das [Produktions-Compose-Bundle](#produktion-mit-docker-compose) als Stack direkt aus diesem Repository bereit:

1. **Stacks → Add stack**, nennen Sie ihn `certmate` und wählen Sie **Repository**.
2. Repository-URL `https://github.com/fabriziosalmi/certmate`, Referenz `refs/heads/main`, Compose-Pfad `deploy/docker-compose.yml`.
3. Fügen Sie unter **Environment variables** `API_BEARER_TOKEN`, `SECRET_KEY` und `CERTMATE_BACKUP_PASSPHRASE` hinzu, jeweils mit einem langen Zufallswert wie der Ausgabe von `openssl rand -hex 32`. Fügen Sie optional `CERTMATE_PORT`, `CERTMATE_BIND` oder `CLOUDFLARE_TOKEN` hinzu.
4. **Deploy the stack.**

Ohne die beiden Pflichtvariablen schlägt das Deployment fehl und nennt die fehlende (`required variable API_BEARER_TOKEN is missing a value`), statt mit Schlüsseln zu starten, die sich bei jedem Redeploy ändern. Zum Aktualisieren verwenden Sie **Pull and redeploy** am Stack: Die benannten Volumes und damit Zertifikate und Einstellungen bleiben erhalten.

Verifiziert mit Portainer CE 2.45: Ein Stack ohne die Variablen wird mit dieser Meldung abgelehnt; mit ihnen startet er gesund, das Token autorisiert die API, und ein Pull and Redeploy erstellt den Container mit intakten Daten neu.

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
# Setzen Sie API_BEARER_TOKEN, bevor Sie eine noch nicht eingerichtete Instanz in
# einem Netzwerk verfügbar machen: Solange kein erster Admin existiert, liefert eine
# Instanz ohne Token jedem, der sie erreichen kann, den Setup-Bypass aus. Wenn gesetzt,
# fügen Sie es einmal im Erststart-Bildschirm ein, um den Admin zu erstellen.
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
| `SECRET_KEY_FILE` | Nein | Pfad zu einer Datei mit dem Flask-Secret-Key (hat Vorrang vor `SECRET_KEY`). Ist die Variable gesetzt und kann die Datei nicht gelesen werden oder ist sie leer, verweigert CertMate den Start: Ein Secret, dessen Einbindung fehlgeschlagen ist, ist ein Konfigurationsfehler, und stattdessen einen Schlüssel zu erzeugen, würde bei jedem Neustart jeden Benutzer abmelden, mit Sitzungen, die von einem Schlüssel signiert sind, den Sie nicht gewählt haben. |
| `API_BEARER_TOKEN` | Nein (automatisch generiert) | API-Authentifizierungs-Token. Wird automatisch generiert, wenn nicht gesetzt, aber setzen Sie es, bevor Sie eine noch nicht eingerichtete Instanz im Netzwerk verfügbar machen; wenn gesetzt, fügen Sie es einmal im Erststart-Bildschirm ein, um den Admin zu erstellen. **Dieser Wert ist maßgeblich:** Weicht er vom bereits gespeicherten Token ab, wird das gespeicherte beim Start ersetzt und funktioniert nicht mehr. Dadurch wird das Hinzufügen oder Rotieren der Variable bei einer bestehenden Installation wirksam — zuvor verwendete die Durchsetzung diesen Wert, während die Authentifizierung noch das alte Token prüfte, und der Erststart-Bildschirm verlangte ein Token, das er dann ablehnte |
| `API_BEARER_TOKEN_FILE` | Nein | Pfad zu einer Datei mit dem API-Bearer-Token (hat Vorrang vor `API_BEARER_TOKEN`) |
| `CERTMATE_LOG_LEVEL` | Nein | `INFO` (Standard), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | **Setzen Sie sie, wenn Sie automatische Backups wollen, aus denen Sie wiederherstellen können** | Verschlüsselt einheitliche Backups im Ruhezustand (`.zip.enc`, PBKDF2-SHA256 + Fernet) und macht automatische Backups erst *vollständig* — mit ihr können sie diese Instanz wiederherstellen, ohne sie bleiben ihre Zugangsdaten maskiert und sie können es nicht. Dieselbe Passphrase wird zur Wiederherstellung benötigt, und CertMate speichert sie nie für Sie. Bewahren Sie sie an einem anderen Ort auf als auf dem Rechner, der die Backups enthält |
| `CLOUDFLARE_TOKEN` | Nein | API-Token für das Standard-Cloudflare-DNS-Konto. Route53 nutzt normalerweise die unter Einstellungen → DNS-Provider konfigurierten Zugangsdaten, aber wenn für sein Konto ausdrücklich `auth_mode: iam_role` gewählt ist, nutzt Certbot die AWS-Anmeldekette des Containers (einschließlich IAM-Rollen). |

Siehe den [Installationsleitfaden](./installation.md#umgebungsvariablen) für die vollständige Liste.

### DNS-Token aus `settings.json` heraushalten

Über die Oberfläche konfigurierte DNS-Provider-Token liegen in `settings.json`
— genau der Datei, die gesichert, kopiert und eingebunden wird. Jedes
Zugangsdatenfeld kann stattdessen **angeben**, wo sein Wert liegt:
`api_token_file` mit einem Pfad oder `api_token_env` mit einem Variablennamen,
so wie es `API_BEARER_TOKEN_FILE` tut. Der Wert wird gelesen, wenn
certbot läuft, und nie zurückgeschrieben. Das OIDC-`client_secret` akzeptiert
dasselbe Paar. Siehe
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
docker compose up -d

# Oder eine andere .env-Datei angeben
docker compose --env-file /path/to/.env up -d
```

---

## Podman (Quadlet, rootless) und OpenShift

### Quadlet: CertMate als systemd-Dienst

[`deploy/podman/certmate.container`](../../deploy/podman/certmate.container) ist eine Quadlet-Unit: Podman macht daraus einen systemd-Dienst. Sie führt das veröffentlichte Image mit benannten Volumes aus, den Port nur auf Loopback, die Geheimnisse als Podman-Secrets, mit Healthcheck und `podman auto-update`-Unterstützung.

Rootless, als Ihr eigener Benutzer:

```bash
# Die drei Secrets, einmalig angelegt. Sie stehen in keiner Datei.
for s in certmate-api-token certmate-secret-key certmate-backup-passphrase; do
  openssl rand -hex 32 | tr -d '\n' | podman secret create "$s" -
done

mkdir -p ~/.config/containers/systemd
curl -fsSL -o ~/.config/containers/systemd/certmate.container \
  https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/podman/certmate.container
systemctl --user daemon-reload
systemctl --user start certmate

# Ohne Anmeldesitzung weiterlaufen lassen und beim Booten starten.
sudo loginctl enable-linger "$USER"
```

Stattdessen rootful: Legen Sie die Datei nach `/etc/containers/systemd/`, erstellen Sie die Secrets als root und führen Sie dann `sudo systemctl daemon-reload && sudo systemctl start certmate` aus.

Öffnen Sie `http://127.0.0.1:8000`. Die erste Seite legt das Administratorkonto an und verlangt das API-Token: `podman secret inspect --showsecret certmate-api-token --format '{{.SecretData}}'`.

Verifiziert auf Fedora 44 mit Podman 5.8, rootful und rootless: Der Dienst startet gesund, das Token autorisiert die API, und er kommt nach einem Neustart zurück (rootless über Lingering).

### Beliebige UIDs (rootless Podman, OpenShift)

Das Image läuft standardmäßig als Nicht-root-Benutzer `1000`, folgt aber auch
dem OpenShift-Muster der **beliebigen UID** (arbitrary UID): Die zur Laufzeit beschreibbaren Verzeichnisse
(`/app/data`, `/app/certificates`, `/app/logs`, `/app/backups`) gehören der
**Gruppe 0 (root-Gruppe)** und sind gruppenbeschreibbar + setgid. Ein
Container-Prozess, der unter *beliebiger* UID läuft, die zur Gruppe 0 gehört (so starten rootless Podman und
OpenShift Container), kann daher Dateien anlegen und umbenennen, ohne dass die
Volumes manuell mit `chown -R 1000:1000` angepasst werden müssen. Geheime Dateien, die die Anwendung schreibt (der private
CA-Schlüssel, der Audit-Signaturschlüssel, DNS-Zugangsdatendateien, `.secret_key`), werden
immer mit `0600` nur für den Besitzer angelegt, sodass die gruppenbeschreibbaren Verzeichnisse nie
einen Schlüssel offenlegen. (Issue [#380](https://github.com/fabriziosalmi/certmate/issues/380).)

### Benannte Volumes

Ein neues **benanntes Volume** übernimmt unter rootful Podman und Docker die
Gruppe-0-Berechtigungen des Images. Unter **rootless** Podman nicht immer: Gemessen mit
Podman 5.8 blieb die Wurzel des Volumes `backups`, dessen Verzeichnis im Image nicht
leer ist, im Besitz von root, und CertMate verweigerte den Start mit *"Required
directories are not writable"*. Fügen Sie `:U` hinzu, das jedes Volume dem
Benutzer des Containers übergibt:

```bash
podman run -d --name certmate \
  -p 127.0.0.1:8000:8000 \
  -v certmate_data:/app/data:U \
  -v certmate_certificates:/app/certificates:U \
  -v certmate_logs:/app/logs:U \
  -v certmate_backups:/app/backups:U \
  docker.io/fabriziosalmi/certmate:latest
```

### Bind-Mounts (Host-Verzeichnisse)

Ein Bind-Mount behält die Besitzrechte des **Host**-Verzeichnisses, die die
Berechtigungen des Images überdecken. Machen Sie die Host-Verzeichnisse einmalig für Gruppe 0 beschreibbar und führen Sie dann aus:

```bash
# Host-Verzeichnisse für Gruppe 0 beschreibbar anlegen (jede UID in Gruppe 0 kann schreiben)
mkdir -p ./{data,certificates,logs,backups}
chgrp -R 0 ./{data,certificates,logs,backups}
chmod -R g+rwX ./{data,certificates,logs,backups}

podman run -d --name certmate \
  -p 8000:8000 \
  -v ./data:/app/data \
  -v ./certificates:/app/certificates \
  -v ./logs:/app/logs \
  -v ./backups:/app/backups \
  docker.io/fabriziosalmi/certmate:latest
```

Alternativ lassen Sie podman die Besitzrechte mit der Mount-Option `:U` für Sie korrigieren
(ändert rekursiv den Besitz der Quelle passend zur UID/GID des Containers):

```bash
podman run -d --name certmate \
  -p 8000:8000 \
  -v ./data:/app/data:U \
  -v ./certificates:/app/certificates:U \
  -v ./logs:/app/logs:U \
  -v ./backups:/app/backups:U \
  docker.io/fabriziosalmi/certmate:latest
```

### rootless podman-compose

```yaml
services:
  certmate:
    image: docker.io/fabriziosalmi/certmate:latest
    ports:
      - "8000:8000"
    volumes:
      - certmate_data:/app/data:U
      - certmate_certificates:/app/certificates:U
      - certmate_logs:/app/logs:U
      - certmate_backups:/app/backups:U
    restart: unless-stopped

volumes:
  certmate_data:
  certmate_certificates:
  certmate_logs:
  certmate_backups:
```

Bricht der Start mit *"Required directories are not writable by the CertMate
process"* ab, ist der Mount für den Benutzer des Containers nicht beschreibbar: Fügen Sie
dem Volume `:U` hinzu, oder wenden Sie bei einem Bind-Mount das obige `chgrp 0 … && chmod g+rwX …` an.

> **Kubernetes / OpenShift:** keine Änderungen nötig. Setzen Sie
> `spec.securityContext.fsGroup: 0` (oder verlassen Sie sich auf die standardmäßige restricted SCC,
> die bereits eine beliebige UID in Gruppe 0 vergibt), und die eingebundenen Volumes
> werden automatisch für Gruppe 0 beschreibbar.

---

## Aktualisieren

CertMate hält seinen persistenten Zustand in `/app/data` (`settings.json`, die Admin-Benutzer,
der automatisch generierte `.secret_key`, der Audit-Signaturschlüssel und die
Scheduler-Datenbank) und in `/app/certificates`. Dieser Zustand übersteht ein Upgrade,
weil diese Pfade von außerhalb des Containers eingebunden werden, wie in jedem Beispiel
auf dieser Seite, und **nicht** im Image liegen: Ein Upgrade bedeutet, ein neueres Image
zu pullen und den Container mit denselben Mounts neu zu erstellen, und Ihre Konfiguration,
Ihre Zertifikate und Ihre Anmeldung bleiben erhalten.

Backups werden nach `/app/backups` geschrieben. Der obige Schnellstart bindet dieses
Verzeichnis nicht ein, sodass ein dort erstelltes Backup mit dem Container verschwindet,
wenn dieser entfernt wird: Laden Sie es vorher herunter, oder binden Sie `/app/backups`
ebenfalls ein, wie es das folgende Beispiel tut.

```bash
# Empfohlen: zuerst ein Backup erstellen (Einstellungen → Backup, oder über die API)

# Docker Compose
docker compose pull          # das neue Image holen
docker compose up -d         # den Container neu erstellen (data/ + certificates/ bleiben erhalten)

# Einfaches docker run: stoppen/entfernen und mit DENSELBEN Mounts neu starten, mit
# denen Sie gestartet haben. Das sind die benannten Volumes des Schnellstarts, plus eines
# für Backups; verwenden Sie stattdessen Ihre Host-Pfade, wenn Sie mit Bind-Mounts gestartet haben.
docker pull fabriziosalmi/certmate:latest
docker rm -f certmate
docker run -d --name certmate --env-file .env -p 127.0.0.1:8000:8000 \
  -v certmate_data:/app/data -v certmate_certificates:/app/certificates \
  -v certmate_backups:/app/backups \
  fabriziosalmi/certmate:latest
```

Migrationen des Einstellungsformats laufen beim Booten automatisch. Pinnen Sie in der Produktion ein
Versions-Tag (z. B. `fabriziosalmi/certmate:2.19`) statt `:latest`, damit erneute Pulls
Sie nicht mit einem ungewollten Upgrade überraschen — der Multi-Plattform-Build
veröffentlicht die Tags `MAJOR`, `MAJOR.MINOR` und `MAJOR.MINOR.PATCH`.

---

## Multi-Plattform-Builds

CertMate unterstützt Multi-Plattform-Docker-Images für ARM- und AMD64-Architekturen.

### Unterstützte Architekturen

| Plattform | Beschreibung | Typische Anwendungsfälle |
|-----------|--------------|--------------------------|
| `linux/amd64` | Intel/AMD 64-Bit | Die meisten Cloud-Server, Desktops |
| `linux/arm64` | ARM 64-Bit | Apple Silicon, ARM-Cloud-Instanzen |
| `linux/arm/v7` | ARM 32-Bit v7 | Raspberry Pi 3+ — **nicht veröffentlicht**: auf Anfrage baubar (siehe unten), die Release-Images sind amd64 + arm64 |

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

# Nur für die aktuelle Plattform bauen
docker build -t certmate:latest .

# Eine Version taggen und pushen
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:v1.0.0 -t USERNAME/certmate:latest --push .

# Raspberry Pi 3+ (linux/arm/v7, nicht veröffentlicht)
docker buildx build --platform linux/arm/v7 -t USERNAME/certmate:armv7 --push .
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
