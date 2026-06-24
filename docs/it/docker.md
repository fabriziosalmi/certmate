# Build e distribuzione con Docker

Questa guida illustra come compilare, distribuire ed eseguire CertMate in Docker — incluso il supporto multi-piattaforma per ARM e AMD64.

---

## Avvio rapido

### Pull ed esecuzione

```bash
# Docker seleziona automaticamente l'architettura corretta
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_data:/app/data \
  -v certmate_certificates:/app/certificates \
  fabriziosalmi/certmate:latest
```

### Build ed esecuzione locale

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

## Sicurezza

Il processo di build garantisce che nessun segreto venga incluso nell'immagine:

- `.dockerignore` esclude tutti i file `.env` e i dati sensibili
- Le variabili d'ambiente vengono fornite **in fase di esecuzione**, non durante la build
- Vengono inclusi solo i file applicativi essenziali
- Le immagini possono essere pubblicate in sicurezza su registry pubblici

### Verificare l'assenza di segreti nell'immagine

```bash
docker history certmate:latest
docker inspect certmate:latest | grep -i env
docker run --rm certmate:latest find / -name "*.env" 2>/dev/null
```

---

## Configurazione in fase di esecuzione

### Opzione 1: File d'ambiente

Crea un file `.env` sull'host (non nell'immagine Docker):

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

### Opzione 2: Variabili d'ambiente dirette

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

### Riferimento alle variabili d'ambiente

| Variabile | Richiesta | Descrizione |
|-----------|-----------|-------------|
| `SECRET_KEY` | No | Chiave segreta Flask per le sessioni (generata automaticamente se non impostata) |
| `SECRET_KEY_FILE` | No | Percorso di un file contenente la chiave segreta Flask (ha precedenza su `SECRET_KEY`) |
| `API_BEARER_TOKEN` | No | Token di autenticazione per l'accesso all'API (generato automaticamente se non impostato) |
| `API_BEARER_TOKEN_FILE` | No | Percorso di un file contenente il token bearer API (ha precedenza su `API_BEARER_TOKEN`) |
| `LOG_LEVEL` | No | `INFO` (predefinito), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | No | Se impostata, i backup unificati vengono cifrati a riposo (`.zip.enc`, PBKDF2-SHA256 + Fernet). La stessa passphrase è richiesta per il ripristino. Non impostata = backup in chiaro `.zip` (comportamento precedente) |
| `CLOUDFLARE_API_TOKEN` | No | Token del provider DNS Cloudflare |
| `AWS_ACCESS_KEY_ID` | No | Chiave di accesso AWS Route53 |
| `AWS_SECRET_ACCESS_KEY` | No | Chiave segreta AWS Route53 |

Consulta la [Guida all'installazione](./installation.md#environment-variables) per l'elenco completo.

---

## Docker Compose

### Configurazione di base

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
# Avvia con il file .env nella stessa directory
docker-compose up -d

# Oppure specifica un file .env diverso
docker-compose --env-file /path/to/.env up -d
```

---

## Build multi-piattaforma

CertMate supporta immagini Docker multi-piattaforma per le architetture ARM e AMD64.

### Architetture supportate

| Piattaforma | Descrizione | Casi d'uso comuni |
|-------------|-------------|-------------------|
| `linux/amd64` | Intel/AMD 64-bit | La maggior parte dei server cloud, desktop |
| `linux/arm64` | ARM 64-bit | Apple Silicon, istanze cloud ARM |
| `linux/arm/v7` | ARM 32-bit v7 | Raspberry Pi 3+ |
| `linux/arm/v6` | ARM 32-bit v6 | Raspberry Pi 1, Zero |

### Script di build

```bash
# Build per la piattaforma corrente soltanto
./build-docker.sh

# Build per piattaforme multiple (ARM64 + AMD64)
./build-docker.sh -m

# Build e push su Docker Hub
./build-docker.sh -m -p -r YOUR_DOCKERHUB_USERNAME

# Script dedicato multi-piattaforma
./build-multiplatform.sh -r USERNAME -v v1.0.0 -p

# Build per Raspberry Pi
./build-multiplatform.sh --platforms linux/arm/v7 -r USERNAME -p
```

### Docker Buildx manuale

```bash
# Creare e utilizzare il builder buildx
docker buildx create --name certmate-builder --use

# Build per piattaforme multiple
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest .

# Build e push
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest --push .
```

### Prerequisiti per il multi-piattaforma

```bash
# Verificare il supporto buildx
docker buildx version
docker buildx inspect --bootstrap

# Abilitare l'emulazione QEMU (se necessario)
docker run --privileged --rm tonistiigi/binfmt --install all
```

### Forzare una piattaforma specifica

```bash
# Forzare AMD64 (es. su Apple Silicon per i test)
docker run --platform linux/amd64 --rm \
  --env-file .env -p 8000:8000 certmate:latest

# Rilevamento automatico (consigliato)
docker run --rm --env-file .env -p 8000:8000 certmate:latest
```

---

## Push su Docker Hub

```bash
# Accesso
docker login

# Tag e push
docker build -t USERNAME/certmate:latest .
docker push USERNAME/certmate:latest

# Con tag di versione
docker build -t USERNAME/certmate:v1.0.0 .
docker push USERNAME/certmate:v1.0.0
```

---

## Integrazione CI/CD

### GitHub Actions

Secret richiesti:
- `DOCKERHUB_USERNAME`
- `DOCKERHUB_TOKEN`

```bash
# Avvio manuale con piattaforme personalizzate
gh workflow run docker-multiplatform.yml \
  -f platforms="linux/amd64,linux/arm64,linux/arm/v7" \
  -f push_to_registry=true
```

---

## Consigli per la produzione

1. **Usa la gestione dei segreti**: Docker secrets, Kubernetes secrets o un gestore di segreti
2. **Abilita TLS**: Esegui dietro un reverse proxy con terminazione TLS
3. **Monitora le risorse**: Imposta limiti di CPU e memoria
4. **Esegui il backup dei volumi**: Esegui regolarmente il backup dei volumi dei certificati e dei dati
5. **Aggiorna regolarmente**: Mantieni l'immagine aggiornata con le patch di sicurezza
6. **Usa la cache dei layer** per build più veloci:
   ```bash
   docker buildx build --cache-from type=registry,ref=USERNAME/certmate:cache .
   ```

---

## Risoluzione dei problemi

### Il container non si avvia

```bash
docker logs certmate
docker exec certmate env
```

### L'health check fallisce

```bash
docker logs certmate
docker exec certmate curl -v http://localhost:8000/health
```

### Problemi di permessi

```bash
docker exec certmate ls -la /app/certificates
docker exec certmate ls -la /app/data
```

### Problemi di build multi-piattaforma

| Errore | Soluzione |
|--------|-----------|
| "multiple platforms not supported for docker driver" | `docker buildx create --name multiplatform --use` |
| "exec format error" | `docker run --privileged --rm tonistiigi/binfmt --install all` |
| Build non native lente | Normale a causa dell'emulazione; usa GitHub Actions per la produzione |
| Impossibile caricare il multi-piattaforma in Docker locale | Usa `--load` con una singola piattaforma per i test locali |

---

## Dimensioni delle immagini

Dimensioni tipiche per architettura:
- **AMD64**: ~200-300 MB
- **ARM64**: ~200-300 MB
- **ARM v7**: ~180-250 MB

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Installazione →](./installation.md) • [Architettura →](./architecture.md)

</div>
