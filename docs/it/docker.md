# Build e distribuzione con Docker

<!-- CERTMATE-TRANSLATED-FROM b3c7a928998dc93e -->

Questa guida illustra come compilare, distribuire ed eseguire CertMate in Docker — incluso il supporto multi-piattaforma per ARM e AMD64.

---

## In produzione con Docker Compose

Il modo più breve per eseguire CertMate in produzione: un solo file, l'immagine pubblicata, niente da compilare e nessun repository da clonare.

```bash
mkdir certmate && cd certmate
curl -fsSLO https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/docker-compose.yml
printf 'API_BEARER_TOKEN=%s\nSECRET_KEY=%s\nCERTMATE_BACKUP_PASSPHRASE=%s\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
```

Apri `http://127.0.0.1:8000`. La prima pagina crea l'account amministratore e chiede l'`API_BEARER_TOKEN` del file `.env` per autorizzarlo. Conserva `.env`: contiene il token usato dai client API, la chiave che firma le sessioni e la passphrase senza la quale un backup non può ripristinare questa istanza.

Cosa fa il file:

- **Fissa l'immagine** dell'ultima release. La copia su `main` viene aggiornata a ogni release. Per restare su una versione, imposta `CERTMATE_VERSION=X.Y.Z` in `.env`.
- **Tiene tutto in volumi con nome** (`certificates`, `data`, `logs`, `backups`). Docker li crea con la proprietà di cui CertMate ha bisogno, quindi non serve alcun `chown`. `docker compose down` li conserva; `down -v` li cancella.
- **Ascolta solo su 127.0.0.1.** Per l'accesso remoto metti davanti un reverse proxy e imposta `BEHIND_PROXY=true`. Con `CERTMATE_BIND=0.0.0.0` lo pubblichi su tutte le interfacce. `CERTMATE_PORT` cambia la porta sull'host.
- **Si rifiuta di partire senza `API_BEARER_TOKEN` e `SECRET_KEY`**, invece di generare valori che cambierebbero a ogni ricreazione del container.

Variabili facoltative per `.env`: `CLOUDFLARE_TOKEN` (crea un account DNS Cloudflare al primo avvio), `LETSENCRYPT_EMAIL`, `BEHIND_PROXY`.

**Aggiornamento:** scarica di nuovo il file (oppure cambia `CERTMATE_VERSION`), poi esegui `docker compose pull && docker compose up -d`.

Il `docker-compose.yml` nella radice del repository compila l'immagine dai sorgenti ed è pensato per lo sviluppo.

---

## Portainer

In Portainer, distribuisci il [bundle compose di produzione](#in-produzione-con-docker-compose) come stack direttamente da questo repository:

1. **Stacks → Add stack**, chiamalo `certmate` e scegli **Repository**.
2. URL del repository `https://github.com/fabriziosalmi/certmate`, riferimento `refs/heads/main`, percorso compose `deploy/docker-compose.yml`.
3. In **Environment variables** aggiungi `API_BEARER_TOKEN`, `SECRET_KEY` e `CERTMATE_BACKUP_PASSPHRASE`, ciascuno con un valore casuale lungo, come l'output di `openssl rand -hex 32`. Facoltativi: `CERTMATE_PORT`, `CERTMATE_BIND` o `CLOUDFLARE_TOKEN`.
4. **Deploy the stack.**

Senza le due variabili obbligatorie il deploy fallisce e dice quale manca (`required variable API_BEARER_TOKEN is missing a value`), invece di partire con chiavi che cambierebbero a ogni redeploy. Per aggiornare usa **Pull and redeploy** sullo stack: i volumi con nome, e con loro certificati e impostazioni, restano.

Verificato su Portainer CE 2.45: uno stack senza le variabili viene rifiutato con quel messaggio; con le variabili parte sano, il token autorizza l'API, e un pull and redeploy ricrea il container mantenendo i dati.

---

## Avvio rapido

### Pull ed esecuzione

Le immagini sono pubblicate su Docker Hub come `fabriziosalmi/certmate`. Le release successive alla v2.42.0 sono pubblicate anche su GHCR, con gli stessi tag, come `ghcr.io/fabriziosalmi/certmate`, che evita i limiti di download anonimo di Docker Hub: nei comandi qui sotto puoi usare l'uno o l'altro nome.

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
# Imposta API_BEARER_TOKEN prima di esporre in rete un'istanza non ancora
# configurata: finché non esiste il primo admin, un'istanza senza token offre
# il bypass della configurazione iniziale a chiunque possa raggiungerla. Quando
# è impostato, incollalo una volta nella schermata di primo avvio per creare l'admin.
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

### Opzione 2: Variabili d'ambiente dirette

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

### Riferimento alle variabili d'ambiente

| Variabile | Richiesta | Descrizione |
|-----------|-----------|-------------|
| `SECRET_KEY` | No | Chiave segreta Flask per le sessioni (generata automaticamente se non impostata) |
| `SECRET_KEY_FILE` | No | Percorso di un file contenente la chiave segreta Flask (ha precedenza su `SECRET_KEY`). Se è impostata e il file non si può leggere o è vuoto, CertMate si rifiuta di partire: un segreto che non è stato montato è un errore di configurazione, e generare al suo posto una chiave disconnetterebbe ogni utente, a ogni riavvio, con sessioni firmate da una chiave che non hai scelto tu. |
| `API_BEARER_TOKEN` | No (auto-generato) | Token di autenticazione API. Generato automaticamente se non impostato, ma impostalo prima di esporre in rete un'istanza non ancora configurata; quando impostato, incollalo una volta nella schermata di primo avvio per creare l'admin. **Questo valore fa fede:** se è diverso dal token già memorizzato, quello memorizzato viene sostituito all'avvio e smette di funzionare. È questo che rende effettiva l'aggiunta o la rotazione della variabile su un'installazione esistente — in precedenza il controllo d'accesso usava questo valore mentre l'autenticazione verificava ancora quello vecchio, e la schermata di primo avvio chiedeva un token che poi rifiutava |
| `API_BEARER_TOKEN_FILE` | No | Percorso di un file contenente il token bearer API (ha precedenza su `API_BEARER_TOKEN`) |
| `CERTMATE_LOG_LEVEL` | No | `INFO` (predefinito), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | **Impostala se vuoi backup automatici da cui poter ripristinare** | Cifra a riposo i backup unificati (`.zip.enc`, PBKDF2-SHA256 + Fernet), ed è ciò che rende *completi* i backup automatici — con essa possono ripristinare questa istanza, senza di essa mantengono le credenziali mascherate e non possono farlo. La stessa passphrase è richiesta per ripristinarli, e CertMate non la memorizza mai al posto tuo. Conservala in un luogo diverso dalla macchina che contiene i backup |
| `CLOUDFLARE_TOKEN` | No | Token API dell'account DNS Cloudflare predefinito. Route53 usa normalmente le credenziali configurate in Impostazioni → Provider DNS, ma quando il suo account seleziona esplicitamente `auth_mode: iam_role`, Certbot usa la catena di credenziali AWS del container (inclusi i ruoli IAM). |

Consulta la [Guida all'installazione](./installation.md#variabili-dambiente) per l'elenco completo.

### Tenere i token DNS fuori da `settings.json`

I token dei provider DNS configurati dall'interfaccia finiscono in
`settings.json`, che è il file che viene copiato, montato e incluso nei backup.
Ogni campo credenziale può invece **indicare** dove sta il valore —
`api_token_file` con un percorso, oppure `api_token_env` con il nome di una
variabile — come già fa `API_BEARER_TOKEN_FILE`. Il valore viene letto quando
certbot viene eseguito e non viene mai riscritto. Lo stesso vale per il
`client_secret` OIDC. Vedi
[SECURITY.md](https://github.com/fabriziosalmi/certmate/blob/main/SECURITY.md#keeping-credentials-out-of-settingsjson).

---

## Docker Compose

### Configurazione di base

```yaml
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    container_name: certmate
    ports:
      - "127.0.0.1:8000:8000"  # solo localhost; per l'accesso esterno mettere davanti un reverse proxy
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
# Avvia con il file .env nella stessa directory
docker compose up -d

# Oppure specifica un file .env diverso
docker compose --env-file /path/to/.env up -d
```

---

## Podman (Quadlet, rootless) e OpenShift

### Quadlet: CertMate come servizio systemd

[`deploy/podman/certmate.container`](../../deploy/podman/certmate.container) è una unit Quadlet: Podman la trasforma in un servizio systemd. Esegue l'immagine pubblicata con volumi con nome, la porta solo su loopback, i segreti come Podman secret, un healthcheck e il supporto a `podman auto-update`.

Rootless, con il tuo utente:

```bash
# I tre segreti, creati una volta sola. Non compaiono mai in un file.
for s in certmate-api-token certmate-secret-key certmate-backup-passphrase; do
  openssl rand -hex 32 | tr -d '\n' | podman secret create "$s" -
done

mkdir -p ~/.config/containers/systemd
curl -fsSL -o ~/.config/containers/systemd/certmate.container \
  https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/podman/certmate.container
systemctl --user daemon-reload
systemctl --user start certmate

# Lo tiene attivo senza una sessione di login e lo avvia al boot.
sudo loginctl enable-linger "$USER"
```

Rootful, invece: metti il file in `/etc/containers/systemd/`, crea i segreti come root, poi esegui `sudo systemctl daemon-reload && sudo systemctl start certmate`.

Apri `http://127.0.0.1:8000`. La prima pagina crea l'account amministratore e chiede il token API: `podman secret inspect --showsecret certmate-api-token --format '{{.SecretData}}'`.

Verificato su Fedora 44 con Podman 5.8, rootful e rootless: il servizio parte sano, il token autorizza l'API e il servizio riparte dopo un riavvio (rootless tramite lingering).

### UID arbitrari (Podman rootless, OpenShift)

Per impostazione predefinita l'immagine gira come utente non root `1000`, ma segue
anche lo schema **UID arbitrario** di OpenShift: le directory scrivibili a runtime
(`/app/data`, `/app/certificates`, `/app/logs`, `/app/backups`) appartengono al
**gruppo 0 (gruppo root)** e sono scrivibili dal gruppo + setgid. Un processo del
container che gira con *qualsiasi* UID appartenente al gruppo 0 — che è il modo in
cui podman rootless e OpenShift avviano i container — può quindi creare e
rinominare file senza un `chown -R 1000:1000` manuale dei volumi. I file segreti
che l'applicazione scrive (la chiave privata della CA, la chiave di firma
dell'audit, i file delle credenziali DNS, `.secret_key`) vengono sempre creati
`0600`, accessibili solo al proprietario, quindi le directory scrivibili dal
gruppo non espongono mai una chiave. (Issue [#380](https://github.com/fabriziosalmi/certmate/issues/380).)

### Volumi con nome

Un **volume con nome** appena creato eredita i permessi del gruppo 0 dell'immagine
con Podman rootful e con Docker. Con Podman **rootless** non sempre: misurato su
Podman 5.8, la radice del volume `backups`, la cui directory nell'immagine non è
vuota, è rimasta di proprietà di root, e CertMate si è rifiutato di partire con
*"Required directories are not writable"*. Aggiungi `:U`, che assegna ogni volume
all'utente del container:

```bash
podman run -d --name certmate \
  -p 127.0.0.1:8000:8000 \
  -v certmate_data:/app/data:U \
  -v certmate_certificates:/app/certificates:U \
  -v certmate_logs:/app/logs:U \
  -v certmate_backups:/app/backups:U \
  docker.io/fabriziosalmi/certmate:latest
```

### Bind mount (directory dell'host)

Un bind mount mantiene la proprietà della directory dell'**host**, che prevale sui
permessi dell'immagine. Rendi una volta per tutte le directory dell'host
scrivibili dal gruppo 0, poi esegui:

```bash
# Crea le directory dell'host scrivibili dal gruppo 0 (qualsiasi UID del gruppo 0 può scrivere)
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

In alternativa lascia che sia podman a sistemare la proprietà con l'opzione di
mount `:U` (esegue un chown ricorsivo della sorgente perché corrisponda a UID/GID del container):

```bash
podman run -d --name certmate \
  -p 8000:8000 \
  -v ./data:/app/data:U \
  -v ./certificates:/app/certificates:U \
  -v ./logs:/app/logs:U \
  -v ./backups:/app/backups:U \
  docker.io/fabriziosalmi/certmate:latest
```

### podman-compose rootless

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

Se l'avvio si interrompe con *"Required directories are not writable by the CertMate
process"*, il mount non è scrivibile dall'utente del container — aggiungi `:U` al
volume oppure, per un bind mount, applica il `chgrp 0 … && chmod g+rwX …` visto sopra.

> **Kubernetes / OpenShift:** non serve alcuna modifica. Imposta
> `spec.securityContext.fsGroup: 0` (oppure affidati alla SCC restricted predefinita,
> che assegna già un UID arbitrario nel gruppo 0) e i volumi montati
> diventano automaticamente scrivibili dal gruppo 0.

---

## Aggiornamento

CertMate conserva il suo stato persistente in `/app/data` (`settings.json`, gli utenti
admin, la `.secret_key` generata automaticamente, la chiave di firma dell'audit e il
database dello scheduler) e in `/app/certificates`. Quello stato sopravvive a un
aggiornamento perché quei percorsi sono montati dall'esterno del container, come in
ogni esempio di questa pagina, e **non** conservati nell'immagine: aggiornare significa
scaricare un'immagine più recente e ricreare il container con gli stessi mount, e
configurazione, certificati e login vengono mantenuti.

I backup vengono scritti in `/app/backups`. L'Avvio rapido qui sopra non lo monta,
quindi un backup creato lì se ne va con il container quando questo viene rimosso:
scaricalo prima, oppure monta anche `/app/backups`, come fa l'esempio qui sotto.

```bash
# Consigliato: esegui prima un backup (Impostazioni → Backup, oppure l'API)

# Docker Compose
docker compose pull          # scarica la nuova immagine
docker compose up -d         # ricrea il container (data/ + certificates/ restano)

# docker run semplice: ferma/rimuovi e riesegui con gli STESSI mount con cui
# l'avevi avviato. Questi sono i volumi con nome dell'Avvio rapido, più uno per
# i backup; se eri partito con dei bind mount, usa invece i tuoi percorsi host.
docker pull fabriziosalmi/certmate:latest
docker rm -f certmate
docker run -d --name certmate --env-file .env -p 127.0.0.1:8000:8000 \
  -v certmate_data:/app/data -v certmate_certificates:/app/certificates \
  -v certmate_backups:/app/backups \
  fabriziosalmi/certmate:latest
```

Le migrazioni del formato delle impostazioni vengono eseguite automaticamente all'avvio.
In produzione, fissa un tag di versione (es. `fabriziosalmi/certmate:2.19`) invece di
`:latest`, così che un nuovo pull non ti sorprenda con un aggiornamento non voluto —
la build multi-piattaforma pubblica i tag `MAJOR`, `MAJOR.MINOR` e `MAJOR.MINOR.PATCH`.

---

## Build multi-piattaforma

CertMate supporta immagini Docker multi-piattaforma per le architetture ARM e AMD64.

### Architetture supportate

| Piattaforma | Descrizione | Casi d'uso comuni |
|-------------|-------------|-------------------|
| `linux/amd64` | Intel/AMD 64-bit | La maggior parte dei server cloud, desktop |
| `linux/arm64` | ARM 64-bit | Apple Silicon, istanze cloud ARM |
| `linux/arm/v7` | ARM 32-bit v7 | Raspberry Pi 3+ — **non pubblicata**: compilabile su richiesta (vedi sotto), le immagini di release sono amd64 + arm64 |

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

# Build per la piattaforma corrente soltanto
docker build -t certmate:latest .

# Taggare una versione e pubblicarla
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:v1.0.0 -t USERNAME/certmate:latest --push .

# Raspberry Pi 3+ (linux/arm/v7, non pubblicata)
docker buildx build --platform linux/arm/v7 -t USERNAME/certmate:armv7 --push .
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
- `DOCKERHUB_USER`
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
