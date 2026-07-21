# Guida all'installazione

Questa guida illustra tutti i metodi di installazione e deploy di CertMate.

---

## Prerequisiti

- Python 3.9 o superiore
- pip (gestore di pacchetti Python)
- Docker (opzionale, per il deploy containerizzato)

---

## Metodo 1: Installazione diretta

### 1. Clonare il repository

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
```

### 2. Creare l'ambiente virtuale

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# oppure
.\venv\Scripts\activate   # Windows
```

### 3. Installare le dipendenze

```bash
pip install -r requirements.txt
```

### 4. Configurare l'ambiente

Creare un file `.env`:

```bash
cp .env.example .env
# Modificare .env con le proprie impostazioni
```

### 5. Avviare l'applicazione

```bash
python app.py
```

---

## Metodo 2: Installazione Docker

### Con Docker Compose (consigliato)

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker-compose up -d
```

### Con Docker Build

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker build -t certmate .
docker run -p 8000:8000 --env-file .env -v ./certificates:/app/certificates certmate
```

> Per il deploy Docker avanzato con build multi-piattaforma, consultare la [Guida Docker](./docker.md).

---

## Dipendenze di sistema

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

## Configurazione del provider DNS

Dopo l'installazione, configurare le credenziali del proprio provider DNS. Consultare la [Guida ai provider DNS](./dns-providers.md) per le istruzioni dettagliate.

Configurazione rapida per i provider più comuni:

### Cloudflare

1. Accedere alla [Dashboard Cloudflare](https://dash.cloudflare.com/profile/api-tokens)
2. Creare un nuovo token API con i permessi `Zone:DNS:Edit`
3. Aggiungere il token nelle impostazioni di CertMate

### AWS Route53

1. Creare un utente IAM con i permessi Route53
2. Generare le chiavi di accesso
3. Aggiungere le credenziali nelle impostazioni di CertMate

### Azure DNS

1. Creare un Service Principal
2. Assegnare il ruolo DNS Zone Contributor
3. Configurare i dettagli della sottoscrizione nelle impostazioni di CertMate

### Google Cloud DNS

1. Creare un Service Account con il ruolo DNS Administrator
2. Scaricare il file di chiave JSON
3. Importare nelle impostazioni di CertMate

---

## Variabili d'ambiente

```bash
# Autenticazione API (generata automaticamente se nessuna è impostata)
# Opzione A: valore diretto
API_BEARER_TOKEN=your_secure_token_here
# Opzione B: percorso a un file contenente il token (ha precedenza su API_BEARER_TOKEN)
API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token

# Chiave segreta di sessione Flask (generata automaticamente se nessuna è impostata)
# Opzione A: valore diretto
SECRET_KEY=your_flask_secret_key
# Opzione B: percorso a un file contenente la chiave (ha precedenza su SECRET_KEY)
SECRET_KEY_FILE=/run/secrets/secret_key

# Reverse proxy — impostare a 'true' quando CertMate è dietro Nginx,
# HAProxy, Traefik, Cloudflare, ecc. Senza questa impostazione, request.remote_addr
# risolve sull'IP del proxy per ogni richiesta, collassando il rate limiting
# per client in un unico bucket.
BEHIND_PROXY=true

# Cifratura dei backup a riposo (opzionale, consigliata).
# Quando impostata, i backup unificati vengono scritti come file .zip.enc
# cifrati (derivazione della chiave PBKDF2-SHA256 + Fernet/AES) invece di
# .zip in chiaro. I backup incorporano ogni chiave privata dei certificati;
# senza questa opzione un file di backup esfiltrato equivale a una
# compromissione totale delle chiavi.
CERTMATE_BACKUP_PASSPHRASE=scegliere-una-lunga-passphrase-casuale

# Provider DNS (scegliere uno o più)
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

### Ordine di risoluzione

| Variabile | Priorità |
|----------|----------|
| `API_BEARER_TOKEN_FILE` | La più alta — se impostata, `API_BEARER_TOKEN` non viene mai letta |
| `API_BEARER_TOKEN` | Usata solo quando `API_BEARER_TOKEN_FILE` è assente |
| *(generata)* | Fallback quando nessuna è impostata o il valore non supera la validazione |
| `SECRET_KEY_FILE` | La più alta — se impostata, `SECRET_KEY` non viene mai letta |
| `SECRET_KEY` | Usata solo quando `SECRET_KEY_FILE` è assente |
| *(generata + persistita)* | Scritta in `data/.secret_key` affinché le sessioni sopravvivano ai riavvii |

> **Suggerimento Docker Secrets**: Usare `API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token` e `SECRET_KEY_FILE=/run/secrets/secret_key` con Docker Swarm o i secret di Kubernetes per evitare di inserire valori sensibili nelle variabili d'ambiente.

---

## Deploy in produzione

### Dietro un reverse proxy

Se CertMate si trova dietro un reverse proxy (Nginx, HAProxy, Traefik, Cloudflare, Kubernetes Ingress) — che è il modo consigliato per eseguirlo con terminazione TLS — impostare `BEHIND_PROXY=true` nell'ambiente del container. Questo attiva il middleware `ProxyFix` di Werkzeug in modo che i seguenti elementi si fidino degli header `X-Forwarded-*` del proxy:

- `request.remote_addr` risolve sull'IP del client originale invece che su quello del proxy. Il rate limiting, le voci del log di audit e gli avvisi "tentativo con token API non valido da X" diventano per client invece che per proxy.
- Lo schema / host / prefisso del proxy vengono rispettati, mantenendo corretti gli URL generati e gli scope dei cookie.

```yaml
# Estratto docker-compose.yml
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    environment:
      BEHIND_PROXY: "true"
    volumes:
      - ./data:/app/data
```

**Quando NON abilitarla.** Se si espone CertMate direttamente sulla rete senza un proxy davanti, lasciare `BEHIND_PROXY` non impostato. Con questa opzione attiva, chiunque possa raggiungere il listener potrebbe falsificare `X-Forwarded-For` e aggirare i limiti di rate per client. Il proxy è il confine di fiducia.

Il proxy deve naturalmente inoltrare gli header. Esempio Nginx:

```nginx
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

#### Esempio: Zion (gateway TLS Rust + WAF)

[Zion](https://github.com/fabriziosalmi/zion) è un reverse proxy Rust ad alte prestazioni con WAF integrato — una scelta ottimale davanti a CertMate quando si desidera la terminazione TLS 1.3 e il filtraggio delle richieste all'edge. CertMate rimane in HTTP semplice sulla rete interna; Zion termina il TLS e inoltra.

`zion.toml`:

```toml
[server]
listen_http  = "0.0.0.0:8080"
listen_https = "0.0.0.0:8443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"
key_path  = "/etc/ssl/zion/tls.key"
min_version = "1.3"
alpn = ["h2", "http/1.1"]

[upstream.backend]
url = "http://certmate:8000"

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
    image: certmate:latest
    environment:
      BEHIND_PROXY: "true"
    expose:
      - "8000"
    volumes:
      - ./data:/app/data

  zion:
    image: zion:latest
    depends_on:
      - certmate
    environment:
      ZION_CONFIG: /etc/zion/zion.toml
    volumes:
      - ./zion.toml:/etc/zion/zion.toml:ro
      - ./certs:/etc/ssl/zion:ro
    ports:
      - "443:8443"
      - "80:8080"
```

Mantenere `BEHIND_PROXY=true` sul servizio CertMate: Zion aggiunge `X-Forwarded-For`, quindi il rate limiting per client, le voci di audit e gli avvisi di autenticazione fallita risolveranno sul vero IP del client anziché su quello di Zion.

### Usare Gunicorn

```bash
pip install gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 app:app
```

### Usare systemd

Creare `/etc/systemd/system/certmate.service`:

```ini
[Unit]
Description=CertMate SSL Certificate Manager
After=network.target

[Service]
Type=simple
User=certmate
WorkingDirectory=/opt/certmate
Environment=PATH=/opt/certmate/venv/bin
ExecStart=/opt/certmate/venv/bin/gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

### Backup e ripristino

```bash
# Creare un backup
curl -X POST http://localhost:8000/api/backups/create \
  -H "Authorization: Bearer IL_PROPRIO_TOKEN_API"

# Elencare i backup
curl http://localhost:8000/api/backups \
  -H "Authorization: Bearer IL_PROPRIO_TOKEN_API"

# Ripristinare un backup
curl -X POST http://localhost:8000/api/backups/restore \
  -H "Authorization: Bearer IL_PROPRIO_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{"name": "backup_20240101_120000.zip"}'
```

---

## Risoluzione dei problemi

### Conflitti di versioni dei plugin DNS

In caso di conflitti di versioni, utilizzare queste versioni specifiche:

```txt
certbot==4.1.1
certbot-dns-cloudflare==4.1.1
certbot-dns-route53==4.1.1
certbot-dns-azure==2.6.1
certbot-dns-google==4.1.1
certbot-dns-powerdns==0.2.1
```

### Comandi di verifica

```bash
# Verificare i plugin certbot
certbot plugins --text

# Verificare che il servizio sia in esecuzione
curl -X GET http://localhost:8000/api/health
```

### Errori comuni

| Errore | Soluzione |
|--------|-----------|
| `ModuleNotFoundError` | Eseguire `pip install -r requirements.txt` |
| `Port already in use` | Cambiare la porta nelle variabili d'ambiente |
| `certbot not found` | Installare certbot: `pip install certbot` |
| `Permission denied` | Verificare i permessi su `/app/data` e `/app/certificates` |
| `Token API non valido` | Verificare `API_BEARER_TOKEN` nel file `.env` |

### Modalità debug

```bash
export FLASK_DEBUG=1
python app.py
```

### Confinamento del traffico in uscita (hardening dell'egress)

CertMate stabilisce connessioni in uscita verso le autorità di certificazione ACME, le API dei provider DNS, lo storage a oggetti e i webhook di notifica via HTTP(S), nonché SMTP per le notifiche email. È possibile confinare e verificare il traffico **HTTP(S)** instradandolo attraverso un **forward proxy** e negando a CertMate qualsiasi altra route verso internet.

I client HTTP(S) di CertMate (`requests`, `certbot`, consegna webhook via `urllib`, `boto3`) rispettano le variabili d'ambiente standard `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, quindi non è necessaria alcuna modifica al codice. **SMTP è l'eccezione:** le notifiche email usano `smtplib`, che apre una connessione TCP diretta e **non** consulta le variabili del proxy HTTP. Su una rete egress chiusa, consentire direttamente l'`host:port` del proprio relay SMTP (regola firewall / NetworkPolicy), oppure usare un canale di notifica webhook al posto dell'email.

Esempio con [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager), un forward proxy self-hosted basato su Squid con WAF, DNS sinkhole e — dalla v3.9.0 — una **allowlist egress default-deny** nativa (solo le destinazioni esplicitamente approvate sono raggiungibili; tutto il resto viene rifiutato):

```yaml
services:
  certmate:
    image: certmate:latest
    environment:
      HTTP_PROXY:  "http://proxy:3128"
      HTTPS_PROXY: "http://proxy:3128"
      NO_PROXY:    "localhost,127.0.0.1"
    networks:
      - egress            # CertMate può raggiungere SOLO il proxy su questa rete
networks:
  egress:
    internal: true        # nessun gateway: CertMate non ha accesso diretto a internet
```

Collocare CertMate su una rete `internal` (senza gateway) condivisa con il proxy fa del proxy il suo **unico** percorso in uscita. Il traffico in uscita diventa un unico punto di controllo verificabile: consentire le destinazioni di cui CertMate ha effettivamente bisogno (la propria CA, provider DNS, storage a oggetti, endpoint di notifica) e rifiutare il resto.

**Kubernetes:** una `NetworkPolicy` egress default-deny che consente il traffico solo verso il Service del proxy, più le variabili d'ambiente `HTTP(S)_PROXY` sul Deployment.

**systemd:** `Environment=HTTPS_PROXY=...` nell'unità, più regole firewall dell'host che limitano l'egress al proxy.

### Posizione di archiviazione per la directory dei dati

CertMate usa le I/O su file bloccanti standard di Python per tutto ciò che si trova sotto `data/` (impostazioni, certificati, log di audit, store SQLite dello scheduler). Il disco locale è fortemente raccomandato.

Se si monta `data/` su un filesystem di rete (NFS, SMB), tenere presente che:

- Un server NFS bloccato può sospendere indefinitamente le letture di file Python senza timeout integrato. Il worker di rinnovo, il writer del log di audit e la sonda /health si bloccheranno tutti sullo stesso punto di mount.
- La modalità journal WAL di SQLite richiede semantiche di lock che NFS non fornisce sempre. CertMate registra un avviso se ha dovuto ricorrere a una modalità journal più debole; la correttezza è preservata, ma la concorrenza diminuisce.

Se NFS è inevitabile, montare con `soft,timeo=30,retrans=3` (o l'equivalente della propria distribuzione) affinché le I/O falliscano rapidamente invece di bloccarsi su un server fermo.

### Usare Gunicorn

```bash
gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 app:app
```

### Usare systemd

Creare `/etc/systemd/system/certmate.service`:

```ini
[Unit]
Description=CertMate SSL Certificate Manager
After=network.target

[Service]
Type=simple
User=certmate
WorkingDirectory=/opt/certmate
Environment=PATH=/opt/certmate/venv/bin
ExecStart=/opt/certmate/venv/bin/gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Abilitare e avviare:

```bash
sudo systemctl enable certmate
sudo systemctl start certmate
```

### Usare Docker in produzione

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

## Risoluzione dei problemi

### Installazione manuale delle dipendenze

Se l'installazione automatica non va a buon fine, installare i provider DNS singolarmente:

```bash
# Core certbot
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

> La maggior parte dei plugin DNS richiede Certbot 4.1.1. Il plugin Azure ha un versioning indipendente (2.6.1) e PowerDNS è un plugin più recente (0.2.1).

### Comandi di verifica

```bash
# Verificare i plugin certbot
certbot plugins --text

# Verificare che il servizio sia in esecuzione
curl -X GET http://localhost:8000/api/health
```

### Errori comuni

| Errore | Soluzione |
|--------|-----------|
| `ModuleNotFoundError` | Eseguire `pip install -r requirements.txt` |
| `Port already in use` | Cambiare la porta nelle variabili d'ambiente |
| `certbot not found` | Installare certbot: `pip install certbot` |
| `Permission denied` | Verificare i permessi su `/app/data` e `/app/certificates` |
| `Token API non valido` | Verificare `API_BEARER_TOKEN` nel file `.env` |

### Modalità debug

```bash
export FLASK_DEBUG=1
python app.py
```

---

## Supporto

In caso di problemi:

1. Controllare i log per gli errori specifici
2. Verificare le credenziali del proprio provider DNS
3. Consultare la [Guida ai provider DNS](./dns-providers.md) per la risoluzione dei problemi specifici per provider
4. Consultare la [Guida ai test](./testing.md) per eseguire la diagnostica

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Provider DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
