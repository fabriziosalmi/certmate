# Guida all'installazione

<!-- CERTMATE-TRANSLATED-FROM 5c5bff50936e6742 -->

Questa guida illustra tutti i metodi di installazione e deploy di CertMate.

---

## Server Linux con systemd

Il metodo consigliato su un host Linux senza Docker. Verificato su Debian 12, Ubuntu 24.04 e Rocky Linux 9; usa `apt` o `dnf`, quindi Fedora, RHEL e Alma Linux seguono la stessa strada.

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/install.sh | sudo sh
```

Cosa fa:

- installa `curl`, `tar`, `gzip` e `openssl` solo se mancano;
- scarica l'ultima release in `/opt/certmate`, di proprietà di root e in sola lettura per il servizio;
- scarica con [uv](https://docs.astral.sh/uv/) un Python 3.12 autonomo in `/opt/certmate` e installa `requirements.lock`, lo stesso insieme fissato da cui è costruita l'immagine container. Il Python di sistema non viene usato, ed è per questo che funzionano anche distribuzioni con un Python più vecchio, come Debian 12 e RHEL 9;
- crea l'utente di sistema `certmate`, proprietario solo di `certificates`, `data`, `backups`, `logs` e `letsencrypt`;
- scrive `/etc/certmate/certmate.env` con `API_BEARER_TOKEN`, `SECRET_KEY` e `CERTMATE_BACKUP_PASSPHRASE` generati, solo se il file non esiste;
- installa e avvia il servizio systemd `certmate`, in ascolto su `127.0.0.1:8000`.

Apri `http://127.0.0.1:8000`. La prima pagina crea l'account amministratore e chiede il token: `sudo grep API_BEARER_TOKEN /etc/certmate/certmate.env`.

- **Una versione specifica:** `curl -fsSL …/install.sh | sudo sh -s -- --version X.Y.Z`. Le release fino alla v2.42.0 sono precedenti all'installer e vengono rifiutate.
- **Aggiornamento:** esegui di nuovo lo stesso comando. Codice e virtualenv vengono sostituiti; certificati, dati, backup e `certmate.env` restano.
- **Ascoltare altrove:** imposta `CERTMATE_BIND` in `/etc/certmate/certmate.env` (per esempio `0.0.0.0:8000`, oppure lascia il loopback dietro un reverse proxy e imposta `BEHIND_PROXY=true`), poi `sudo systemctl restart certmate`.
- **Log:** `journalctl -u certmate`.
- **SELinux:** l'installer non è ancora stato verificato con SELinux in modalità enforcing. Se su un host del genere il servizio non parte, il journal dice perché; segnalacelo.

### Configurarlo a mano

[`deploy/install.sh`](../../deploy/install.sh) è un breve script POSIX, e l'elenco qui sopra è tutto ciò che fa: è quindi il riferimento per una configurazione manuale. Ciò che una configurazione manuale deve rispettare:

- l'unità è [`certmate.service`](../../certmate.service) di questo repository, installata come `/etc/systemd/system/certmate.service`. I suoi commenti spiegano ogni riga: `PATH` mantiene le directory di sistema perché gli hook di deploy possano girare, un solo worker perché le sessioni e il limitatore dei login vivono in un solo processo, `GUNICORN_TIMEOUT=300` perché DNS-01 aspetta la propagazione;
- esegue gunicorn da `/opt/certmate/venv` come utente `certmate`, isolato con `ProtectSystem=strict`. Gli unici percorsi scrivibili sono `certificates`, `data`, `backups`, `logs` e `letsencrypt` sotto `/opt/certmate`, e devono esistere tutti e cinque prima che il servizio parta;
- legge `/etc/certmate/certmate.env`, dove l'installer scrive `API_BEARER_TOKEN`, `SECRET_KEY` e `CERTMATE_BACKUP_PASSPHRASE`, di proprietà `root:certmate` con modo `0640`. Un token più corto di 32 caratteri, o un segnaposto, viene rifiutato all'avvio. Senza `CERTMATE_BACKUP_PASSPHRASE`, i backup automatici non possono ripristinare l'istanza;
- dopo aver modificato `certmate.env`, usa `systemctl restart`: `reload` manda solo un segnale a gunicorn e non rilegge il file.

---

## Una VM cloud con cloud-init

Per una VM nuova su qualsiasi provider che accetta user data (Hetzner, DigitalOcean, AWS, Azure, GCP, OpenStack, Proxmox): incolla [`deploy/cloud-init/certmate.yaml`](../../deploy/cloud-init/certmate.yaml) nel campo "user data" o "cloud-init" della VM quando la crei ([file grezzo](https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/cloud-init/certmate.yaml)). Installa Docker, scarica il [bundle compose di produzione](docker.md#in-produzione-con-docker-compose), genera i segreti sulla VM in `/srv/certmate/.env` (permessi 600, mai nello user data) e avvia CertMate.

CertMate ascolta su `127.0.0.1:8000` dentro la VM. Raggiungilo con un tunnel SSH, `ssh -L 8000:127.0.0.1:8000 <user>@<vm>`, poi apri `http://127.0.0.1:8000`. La prima pagina crea l'account amministratore e chiede il token: `sudo grep API_BEARER_TOKEN /srv/certmate/.env`.

Verificato sull'immagine cloud di Ubuntu 24.04: cloud-init termina con `done`, CertMate è in salute pochi minuti dopo l'avvio e riparte dopo un riavvio.

---

## Prerequisiti

- Python 3.12
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
source venv/bin/activate  # Su Windows: venv\Scripts\activate
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

Scarica il bundle di produzione e avvialo: un solo file, l'immagine pubblicata, niente clone e niente compilazione. I comandi e il significato di ogni impostazione sono in [Docker: In produzione con Docker Compose](docker.md#in-produzione-con-docker-compose).

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

Dopo l'installazione, configurare le credenziali del proprio provider DNS. Consultare la [Guida ai provider DNS](./dns-providers.md) per le istruzioni di configurazione dettagliate di ogni provider supportato.

Configurazione rapida per i provider più comuni:

### Cloudflare

1. Accedere alla [Dashboard Cloudflare](https://dash.cloudflare.com/profile/api-tokens)
2. Creare un nuovo token API con i permessi `Zone:DNS:Edit`
3. Aggiungere il token nelle impostazioni di CertMate

### AWS Route53

1. Concedere i permessi DNS Route53 a un ruolo IAM associato all'host/pod, oppure a un utente IAM.
2. Nelle impostazioni di CertMate → Provider DNS, selezionare **AWS credentials / IAM role** per usare la catena di credenziali AWS, oppure inserire le chiavi di accesso dell'utente.
3. Facoltativamente, impostare **Assume role ARN** se l'identità di origine può assumere un altro ruolo Route53. Vedere [Provider DNS](./dns-providers.md#aws-route53).

### Azure DNS

1. Creare un Service Principal
2. Assegnare il ruolo DNS Zone Contributor
3. Configurare i dettagli della sottoscrizione nelle impostazioni di CertMate

### Google Cloud DNS

1. Creare un Service Account con il ruolo DNS Administrator
2. Scaricare il file di chiave JSON
3. Importarlo nelle impostazioni di CertMate

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
# per client in un unico bucket. Vedere la sezione "Dietro un reverse
# proxy" in Deploy in produzione per i dettagli.
BEHIND_PROXY=true

# Cifratura dei backup a riposo (opzionale, consigliata).
# Quando impostata, i backup unificati vengono scritti come file .zip.enc
# cifrati (derivazione della chiave PBKDF2-SHA256 + Fernet/AES) invece di .zip in chiaro.
# Un backup di disaster recovery (include_secrets=true) incorpora ogni
# chiave privata dei certificati e ogni credenziale, quindi senza questa opzione
# una copia esfiltrata equivale a una compromissione totale; il backup predefinito,
# sicuro da condividere, non contiene né le une né le altre. La stessa passphrase
# deve essere presente per il ripristino. Volutamente solo da ambiente: una passphrase
# salvata in settings.json finirebbe essa stessa dentro i backup in chiaro.
CERTMATE_BACKUP_PASSPHRASE=choose-a-long-random-passphrase

# Provider DNS. Cloudflare è l'unico provider letto dall'ambiente:
# questo token imposta l'account Cloudflare predefinito. Route53, Azure,
# Google Cloud DNS, PowerDNS e gli altri si configurano in Impostazioni -> Provider DNS
# o tramite l'API; AWS_*, AZURE_* e variabili simili qui non hanno alcun effetto.
CLOUDFLARE_TOKEN=your_cloudflare_token
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

Se CertMate si trova dietro un reverse proxy (Nginx, HAProxy, Traefik,
Cloudflare, Kubernetes Ingress) — che è il modo consigliato per eseguirlo
con terminazione TLS — impostare `BEHIND_PROXY=true` nell'ambiente del
container. Questo attiva il middleware `ProxyFix` di Werkzeug in modo che i
seguenti elementi si fidino degli header `X-Forwarded-*` del proxy:

- `request.remote_addr` risolve sull'IP del client originale invece che su
  quello del proxy. Il rate limiting, le voci del log di audit e gli avvisi
  "tentativo con token API non valido da X" diventano per client invece che
  per proxy.
- Gli header di schema / host / prefisso del proxy vengono rispettati, il che
  mantiene corretti gli URL generati e gli scope dei cookie.

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

**Quando NON abilitarla.** Se si espone CertMate direttamente sulla
rete senza un proxy davanti, lasciare `BEHIND_PROXY` non impostato. Con questa
opzione attiva, chiunque possa raggiungere il listener potrebbe falsificare
`X-Forwarded-For` e aggirare i limiti di rate per client. Il proxy è il confine di fiducia.

Il proxy deve naturalmente inoltrare gli header. Esempio Nginx:

```nginx
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

#### Il profilo nginx incluso

`docker-compose.yml` include un servizio `nginx` opzionale (`--profile nginx`)
che termina il TLS davanti a CertMate. La sua configurazione **non** è
tracciata come `nginx.conf` — quel file appartiene all'utente ed è ignorato da git — ma come
`nginx.conf.example`, lo stesso schema di `.env.example` / `.env`:

```bash
cp nginx.conf.example nginx.conf
# modificare nginx.conf: sostituire ogni <your-domain> in ssl_certificate / ssl_certificate_key
docker compose --profile nginx up -d
```

Copiare **prima** di `up`: se `nginx.conf` non esiste sull'host quando viene
creato il bind mount, Docker lo crea come *directory* vuota e nginx non
riesce ad avviarsi. Aggiornando da una release in cui `nginx.conf` era tracciato:
la copia modificata resta al suo posto (ora git la ignora); dopo un pull,
confrontarla con il nuovo `nginx.conf.example` per recepire le modifiche upstream.

#### Esempio: Zion (gateway TLS Rust + WAF)

[Zion](https://github.com/fabriziosalmi/zion) è un reverse proxy TLS in Rust ad alte
prestazioni con WAF integrato — una buona scelta davanti a CertMate quando si
desidera la terminazione TLS 1.3 e il filtraggio delle richieste all'edge. CertMate
rimane in HTTP semplice sulla rete interna; Zion termina il TLS e inoltra.

`zion.toml`:

```toml
[server]
listen_http  = "0.0.0.0:8080"
listen_https = "0.0.0.0:8443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"   # il proprio certificato, oppure l'ACME di Zion (--features acme)
key_path  = "/etc/ssl/zion/tls.key"
min_version = "1.3"
alpn = ["h2", "http/1.1"]

[upstream.backend]
url = "http://certmate:8000"

# Catch-all verso il backend. La route "/" esplicita è innocua e documenta
# l'intento; le versioni recenti di Zion registrano anche "/" in automatico per un catch-all alla radice.
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
    image: certmate:latest          # l'immagine pubblicata, o la propria build locale
    environment:
      BEHIND_PROXY: "true"          # fidarsi degli header X-Forwarded-* di Zion
    expose:
      - "8000"                       # solo interna; non pubblicata sull'host
    volumes:
      - ./data:/app/data

  zion:
    image: zion:latest              # l'immagine pubblicata, o la propria build locale
    depends_on:
      - certmate
    environment:
      ZION_CONFIG: /etc/zion/zion.toml
    volumes:
      - ./zion.toml:/etc/zion/zion.toml:ro
      - ./certs:/etc/ssl/zion:ro
    ports:
      - "443:8443"                   # host 443 -> listener HTTPS di Zion
      - "80:8080"                    # host 80  -> listener HTTP di Zion
```

Mantenere `BEHIND_PROXY=true` sul servizio CertMate: Zion aggiunge
`X-Forwarded-For`, quindi il rate limiting per client, le voci di audit e gli
avvisi di autenticazione fallita risolvono sul vero IP del client anziché su quello di Zion.

> **`/metrics` è servito da Zion, non inoltrato.** Zion espone il proprio endpoint
> Prometheus su `/metrics` (serie `zion_*` per il proxy), che nasconde il `/metrics`
> di CertMate. Raccoglierli separatamente: il `/metrics` di Zion dall'interno della
> rete dell'host / del cluster (Zion lo limita agli IP sorgente privati e restituisce
> 403 ai client pubblici), e le serie `certmate_*` di CertMate direttamente
> sull'indirizzo interno `certmate:8000` con un Bearer token admin (vedere
> [`monitoring/`](../../monitoring/) per la dashboard e la configurazione di scrape).

### Confinamento del traffico in uscita (hardening dell'egress)

CertMate stabilisce connessioni in uscita verso le autorità di certificazione ACME,
le API dei provider DNS, lo storage a oggetti e i webhook di notifica via HTTP(S),
nonché SMTP per le notifiche email. È possibile confinare e verificare il traffico
**HTTP(S)** instradandolo attraverso un **forward proxy** e negando a CertMate
qualsiasi altra via verso internet.

I client HTTP(S) di CertMate (`requests`, `certbot`, consegna webhook via
`urllib`, `boto3`) rispettano le variabili d'ambiente standard `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`,
quindi non è necessaria alcuna modifica al codice. Lo fanno anche le sonde TLS:
il controllo dello stato di deploy, la scansione dell'inventario, l'endpoint
`POST /api/probe`, il controllo HSTS/header e quello su TLS 1.0/1.1 incanalano tutti
il proprio segmento TCP con HTTP CONNECT, e il recupero OCSP/CRL per la revoca —
che è HTTP in chiaro — passa da `HTTP_PROXY`. Un bersaglio che risolve a un
indirizzo privato o di loopback viene sempre contattato direttamente, perché
nessun proxy in uscita lo serve.

**Due cose non passano dal proxy:**

- **SMTP.** Le notifiche email usano `smtplib`, che apre una connessione TCP
  diretta e **non** consulta le variabili del proxy HTTP. Consentire direttamente
  l'`host:port` del proprio relay SMTP (regola firewall / NetworkPolicy), oppure
  usare un canale di notifica webhook al posto dell'email.
- **WHOIS.** Il controllo della scadenza di registrazione ripiega su WHOIS sulla
  porta 43 per i TLD senza RDAP, e un proxy HTTP non può trasportare quel protocollo.
  RDAP — che è HTTPS, ed è ciò che risponde per la maggior parte dei TLD — passa
  invece dal proxy. Consentire la porta 43 verso i registri necessari, oppure
  lasciare che quei TLD riportino `unavailable`.

Esempio con [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager),
un forward proxy self-hosted basato su Squid con WAF, DNS sinkhole e — dalla
v3.9.0 — una **allowlist egress default-deny** nativa (solo le destinazioni
esplicitamente approvate sono raggiungibili; tutto il resto viene rifiutato):

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
  # Lo stack di Secure Proxy Manager fornisce il servizio `proxy` su :3128.
  # Collegare quel proxy SIA alla rete `egress` (così CertMate può raggiungerlo)
  # SIA a una seconda rete non interna (così il proxy stesso raggiunge
  # internet). Il proxy è allora l'unica via d'uscita di CertMate.
networks:
  egress:
    internal: true        # nessun gateway: CertMate non ha accesso diretto a internet
```

Collocare CertMate su una rete `internal` (senza gateway) condivisa con il proxy
fa del proxy il suo **unico** percorso in uscita. Il traffico in uscita diventa un
unico punto di controllo verificabile: consentire le destinazioni di cui CertMate ha
effettivamente bisogno (la propria CA, il provider DNS, lo storage a oggetti, gli
endpoint di notifica) e rifiutare il resto; le destinazioni espresse come IP letterali
vengono bloccate dal proxy invece di essere accettate alla cieca. Se si usa la
delega DNS-alias / CNAME, consentire anche `cloudflare-dns.com` — CertMate
risolve quei CNAME tramite DoH.

Con Secure Proxy Manager v3.9.0+ questa è una modalità integrata invece di un
esercizio manuale di ACL: abilitare **Default-deny egress** nelle impostazioni e
popolare la **Egress Allowlist** con le destinazioni di cui CertMate ha bisogno.
Ogni voce è un dominio o un IP/CIDR (classificato automaticamente), e l'endpoint
`/api/egress-allowlist` consente di gestire l'elenco da IaC. Una allowlist
iniziale rappresentativa:

- l'host API della propria CA ACME — es. `acme-v02.api.letsencrypt.org` (più
  `acme-staging-v02.api.letsencrypt.org` se si emette su staging), oppure
  l'endpoint della CA configurata, qualunque essa sia;
- l'host API del proprio provider DNS — varia a seconda del provider (per esempio
  `api.cloudflare.com`);
- l'endpoint dello storage a oggetti, se il backup off-site è abilitato;
- l'host delle notifiche — l'endpoint webhook, Gotify, ntfy o Telegram, se
  usati;
- `cloudflare-dns.com`, se si usa la delega DNS-alias / CNAME (risolta tramite
  DoH, come sopra).

Tutto il resto viene rifiutato dal proxy, quindi un errore di configurazione o una
dipendenza compromessa non possono esfiltrare dati di nascosto verso un host
arbitrario. Per HTTPS l'allowlist confronta l'host della richiesta `CONNECT`,
quindi funziona senza intercettazione TLS.

- **Kubernetes:** una `NetworkPolicy` egress default-deny che consente il traffico
  solo verso il Service del proxy, più le variabili d'ambiente `HTTP(S)_PROXY` sul Deployment.
- **systemd:** `Environment=HTTPS_PROXY=...` nell'unità, più regole firewall
  dell'host che limitano l'egress al proxy.

**Ispezione dei contenuti HTTPS (opzionale, avanzata).** Un forward proxy vede solo
SNI / host / IP di una connessione HTTPS — il consenso o il rifiuto delle destinazioni
funziona su questi dati, senza decifrare. Se sul proxy si abilita anche
l'intercettazione TLS (SSL-bump) per ispezionare il *contenuto* in uscita, CertMate
deve **fidarsi della CA di intercettazione del proxy**: puntare `REQUESTS_CA_BUNDLE`
(e `SSL_CERT_FILE`) a un bundle che la includa, oppure aggiungerla al trust store
di sistema del container. **Escludere (`splice`) gli endpoint ACME
dall'intercettazione** — non si vuole fare MITM sulla connessione verso la propria
Certificate Authority, e alcuni endpoint fanno pinning dei certificati.
Non si tratta di mutual TLS; è una fiducia unidirezionale in una CA privata.

### Posizione di archiviazione per la directory dei dati

CertMate usa le I/O su file bloccanti standard di Python per tutto ciò che si trova
sotto `data/` (impostazioni, certificati, log di audit, store SQLite dello scheduler).
Il disco locale è fortemente raccomandato.

Se si monta `data/` su un filesystem di rete (NFS, SMB), tenere presente che:

- Un server NFS bloccato può sospendere indefinitamente le letture di file Python
  senza timeout integrato. Il worker di rinnovo, il writer del log di audit e la
  sonda /health si bloccheranno tutti sullo stesso punto di mount.
- La modalità journal WAL di SQLite richiede semantiche di lock che NFS non
  fornisce sempre. CertMate registra un avviso se ha dovuto ricorrere a una
  modalità journal più debole; la correttezza è preservata, ma la concorrenza diminuisce.

Se NFS è inevitabile, montare con `soft,timeo=30,retrans=3` (o l'equivalente
della propria distribuzione) affinché le I/O falliscano rapidamente invece di
bloccarsi su un server fermo, e dopo il primo avvio controllare nel log
dell'applicazione l'avviso di fallback da WAL (stdout, oppure il file indicato da
`CERTMATE_LOG_FILE` se impostato).

### Usare Gunicorn

```bash
gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 --timeout 300 app:app
```

### Usare systemd

Usa l'installer, oppure l'unità del repository a mano: vedi [Server Linux con systemd](#server-linux-con-systemd).

### Usare Docker in produzione

```yaml
services:
  certmate:
    build: .
    ports:
      - "127.0.0.1:8000:8000"  # solo localhost; è il reverse proxy a stare sulla rete
    environment:
      - API_BEARER_TOKEN=${API_BEARER_TOKEN}
      - CLOUDFLARE_TOKEN=${CLOUDFLARE_TOKEN}
    volumes:
      - ./certificates:/app/certificates
      - ./data:/app/data
      - ./logs:/app/logs
      - ./backups:/app/backups
    restart: unless-stopped
```

---

## Risoluzione dei problemi

### Conflitti di versioni dei plugin DNS

Installare dal file requirements che CertMate distribuisce. Quell'insieme viene
risolto, costruito e avviato dalla CI a ogni esecuzione; un elenco assemblato a
mano no.

```bash
pip install -r requirements.txt            # tutti i provider inclusi
pip install -r requirements-minimal.txt    # solo certbot + Cloudflare
pip install -r requirements-extended.txt   # altri provider, sopra minimal
pip install -r requirements-aws.txt        # Route53, sopra uno dei due
```

> Questa pagina pubblicava un proprio elenco di versioni, andato alla deriva
> fino a `certbot==4.1.1` in tutte e cinque le lingue mentre il progetto era
> vincolato a `2.10.0`. Il progetto usa ora certbot `5.8.0` (issue #103).
>
> Correggere quei numeri non basta, ed è il motivo per cui l'elenco è stato
> rimosso anziché aggiornato. A tenere insieme lo stack non sono le versioni dei
> plugin ma il fatto che certbot, `acme`, `josepy`, i plugin ufficiali,
> `cryptography` e `pyopenssl` combacino tra loro: certbot e `acme` 5.8.0
> richiedono `cryptography>=47`, e pyOpenSSL 26.4.0 richiede `>=49,<51`.
> Assemblato a mano, un pin finisce fuori da quella finestra; il file fornito da
> CertMate è l'insieme risolto, costruito e avviato in CI. Vedi SECURITY.md,
> "Known dependency constraint".
>
> `certbot-dns-powerdns` richiede un ambiente separato: vuole
> `dns-lexicon<=3.5.6` mentre i plugin Linode, OVH, RFC2136, DNSMadeEasy e NS1
> richiedono `>=3.14.1`, e pip non può soddisfare entrambi.

### Installazione manuale delle dipendenze

Se un singolo provider non si installa, aggiungerlo sopra una base funzionante
invece di assemblarne una a mano:

```bash
pip install -r requirements-minimal.txt    # prima la base funzionante
pip install -r requirements-aws.txt        # Route53 + boto3
pip install -r requirements-gcp.txt        # Google Cloud DNS
pip install -r requirements-azure.txt      # Azure DNS
```

Ogni file porta le versioni di cui il suo plugin ha bisogno, e la CI risolve
ogni combinazione a ogni esecuzione — compresa la verifica che certbot non si
sposti dal suo pin.

### Comandi di verifica

```bash
# Verificare i plugin certbot
certbot plugins --text

# Verificare che il servizio sia in esecuzione
curl -X GET http://localhost:8000/api/health
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
