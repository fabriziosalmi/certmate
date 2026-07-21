# Guide d'installation

Ce guide couvre toutes les méthodes d'installation et de déploiement de CertMate.

---

## Prérequis

- Python 3.9 ou supérieur
- pip (gestionnaire de paquets Python)
- Docker (optionnel, pour le déploiement conteneurisé)

---

## Méthode 1 : Installation directe

### 1. Cloner le dépôt

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
```

### 2. Créer l'environnement virtuel

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
.\venv\Scripts\activate   # Windows
```

### 3. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 4. Configurer l'environnement

Créez un fichier `.env` :

```bash
cp .env.example .env
# Modifiez .env avec vos paramètres
```

### 5. Lancer l'application

```bash
python app.py
```

---

## Méthode 2 : Installation Docker

### Avec Docker Compose (recommandé)

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker-compose up -d
```

### Avec Docker Build

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker build -t certmate .
docker run -p 8000:8000 --env-file .env -v ./certificates:/app/certificates certmate
```

> Pour le déploiement Docker avancé incluant les constructions multi-plateforme, voir le [Guide Docker](./docker.md).

---

## Dépendances système

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

## Configuration du fournisseur DNS

Après l'installation, configurez les identifiants de votre fournisseur DNS. Voir le [Guide des fournisseurs DNS](./dns-providers.md) pour les instructions détaillées.

Configuration rapide pour les fournisseurs courants :

### Cloudflare

1. Allez dans le [Tableau de bord Cloudflare](https://dash.cloudflare.com/profile/api-tokens)
2. Créez un nouveau jeton API avec les permissions `Zone:DNS:Edit`
3. Ajoutez le jeton dans les paramètres CertMate

### AWS Route53

1. Créez un utilisateur IAM avec les permissions Route53
2. Générez des clés d'accès
3. Ajoutez les identifiants dans les paramètres CertMate

### Azure DNS

1. Créez un Service Principal
2. Attribuez le rôle DNS Zone Contributor
3. Configurez les détails de l'abonnement dans les paramètres CertMate

### Google Cloud DNS

1. Créez un compte de service avec le rôle DNS Administrator
2. Téléchargez le fichier JSON de clé
3. Importez dans les paramètres CertMate

---

## Variables d'environnement

```bash
# Authentification API (auto-générée si aucune n'est définie)
# Option A : valeur directe
API_BEARER_TOKEN=votre_token_securise
# Option B : chemin vers un fichier contenant le token (prioritaire sur API_BEARER_TOKEN)
API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token

# Clé secrète de session Flask (auto-générée si aucune n'est définie)
# Option A : valeur directe
SECRET_KEY=votre_cle_secrete_flask
# Option B : chemin vers un fichier contenant la clé (prioritaire sur SECRET_KEY)
SECRET_KEY_FILE=/run/secrets/secret_key

# Proxy inverse — mettre à 'true' quand CertMate est derrière Nginx,
# HAProxy, Traefik, Cloudflare, etc. Sans cela, request.remote_addr
# résout sur l'IP du proxy pour chaque requête, ce qui fusionne la
# limitation de débit par client en un seul bucket.
BEHIND_PROXY=true

# Chiffrement des sauvegardes au repos (optionnel, recommandé).
# Quand défini, les sauvegardes unifiées sont écrites sous forme de
# fichiers .zip.enc chiffrés (dérivation PBKDF2-SHA256 + Fernet/AES)
# au lieu de .zip en clair. Les sauvegardes contiennent chaque clé
# privée de certificat ; sans cela, un fichier de sauvegarde exfiltré
# est une compromission totale des clés.
CERTMATE_BACKUP_PASSPHRASE=choisissez-une-longue-phrase-de-passe-aleatoire

# Fournisseurs DNS (choisissez un ou plusieurs)
CLOUDFLARE_TOKEN=votre_token_cloudflare
AWS_ACCESS_KEY_ID=votre_access_key_aws
AWS_SECRET_ACCESS_KEY=votre_secret_key_aws
AZURE_SUBSCRIPTION_ID=votre_subscription_azure
AZURE_TENANT_ID=votre_tenant_azure
AZURE_CLIENT_ID=votre_client_azure
AZURE_CLIENT_SECRET=votre_secret_azure
GOOGLE_PROJECT_ID=votre_projet_gcp
POWERDNS_API_URL=https://votre-powerdns:8081
POWERDNS_API_KEY=votre_cle_powerdns
```

### Ordre de résolution

| Variable | Priorité |
|----------|----------|
| `API_BEARER_TOKEN_FILE` | La plus haute — si défini, `API_BEARER_TOKEN` n'est jamais lu |
| `API_BEARER_TOKEN` | Utilisé seulement quand `API_BEARER_TOKEN_FILE` est absent |
| *(généré)* | Repli quand aucun n'est défini ou que la valeur échoue la validation |
| `SECRET_KEY_FILE` | La plus haute — si défini, `SECRET_KEY` n'est jamais lu |
| `SECRET_KEY` | Utilisé seulement quand `SECRET_KEY_FILE` est absent |
| *(généré + persisté)* | Écrit dans `data/.secret_key` pour que les sessions survivent aux redémarrages |

> **Astuce Docker Secrets** : Utilisez `API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token` et `SECRET_KEY_FILE=/run/secrets/secret_key` avec Docker Swarm ou les secrets Kubernetes pour éviter de mettre des valeurs sensibles dans les variables d'environnement.

---

## Déploiement en production

### Derrière un proxy inverse

Si CertMate est derrière un proxy inverse (Nginx, HAProxy, Traefik, Cloudflare, Kubernetes Ingress) — ce qui est la manière recommandée de l'exécuter pour la terminaison TLS — définissez `BEHIND_PROXY=true` dans l'environnement du conteneur. Cela active le middleware `ProxyFix` de Werkzeug afin que les éléments suivants fassent confiance aux en-têtes `X-Forwarded-*` de votre proxy :

- `request.remote_addr` résout sur l'IP client d'origine au lieu de l'IP du proxy. La limitation de débit, les entrées de journal d'audit et les avertissements "tentative de token API invalide depuis X" deviennent par client au lieu de par proxy.
- Le schéma / hôte / préfixe du proxy sont respectés, ce qui maintient l'exactitude des URL générées et des scopes de cookies.

```yaml
# Extrait docker-compose.yml
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    environment:
      BEHIND_PROXY: "true"
    volumes:
      - ./data:/app/data
```

**Quand NE PAS l'activer.** Si vous exposez CertMate directement sur le réseau sans proxy devant, laissez `BEHIND_PROXY` non défini. Avec cette option activée, quiconque peut atteindre le listener pourrait usurper `X-Forwarded-For` et contourner les limites de débit par client. Le proxy est la frontière de confiance.

Votre proxy doit bien sûr transmettre les en-têtes. Exemple Nginx :

```nginx
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

#### Exemple : Zion (passerelle TLS Rust + WAF)

[Zion](https://github.com/fabriziosalmi/zion) est un proxy inverse Rust haute performance avec un WAF intégré — un bon choix devant CertMate quand vous souhaitez la terminaison TLS 1.3 et le filtrage des requêtes en périphérie. CertMate reste en HTTP simple sur le réseau interne ; Zion termine le TLS et transmet.

`zion.toml` :

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

`docker-compose.yml` :

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

Gardez `BEHIND_PROXY=true` sur le service CertMate : Zion ajoute `X-Forwarded-For`, ce qui permet à la limitation de débit par client, aux entrées d'audit et aux avertissements d'échec d'authentification de résoudre sur la vraie IP client plutôt que celle de Zion.

### Utiliser Gunicorn

```bash
pip install gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 app:app
```

### Utiliser systemd

Créez `/etc/systemd/system/certmate.service` :

```ini
[Unit]
Description=CertMate Gestionnaire de Certificats SSL
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

### Backup et restauration

```bash
# Créer une sauvegarde
curl -X POST http://localhost:8000/api/backups/create \
  -H "Authorization: Bearer VOTRE_TOKEN_API"

# Lister les sauvegardes
curl http://localhost:8000/api/backups \
  -H "Authorization: Bearer VOTRE_TOKEN_API"

# Restaurer une sauvegarde
curl -X POST http://localhost:8000/api/backups/restore \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{"name": "backup_20240101_120000.zip"}'
```

---

## Dépannage

### Conflits de versions de plugins DNS

Si vous rencontrez des conflits de versions, utilisez ces versions spécifiques :

```txt
certbot==4.1.1
certbot-dns-cloudflare==4.1.1
certbot-dns-route53==4.1.1
certbot-dns-azure==2.6.1
certbot-dns-google==4.1.1
certbot-dns-powerdns==0.2.1
```

### Commandes de validation

```bash
# Vérifier les plugins certbot
certbot plugins --text

# Vérifier que le service fonctionne
curl -X GET http://localhost:8000/api/health
```

### Erreurs courantes

| Erreur | Solution |
|--------|----------|
| `ModuleNotFoundError` | Exécutez `pip install -r requirements.txt` |
| `Port already in use` | Changez le port dans les variables d'environnement |
| `certbot not found` | Installez certbot : `pip install certbot` |
| `Permission denied` | Vérifiez les permissions sur `/app/data` et `/app/certificates` |
| `Token API invalide` | Vérifiez `API_BEARER_TOKEN` dans votre fichier `.env` |

### Mode débogage

```bash
export FLASK_DEBUG=1
python app.py
```

### Confinement du trafic sortant (durcissement de l'egress)

CertMate établit des connexions sortantes vers les autorités de certification ACME, les API des fournisseurs DNS, le stockage d'objets et les webhooks de notification via HTTP(S), ainsi que SMTP pour les notifications email. Vous pouvez confiner et auditer le trafic **HTTP(S)** en le routant via un **proxy direct (forward proxy)** et en refusant à CertMate toute autre route vers internet.

Les clients HTTP(S) de CertMate (`requests`, `certbot`, livraison webhook via `urllib`, `boto3`) respectent les variables d'environnement standard `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, donc aucune modification de code n'est nécessaire. **SMTP fait exception :** les notifications email utilisent `smtplib`, qui ouvre une connexion TCP directe et ne consulte **pas** les variables de proxy HTTP. Sur un réseau egress verrouillé, autorisez directement le `host:port` de votre relais SMTP (règle de pare-feu / NetworkPolicy), ou utilisez un canal de notification webhook au lieu de l'email.

Exemple avec [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager), un proxy direct auto-hébergé basé sur Squid avec un WAF, un DNS sinkhole et — depuis v3.9.0 — une liste d'autorisation egress **default-deny** (seules les destinations explicitement approuvées sont atteignables ; tout le reste est refusé) :

```yaml
services:
  certmate:
    image: certmate:latest
    environment:
      HTTP_PROXY:  "http://proxy:3128"
      HTTPS_PROXY: "http://proxy:3128"
      NO_PROXY:    "localhost,127.0.0.1"
    networks:
      - egress            # CertMate peut atteindre UNIQUEMENT le proxy sur ce réseau
networks:
  egress:
    internal: true        # pas de passerelle : CertMate n'a pas d'internet direct
```

Placer CertMate sur un réseau `internal` (pas de passerelle) partagé avec le proxy fait du proxy son **seul** chemin sortant. Le trafic sortant devient un point de contrôle unique et vérifiable : autorisez les destinations dont CertMate a réellement besoin (votre CA, fournisseur DNS, stockage d'objets, endpoints de notification), refusez le reste.

**Kubernetes :** une `NetworkPolicy` egress default-deny qui n'autorise le trafic que vers le Service du proxy, plus les variables d'environnement `HTTP(S)_PROXY` sur le Deployment.

**systemd :** `Environment=HTTPS_PROXY=...` dans l'unité, plus des règles de pare-feu hôte qui restreignent l'egress au proxy.

### Emplacement de stockage pour le répertoire de données

CertMate utilise les E/S fichiers bloquantes standard de Python pour tout ce qui se trouve sous `data/` (paramètres, certificats, journal d'audit, stockage SQLite du planificateur). Le disque local est fortement recommandé.

Si vous montez `data/` sur un système de fichiers réseau (NFS, SMB), sachez que :

- Un serveur NFS gelé peut bloquer les lectures de fichiers Python indéfiniment sans timeout intégré. Le worker de renouvellement, le rédacteur du journal d'audit et la sonde /health se bloqueront tous sur le même point de montage.
- Le mode journal WAL de SQLite nécessite des sémantiques de verrouillage que NFS ne fournit pas toujours. CertMate journalise un avertissement s'il a dû revenir à un mode journal plus faible ; l'exactitude est préservée, mais la concurrence diminue.

Si NFS est inévitable, montez avec `soft,timeo=30,retrans=3` (ou l'équivalent de votre distribution) pour que les E/S échouent rapidement au lieu de bloquer sur un serveur arrêté.

### Utiliser Gunicorn

```bash
gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 app:app
```

### Utiliser systemd

Créez `/etc/systemd/system/certmate.service` :

```ini
[Unit]
Description=CertMate Gestionnaire de Certificats SSL
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

Activez et démarrez :

```bash
sudo systemctl enable certmate
sudo systemctl start certmate
```

### Utiliser Docker en production

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

## Dépannage

### Installation manuelle des dépendances

Si l'installation automatique échoue, installez les fournisseurs DNS individuellement :

```bash
# Noyau certbot
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

> La plupart des plugins DNS nécessitent Certbot 4.1.1. Le plugin Azure a un versionnement indépendant (2.6.1) et PowerDNS est un plugin plus récent (0.2.1).

### Commandes de validation

```bash
# Vérifier les plugins certbot
certbot plugins --text

# Vérifier que le service fonctionne
curl -X GET http://localhost:8000/api/health
```

### Erreurs courantes

| Erreur | Solution |
|--------|----------|
| `ModuleNotFoundError` | Exécutez `pip install -r requirements.txt` |
| `Port already in use` | Changez le port dans les variables d'environnement |
| `certbot not found` | Installez certbot : `pip install certbot` |
| `Permission denied` | Vérifiez les permissions sur `/app/data` et `/app/certificates` |
| `Token API invalide` | Vérifiez `API_BEARER_TOKEN` dans votre fichier `.env` |

### Mode débogage

```bash
export FLASK_DEBUG=1
python app.py
```

---

## Support

Si vous rencontrez des problèmes :

1. Vérifiez les journaux pour les erreurs spécifiques
2. Vérifiez les identifiants de votre fournisseur DNS
3. Consultez le [Guide des fournisseurs DNS](./dns-providers.md) pour le dépannage spécifique
4. Consultez le [Guide de test](./testing.md) pour exécuter des diagnostics

---

<div align="center">

[← Retour à la documentation](./README.md) • [Fournisseurs DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
