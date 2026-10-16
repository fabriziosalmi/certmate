# Construction et déploiement Docker

<!-- CERTMATE-TRANSLATED-FROM b3c7a928998dc93e -->

Ce guide couvre la construction, le déploiement et l'exécution de CertMate dans Docker — incluant le support multi-plateforme pour ARM et AMD64.

---

## En production avec Docker Compose

Le moyen le plus court d'exécuter CertMate en production : un seul fichier, l'image publiée, rien à compiler et aucun dépôt à cloner.

```bash
mkdir certmate && cd certmate
curl -fsSLO https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/docker-compose.yml
printf 'API_BEARER_TOKEN=%s\nSECRET_KEY=%s\nCERTMATE_BACKUP_PASSPHRASE=%s\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
```

Ouvrez `http://127.0.0.1:8000`. La première page crée le compte administrateur et demande l'`API_BEARER_TOKEN` du fichier `.env` pour l'autoriser. Conservez `.env` : il contient le jeton utilisé par les clients API, la clé qui signe les sessions et la phrase secrète sans laquelle une sauvegarde ne peut pas restaurer cette instance.

Ce que fait le fichier :

- **Épingle l'image** de la dernière version. La copie sur `main` est mise à jour à chaque version. Pour rester sur une version, définissez `CERTMATE_VERSION=X.Y.Z` dans `.env`.
- **Conserve tout dans des volumes nommés** (`certificates`, `data`, `logs`, `backups`). Docker les crée avec les droits dont CertMate a besoin, il n'y a donc aucun `chown` à faire. `docker compose down` les conserve ; `down -v` les supprime.
- **N'écoute que sur 127.0.0.1.** Pour un accès distant, placez un reverse proxy devant et définissez `BEHIND_PROXY=true`. Définir `CERTMATE_BIND=0.0.0.0` le publie sur toutes les interfaces. `CERTMATE_PORT` change le port de l'hôte.
- **Refuse de démarrer sans `API_BEARER_TOKEN` et `SECRET_KEY`**, au lieu de générer des valeurs qui changeraient à chaque recréation du conteneur.

Variables facultatives pour `.env` : `CLOUDFLARE_TOKEN` (crée un compte DNS Cloudflare au premier démarrage), `LETSENCRYPT_EMAIL`, `BEHIND_PROXY`.

**Mise à jour :** téléchargez de nouveau le fichier (ou changez `CERTMATE_VERSION`), puis exécutez `docker compose pull && docker compose up -d`.

Le `docker-compose.yml` à la racine du dépôt construit l'image à partir des sources et sert au développement.

---

## Portainer

Dans Portainer, déployez le [bundle compose de production](#en-production-avec-docker-compose) comme stack directement depuis ce dépôt :

1. **Stacks → Add stack**, nommez-le `certmate` et choisissez **Repository**.
2. URL du dépôt `https://github.com/fabriziosalmi/certmate`, référence `refs/heads/main`, chemin compose `deploy/docker-compose.yml`.
3. Dans **Environment variables**, ajoutez `API_BEARER_TOKEN`, `SECRET_KEY` et `CERTMATE_BACKUP_PASSPHRASE`, chacun avec une longue valeur aléatoire comme la sortie de `openssl rand -hex 32`. Ajoutez éventuellement `CERTMATE_PORT`, `CERTMATE_BIND` ou `CLOUDFLARE_TOKEN`.
4. **Deploy the stack.**

Sans les deux variables obligatoires, le déploiement échoue en indiquant laquelle manque (`required variable API_BEARER_TOKEN is missing a value`), au lieu de démarrer avec des clés qui changeraient à chaque redéploiement. Pour mettre à jour, utilisez **Pull and redeploy** sur la stack : les volumes nommés, et donc les certificats et les réglages, sont conservés.

Vérifié sur Portainer CE 2.45 : une stack sans les variables est refusée avec ce message ; avec elles, elle démarre saine, le jeton autorise l'API, et un pull and redeploy recrée le conteneur en conservant les données.

---

## Démarrage rapide

### Pull et exécution

Les images sont publiées sur Docker Hub sous `fabriziosalmi/certmate`. Les versions postérieures à v2.42.0 sont aussi publiées, avec les mêmes tags, sur GHCR sous `ghcr.io/fabriziosalmi/certmate`, ce qui évite les limites de téléchargement anonyme de Docker Hub : utilisez l'un ou l'autre nom ci-dessous.

```bash
# Docker sélectionne automatiquement la bonne architecture
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_data:/app/data \
  -v certmate_certificates:/app/certificates \
  fabriziosalmi/certmate:latest
```

### Construction et exécution locale

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

## Sécurité

Le processus de construction garantit qu'aucun secret n'est inclus dans l'image :

- `.dockerignore` exclut tous les fichiers `.env` et les données sensibles
- Les variables d'environnement sont fournies **à l'exécution**, pas à la construction
- Seuls les fichiers applicatifs essentiels sont inclus
- Les images peuvent être poussées en toute sécurité vers des registres publics

### Vérifier l'absence de secrets dans l'image

```bash
docker history certmate:latest
docker inspect certmate:latest | grep -i env
docker run --rm certmate:latest find / -name "*.env" 2>/dev/null
```

---

## Configuration d'exécution

### Option 1 : Fichier d'environnement

Créez un fichier `.env` sur votre hôte (pas dans l'image Docker) :

```bash
SECRET_KEY=your-super-secret-key-here
# SECRET_KEY_FILE=/run/secrets/secret_key  # Alternative : prioritaire sur SECRET_KEY
# Définissez API_BEARER_TOKEN avant d'exposer sur un réseau une instance pas
# encore configurée : tant que le premier administrateur n'existe pas, une instance
# sans token offre le contournement de la configuration initiale à quiconque peut
# l'atteindre. Une fois défini, collez-le une fois sur l'écran de premier démarrage pour créer l'admin.
API_BEARER_TOKEN=your-api-bearer-token-here
# API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token  # Alternative : prioritaire sur API_BEARER_TOKEN
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

### Option 2 : Variables d'environnement directes

```bash
docker run -d --name certmate \
  -e SECRET_KEY="your-secret-key" \
  # -e SECRET_KEY_FILE="/run/secrets/secret_key" \  # Alternative : prioritaire sur SECRET_KEY
  -e API_BEARER_TOKEN="your-api-bearer-token" \
  # -e API_BEARER_TOKEN_FILE="/run/secrets/api_bearer_token" \  # Alternative : prioritaire sur API_BEARER_TOKEN
  -e CLOUDFLARE_TOKEN="your-api-token" \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  certmate:latest
```

### Référence des variables d'environnement

| Variable | Requis | Description |
|----------|--------|-------------|
| `SECRET_KEY` | Non | Clé secrète Flask pour les sessions (auto-générée si non définie) |
| `SECRET_KEY_FILE` | Non | Chemin vers un fichier contenant la clé secrète Flask (prioritaire sur `SECRET_KEY`). S'il est défini et que le fichier ne peut pas être lu ou est vide, CertMate refuse de démarrer : un secret dont le montage a échoué est une erreur de configuration, et générer une clé à la place déconnecterait chaque utilisateur, à chaque redémarrage, avec des sessions signées par une clé que vous n'avez pas choisie. |
| `API_BEARER_TOKEN` | Non (auto-généré) | Token d'authentification de l'API. Auto-généré si non défini, mais définissez-le avant d'exposer sur un réseau une instance pas encore configurée ; une fois défini, collez-le une fois sur l'écran de premier démarrage pour créer l'administrateur. **Cette valeur fait autorité :** si elle diffère du token déjà enregistré, celui-ci est remplacé au démarrage et cesse de fonctionner. C'est ce qui permet à l'ajout ou à la rotation de la variable sur une installation existante de prendre effet — auparavant, le contrôle d'accès utilisait cette valeur alors que l'authentification vérifiait encore l'ancienne, et l'écran de premier démarrage demandait un token qu'il refusait ensuite |
| `API_BEARER_TOKEN_FILE` | Non | Chemin vers un fichier contenant le token bearer API (prioritaire sur `API_BEARER_TOKEN`) |
| `CERTMATE_LOG_LEVEL` | Non | `INFO` (défaut), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | **À définir si vous voulez des sauvegardes automatiques à partir desquelles restaurer** | Chiffre au repos les sauvegardes unifiées (`.zip.enc`, PBKDF2-SHA256 + Fernet), et c'est elle qui rend les sauvegardes automatiques *complètes* — avec elle, elles peuvent restaurer cette instance ; sans elle, elles gardent leurs identifiants masqués et ne le peuvent pas. La même phrase secrète est requise pour les restaurer, et CertMate ne la stocke jamais à votre place. Conservez-la ailleurs que sur la machine qui contient les sauvegardes |
| `CLOUDFLARE_TOKEN` | Non | Token API du compte DNS Cloudflare par défaut. Route53 utilise normalement les identifiants configurés dans Paramètres → Fournisseurs DNS, mais quand son compte choisit explicitement `auth_mode: iam_role`, Certbot utilise la chaîne d'identification AWS du conteneur (y compris les rôles IAM). |

Voir le [Guide d'installation](./installation.md#variables-denvironnement) pour la liste complète.

### Garder les jetons DNS hors de `settings.json`

Les jetons des fournisseurs DNS configurés depuis l'interface sont stockés dans
`settings.json`, c'est-à-dire le fichier qui est sauvegardé, copié et monté.
Chaque champ d'identifiant peut à la place **indiquer** où se trouve sa valeur :
`api_token_file` avec un chemin, ou `api_token_env` avec un nom de variable,
comme le fait déjà `API_BEARER_TOKEN_FILE`. La valeur est lue au moment où
certbot s'exécute et n'est jamais réécrite. Le `client_secret` OIDC accepte la
même paire. Voir
[SECURITY.md](https://github.com/fabriziosalmi/certmate/blob/main/SECURITY.md#keeping-credentials-out-of-settingsjson).

---

## Docker Compose

### Configuration de base

```yaml
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    container_name: certmate
    ports:
      - "127.0.0.1:8000:8000"  # localhost uniquement ; placez un reverse proxy devant pour l'accès externe
    environment:
      - SECRET_KEY=${SECRET_KEY:-}
      # - SECRET_KEY_FILE=${SECRET_KEY_FILE:-}  # Alternative : chemin vers un fichier contenant la clé secrète
      - API_BEARER_TOKEN=${API_BEARER_TOKEN:-}
      # - API_BEARER_TOKEN_FILE=${API_BEARER_TOKEN_FILE:-}  # Alternative : chemin vers un fichier contenant le token bearer
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
# Démarrer avec le fichier .env dans le même répertoire
docker compose up -d

# Ou spécifier un fichier .env différent
docker compose --env-file /path/to/.env up -d
```

---

## Podman (Quadlet, rootless) et OpenShift

### Quadlet : CertMate comme service systemd

[`deploy/podman/certmate.container`](../../deploy/podman/certmate.container) est une unité Quadlet : Podman en fait un service systemd. Elle exécute l'image publiée avec des volumes nommés, le port uniquement sur loopback, les secrets comme secrets Podman, un healthcheck et la prise en charge de `podman auto-update`.

En rootless, avec votre propre utilisateur :

```bash
# Les trois secrets, créés une seule fois. Ils n'apparaissent jamais dans un fichier.
for s in certmate-api-token certmate-secret-key certmate-backup-passphrase; do
  openssl rand -hex 32 | tr -d '\n' | podman secret create "$s" -
done

mkdir -p ~/.config/containers/systemd
curl -fsSL -o ~/.config/containers/systemd/certmate.container \
  https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/podman/certmate.container
systemctl --user daemon-reload
systemctl --user start certmate

# Le garder actif sans session ouverte, et le démarrer au boot.
sudo loginctl enable-linger "$USER"
```

En rootful à la place : placez le fichier dans `/etc/containers/systemd/`, créez les secrets en root, puis exécutez `sudo systemctl daemon-reload && sudo systemctl start certmate`.

Ouvrez `http://127.0.0.1:8000`. La première page crée le compte administrateur et demande le jeton API : `podman secret inspect --showsecret certmate-api-token --format '{{.SecretData}}'`.

Vérifié sur Fedora 44 avec Podman 5.8, en rootful et en rootless : le service démarre sain, le jeton autorise l'API, et il revient après un redémarrage (en rootless grâce au lingering).

### UID arbitraires (Podman rootless, OpenShift)

L'image s'exécute par défaut avec l'utilisateur non root `1000`, mais elle suit
aussi le modèle OpenShift des **UID arbitraires** : les répertoires accessibles
en écriture à l'exécution (`/app/data`, `/app/certificates`, `/app/logs`,
`/app/backups`) appartiennent au **groupe 0 (groupe root)**, sont accessibles en
écriture au groupe et ont le bit setgid. Un processus de conteneur exécuté avec
*n'importe quel* UID appartenant au groupe 0 — c'est ainsi que podman rootless
et OpenShift lancent les conteneurs — peut donc créer et renommer des fichiers
sans `chown -R 1000:1000` manuel des volumes. Les fichiers secrets que
l'application écrit (la clé privée de la CA, la clé de signature de l'audit, les
fichiers d'identifiants DNS, `.secret_key`) sont toujours créés en `0600`,
réservés au propriétaire, de sorte que les répertoires accessibles en écriture
au groupe n'exposent jamais une clé. (Ticket [#380](https://github.com/fabriziosalmi/certmate/issues/380).)

### Volumes nommés

Un **volume nommé** neuf hérite des permissions groupe 0 de l'image sous Podman
rootful et sous Docker. Sous Podman **rootless**, ce n'est pas toujours le cas :
mesuré sur Podman 5.8, la racine du volume `backups`, dont le répertoire dans
l'image n'est pas vide, est restée la propriété de root, et CertMate a refusé de
démarrer avec *"Required directories are not writable"*. Ajoutez `:U`, qui
attribue chaque volume à l'utilisateur du conteneur :

```bash
podman run -d --name certmate \
  -p 127.0.0.1:8000:8000 \
  -v certmate_data:/app/data:U \
  -v certmate_certificates:/app/certificates:U \
  -v certmate_logs:/app/logs:U \
  -v certmate_backups:/app/backups:U \
  docker.io/fabriziosalmi/certmate:latest
```

### Bind mounts (répertoires de l'hôte)

Un bind mount conserve la propriété du répertoire de l'**hôte**, qui masque les
permissions de l'image. Rendez une fois les répertoires de l'hôte accessibles en
écriture au groupe 0, puis exécutez :

```bash
# Créer les répertoires de l'hôte accessibles en écriture au groupe 0 (tout UID du groupe 0 peut écrire)
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

Vous pouvez aussi laisser podman corriger la propriété à votre place avec
l'option de montage `:U` (qui applique un chown récursif à la source pour
correspondre à l'UID/GID du conteneur) :

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

Si le démarrage s'interrompt avec *"Required directories are not writable by the
CertMate process"*, le montage n'est pas accessible en écriture à l'utilisateur
du conteneur — ajoutez `:U` au volume ou, pour un bind mount, appliquez le
`chgrp 0 … && chmod g+rwX …` ci-dessus.

> **Kubernetes / OpenShift :** aucune modification nécessaire. Définissez
> `spec.securityContext.fsGroup: 0` (ou appuyez-vous sur la SCC restricted par
> défaut, qui attribue déjà un UID arbitraire du groupe 0) et les volumes montés
> deviennent automatiquement accessibles en écriture au groupe 0.

---

## Mise à jour

CertMate conserve son état persistant dans `/app/data` (`settings.json`, les
utilisateurs administrateurs, la `.secret_key` auto-générée, la clé de signature
de l'audit et la base de données du planificateur) et `/app/certificates`. Cet
état survit à une mise à jour parce que ces chemins sont montés depuis
l'extérieur du conteneur, comme dans tous les exemples de cette page, et **non**
conservés dans l'image : mettre à jour consiste à récupérer une image plus récente
et à recréer le conteneur avec les mêmes montages, et votre configuration, vos
certificats et votre connexion sont conservés.

Les sauvegardes sont écrites dans `/app/backups`. Le Démarrage rapide ci-dessus ne
le monte pas, donc une sauvegarde prise à cet endroit disparaît avec le conteneur
quand il est supprimé : téléchargez-la d'abord, ou montez aussi `/app/backups`,
comme le fait l'exemple ci-dessous.

```bash
# Recommandé : faites d'abord une sauvegarde (Paramètres → Sauvegarde, ou l'API)

# Docker Compose
docker compose pull          # récupère la nouvelle image
docker compose up -d         # recrée le conteneur (data/ + certificates/ sont conservés)

# docker run simple : arrêter/supprimer puis relancer avec les MÊMES montages
# qu'au démarrage. Ce sont les volumes nommés du Démarrage rapide, plus un pour les
# sauvegardes ; utilisez plutôt vos chemins hôte si vous avez démarré avec des bind mounts.
docker pull fabriziosalmi/certmate:latest
docker rm -f certmate
docker run -d --name certmate --env-file .env -p 127.0.0.1:8000:8000 \
  -v certmate_data:/app/data -v certmate_certificates:/app/certificates \
  -v certmate_backups:/app/backups \
  fabriziosalmi/certmate:latest
```

Les migrations du format des paramètres s'exécutent automatiquement au démarrage.
En production, épinglez un tag de version (par ex. `fabriziosalmi/certmate:2.19`)
plutôt que `:latest`, afin qu'un nouveau pull ne vous surprenne pas avec une mise
à jour non voulue — la construction multi-plateforme publie les tags `MAJOR`,
`MAJOR.MINOR` et `MAJOR.MINOR.PATCH`.

---

## Constructions multi-plateforme

CertMate supporte les images Docker multi-plateforme pour les architectures ARM et AMD64.

### Architectures supportées

| Plateforme | Description | Cas d'usage courants |
|------------|-------------|----------------------|
| `linux/amd64` | Intel/AMD 64-bit | La plupart des serveurs cloud, postes de travail |
| `linux/arm64` | ARM 64-bit | Apple Silicon, instances cloud ARM |
| `linux/arm/v7` | ARM 32-bit v7 | Raspberry Pi 3+ — **non publiée** : constructible à la demande (voir ci-dessous), les images des versions sont amd64 + arm64 |

### Docker Buildx manuel

```bash
# Créer et utiliser le builder buildx
docker buildx create --name certmate-builder --use

# Construire pour plusieurs plateformes
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest .

# Construire et pousser
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest --push .

# Construire pour la plateforme courante uniquement
docker build -t certmate:latest .

# Étiqueter une version et la pousser
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:v1.0.0 -t USERNAME/certmate:latest --push .

# Raspberry Pi 3+ (linux/arm/v7, non publiée)
docker buildx build --platform linux/arm/v7 -t USERNAME/certmate:armv7 --push .
```

### Prérequis pour le multi-plateforme

```bash
# Vérifier le support buildx
docker buildx version
docker buildx inspect --bootstrap

# Activer l'émulation QEMU (si nécessaire)
docker run --privileged --rm tonistiigi/binfmt --install all
```

### Forcer une plateforme spécifique

```bash
# Forcer AMD64 (ex. sur Apple Silicon pour les tests)
docker run --platform linux/amd64 --rm \
  --env-file .env -p 8000:8000 certmate:latest

# Détection automatique (recommandé)
docker run --rm --env-file .env -p 8000:8000 certmate:latest
```

---

## Pousser vers Docker Hub

```bash
# Connexion
docker login

# Tagger et pousser
docker build -t USERNAME/certmate:latest .
docker push USERNAME/certmate:latest

# Avec un tag de version
docker build -t USERNAME/certmate:v1.0.0 .
docker push USERNAME/certmate:v1.0.0
```

---

## Intégration CI/CD

### GitHub Actions

Secrets requis :
- `DOCKERHUB_USER`
- `DOCKERHUB_TOKEN`

```bash
# Déclenchement manuel avec plateformes personnalisées
gh workflow run docker-multiplatform.yml \
  -f platforms="linux/amd64,linux/arm64,linux/arm/v7" \
  -f push_to_registry=true
```

---

## Conseils pour la production

1. **Utilisez la gestion des secrets** : Docker secrets, Kubernetes secrets ou un gestionnaire de secrets
2. **Activez TLS** : Exécutez derrière un proxy inverse avec terminaison TLS
3. **Surveillez les ressources** : Définissez des limites CPU et mémoire
4. **Sauvegardez les volumes** : Sauvegardez régulièrement les volumes de certificats et de données
5. **Mettez à jour régulièrement** : Gardez l'image à jour avec les correctifs de sécurité
6. **Utilisez le cache de couches** pour des constructions plus rapides :
   ```bash
   docker buildx build --cache-from type=registry,ref=USERNAME/certmate:cache .
   ```

---

## Dépannage

### Le conteneur ne démarre pas

```bash
docker logs certmate
docker exec certmate env
```

### L'health check échoue

```bash
docker logs certmate
docker exec certmate curl -v http://localhost:8000/health
```

### Problèmes de permissions

```bash
docker exec certmate ls -la /app/certificates
docker exec certmate ls -la /app/data
```

### Problèmes de construction multi-plateforme

| Erreur | Solution |
|--------|----------|
| "multiple platforms not supported for docker driver" | `docker buildx create --name multiplatform --use` |
| "exec format error" | `docker run --privileged --rm tonistiigi/binfmt --install all` |
| Constructions non-natives lentes | Normal dû à l'émulation ; utilisez GitHub Actions pour la production |
| Impossible de charger multi-plateforme dans Docker local | Utilisez `--load` avec une seule plateforme pour les tests locaux |

---

## Tailles d'image

Tailles typiques par architecture :
- **AMD64** : ~200-300 MB
- **ARM64** : ~200-300 MB
- **ARM v7** : ~180-250 MB

---

<div align="center">

[← Retour à la documentation](./README.md) • [Installation →](./installation.md) • [Architecture →](./architecture.md)

</div>
