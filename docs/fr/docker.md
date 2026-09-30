# Construction et déploiement Docker

<!-- CERTMATE-TRANSLATED-FROM 875370d723412467 -->

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
- **N'écoute que sur 127.0.0.1.** Pour un accès distant, placez un reverse proxy devant et définissez `BEHIND_PROXY=true`. `CERTMATE_BIND=0.0.0.0` le publie sur toutes les interfaces. `CERTMATE_PORT` change le port de l'hôte.
- **Refuse de démarrer sans `API_BEARER_TOKEN` et `SECRET_KEY`**, au lieu de générer des valeurs qui changeraient à chaque recréation du conteneur.

Variables facultatives pour `.env` : `CLOUDFLARE_TOKEN` (crée un compte DNS Cloudflare au premier démarrage), `LETSENCRYPT_EMAIL`, `BEHIND_PROXY`.

**Mise à jour :** téléchargez de nouveau le fichier (ou changez `CERTMATE_VERSION`), puis exécutez `docker compose pull && docker compose up -d`.

Le `docker-compose.yml` à la racine du dépôt construit l'image à partir des sources et sert au développement.

---

## Portainer

Dans Portainer, déployez le [bundle compose de production](#en-production-avec-docker-compose) comme stack directement depuis ce dépôt :

1. **Stacks → Add stack**, nommez-le `certmate` et choisissez **Repository**.
2. URL du dépôt `https://github.com/fabriziosalmi/certmate`, référence `refs/heads/main`, chemin compose `deploy/docker-compose.yml`.
3. Dans **Environment variables**, ajoutez `API_BEARER_TOKEN`, `SECRET_KEY` et `CERTMATE_BACKUP_PASSPHRASE`, chacun avec une longue valeur aléatoire comme la sortie de `openssl rand -hex 32`. Facultatifs : `CERTMATE_PORT`, `CERTMATE_BIND` ou `CLOUDFLARE_TOKEN`.
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
SECRET_KEY=votre-cle-super-secrete
# SECRET_KEY_FILE=/run/secrets/secret_key  # Alternative : prioritaire sur SECRET_KEY
API_BEARER_TOKEN=votre-token-bearer-api
# API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token  # Alternative : prioritaire sur API_BEARER_TOKEN
CLOUDFLARE_TOKEN=votre-token-cloudflare
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
  -e SECRET_KEY="votre-cle-secrete" \
  -e API_BEARER_TOKEN="votre-token-bearer-api" \
  -e CLOUDFLARE_TOKEN="votre-token-api" \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  certmate:latest
```

### Référence des variables d'environnement

| Variable | Requis | Description |
|----------|--------|-------------|
| `SECRET_KEY` | Non | Clé secrète Flask pour les sessions (auto-générée si non définie) |
| `SECRET_KEY_FILE` | Non | Chemin vers un fichier contenant la clé secrète Flask (prioritaire sur `SECRET_KEY`) |
| `API_BEARER_TOKEN` | Non (auto-généré) | Token d'authentification de l'API. Auto-généré si non défini, mais définissez-le avant d'exposer sur un réseau une instance pas encore configurée ; une fois défini, collez-le une fois sur l'écran de premier démarrage pour créer l'administrateur |
| `API_BEARER_TOKEN_FILE` | Non | Chemin vers un fichier contenant le token bearer API (prioritaire sur `API_BEARER_TOKEN`) |
| `CERTMATE_LOG_LEVEL` | Non | `INFO` (défaut), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | Non | Quand défini, sauvegardes chiffrées au repos (`.zip.enc`, PBKDF2-SHA256 + Fernet) |
| `CLOUDFLARE_TOKEN` | Non | Token API du compte DNS Cloudflare par défaut. Cloudflare est le seul fournisseur DNS lu depuis l'environnement : Route53 et les autres se configurent dans Paramètres → Fournisseurs DNS ou via l'API, et définir `AWS_ACCESS_KEY_ID` dans le conteneur n'a aucun effet |

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
      - API_BEARER_TOKEN=${API_BEARER_TOKEN:-}
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
docker-compose up -d

# Ou spécifier un fichier .env différent
docker-compose --env-file /chemin/vers/.env up -d
```

---

## Podman (Quadlet, rootless) et OpenShift

[`deploy/podman/certmate.container`](../../deploy/podman/certmate.container) est une unité Quadlet : Podman en fait un service systemd. Elle exécute l'image publiée avec des volumes nommés, le port uniquement sur loopback, les secrets comme secrets Podman, un healthcheck et la prise en charge de `podman auto-update`.

En rootless, avec votre propre utilisateur (les trois secrets sont créés une fois et n'apparaissent dans aucun fichier ; `enable-linger` le garde actif sans session et le démarre au boot) :

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

En rootful : placez le fichier dans `/etc/containers/systemd/`, créez les secrets en root, puis `sudo systemctl daemon-reload && sudo systemctl start certmate`.

Ouvrez `http://127.0.0.1:8000`. La première page crée le compte administrateur et demande le jeton API : `podman secret inspect --showsecret certmate-api-token --format '{{.SecretData}}'`.

Vérifié sur Fedora 44 avec Podman 5.8, en rootful et en rootless : le service démarre sain, le jeton autorise l'API, et il revient après un redémarrage (en rootless grâce au lingering). Les volumes utilisent `:U` : en rootless, Podman laissait la racine du volume `backups` à root et CertMate ne démarrait pas. Les UID arbitraires, les bind mounts et podman-compose sont décrits dans la [page anglaise](../docker.md#podman-quadlet-rootless-and-openshift).

---

## Constructions multi-plateforme

CertMate supporte les images Docker multi-plateforme pour les architectures ARM et AMD64.

### Architectures supportées

| Plateforme | Description | Cas d'usage courants |
|------------|-------------|----------------------|
| `linux/amd64` | Intel/AMD 64-bit | La plupart des serveurs cloud, postes de travail |
| `linux/arm64` | ARM 64-bit | Apple Silicon, instances cloud ARM |
| `linux/arm/v7` | ARM 32-bit v7 | Raspberry Pi 3+ |
| `linux/arm/v6` | ARM 32-bit v6 | Raspberry Pi 1, Zero |

### Scripts de construction

```bash
# Construire pour la plateforme courante uniquement
./build-docker.sh

# Construire pour plusieurs plateformes (ARM64 + AMD64)
./build-docker.sh -m

# Construire et pousser vers Docker Hub
./build-docker.sh -m -p -r VOTRE_UTILISATEUR_DOCKERHUB

# Script dédié multi-plateforme
./build-multiplatform.sh -r UTILISATEUR -v v1.0.0 -p

# Construire pour Raspberry Pi
./build-multiplatform.sh --platforms linux/arm/v7 -r UTILISATEUR -p
```

### Docker Buildx manuel

```bash
# Créer et utiliser le builder buildx
docker buildx create --name certmate-builder --use

# Construire pour plusieurs plateformes
docker buildx build --platform linux/amd64,linux/arm64 \
  -t UTILISATEUR/certmate:latest .

# Construire et pousser
docker buildx build --platform linux/amd64,linux/arm64 \
  -t UTILISATEUR/certmate:latest --push .
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
docker build -t UTILISATEUR/certmate:latest .
docker push UTILISATEUR/certmate:latest

# Avec un tag de version
docker build -t UTILISATEUR/certmate:v1.0.0 .
docker push UTILISATEUR/certmate:v1.0.0
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
   docker buildx build --cache-from type=registry,ref=UTILISATEUR/certmate:cache .
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
