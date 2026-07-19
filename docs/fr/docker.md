# Construction et déploiement Docker

Ce guide couvre la construction, le déploiement et l'exécution de CertMate dans Docker — incluant le support multi-plateforme pour ARM et AMD64.

---

## Démarrage rapide

### Pull et exécution

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
CLOUDFLARE_API_TOKEN=votre-token-cloudflare
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

### Option 2 : Variables d'environnement directes

```bash
docker run -d --name certmate \
  -e SECRET_KEY="votre-cle-secrete" \
  -e API_BEARER_TOKEN="votre-token-bearer-api" \
  -e CLOUDFLARE_API_TOKEN="votre-token-api" \
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
| `LOG_LEVEL` | Non | `INFO` (défaut), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | Non | Quand défini, sauvegardes chiffrées au repos (`.zip.enc`, PBKDF2-SHA256 + Fernet) |
| `CLOUDFLARE_API_TOKEN` | Non | Token du fournisseur DNS Cloudflare |
| `AWS_ACCESS_KEY_ID` | Non | Clé d'accès AWS Route53 |
| `AWS_SECRET_ACCESS_KEY` | Non | Clé secrète AWS Route53 |

Voir le [Guide d'installation](./installation.md#variables-denvironnement) pour la liste complète.

---

## Docker Compose

### Configuration de base

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
      - API_BEARER_TOKEN=${API_BEARER_TOKEN:-}
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
# Démarrer avec le fichier .env dans le même répertoire
docker-compose up -d

# Ou spécifier un fichier .env différent
docker-compose --env-file /chemin/vers/.env up -d
```

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
- `DOCKERHUB_USERNAME`
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
