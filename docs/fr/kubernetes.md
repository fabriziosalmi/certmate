# CertMate sur Kubernetes

<!-- CERTMATE-TRANSLATED-FROM c0ef74162bfa4e87 -->

Installez CertMate avec son chart Helm, directement ou via Argo CD ou Flux, puis dimensionnez-le pour la production. Le README du chart décrit chaque valeur : [charts/certmate/README.md](../../charts/certmate/README.md).

## Installer avec Helm

Le chart est publié sur GHCR en tant qu'artefact OCI à chaque version, il n'y a donc pas d'étape `helm repo add` (Helm 3.8+). Sa version est celle de CertMate : sans `--version`, Helm prend la plus récente, et `--version X.Y.Z` en fixe une.

Créez d'abord le Secret, afin que l'instance conserve le même jeton et la même clé de session entre les redémarrages :

```bash
kubectl create namespace certmate
kubectl -n certmate create secret generic certmate-secrets \
  --from-literal=API_BEARER_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=CERTMATE_BACKUP_PASSPHRASE="$(openssl rand -hex 32)"

helm install certmate oci://ghcr.io/fabriziosalmi/charts/certmate \
  --namespace certmate \
  --set secrets.existingSecret=certmate-secrets

kubectl -n certmate port-forward svc/certmate 8000:8000
```

Ouvrez `http://127.0.0.1:8000`. La première page crée le compte administrateur et demande le `API_BEARER_TOKEN` stocké dans le Secret (`kubectl -n certmate get secret certmate-secrets -o jsonpath='{.data.API_BEARER_TOKEN}' | base64 -d`). Ajoutez `CLOUDFLARE_TOKEN` au même Secret pour initialiser un compte DNS Cloudflare ; les autres fournisseurs DNS se configurent dans l'interface web.

Mettez à jour avec `helm upgrade certmate oci://ghcr.io/fabriziosalmi/charts/certmate --namespace certmate --reuse-values`. Pour l'Ingress, la persistance et les sauvegardes, consultez le README du chart.

## GitOps avec Argo CD

Le Secret ci-dessus est créé une seule fois, en dehors de Git. Ensuite :

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: certmate
  namespace: argocd
spec:
  project: default
  source:
    repoURL: ghcr.io/fabriziosalmi/charts
    chart: certmate
    targetRevision: "2.*"
    helm:
      valuesObject:
        secrets:
          existingSecret: certmate-secrets
  destination:
    server: https://kubernetes.default.svc
    namespace: certmate
  syncPolicy:
    automated: {}
```

`repoURL` n'a pas de préfixe `oci://` : Argo CD prend séparément le chemin du registre et le nom du chart. `2.*` suit les nouvelles versions 2.x ; indiquez une version exacte pour en fixer une.

## GitOps avec Flux

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: certmate
  namespace: certmate
spec:
  interval: 1h
  url: oci://ghcr.io/fabriziosalmi/charts/certmate
  ref:
    semver: "2.x"
  layerSelector:
    mediaType: application/vnd.cncf.helm.chart.content.v1.tar+gzip
    operation: copy
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: certmate
  namespace: certmate
spec:
  interval: 1h
  chartRef:
    kind: OCIRepository
    name: certmate
  values:
    secrets:
      existingSecret: certmate-secrets
```

`semver: "2.x"` suit les nouvelles versions 2.x ; utilisez `tag: X.Y.Z` pour en fixer une.

Ces trois méthodes ont été vérifiées sur un cluster k3s 1.31, avec Helm 4.1, Argo CD 3.5 et Flux (source-controller 1.9) : chacune installe le chart et l'instance se déclare en bonne santé.

---

# Notes de production

Cette partie présente la configuration de dimensionnement de base pour CertMate
en production lorsqu'il fonctionne derrière un Ingress/HTTPRoute Kubernetes et
utilise un backend de certificats distant comme Azure Key Vault.

## Ressources recommandées

CertMate exécute gunicorn plus des sous-processus certbot dans le même conteneur.
Pendant la création ou le renouvellement de certificats, certbot et les plugins
DNS peuvent temporairement ajouter un pic de mémoire important. Avec Azure Key
Vault en mode `both`, lister les certificats effectue également des appels
distants, donc des limites très restreintes peuvent transformer des opérations
de routine en redémarrages OOM.

Utilisez cette configuration de base pour les pods de production gérant des dizaines de certificats :

```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 1536Mi
env:
  - name: CERTMATE_CERT_INFO_CACHE_TTL
    value: "60"
  - name: GUNICORN_TIMEOUT
    value: "300"
```

Avec le chart Helm, définissez la même chose dans votre fichier de valeurs. La limite mémoire par défaut du chart est de 512Mi, ce qui, comme l'explique le paragraphe suivant, est trop peu pour l'émission sous charge :

```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 1536Mi
extraEnv:
  - name: CERTMATE_CERT_INFO_CACHE_TTL
    value: "60"
```

Pour le mode de défaillance spécifique où un pod avec `memory: 512Mi` redémarre
pendant la création d'un certificat, augmentez d'abord la limite mémoire. Le
chemin de code évite désormais les sous-processus `openssl` de l'ancienne vue
liste, utilise des lectures légères d'informations de certificat Azure Key Vault,
et exclut les répertoires temporaires/historique de certbot des sauvegardes de
routine, mais certbot a toujours besoin de marge pendant l'émission des certificats.

## Exemple de patch du Deployment

Pour un Deployment qui n'est pas géré par le chart Helm (le chart étiquette ses pods `app.kubernetes.io/name=certmate`, et non `app=certmate`). Avec le chart, utilisez plutôt les valeurs ci-dessus.

```bash
kubectl -n certificate-management patch deployment certmate --type='strategic' -p '
spec:
  template:
    spec:
      containers:
        - name: certmate
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: "1"
              memory: 1536Mi
          env:
            - name: CERTMATE_CERT_INFO_CACHE_TTL
              value: "60"
            - name: GUNICORN_TIMEOUT
              value: "300"
'
```

Vérifiez la prochaine raison de redémarrage après l'application :

```bash
kubectl -n certificate-management describe pod -l app=certmate | grep -A6 "Last State"
kubectl -n certificate-management top pod -l app=certmate
```

## Nombre de réplicas

Exécutez `replicas: 1`. CertMate exécute son planificateur de renouvellement des
certificats **dans le processus**, de sorte que chaque pod (et chaque worker
gunicorn) déclenche la vérification de renouvellement indépendamment. Avec plus
d'un écrivain, cela signifie des commandes ACME en double et la limite de débit
de la CA sur les certificats en double — ainsi que des accès concurrents sur les
paramètres locaux, les métadonnées, les sauvegardes et l'état d'exécution que
CertMate conserve même lorsque les certificats résident dans un backend distant
(Azure Key Vault, Vault, S3).

Un `flock` local à l'hôte (`/app/data/.renewal.lock`) empêche les renouvellements
en double lorsque plusieurs workers/conteneurs partagent le **même** volume de
données sur un hôte, mais il ne coordonne **pas** les pods sur des volumes/nœuds
distincts. N'augmentez donc le nombre de réplicas que si chaque chemin mutable
(`/app/data`, `/app/certificates`, `/app/backups`, `/app/logs`) est un volume
unique partagé par tous les pods ET que vous avez validé le comportement du
renouvellement — sinon, conservez un seul écrivain et, pour la disponibilité,
placez une seule instance active derrière un frontal plutôt que de mettre à
l'échelle ce Deployment.

## Le badge de statut de déploiement indique "Backend : Inaccessible"

*Mis à jour le 2026-05-25 (voir [#263](https://github.com/fabriziosalmi/certmate/issues/263)).*

Le badge de statut de déploiement sur le tableau de bord est un indicateur de
santé optionnel et **n'affecte pas** l'émission, le renouvellement ou le
téléchargement. Le processus CertMate ouvre une connexion TLS directe vers
`<domain>:443` et compare l'empreinte du certificat servi avec celle stockée :

- **Déployé** — la poignée de main a réussi et l'empreinte correspond.
- **Mauvais certificat** — la poignée de main a réussi mais un certificat différent est servi.
- **Inaccessible** — le pod n'a pas pu établir de connexion TLS vers le domaine.

Sur Kubernetes, **Inaccessible pour chaque certificat est normal** lorsque le
pod CertMate ne peut pas établir de connexion directe avec votre IP
publique/Ingress. Causes courantes :

- Le domaine résout une IP publique/Ingress qui n'est pas routable depuis
  l'intérieur du pod (hairpin/NAT ou DNS split-horizon).
- Une `NetworkPolicy` de sortie bloque le port 443 sortant.
- TLS est terminé par votre contrôleur Ingress ou un équilibreur de charge externe,
  donc il n'y a aucun endpoint que CertMate peut atteindre directement.
- La sonde est simplement lente et dépasse le budget par défaut de 3 secondes.

Si la cible est accessible mais lente, augmentez le budget de sondage :

```yaml
env:
  - name: CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
    value: "10"   # accepts 1–30 seconds; default is 3
```

Sinon, le badge peut être ignoré en toute sécurité dans une topologie
Ingress/Kubernetes — les certificats sont émis et servis correctement même
lorsque CertMate ne peut pas les sonder lui-même.
