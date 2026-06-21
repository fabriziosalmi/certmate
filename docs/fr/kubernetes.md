# Notes de production Kubernetes

Ce guide capture la configuration de dimensionnement de base pour CertMate lorsqu'il fonctionne derrière un Ingress/HTTPRoute Kubernetes et utilise un backend de certificats distant comme Azure Key Vault.

## Ressources recommandées

CertMate exécute gunicorn plus des sous-processus certbot dans le même conteneur. Pendant la création ou le renouvellement de certificats, certbot et les plugins DNS peuvent temporairement ajouter un pic de mémoire important. Avec Azure Key Vault en mode `both`, lister les certificats effectue également des appels distants, donc des limites très restreintes peuvent transformer des opérations de routine en redémarrages OOM.

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

Pour le mode de défaillance spécifique où un pod avec `memory: 512Mi` redémarre pendant la création d'un certificat, augmentez d'abord la limite mémoire. Le chemin de code évite désormais les sous-processus `openssl` de l'ancienne vue liste, utilise des lectures légères d'informations de certificat Azure Key Vault, et exclut les répertoires temporaires/historique de certbot des sauvegardes de routine, mais certbot a toujours besoin de marge pendant l'émission des certificats.

## Exemple d'application du patch

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

Exécutez `replicas: 1` sauf si tous les chemins mutables (`/app/data`, `/app/certificates`, `/app/backups`, `/app/logs`) sont soutenus par un stockage sûr pour les accès concurrents et que vous avez validé le comportement du planificateur/renouvellement pour plusieurs pods. Azure Key Vault peut stocker les certificats à distance, mais CertMate conserve toujours localement les paramètres, métadonnées, sauvegardes et état d'exécution.

## Le badge de statut de déploiement indique "Backend : Inaccessible"

*Mis à jour le 2026-05-25 (voir [#263](https://github.com/fabriziosalmi/certmate/issues/263)).*

Le badge de statut de déploiement sur le tableau de bord est un indicateur de santé optionnel et **n'affecte pas** l'émission, le renouvellement ou le téléchargement. Le processus CertMate ouvre une connexion TLS directe vers `<domain>:443` et compare l'empreinte du certificat servi avec celle stockée :

- **Déployé** — la poignée de main a réussi et l'empreinte correspond.
- **Mauvais certificat** — la poignée de main a réussi mais un certificat différent est servi.
- **Inaccessible** — le pod n'a pas pu établir de connexion TLS vers le domaine.

Sur Kubernetes, **Inaccessible pour chaque certificat est normal** lorsque le pod CertMate ne peut pas établir de connexion directe avec votre IP publique/Ingress. Causes courantes :

- Le domaine résout une IP publique/Ingress qui n'est pas routable depuis l'intérieur du pod (hairpin/NAT ou DNS split-horizon).
- Une `NetworkPolicy` de sortie bloque le port 443 sortant.
- TLS est terminé par votre contrôleur Ingress ou un équilibreur de charge externe, donc il n'y a aucun endpoint que CertMate peut atteindre directement.
- La sonde est simplement lente et dépasse le budget par défaut de 3 secondes.

Si la cible est accessible mais lente, augmentez le budget de sondage :

```yaml
env:
  - name: CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
    value: "10"   # accepte 1–30 secondes ; défaut 3
```

Sinon, le badge peut être ignoré en toute sécurité dans une topologie Ingress/Kubernetes — les certificats sont émis et servis correctement même lorsque CertMate ne peut pas les sonder lui-même.

---

<div align="center">

[← Retour à la documentation](./README.md) • [Guide Docker →](./docker.md)

</div>
