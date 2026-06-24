# Documentation CertMate

Bienvenue dans la documentation de CertMate. Ce dossier contient des guides complets pour toutes les fonctionnalités.

---

## Navigation rapide

### Pour commencer
- **[Guide d'installation](./installation.md)** — Configuration, dépendances, déploiement en production
- **[Guide Docker](./docker.md)** — Constructions Docker, multi-plateforme, Docker Compose
- **[Notes Kubernetes](./kubernetes.md)** — Ressources production, dimensionnement OOM, correctifs runtime

### Fonctionnalités principales
- **[Fournisseurs DNS](./dns-providers.md)** — Fournisseurs supportés, multi-comptes, alias de domaine
- **[Fournisseurs CA](./ca-providers.md)** — Let's Encrypt, DigiCert, CA privée
- **[Certificats clients](./guide.md)** — Cycle de vie des certificats clients, tableau de bord Web, opérations par lots
- **[Serveur MCP (Model Context Protocol)](./mcp.md)** — Serveur Node.js autonome pour l'intégration avec des agents IA

### Référence
- **[Référence API](./api.md)** — Documentation complète de l'API REST
- **[Architecture](./architecture.md)** — Conception du système, composants, flux de données
- **[Guide de test](./testing.md)** — Framework de test, CI/CD, couverture

---

## Documentation par public

### Pour les nouveaux utilisateurs

1. **[Installation](./installation.md)** — Faire fonctionner CertMate
2. **[Fournisseurs DNS](./dns-providers.md)** — Configurer votre fournisseur DNS
3. **[Guide des certificats clients](./guide.md)** — Créer votre premier certificat

### Pour les développeurs

1. **[Référence API](./api.md)** — Tous les endpoints avec exemples
2. **[Architecture](./architecture.md)** — Fonctionnement interne et conception
3. **[Guide de test](./testing.md)** — Comment écrire et exécuter des tests

### Pour les administrateurs

1. **[Déploiement Docker](./docker.md)** — Configuration Docker pour la production
2. **[Notes Kubernetes](./kubernetes.md)** — Dimensionnement des pods et correctifs opérationnels
3. **[Fournisseurs CA](./ca-providers.md)** — Configurer les autorités de certification
4. **[Fournisseurs DNS](./dns-providers.md#support-multi-comptes)** — Configuration multi-comptes entreprise

---

## Aperçu des fonctionnalités

### Certificats serveur
- **Plus de deux douzaines de fournisseurs DNS** pour les défis Let's Encrypt DNS-01 (voir [Fournisseurs DNS](./dns-providers.md) pour la liste complète)
- **Plusieurs fournisseurs CA** : Let's Encrypt, DigiCert, CA privée
- **Support multi-comptes** par fournisseur DNS
- **Backends de stockage interchangeables** : Local, Azure Key Vault, AWS, Vault, Infisical
- **Renouvellement automatique** avec seuils configurables
- **Support Docker** avec constructions multi-plateforme (ARM64 + AMD64)
- **Nettoyeur de logs** — Supprime automatiquement les tokens API, clés privées et identifiants sensibles des logs CertMate
- **Analyseur de certificats zombies** — Analyseur multi-threadé du système de fichiers pour identifier et nettoyer les certificats orphelins
- **Serveur MCP (Model Context Protocol)** — Serveur Node.js autonome pour l'intégration avec des assistants IA agentiques

### Certificats clients
- **CA auto-signée** avec clés RSA 4096 bits
- **Gestion complète du cycle de vie** — créer, renouveler, révoquer, surveiller
- **OCSP & CRL** — statut en temps réel et listes de révocation
- **Tableau de bord Web** sur `/client-certificates`
- **Opérations par lots** — importer 100 à 30 000 certificats via CSV
- **Journalisation d'audit** et **limitation de débit**

---

## Référence rapide des endpoints API

| Méthode | Endpoint                                 | Description              |
| ------- | ---------------------------------------- | ------------------------ |
| POST    | `/api/client-certs/create`               | Créer un certificat      |
| GET     | `/api/client-certs`                      | Lister les certificats   |
| GET     | `/api/client-certs/<id>`                 | Obtenir les métadonnées  |
| GET     | `/api/client-certs/<id>/download/<type>` | Télécharger cert/clé/csr |
| POST    | `/api/client-certs/<id>/revoke`          | Révoquer un certificat   |
| POST    | `/api/client-certs/<id>/renew`           | Renouveler un certificat |
| GET     | `/api/client-certs/stats`                | Obtenir les statistiques |
| POST    | `/api/client-certs/batch`                | Import CSV par lots      |
| GET     | `/api/ocsp/status/<serial>`              | Statut OCSP              |
| GET     | `/api/crl/download/<format>`             | Télécharger la CRL       |

Voir la [Référence API](./api.md#endpoints) pour la documentation complète.

---

## Tests

Toutes les fonctionnalités sont testées de manière approfondie :

```bash
# Exécuter les tests
python -m pytest tests/ -v
```

La couverture des tests inclut :
- Opérations CA
- Opérations CSR
- Cycle de vie des certificats
- Filtrage et recherche
- Opérations par lots
- OCSP & CRL
- Audit et limitation de débit

---

## Fonctionnalités de sécurité

- **RSA 4096 bits** pour les clés CA
- **Algorithme de signature** SHA256
- **Authentification** par Bearer token
- **Limitation de débit** sur tous les endpoints
- **Journalisation d'audit** de toutes les opérations
- **Permissions de fichiers** 0600 pour les clés privées

---

## Performance

- Supporte **30 000+ certificats simultanés**
- Requêtes **multi-filtres** efficaces
- Planification du **renouvellement automatique**
- **Opérations par lots** avec suivi des erreurs

---

## Structure des fichiers

```
docs/
  README.md            ← Vous êtes ici
  index.md             ← Page d'accueil des certificats clients
  installation.md      ← Installation et configuration
  kubernetes.md        ← Notes de production Kubernetes
  dns-providers.md     ← Fournisseurs DNS et multi-comptes
  ca-providers.md      ← Fournisseurs d'autorité de certification
  docker.md            ← Construction et déploiement Docker
  testing.md           ← Framework de test et CI/CD
  guide.md             ← Guide d'utilisation des certificats clients
  api.md               ← Référence API complète
  architecture.md      ← Architecture du système
```

---

## Parcours d'apprentissage

**Débutant** → [Commencer ici](./index.md) → [Guide de démarrage](./guide.md)

**Développeur** → [Référence API](./api.md) → [Architecture](./architecture.md)

**Avancé** → [Documentation API complète](./api.md) → [Détails d'architecture](./architecture.md)

---

## Liens importants

- **Tableau de bord Web** : `http://localhost:8000/client-certificates`
- **Documentation API** : `http://localhost:8000/docs/`
- **Vérification de santé** : `http://localhost:8000/health`
- **Journaux d'audit** : `logs/audit/certificate_audit.log`

---

## Tableau de bord des statuts

| Composant           | Statut    | Tests     |
| ------------------- | --------- | --------- |
| Fondation CA        | Prêt      | 3/3       |
| Gestionnaire CSR    | Prêt      | 3/3       |
| Gestionnaire cert.  | Prêt      | 8/8       |
| Filtrage            | Prêt      | 3/3       |
| Opérations par lots | Prêt      | 2/2       |
| OCSP/CRL            | Prêt      | 5/5       |
| Audit/Limitation    | Prêt      | 3/3       |
| **Total**           | **Prêt**  | **27/27** |

---

## Exemples rapides

### Créer un certificat via l'API

```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer VOTRE_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
   "common_name": "user@example.com",
   "organization": "ACME Corp",
   "cert_usage": "api-mtls",
   "days_valid": 365
 }'
```

### Lister les certificats

```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer VOTRE_TOKEN"
```

### Télécharger un certificat

```bash
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer VOTRE_TOKEN" \
 -o certificate.crt
```

Voir le [Guide API](./api.md) pour plus d'exemples.

---

## Licence

CertMate est sous licence MIT. Voir le fichier LICENSE dans le dépôt.

---

## Questions ou problèmes ?

- Consultez la page de documentation pertinente
- Passez en revue les fichiers de test pour des exemples d'utilisation
- Consultez la [Référence API](./api.md) pour les détails des endpoints

---

<div align="center">

[Accueil](../README.md) • [Documentation](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
