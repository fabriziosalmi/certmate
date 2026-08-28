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
- **[Découverte et inventaire](../discovery-inventory.md)** — Découverte par sonde/CT-log, inventaire, adoption, maturité cryptographique *(en anglais)*
- **[Deploy hooks](./deploy-hooks.md)** — Hooks post-émission : configuration, test, expurgation de la sortie
- **[Conformité](./compliance.md)** — Chaîne d'audit, attribution des actions, posture NIS2/eIDAS
- **[Sondes de déploiement](./probes.md)** — Vérifier que le certificat renouvelé est réellement servi

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
- **Backends de stockage interchangeables** : Local, Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical, S3-compatible
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
- **Opérations par lots** — import CSV, 100 lignes maximum par requête
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
# La suite UI pilote Playwright contre un serveur vivant et ne peut pas
# partager le processus avec le reste ; e2e exige une instance active.
# La meme selection que `make test` et scripts/release.sh.
pytest -v --tb=short -m "not ui and not e2e"
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

<!-- Checked by tests/test_docs_navigation.py: this listing must match
     what is actually on disk. It used to omit six pages. -->

```
docs/fr/
  README.md           this file — documentation index  <- you are here
  THEME_MIGRATION.md  one-off theme migration record
  api.md              complete REST API reference
  architecture.md     system architecture
  ca-providers.md     certificate authorities
  compliance.md       audit chain, attribution, NIS2/eIDAS
  deploy-hooks.md     post-issuance deploy hooks
  dns-providers.md    DNS providers, multi-account, domain alias
  docker.md           Docker build and deployment
  guide.md            client-certificate user guide
  index.md            client-certificate landing page
  installation.md     installation and setup
  kubernetes.md       Kubernetes production notes and Helm chart
  mcp.md              MCP server for AI agents
  probes.md           deployment probes
  testing.md          test framework and CI/CD
```

---

## Parcours d'apprentissage

**Débutant** → [Commencer ici](./guide.md) → [Guide de démarrage](./guide.md)

**Développeur** → [Référence API](./api.md) → [Architecture](./architecture.md)

**Avancé** → [Documentation API complète](./api.md) → [Détails d'architecture](./architecture.md)

---

## Liens importants

- **Tableau de bord Web** : `http://localhost:8000/client-certificates`
- **Documentation API** : `http://localhost:8000/docs/`
- **Vérification de santé** : `http://localhost:8000/health`
- **Journaux d'audit** : `logs/audit/certificate_audit.log`

---

## Etat des tests

Il n'y a pas ici de tableau de bord maintenu a la main. Un decompte de tests est perime des le lendemain : celui-ci indiquait `27/27` alors que la suite depassait les deux mille.

Le signal faisant autorite est la CI sur `main` : les badges en haut du [README du projet](../../README.md) et le plancher de couverture impose dans [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

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

---

**Version actuelle** : 2.26.1

<div align="center">

[Accueil](../README.md) • [Documentation](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
