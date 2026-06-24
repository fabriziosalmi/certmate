# CertMate - Certificats Clients

<div align="center">

![CertMate](https://img.shields.io/badge/CertMate-Certificats%20Clients-blue?style=for-the-badge)
![Statut](https://img.shields.io/badge/Statut-Prêt%20Production-green?style=for-the-badge)

**Gestion complète de certificats clients pour CertMate**

[Documentation](#documentation) • [Démarrage rapide](#démarrage-rapide) • [Référence API](./api.md) • [Architecture](./architecture.md)

</div>

---

## Vue d'ensemble

CertMate Certificats Clients est une solution complète et prête pour la production pour la gestion de certificats clients avec :

- **CA auto-signée** — Générez et gérez votre propre Autorité de Certification
- **Gestion complète du cycle de vie** — Créez, renouvelez, révoquez et surveillez les certificats clients
- **OCSP & CRL** — Statut des certificats en temps réel et listes de révocation
- **Tableau de bord Web** — Interface intuitive pour la gestion des certificats
- **API REST** — API complète pour l'automatisation
- **Opérations par lots** — Importez 100 à 30 000 certificats via CSV
- **Journal d'audit** — Suivez toutes les opérations pour la conformité
- **Limitation de débit** — Protection intégrée contre les abus

---

## Fonctionnalités

### Phase 1 : Fondation CA
- **PrivateCAGenerator** : CA auto-signée avec clés RSA 4096 bits, validité 10 ans
- **CSRHandler** : Validez, créez et analysez les demandes de signature de certificat
- **Stockage sécurisé** : Permissions de fichiers appropriées (0600) pour les clés privées

### Phase 2 : Moteur de certificats clients
- **Cycle de vie complet** : Créez, listez, filtrez, révoquez et renouvelez les certificats
- **Requêtes multi-filtres** : Recherche par type d'utilisation, statut de révocation, nom commun
- **Renouvellement automatique** : Vérifications quotidiennes planifiées pour les certificats expirants
- **Support pour 30k+ certificats** : Stockage par répertoire pour une scalabilité linéaire
- **Gestion des métadonnées** : Suivi du CN, email, organisation, utilisation, dates d'expiration

### Phase 3 : Interface utilisateur et fonctionnalités avancées
- **Tableau de bord Web** : Interface de gestion réactive avec mode sombre
- **Répondeur OCSP** : Interrogez le statut des certificats en temps réel
- **Gestionnaire CRL** : Générez et distribuez les listes de révocation (PEM/DER)
- **API REST** : 10 endpoints dans 3 espaces de noms pour une automatisation complète
- **Opérations par lots** : Importez des certificats depuis des fichiers CSV

### Phase 4 : Gains rapides
- **Journal d'audit** : Suivez toutes les opérations sur les certificats avec informations utilisateur/IP
- **Limitation de débit** : Limites configurables par endpoint avec valeurs par défaut sensées
- **Prêt pour l'intégration** : Les deux gestionnaires disponibles dans l'application pour une utilisation immédiate

---

## Démarrage rapide

### Installation

```bash
pip install -r requirements.txt
python app.py
```

Le serveur démarre sur `http://localhost:8000`

### Utilisation de base

#### 1. Accéder au tableau de bord Web
```
Accédez à : http://localhost:8000/client-certificates
```

#### 2. Créer un certificat via l'API
```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer VOTRE_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true
 }'
```

#### 3. Lister les certificats
```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer VOTRE_TOKEN"
```

#### 4. Télécharger les fichiers de certificat
```bash
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer VOTRE_TOKEN" \
 -o user.crt

curl http://localhost:8000/api/client-certs/USER_ID/download/key \
 -H "Authorization: Bearer VOTRE_TOKEN" \
 -o user.key
```

---

## Documentation

### Documentation principale

- **[Guide d'installation](./installation.md)** — Configuration, dépendances, déploiement
- **[Notes Kubernetes](./kubernetes.md)** — Dimensionnement des pods et dépannage OOM
- **[Fournisseurs DNS](./dns-providers.md)** — Fournisseurs supportés, multi-comptes, alias de domaine
- **[Fournisseurs CA](./ca-providers.md)** — Let's Encrypt, Actalis, DigiCert, CA privée
- **[Guide Docker](./docker.md)** — Constructions Docker, multi-plateforme, Compose
- **[Guide de test](./testing.md)** — Framework de test, CI/CD, couverture
- **[Référence API](./api.md)** — Documentation complète de l'API REST avec exemples
- **[Architecture](./architecture.md)** — Conception du système, composants et flux de données
- **[Guide d'utilisation](./guide.md)** — Guide pas à pas pour les tâches courantes

### Liens rapides

- [Endpoints API](./api.md#endpoints) — Tous les endpoints disponibles
- [Types de certificats](./api.md#certificate-types) — VPN, API mTLS, etc.
- [Limitation de débit](./api.md#rate-limiting) — Limites par défaut et configuration
- [Journal d'audit](./api.md#audit-logging) — Comprendre les pistes d'audit

---

## Tests

Toutes les fonctionnalités ont été testées de manière approfondie :

```bash
python -m pytest tests/ -v
```

### Couverture des tests
- Opérations CA (3 tests)
- Opérations CSR (3 tests)
- Cycle de vie des certificats (8 tests)
- Filtrage et recherche (3 tests)
- Opérations par lots (2 tests)
- OCSP et CRL (5 tests)
- Audit et limitation de débit (3 tests)

---

## Résumé des endpoints API

| Méthode | Endpoint                                 | Objectif                        |
| ------- | ---------------------------------------- | ------------------------------- |
| `POST`  | `/api/client-certs/create`               | Créer un nouveau certificat     |
| `GET`   | `/api/client-certs`                      | Lister les certificats avec filtres |
| `GET`   | `/api/client-certs/<id>`                 | Obtenir les métadonnées d'un certificat |
| `GET`   | `/api/client-certs/<id>/download/<type>` | Télécharger cert/key/csr        |
| `POST`  | `/api/client-certs/<id>/revoke`          | Révoquer un certificat          |
| `POST`  | `/api/client-certs/<id>/renew`           | Renouveler un certificat        |
| `GET`   | `/api/client-certs/stats`                | Obtenir les statistiques        |
| `POST`  | `/api/client-certs/batch`                | Import CSV par lots             |
| `GET`   | `/api/ocsp/status/<serial>`              | Requête de statut OCSP          |
| `GET`   | `/api/crl/download/<format>`             | Télécharger la CRL (PEM/DER)    |

---

## Architecture

Le système est construit avec une architecture modulaire en couches :

```

 Interface Web et API REST
 (/client-certificates, /api/*)

 Ressources API et gestionnaires
 (OCSP, CRL, Audit, Limitation de débit)

 Modules principaux
 (Gestion des certificats, CSR, CA, Stockage)

 Cryptographie et stockage
 (OpenSSL, Système de fichiers, Backends)

```

Voir la [Documentation d'architecture](./architecture.md) pour des informations détaillées.

---

## Sécurité

### Robustesse cryptographique
- **CA** : Clés RSA 4096 bits, validité 10 ans
- **Certificats clients** : RSA 2048 ou 4096 bits (configurable)
- **Signatures** : SHA256
- **Stockage des clés** : Permissions 0600 sur les systèmes Unix

### Contrôle d'accès
- **Authentification par jeton Bearer** sur tous les endpoints API
- **Limitation de débit** : Limites configurables par endpoint
- **Journal d'audit** : Toutes les opérations suivies avec informations utilisateur/IP

### Conformité
- Suivi des métadonnées des certificats
- Piste d'audit des révocations
- Journaux d'opérations persistants
- Support des requêtes de conformité

---

## Performance

L'implémentation est optimisée pour :
- **Scalabilité** : Le stockage par répertoire supporte 30k+ certificats simultanés
- **Vitesse** : Requêtes multi-filtres efficaces
- **Fiabilité** : Planification automatique du renouvellement
- **Réactivité** : JavaScript asynchrone dans l'interface Web

---

## Support

Pour des questions ou problèmes :
1. Consultez le [Guide d'utilisation](./guide.md)
2. Consultez la [Documentation API](./api.md)
3. Consultez la section [Architecture](./architecture.md)
4. Passez en revue les cas de test dans `test_e2e_complete.py`

---

## Licence

Voir le fichier LICENSE dans le dépôt

---

## Version

**Version actuelle** : 2.3.0
**Statut** : Prêt pour la production

---

<div align="center">

[Documentation](.) • [Licence](../LICENSE)

</div>
