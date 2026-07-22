# Architecture de CertMate

Ce document couvre l'architecture complète de CertMate — à la fois le système de certificats serveur principal et le sous-système de certificats clients.

---

## Table des matières

- [Architecture du système principal](#architecture-du-système-principal)
- [Diagramme haut niveau](#diagramme-haut-niveau)
- [Classes de gestion (Managers)](#classes-de-gestion-managers)
- [Flux de création de certificat](#flux-de-création-de-certificat)
- [Architecture de stockage](#architecture-de-stockage)
- [Structure de configuration](#structure-de-configuration)
- [Endpoints API](#endpoints-api)
- [Pile technologique](#pile-technologique)
- [Architecture des certificats clients](#architecture-des-certificats-clients)

---

## Architecture du système principal

CertMate est un système modulaire et extensible de gestion de certificats SSL/TLS construit avec Python/Flask. Il supporte plusieurs fournisseurs CA, plus de deux douzaines de fournisseurs DNS et des backends de stockage interchangeables.

**Points clés :**
- **Langage** : Python 3.9+ (Flask, Flask-RESTX)
- **Stockage** : Système de fichiers local par défaut + 4 backends cloud (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical)
- **Fournisseurs CA** : Let's Encrypt, DigiCert ACME, CA privée
- **Fournisseurs DNS** : plus de deux douzaines supportés (Cloudflare, AWS Route53, Azure, Google, etc. — voir [Fournisseurs DNS](./dns-providers.md) pour la liste complète)
- **API** : REST avec Swagger/OpenAPI via Flask-RESTX
- **Types de certificats actuels** : TLS côté serveur (DV, OV, EV)

---

## Diagramme haut niveau

```
┌─────────────────────────────────────────────────────┐
│              Application CertMate                   │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │           Couche Web (Flask)                   │  │
│  │  Dashboard    Paramètres    Aide    Cert. Clts │  │
│  └────────────────────┬──────────────────────────┘  │
│                       ↓                             │
│  ┌──────────────────┐   ┌────────────────────────┐  │
│  │  API REST         │   │  Routes Web            │  │
│  │  /api/certificates│   │  /api/web/certificates │  │
│  │  /api/client-certs│   │  /client-certificates  │  │
│  └────────┬─────────┘   └────────┬───────────────┘  │
│           └──────────┬───────────┘                   │
│                      ↓                               │
│  ┌───────────────────────────────────────────────┐  │
│  │     Couche Manager (Logique métier)            │  │
│  │                                               │  │
│  │  CertificateManager    CAManager              │  │
│  │  DNSManager            StorageManager         │  │
│  │  AuthManager           SettingsManager        │  │
│  │  CacheManager          FileOperations         │  │
│  │  ClientCertManager     OCSPResponder          │  │
│  │  CRLManager            AuditLogger            │  │
│  └────────────────────┬──────────────────────────┘  │
│                       ↓                             │
│  ┌───────────────────────────────────────────────┐  │
│  │          Couche d'exécution                   │  │
│  │  Certbot (certs serveur via DNS-01 ACME)      │  │
│  │  PrivateCA (certs clients via signature directe)│ │
│  └────────────────────┬──────────────────────────┘  │
│                       ↓                             │
│  ┌───────────────────────────────────────────────┐  │
│  │     Couche de stockage (Backends interchange.) │  │
│  │  Local FS │ Azure KV │ AWS SM │ Vault │ Infis │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

---

## Classes de gestion (Managers)

```
CertMateApp (application principale)
  ├── FileOperations          # Entrées/Sorties fichiers, sauvegardes
  ├── SettingsManager         # Chargement/sauvegarde settings.json
  ├── AuthManager             # Validation des tokens
  ├── CertificateManager      # Créer/renouveler/infos (certs serveur)
  ├── CAManager               # Config fournisseur CA, construction certbot
  ├── DNSManager              # Comptes fournisseurs DNS
  ├── CacheManager            # Cache de déploiement
  ├── StorageManager          # Abstraction des backends
  ├── ClientCertificateManager # Cycle de vie des certificats clients
  ├── PrivateCAGenerator      # Gestion de la CA auto-signée
  ├── OCSPResponder           # Requêtes de statut de certificats
  ├── CRLManager              # Génération de listes de révocation
  └── AuditLogger             # Suivi des opérations
```

---

## Flux de création de certificat

### Certificats serveur (via Certbot + ACME)

```
1. L'utilisateur soumet : domaine, email, fournisseur DNS, fournisseur CA
2. Validation des entrées (format du domaine, email, existence du fournisseur)
3. Récupération de la config CA (URL ACME, identifiants EAB si DigiCert)
4. Récupération de la config DNS (identifiants du compte depuis settings)
5. Création du répertoire : certificates/{domaine}/
6. Construction de la commande certbot :
   certbot certonly --non-interactive --agree-tos
     --server {acme_url}
     --email {email}
     --{dns_plugin} --{dns_plugin}-credentials {cred_file}
     --{dns_plugin}-propagation-seconds {timeout}
     --eab-kid/--eab-hmac-key (si requis)
     -d {domaine}
7. Création du fichier temporaire d'identifiants DNS (permissions 600)
8. Exécution de certbot (timeout de 30 minutes)
9. Résolution des liens symboliques, copie des fichiers cert vers le répertoire racine du domaine
10. Stockage via le backend configuré + création de metadata.json
11. Nettoyage du fichier d'identifiants
```

### Certificats clients (via CA privée)

```
1. L'utilisateur soumet : common_name, email, organisation, cert_usage
2. Initialisation ou chargement de la CA existante (RSA 4096 bits)
3. Génération du CSR (ou acceptation d'un CSR fourni)
4. Signature du CSR avec la CA privée
5. Stockage des fichiers cert/clé/csr + metadata.json
6. Journalisation dans la piste d'audit
```

---

## Architecture de stockage

### Certificats serveur

```
certificates/
  example.com/
    cert.pem          # Certificat serveur
    chain.pem         # Chaîne CA intermédiaire
    fullchain.pem     # cert + chaîne
    privkey.pem       # Clé privée (permissions 600)
    metadata.json     # Métadonnées du certificat
```

### Certificats clients

```
data/certs/
  ca/
    ca.crt            # Certificat CA
    ca.key            # Clé privée CA (permissions 600)
    ca_metadata.json  # Métadonnées CA
    crl.pem           # Liste de révocation des certificats
  client/
    api-mtls/         # Certificats par type d'usage
      cert-001/
        cert.crt
        cert.key
        cert.csr
        metadata.json
    vpn/
      cert-002/
        ...
```

### Backends de stockage

Tous les backends implémentent `CertificateStorageBackend` :

| Backend | Emplacement de stockage |
|---------|------------------------|
| **Système de fichiers local** | `certificates/{domaine}/` (défaut) |
| **Azure Key Vault** | Secrets, objets Certificate natifs, ou les deux — voir ci-dessous |
| **AWS Secrets Manager** | AWS Secrets Manager |
| **HashiCorp Vault** | Vault KV v1/v2 |
| **Infisical** | Secrets Infisical |

#### Azure Key Vault — modes de stockage

Le backend Azure Key Vault peut persister les certificats comme Secrets (par défaut), comme objets Certificate natifs, ou les deux, contrôlé par `certificate_storage.azure_keyvault.storage_mode` dans `settings.json`.

| Mode | Écrit Secrets | Écrit objet Certificate | Quand l'utiliser |
|---|---|---|---|
| `secrets` (défaut) | oui | non | Comportement rétrocompatible. Chaque `cert.pem` / `chain.pem` / `fullchain.pem` / `privkey.pem` et les métadonnées sont stockés comme des secrets Key Vault distincts. |
| `certificate` | non | oui | Lier directement depuis App Service, Application Gateway, Front Door, API Management, AKS Ingress, etc. Le cert + chaîne + clé privée sont importés comme un seul objet `Certificate` PKCS12 avec `issuer_name="Unknown"` pour que Key Vault n'essaie pas de le renouveler. |
| `both` | oui | oui | Configurations transitoires ou à consommateurs mixtes. Les lectures privilégient toujours le chemin Secrets (moins coûteux). |

Une action manuelle **Backfill Certificate objects** dans le panneau des paramètres de stockage (`POST /api/storage/azure-keyvault/backfill-certificates`) importe un objet Certificate pour chaque domaine qui existe déjà dans le coffre comme Secret mais n'en a pas encore. Les objets Certificate existants sont ignorés. L'endpoint accepte un paramètre de requête optionnel `?limit=N` pour limiter le nombre de domaines traités par appel ; les grands coffres peuvent paginer en appelant de manière répétée jusqu'à ce que la réponse indique `0` restants.

##### Note de sécurité — les objets Certificate exposent la clé privée via l'API Secrets

Quand Key Vault importe un objet Certificate PKCS12, il crée également un **Secret** compagnon du même nom dont la valeur est le PFX complet (incluant la clé privée). C'est conçu ainsi dans Azure : c'est la manière documentée pour les extensions de VM et App Service de consommer le certificat, et tout principal ayant `Secrets/Get` sur le coffre peut donc télécharger la clé privée — *la permission `Get` sur Certificates seule ne suffit pas pour extraire la clé privée, mais `Secrets/Get` le peut*. Les opérateurs exécutant CertMate en mode `certificate` ou `both` doivent limiter `Secrets/Get` avec précaution et préférer Azure RBAC aux stratégies d'accès du coffre pour un contrôle plus fin. Voir [Microsoft Learn — Certificats dans Key Vault](https://learn.microsoft.com/azure/key-vault/certificates/about-certificates) pour le modèle complet.

##### Permissions du Service Principal

| Mode | Permissions requises sur le coffre |
|---|---|
| `secrets` | Secrets `Get/Set/List/Delete` |
| `certificate` / `both` | Ajoute Certificates `Get/List/Import/Delete` et conserve Secrets `Get/List` (Key Vault expose le PFX importé, incluant la clé privée, uniquement via le Secret du même nom que l'objet Certificate). |

---

## Structure de configuration

Tous les paramètres sont stockés dans `data/settings.json` :

```json
{
  "email": "admin@example.com",
  "domains": ["example.com", "*.example.com"],
  "auto_renew": true,
  "renewal_threshold_days": 30,
  "api_bearer_token": "secure-token",
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {
      "accounts": {
        "production": {"api_token": "token-prod"},
        "staging": {"api_token": "token-staging"}
      }
    }
  },
  "default_accounts": {
    "cloudflare": "production"
  },
  "ca_providers": {
    "letsencrypt": {
      "accounts": {
        "default": {"email": "admin@example.com"}
      }
    }
  },
  "certificate_storage": {
    "backend": "local_filesystem",
    "cert_dir": "certificates"
  },
  "default_key_type": "rsa",
  "default_key_size": 2048,
  "default_elliptic_curve": "secp256r1"
}
```

### Type/taille de clé de certificat

Trois clés de premier niveau contrôlent la forme de la clé publique des certificats nouvellement émis :

| Clé | Valeurs | S'applique quand |
|---|---|---|
| `default_key_type` | `rsa` (défaut) / `ecdsa` | toujours |
| `default_key_size` | `2048` (défaut) / `3072` / `4096` | `default_key_type == "rsa"` |
| `default_elliptic_curve` | `secp256r1` (défaut) / `secp384r1` | `default_key_type == "ecdsa"` |

Une surcharge par certificat est supportée : chaque entrée dans `domains` peut porter un `key_type` optionnel plus soit `key_size` (RSA) soit `elliptic_curve` (ECDSA). Quand la surcharge est présente, elle l'emporte ; sinon la valeur globale par défaut s'applique. Les valeurs par défaut `rsa`/`2048` reflètent la valeur par défaut implicite de certbot que CertMate émettait avant l'existence de ce paramètre, donc les installations mises à jour ne voient aucun changement à moins que l'opérateur ne choisisse autre chose.

Les renouvellements préservent toujours la forme qui était en vigueur à la création : certbot persiste `--key-type`, `--rsa-key-size` et `--elliptic-curve` dans son propre `renewal/<domaine>.conf` lors de la première émission, et `certbot renew --cert-name <domaine>` réutilise ces valeurs automatiquement.

---

## Endpoints API

### Certificats serveur

| Méthode | Endpoint | Objectif |
|--------|----------|---------|
| GET | `/api/health` | Vérification de santé |
| GET | `/api/certificates` | Lister tous les certificats |
| POST | `/api/certificates` | Créer un nouveau certificat |
| GET | `/api/certificates/{domain}` | Obtenir les infos d'un certificat |
| POST | `/api/certificates/{domain}/renew` | Renouveler un certificat |
| GET | `/api/certificates/{domain}/download` | Télécharger en ZIP |
| GET | `/{domain}/tls` | Téléchargement direct fullchain |

### Certificats clients

| Méthode | Endpoint | Objectif |
|--------|----------|---------|
| POST | `/api/client-certs/create` | Créer un certificat |
| GET | `/api/client-certs` | Lister avec filtres |
| GET | `/api/client-certs/{id}` | Obtenir les métadonnées |
| GET | `/api/client-certs/{id}/download/{type}` | Télécharger cert/clé/csr |
| POST | `/api/client-certs/{id}/revoke` | Révoquer un certificat |
| POST | `/api/client-certs/{id}/renew` | Renouveler un certificat |
| GET | `/api/client-certs/stats` | Statistiques |
| POST | `/api/client-certs/batch` | Import CSV par lots |
| GET | `/api/ocsp/status/{serial}` | Statut OCSP |
| GET | `/api/crl/download/{format}` | Télécharger la CRL |

---

## Pile technologique

| Couche | Technologies |
|-------|-------------|
| **Backend** | Python 3.9+, Flask, Flask-RESTX, APScheduler, Certbot |
| **Frontend** | HTML5, Tailwind CSS, Vanilla JavaScript, Font Awesome |
| **SDKs Cloud** | Azure SDK, boto3, hvac, infisical-python |
| **Cryptographie** | cryptography (OpenSSL), plugins certbot |
| **Déploiement** | Docker, Docker Compose, Gunicorn, systemd |

---

## Limitations clés

1. **Certbot uniquement pour les certificats serveur** : Défis DNS-01 ACME seulement
2. **Stockage serveur centré sur le domaine** : Un certificat par répertoire de domaine
3. **Pas de base de données** : Un seul fichier JSON pour la configuration
4. **Usage des clés des certificats serveur** : Pas de contrôle sur les extensions keyUsage/extendedKeyUsage

---

# Architecture des certificats clients

## Vue d'ensemble du système

```

 Couche Interface Web
 (tableau de bord web /client-certificates)

 

 Couche API
 (/api/client-certs, /api/ocsp, /api/crl)
 (endpoints REST avec Flask-RESTX)

 

 Couche Managers

 ClientCertificateManager (cycle de vie + métadonnées)
 OCSPResponder (requêtes de statut de certificats)
 CRLManager (génération de listes de révocation)
 AuditLogger (suivi des opérations)
 SimpleRateLimiter (limitation des requêtes)

 

 Couche Modules principaux

 PrivateCAGenerator (gestion CA)
 CSRHandler (validation et création CSR)
 ClientCertificateManager (opérations sur les certificats)
 OCSPResponder (réponses de statut)
 CRLManager (listes de révocation)
 AuditLogger (journalisation)
 RateLimitConfig/SimpleRateLimiter (limitation)

 

 Couche Cryptographie et stockage

 Cryptography Library (OpenSSL)
 Stockage système de fichiers (data/certs/)
 Backends de stockage (Azure, AWS, Vault, etc.)

```

---

## Composants principaux

### 1. PrivateCAGenerator (`modules/core/private_ca.py`)

**Objectif** : Générer et gérer l'Autorité de Certification auto-signée

**Fonctionnalités clés** :
- Génère des clés RSA 4096 bits pour la CA
- Période de validité de 10 ans
- Certificats auto-signés avec les extensions appropriées
- Fonctionnalité de sauvegarde et restauration de la CA
- Capacité de signature CRL

**Fichiers créés** :
- `data/certs/ca/ca.crt` — Certificat CA (PEM)
- `data/certs/ca/ca.key` — Clé privée CA (PEM, permissions 0600)
- `data/certs/ca/ca_metadata.json` — Métadonnées CA
- `data/certs/ca/crl.pem` — Liste de révocation des certificats

**Méthodes principales** :
```python
initialize() # Initialiser ou charger la CA existante
sign_certificate_request() # Signer un CSR
generate_crl() # Générer la CRL à partir des numéros de série révoqués
get_crl_pem() # Obtenir la CRL au format PEM
```

---

### 2. CSRHandler (`modules/core/csr_handler.py`)

**Objectif** : Valider, analyser et créer des demandes de signature de certificat

**Fonctionnalités clés** :
- Créer de nouveaux CSR avec clés privées (2048 ou 4096 bits)
- Valider les CSR encodés en PEM
- Extraire les informations du CSR (CN, Org, Email, SAN, etc.)
- Support des noms d'alternatifs du sujet (SAN)
- Sauvegarder le CSR et les paires de clés sur le disque

**Méthodes principales** :
```python
create_csr() # Créer un nouveau CSR avec clé privée
validate_csr_pem() # Valider et charger un CSR depuis PEM
get_csr_info() # Extraire les informations d'un CSR
save_csr_and_key() # Sauvegarder CSR et clé dans des fichiers
```

---

### 3. ClientCertificateManager (`modules/core/client_certificates.py`)

**Objectif** : Gestion complète du cycle de vie des certificats clients

**Fonctionnalités clés** :
- Créer des certificats (signés par CA ou via CSR)
- Lister/filtrer les certificats (par usage, statut, recherche)
- Révoquer des certificats avec piste d'audit
- Renouveler des certificats (même CN, nouveau numéro de série)
- Planification du renouvellement automatique
- Stockage des métadonnées (JSON par certificat)
- Support de 30 000+ certificats simultanés

**Structure de stockage** :
```
data/certs/client/
  api-mtls/ # Certificats pour API mTLS
    cert-001/
      cert.crt
      cert.key
      cert.csr
      metadata.json
  vpn/ # Certificats pour VPN
    cert-002/
      ...
  other/ # Autres types d'usage
    ...
```

**Structure des métadonnées** (JSON) :
```json
{
  "type": "client_certificate",
  "identifier": "cert-001",
  "common_name": "user@example.com",
  "email": "user@example.com",
  "organization": "ACME Corp",
  "organizational_unit": "Engineering",
  "country": "US",
  "state": "California",
  "locality": "San Francisco",
  "serial_number": "12345678901234567890",
  "key_usage": ["digitalSignature", "keyEncipherment"],
  "extended_key_usage": ["serverAuth", "clientAuth"],
  "created_at": "2024-10-30T18:00:00Z",
  "expires_at": "2025-10-30T18:00:00Z",
  "cert_usage": "api-mtls",
  "notes": "Production certificate",
  "revocation": {
    "revoked": false,
    "revoked_at": null,
    "reason_revoked": null
  },
  "renewal": {
    "renewal_enabled": true,
    "renewal_threshold_days": 30,
    "last_renewed_at": null
  }
}
```

**Méthodes principales** :
```python
create_client_certificate() # Créer un nouveau certificat
list_client_certificates() # Lister avec filtres optionnels
get_certificate_metadata() # Obtenir les métadonnées d'un certificat
get_certificate_file() # Obtenir le fichier cert/clé/csr
revoke_certificate() # Révoquer avec raison
renew_certificate() # Renouveler un certificat
check_renewals() # Vérification des renouvellements automatiques
get_statistics() # Obtenir les statistiques d'utilisation
```

---

### 4. OCSPResponder (`modules/core/ocsp_crl.py`)

**Objectif** : Fournir des réponses au protocole de statut de certificat en ligne (OCSP)

**Fonctionnalités clés** :
- Interroger le statut d'un certificat (good/revoked/unknown)
- Générer des réponses OCSP
- Recherches de statut en temps réel
- Support de plusieurs types de statut

**Statuts** :
- `good` — Le certificat est valide
- `revoked` — Le certificat a été révoqué
- `unknown` — Certificat non trouvé

**Méthodes principales** :
```python
get_cert_status() # Obtenir le statut du certificat
generate_ocsp_response() # Générer la réponse OCSP
```

**Format de réponse** :
```json
{
  "response_status": "successful",
  "certificate_status": "good|revoked|unknown",
  "certificate_serial": 12345678,
  "this_update": "2024-10-30T18:00:00Z",
  "next_update": null,
  "responder_name": "CertMate OCSP Responder",
  "revocation_time": null,
  "revocation_reason": null
}
```

---

### 5. CRLManager (`modules/core/ocsp_crl.py`)

**Objectif** : Générer et distribuer les listes de révocation de certificats

**Fonctionnalités clés** :
- Générer la CRL avec tous les certificats révoqués
- Distribuer aux formats PEM et DER
- Stocker les métadonnées et informations CRL
- Mises à jour automatiques de la CRL

**Méthodes principales** :
```python
get_revoked_serials() # Obtenir les numéros de série des certificats révoqués
update_crl() # Générer/mettre à jour la CRL
get_crl_pem() # Obtenir la CRL au format PEM
get_crl_der() # Obtenir la CRL au format DER
get_crl_info() # Obtenir les métadonnées de la CRL
```

---

### 6. AuditLogger (`modules/core/audit.py`)

**Objectif** : Suivre toutes les opérations sur les certificats pour la conformité et le débogage

**Fonctionnalités clés** :
- Journalisation au format JSON
- Fichier d'audit persistant
- Suivi des opérations, utilisateurs, adresses IP
- Interrogation des entrées par ressource ou période

**Format du journal** :
```json
{
  "timestamp": "2024-10-30T18:00:00Z",
  "operation": "create|revoke|renew|download|batch_import",
  "resource_type": "certificate|endpoint",
  "resource_id": "cert-001",
  "status": "success|failure|denied",
  "user": "admin@example.com",
  "ip_address": "192.168.1.1",
  "details": {},
  "error": null
}
```

**Fichier journal** : `logs/audit/certificate_audit.log`

**Méthodes principales** :
```python
log_certificate_created() # Journaliser la création de certificat
log_certificate_revoked() # Journaliser la révocation
log_certificate_renewed() # Journaliser le renouvellement
log_certificate_downloaded() # Journaliser les téléchargements
log_batch_operation() # Journaliser les opérations par lots
log_api_request() # Journaliser les requêtes API
get_recent_entries() # Obtenir les dernières entrées d'audit
```

---

### 7. Limitation de débit (`modules/core/rate_limit.py`)

**Objectif** : Protéger l'API contre les abus avec une limitation du taux de requêtes

**Configuration** :
- Par défaut : 100 req/min
- Création de certificat : 30 req/min (coûteux)
- Opérations par lots : 10 req/min (très coûteux)
- Statut OCSP : 200 req/min (peu coûteux)
- Téléchargement CRL : 60 req/min

**Classes principales** :
```python
RateLimitConfig # Conteneur de configuration
SimpleRateLimiter # Limiteur en mémoire
rate_limit_decorator # Décorateur d'endpoint Flask
```

**Réponse en cas de limite atteinte** :
```json
{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please try again later.",
  "retry_after": 60
}
```

Statut HTTP : `429 Too Many Requests`

---

## Flux de données

### Flux de création de certificat

```
Requête Utilisateur/API
 ↓
ClientCertificateManager.create_client_certificate()
 Générer le CSR (ou accepter un CSR fourni)
 Signer le CSR avec la CA privée
 Créer metadata.json
 Stocker les fichiers cert/clé/csr
 Journaliser dans la piste d'audit
 Retourner les données du certificat
 ↓
Réponse à l'Utilisateur
```

### Flux de révocation de certificat

```
Requête Utilisateur/API (endpoint de révocation)
 ↓
ClientCertificateManager.revoke_certificate()
 Charger les métadonnées du certificat
 Mettre à jour le statut de révocation
 Sauvegarder les métadonnées mises à jour
 Journaliser dans la piste d'audit
 Déclencher la mise à jour de la CRL
 Retourner le succès
 ↓
Réponse à l'Utilisateur
```

### Flux de requête OCSP

```
Requête OCSP du client (numéro de série)
 ↓
OCSPResponder.get_cert_status()
 Rechercher le certificat par numéro de série
 Vérifier le statut de révocation
 Retourner le statut (good/revoked/unknown)
 ↓
OCSPResponder.generate_ocsp_response()
 Formater la réponse OCSP
 Ajouter les horodatages
 Retourner la réponse
 ↓
Réponse au Client
```

---

## Architecture de stockage

### Structure des répertoires

```
data/certs/
  ca/                      # Autorité de Certification
    ca.crt                 # Certificat CA (public)
    ca.key                 # Clé privée CA (0600)
    ca_metadata.json       # Métadonnées CA
    crl.pem                # Liste de révocation des certificats

  client/                  # Certificats clients
    api-mtls/              # Certificats API mTLS
      cert-001/
        cert.crt
        cert.key
        cert.csr
        metadata.json
      ...
    vpn/                   # Certificats VPN
      ...
    other/                 # Autres types d'usage
      ...

  crl/                     # Stockage CRL
    (CRL générées)
```

### Fichiers de métadonnées

Chaque certificat a un fichier `metadata.json` contenant :
- Identification du certificat (CN, numéro de série, empreinte)
- Informations sur le sujet (Org, email, emplacement)
- Dates de validité
- Statut et historique de révocation
- Configuration du renouvellement
- Notes personnalisées

---

## Modèle de sécurité

### Protection des clés

- **Permissions des fichiers** : 0600 (lecture/écriture pour le propriétaire uniquement)
- **Format des clés** : PEM au format traditionnel OpenSSL
- **Chiffrement des clés** : Clés stockées chiffrées au repos si utilisation de backends de stockage

### Signature des certificats

- **Algorithme de signature** : SHA256withRSA
- **Taille de clé** : RSA 4096 bits pour la CA, 2048/4096 bits pour les clients
- **Validité** : Configurable (défaut 1 an pour les certificats clients)

### Contrôle d'accès

- **Authentification** : Bearer token sur tous les endpoints API
- **Autorisation** : Basée sur les tokens (peut être étendue avec des rôles)
- **Limitation de débit** : Protection par endpoint

### Piste d'audit

- Toutes les opérations journalisées avec horodatage
- Suivi de l'utilisateur et de l'adresse IP
- Fichier de journal d'audit immuable
- Interrogeable pour la conformité

---

## Passage à l'échelle

### Stockage des certificats

- **Scalabilité linéaire** : Stockage basé sur les répertoires
- **Capacité** : Testé avec 30 000+ certificats
- **Performance** : Analyses de répertoire O(n) efficaces

### Performance API

- **Limitation de débit** : Empêche l'épuisement des ressources
- **Conception sans état** : Peut exécuter plusieurs instances
- **Opérations par lots** : Gère 100 à 30 000 certificats par requête

### Renouvellement automatique

- **Planifié** : Tous les jours à 3h du matin (configurable)
- **Seuil** : 30 jours avant l'expiration (configurable)
- **Progressif** : Continue en cas d'erreur, journalise pour examen

---

## Considérations de déploiement

### Configuration minimale

- Python 3.9+
- 100 Mo d'espace disque pour la CA et les certificats initiaux
- 50 Mo pour les journaux d'audit par million d'opérations
- Faible empreinte mémoire

### Recommandations pour la production

- Utiliser un backend de stockage (Azure, AWS, Vault) pour la haute disponibilité
- Activer la journalisation d'audit pour la conformité
- Configurer la limitation de débit en fonction de la charge
- Mises à jour régulières de la CRL (quotidiennes ou lors des révocations)
- Sauvegarder les clés CA et les métadonnées
- Surveiller les journaux d'audit pour les activités suspectes

### Haute disponibilité

Pour les déploiements multi-instances :
1. Utiliser un backend de stockage partagé pour les certificats
2. Synchroniser les journaux d'audit vers un emplacement central
3. Utiliser un équilibreur de charge avec sessions persistantes
4. Surveiller les compteurs de limitation de débit entre les instances

---

## Points d'intégration

### Avec le système principal CertMate

- Utilise les backends de stockage existants de CertMate
- Intégré dans les managers de app.py
- Intégré dans la structure API Flask-RESTX
- Planifié avec APScheduler

### Systèmes externes

- Peut exporter des certificats via l'API
- Peut interroger le statut via OCSP
- Peut récupérer la CRL pour validation
- Supporte l'intégration webhook/callback (futur)

---

## Extensibilité future

### Améliorations prévues

1. **Protection par mot de passe de la CA** — Chiffrer les clés CA avec un mot de passe
2. **Audit avancé** — Contrôle d'accès basé sur les rôles
3. **Notifications Webhook** — Lors d'événements de certificats
4. **Signature de certificats** — Accepter les CSR de sources externes
5. **Jetons matériels** — Support PKCS#11 pour les HSM

### Points d'extension

1. **Backends de stockage** — Supporte déjà plusieurs backends
2. **Destinations d'audit** — Peut envoyer les journaux d'audit vers des systèmes externes
3. **Middleware API** — Ajouter une authentification/autorisation personnalisée
4. **Système de notification** — Intégration avec les systèmes d'alerte

---

## Surveillance et observabilité

### Métriques clés

- Nombre de certificats (total, actif, révoqué, expirant bientôt)
- Performance des endpoints API
- Violations de limite de débit
- Volume des journaux d'audit
- Taux de succès/échec des renouvellements automatiques

### Vérifications de santé

- Disponibilité de la CA
- Fonctionnement du journal d'audit
- Réactivité du limiteur de débit
- Statut de génération de la CRL

---

<div align="center">

[← Retour à la documentation](./README.md) • [Démarrage rapide →](./guide.md) • [Référence API →](./api.md)

</div>
