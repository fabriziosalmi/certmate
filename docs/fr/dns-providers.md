# Fournisseurs DNS

CertMate supporte une large gamme de fournisseurs DNS pour les défis Let's Encrypt DNS-01 via des plugins certbot individuels. La liste complète est dans le tableau ci-dessous.

---

## Fournisseurs supportés

| Fournisseur | Plugin | Identifiants requis | Catégorie |
|---|---|---|---|
| **Cloudflare** | `certbot-dns-cloudflare` | Jeton API | Cloud majeur |
| **AWS Route53** | `certbot-dns-route53` | Access Key, Secret Key | Cloud majeur |
| **Azure DNS** | `certbot-dns-azure` | Service Principal | Cloud majeur |
| **Google Cloud DNS** | `certbot-dns-google` | Service Account JSON | Cloud majeur |
| **PowerDNS** | `certbot-dns-powerdns` | URL API, Clé API | Entreprise |
| **DNS Made Easy** | `certbot-dns-dnsmadeeasy` | Clé API, Secret Key | Entreprise |
| **NS1** | `certbot-dns-nsone` | Clé API | Entreprise |
| **DigitalOcean** | `certbot-dns-digitalocean` | Jeton API | Cloud |
| **Linode (Akamai Connected Cloud)** | `certbot-dns-linode` | Clé API | Cloud |
| **Akamai Edge DNS** | `certbot-plugin-edgedns` | EdgeGrid `.edgerc` (client_token, client_secret, access_token, host) | Entreprise |
| **Vultr** | `certbot-dns-vultr` | Clé API | Cloud |
| **Hetzner (DNS legacy)** | `certbot-dns-hetzner` | Jeton API | Cloud |
| **Hetzner Cloud** | `certbot-dns-hetzner-cloud` | Jeton API | Cloud |
| **Gandi** | `certbot-dns-gandi` | Jeton API | Registrar |
| **Namecheap** | `certbot-dns-namecheap` | Nom d'utilisateur, Clé API | Registrar |
| **Porkbun** | `certbot-dns-porkbun` | Clé API, Secret Key | Registrar |
| **GoDaddy** | `certbot-dns-godaddy` | Clé API, Secret | Registrar |
| **OVH** | `certbot-dns-ovh` | Identifiants API | Régional |
| **Infomaniak** | `certbot-dns-infomaniak` | Jeton API | Régional |
| **ArvanCloud** | `certbot-dns-arvancloud` | Clé API | Régional |
| **RFC2136** | `certbot-dns-rfc2136` | Serveur DNS, Clé TSIG | Protocole standard |
| **ACME-DNS** | `certbot-acme-dns` | URL API, Nom d'utilisateur, Mot de passe | Spécialisé |
| **Hurricane Electric** | `certbot-dns-he-ddns` | Nom d'utilisateur, Mot de passe | DNS gratuit |
| **Dynu** | `certbot-dns-dynudns` | Jeton API | DNS dynamique |
| **DuckDNS** | `certbot-dns-duckdns` | Jeton de compte | DDNS gratuit (sans domaine) |
| **deSEC** | `certbot-dns-desec` | Jeton API | Gratuit, UE (DE), DNSSEC — déléguer NS à `ns1.desec.io` / `ns2.desec.org` |
| **Scaleway** | `certbot-dns-scaleway` | Clé secrète API | Cloud souverain UE (FR) — plugin communautaire (alpha), installer séparément : `pip install certbot-dns-scaleway` |
| **Script personnalisé** | aucun (certbot `--manual`) | Chemin du script auth (+ script cleanup optionnel) | Apportez le vôtre |

---

## Configuration

### Via l'interface Web

1. Allez dans **Paramètres**
2. Sélectionnez votre fournisseur DNS dans la liste déroulante
3. Remplissez les identifiants requis
4. Sauvegardez les paramètres

### Via l'API

```bash
curl -X POST http://localhost:8000/api/settings \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{
    "dns_provider": "cloudflare",
    "dns_providers": {
      "cloudflare": {
        "api_token": "votre_token_cloudflare"
      }
    }
  }'
```

---

## Exemples de configuration par fournisseur

### Cloudflare

```json
{
  "dns_provider": "cloudflare",
  "dns_providers": {
    "cloudflare": {
      "api_token": "votre_token_api_cloudflare"
    }
  }
}
```

### AWS Route53

```json
{
  "dns_provider": "route53",
  "dns_providers": {
    "route53": {
      "access_key_id": "AKIAIOSFODNN7EXAMPLE",
      "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "region": "us-east-1"
    }
  }
}
```

### Azure DNS

```json
{
  "dns_provider": "azure",
  "dns_providers": {
    "azure": {
      "subscription_id": "votre_subscription_id",
      "resource_group": "votre_resource_group",
      "tenant_id": "votre_tenant_id",
      "client_id": "votre_client_id",
      "client_secret": "votre_client_secret"
    }
  }
}
```

### Google Cloud DNS

```json
{
  "dns_provider": "google",
  "dns_providers": {
    "google": {
      "project_id": "votre_project_id",
      "service_account_key": "{ ... JSON du compte de service ... }"
    }
  }
}
```

### PowerDNS

```json
{
  "dns_provider": "powerdns",
  "dns_providers": {
    "powerdns": {
      "api_url": "https://votre-serveur-powerdns:8081",
      "api_key": "votre_cle_api_powerdns"
    }
  }
}
```

### Vultr

```json
{
  "dns_provider": "vultr",
  "dns_providers": {
    "vultr": {
      "api_key": "votre_cle_api_vultr"
    }
  }
}
```

### DNS Made Easy

```json
{
  "dns_provider": "dnsmadeeasy",
  "dns_providers": {
    "dnsmadeeasy": {
      "api_key": "votre_cle_api",
      "secret_key": "votre_cle_secrete"
    }
  }
}
```

### NS1

```json
{
  "dns_provider": "nsone",
  "dns_providers": {
    "nsone": {
      "api_key": "votre_cle_api_nsone"
    }
  }
}
```

### RFC2136

Pour les serveurs DNS compatibles RFC2136 (y compris **Technitium DNS Server**) :

```json
{
  "dns_provider": "rfc2136",
  "dns_providers": {
    "rfc2136": {
      "nameserver": "ns.example.com",
      "tsig_key": "mykey",
      "tsig_secret": "secret-encode-en-base64",
      "tsig_algorithm": "HMAC-SHA512"
    }
  }
}
```

> **Technitium DNS** : Activez Dynamic Updates dans Zone Options, créez une clé TSIG (ex. `certmate-key` avec HMAC-SHA512), puis utilisez le secret généré dans la configuration ci-dessus.

### Hetzner (API DNS legacy)

> **Avis de dépréciation :** L'API console DNS Hetzner sera arrêtée en mai 2025. Les nouveaux utilisateurs doivent utiliser le fournisseur **Hetzner Cloud** ci-dessous. Les utilisateurs existants doivent migrer vers `hetzner-cloud` avant la date d'arrêt. Voir [page de statut Hetzner](https://status.hetzner.com/incident/c2146c42-6dd2-4454-916a-19f07e0e5a44) pour plus de détails.

```json
{
  "dns_provider": "hetzner",
  "dns_providers": {
    "hetzner": {
      "api_token": "votre_token_api_dns_hetzner"
    }
  }
}
```

### Hetzner Cloud

Utilise la nouvelle [API Hetzner Cloud](https://docs.hetzner.cloud/reference/cloud) qui remplace l'API DNS Hetzner dépréciée. C'est le fournisseur recommandé pour tous les utilisateurs Hetzner.

```json
{
  "dns_provider": "hetzner-cloud",
  "dns_providers": {
    "hetzner-cloud": {
      "api_token": "votre_token_api_hetzner_cloud"
    }
  }
}
```

> Générez un jeton API Hetzner Cloud depuis la [Console Hetzner Cloud](https://console.hetzner.cloud/) dans la section des jetons API de votre projet. Le jeton nécessite les permissions DNS en lecture/écriture.

### Infomaniak

```json
{
  "dns_provider": "infomaniak",
  "dns_providers": {
    "infomaniak": {
      "api_token": "votre_token_api_infomaniak"
    }
  }
}
```

> Obtenez le jeton API depuis Infomaniak Manager (section API avec scope "Domain").

### Porkbun

```json
{
  "dns_provider": "porkbun",
  "dns_providers": {
    "porkbun": {
      "api_key": "votre_cle_api_porkbun",
      "secret_key": "votre_cle_secrete_porkbun"
    }
  }
}
```

### GoDaddy

```json
{
  "dns_provider": "godaddy",
  "dns_providers": {
    "godaddy": {
      "api_key": "votre_cle_api_godaddy",
      "secret": "votre_secret_godaddy"
    }
  }
}
```

### OVH

```json
{
  "dns_provider": "ovh",
  "dns_providers": {
    "ovh": {
      "endpoint": "ovh-eu",
      "application_key": "votre_app_key",
      "application_secret": "votre_app_secret",
      "consumer_key": "votre_consumer_key"
    }
  }
}
```

### Hurricane Electric

```json
{
  "dns_provider": "he-ddns",
  "dns_providers": {
    "he-ddns": {
      "username": "votre_nom_utilisateur_he",
      "password": "votre_mot_de_passe_he"
    }
  }
}
```

### Dynu

```json
{
  "dns_provider": "dynudns",
  "dns_providers": {
    "dynudns": {
      "token": "votre_token_api_dynu"
    }
  }
}
```

### ArvanCloud

```json
{
  "dns_provider": "arvancloud",
  "dns_providers": {
    "arvancloud": {
      "api_key": "votre_cle_api_arvancloud"
    }
  }
}
```

### ACME-DNS

```json
{
  "dns_provider": "acme-dns",
  "dns_providers": {
    "acme-dns": {
      "api_url": "https://auth.acme-dns.io",
      "username": "votre_nom_utilisateur_acme",
      "password": "votre_mot_de_passe_acme",
      "subdomain": "votre_sous_domaine"
    }
  }
}
```

### DuckDNS (sans domaine requis)

DuckDNS fournit gratuitement des sous-domaines `<nom>.duckdns.org` — le moyen le plus simple d'obtenir un certificat de confiance publique quand vous ne possédez pas de domaine. Cas d'usage typiques : homelabs, services auto-hébergés, appareils IoT, tableaux de bord internes auparavant bloqués sur des certificats auto-signés.

1. Connectez-vous sur <https://www.duckdns.org/> (SSO Google / GitHub / Twitter / Reddit).
2. Choisissez un sous-domaine (ex. `mybox` → `mybox.duckdns.org`).
3. Copiez le jeton de compte affiché en haut de la page.

```json
{
  "dns_provider": "duckdns",
  "domains": ["mybox.duckdns.org"],
  "dns_providers": {
    "duckdns": {
      "api_token": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
    }
  }
}
```

Les wildcards comme `*.mybox.duckdns.org` sont supportés avec le même jeton. DuckDNS ne stockant qu'un seul enregistrement TXT par domaine à la fois, une seule exécution certbot par sous-domaine DuckDNS est nécessaire — les certificats SAN couvrant plusieurs sous-domaines DuckDNS ne sont pas supportés.

### Script personnalisé (apportez votre propre fournisseur)

Pour les fournisseurs DNS sans plugin certbot — Oracle Cloud (OCI), DNS interne, API d'appliance — pointez CertMate vers vos propres scripts et il les pilotera via le mode `--manual` de certbot. Aucune installation de plugin requise.

```json
{
  "dns_provider": "custom-script",
  "dns_providers": {
    "custom-script": {
      "auth_hook": "/usr/local/bin/certmate-dns-auth.sh",
      "cleanup_hook": "/usr/local/bin/certmate-dns-cleanup.sh"
    }
  }
}
```

certbot invoque le auth hook une fois par défi de validation avec l'environnement standard [manual-hook](https://eff-certbot.readthedocs.io/en/stable/using.html#hooks) : `CERTBOT_DOMAIN` (le domaine en cours de validation) et `CERTBOT_VALIDATION` (la valeur TXT). Le script doit créer l'enregistrement TXT `_acme-challenge.$CERTBOT_DOMAIN` **et attendre sa propagation** — certbot valide immédiatement après le retour du hook. Le cleanup hook optionnel s'exécute après validation pour supprimer l'enregistrement.

Exemple pour OCI DNS (couvre [#285](https://github.com/fabriziosalmi/certmate/issues/285)). Notez qu'un certificat couvrant à la fois `example.com` et `*.example.com` produit DEUX défis de validation sur le même nom `_acme-challenge.example.com`, et certbot exécute tous les auth hooks avant de valider — le hook doit donc AJOUTER au rrset TXT, jamais le remplacer :

```bash
#!/bin/sh
# /usr/local/bin/certmate-dns-auth.sh
set -eu
ZONE="example.com"
NAME="_acme-challenge.${CERTBOT_DOMAIN}"
# Fusionne le nouveau jeton de validation avec les enregistrements déjà présents
EXISTING=$(oci dns record rrset get --zone-name-or-id "$ZONE" \
  --domain "$NAME" --rtype TXT \
  --query 'data.items[].rdata' --raw-output 2>/dev/null || echo '[]')
ITEMS=$(printf '%s' "$EXISTING" | python3 -c "
import json, os, sys
name = os.environ['NAME']
rdata = [r.strip('\"') for r in json.load(sys.stdin)]
rdata.append(os.environ['CERTBOT_VALIDATION'])
print(json.dumps([
    {'domain': name, 'rdata': v, 'rtype': 'TXT', 'ttl': 60} for v in rdata
]))
")
NAME="$NAME" oci dns record rrset update --force \
  --zone-name-or-id "$ZONE" \
  --domain "$NAME" \
  --rtype TXT \
  --items "$ITEMS"
sleep "${CERTMATE_DNS_PROPAGATION_SECONDS:-60}"
```

Prérequis et modèle de confiance :

- Les chemins doivent être **absolus**, les fichiers doivent exister, être **exécutables**, ne pas être modifiables par le monde, et ne pas contenir d'espaces ou de métacaractères shell (certbot exécute les hooks via le shell). Validé à l'émission et par l'endpoint API de test (`POST /api/web/certificates/test-provider`)
- Les scripts s'exécutent avec les privilèges de CertMate — même modèle de confiance que les hooks de déploiement : seuls les administrateurs peuvent les configurer, traitez-les comme faisant partie de votre déploiement
- Le paramètre `dns_propagation_seconds` par fournisseur est exporté vers les scripts via `CERTMATE_DNS_PROPAGATION_SECONDS` (un champ `propagation_seconds` au niveau du compte le surcharge)
- Les renouvellements rejouent les chemins des hooks depuis la configuration de renouvellement certbot : gardez les scripts à un chemin stable (si vous les déplacez, réémettez)
- Les certificats wildcard fonctionnent (le hook reçoit chaque enregistrement de validation)

---

## Créer des certificats

### Utilisation du fournisseur par défaut

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Utilisation d'un fournisseur spécifique

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "vultr"
  }'
```

### Utilisation d'un compte spécifique

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "cloudflare",
    "account_id": "production"
  }'
```

---

## Support multi-comptes

CertMate supporte plusieurs comptes par fournisseur DNS pour les environnements d'entreprise.

### Cas d'usage

- **Séparation des environnements** : Comptes production, staging et DR
- **Multi-régions** : Différents comptes pour les domaines US, UE, APAC
- **Isolation des permissions** : Comptes admin, limité, et CI/CD

### Ajouter plusieurs comptes

```bash
# Ajouter un compte production
curl -X POST http://localhost:8000/api/dns/cloudflare/accounts \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "production",
    "config": {
      "name": "Environnement Production",
      "description": "Compte Cloudflare principal de production",
      "api_token": "token_production_cloudflare"
    }
  }'

# Ajouter un compte staging
curl -X POST http://localhost:8000/api/dns/cloudflare/accounts \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "staging",
    "config": {
      "name": "Environnement Staging",
      "description": "Compte de développement et test",
      "api_token": "token_staging_cloudflare"
    }
  }'

# Définir production par défaut (pas d'endpoint dédié :
# "set_as_default" accompagne les données du compte)
curl -X PUT http://localhost:8000/api/dns/cloudflare/accounts/production \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{"set_as_default": true}'
```

### Gérer les comptes

```bash
# Lister tous les comptes d'un fournisseur
curl -X GET http://localhost:8000/api/dns/cloudflare/accounts \
  -H "Authorization: Bearer VOTRE_TOKEN_API"

# Mettre à jour un compte
curl -X PUT http://localhost:8000/api/dns/cloudflare/accounts/staging \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "name": "Staging & Testing",
      "api_token": "nouveau_token_staging"
    }
  }'

# Supprimer un compte
curl -X DELETE http://localhost:8000/api/dns/cloudflare/accounts/old-account \
  -H "Authorization: Bearer VOTRE_TOKEN_API"
```

### Structure de configuration multi-comptes

```json
{
  "dns_provider": "cloudflare",
  "default_accounts": {
    "cloudflare": "production",
    "route53": "main-aws"
  },
  "dns_providers": {
    "cloudflare": {
      "production": {
        "name": "Environnement Production",
        "api_token": "***masqué***"
      },
      "staging": {
        "name": "Environnement Staging",
        "api_token": "***masqué***"
      }
    },
    "route53": {
      "main-aws": {
        "name": "Compte AWS Principal",
        "access_key_id": "***masqué***",
        "secret_access_key": "***masqué***",
        "region": "us-east-1"
      }
    }
  }
}
```

### Rétrocompatibilité

Les configurations mono-compte existantes sont automatiquement migrées vers le format multi-comptes lors de la première utilisation. Aucun temps d'arrêt ni migration manuelle requis.

---

## DNS multi-maître et alias de domaine (délégation CNAME)

Lorsque votre domaine est géré par plusieurs fournisseurs DNS simultanément (configuration multi-maître), utilisez la **délégation CNAME** standard pour centraliser la validation ACME DNS sur un seul fournisseur.

### Le problème

Avec le DNS multi-maître (ex. deSEC + gcore), vous ne pouvez configurer qu'un seul fournisseur DNS par demande de certificat, mais la validation ACME nécessite de créer des enregistrements TXT `_acme-challenge`.

### La solution

La validation par alias DNS fonctionne via délégation CNAME. Let's Encrypt suit les chaînes CNAME pendant la validation DNS-01 ; CertMate écrit l'enregistrement TXT requis sur le nom de validation délégué.

1. **Créez un domaine de validation** sur un fournisseur supporté (ex. `validation.example.org` sur Cloudflare, PowerDNS, Route53 ou ACME-DNS)
2. **Ajoutez des enregistrements CNAME** dans tous vos fournisseurs DNS pointant vers le domaine de validation :
   ```dns
   _acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
   ```
3. **Demandez le certificat** en spécifiant le fournisseur qui gère le domaine de validation :
   ```bash
   curl -X POST http://localhost:8000/api/certificates/create \
     -H "Authorization: Bearer VOTRE_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "domain": "example.com",
       "dns_provider": "cloudflare",
       "domain_alias": "validation.example.org"
     }'
   ```

   Quand `domain_alias` est défini avec un fournisseur supporté, CertMate utilise un hook DNS manuel certbot pour créer l'enregistrement TXT sur `_acme-challenge.validation.example.org`. Le CNAME garantit que Let's Encrypt trouve cette valeur TXT en interrogeant `_acme-challenge.example.com`.

### Avantages

- Fonctionne quel que soit le fournisseur DNS qui sert la requête
- Aucune synchronisation nécessaire entre les fournisseurs
- Fonctionne avec des fournisseurs non nativement supportés par CertMate (deSEC, gcore)
- Les identifiants DNS sont limités au seul domaine de validation
- Implémenté pour les fournisseurs DNS de première classe de CertMate ; les fournisseurs génériques sont rejetés jusqu'à ce que des adaptateurs d'alias dédiés existent

### Exemples par fournisseur

Cloudflare, PowerDNS et Route53 utilisent tous la même forme de requête :

```json
{
  "domain": "example.com",
  "dns_provider": "route53",
  "domain_alias": "validation.example.org"
}
```

Pour ACME-DNS, `domain_alias` doit correspondre exactement au `subdomain`/fulldomain ACME-DNS configuré. CertMate met à jour cet enregistrement ACME-DNS directement et ne tente pas de nettoyage car ACME-DNS stocke la dernière valeur de validation.

### Certificats wildcard avec alias de domaine

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer VOTRE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "*.example.com",
    "dns_provider": "cloudflare",
    "domain_alias": "validation.example.org"
  }'
```

Assurez-vous que le CNAME est en place avant de demander le certificat :

```dns
_acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
```

### Dépannage de l'alias de domaine

```bash
# Vérifier la propagation CNAME
dig @8.8.8.8 _acme-challenge.example.com CNAME +short
# Attendu : _acme-challenge.validation.example.org.

# Après avoir demandé un certificat, vérifier l'enregistrement TXT sur le domaine de validation
dig _acme-challenge.validation.example.org TXT +short
# Attendu : un jeton de défi ACME encodé en base64
```

---

## Variables d'environnement

Définissez les identifiants du fournisseur DNS via des variables d'environnement pour les workflows CI/CD :

```bash
# Cloudflare
CLOUDFLARE_API_TOKEN=votre_token

# AWS Route53
AWS_ACCESS_KEY_ID=votre_access_key
AWS_SECRET_ACCESS_KEY=votre_secret_key
AWS_DEFAULT_REGION=us-east-1

# Azure
AZURE_SUBSCRIPTION_ID=votre_subscription_id
AZURE_RESOURCE_GROUP=votre_resource_group
AZURE_TENANT_ID=votre_tenant_id
AZURE_CLIENT_ID=votre_client_id
AZURE_CLIENT_SECRET=votre_client_secret

# Google Cloud
GOOGLE_PROJECT_ID=votre_project_id
GOOGLE_APPLICATION_CREDENTIALS=/chemin/vers/service-account.json

# PowerDNS
POWERDNS_API_URL=https://votre-serveur-powerdns:8081
POWERDNS_API_KEY=votre_cle_api
```

### Priorité de configuration (de la plus haute à la plus basse)

1. Variables d'environnement
2. Paramètres spécifiques au domaine
3. Paramètres du compte par défaut
4. Paramètre global du fournisseur
5. Valeur par défaut du système (Cloudflare)

---

## Temps de propagation DNS

| Vitesse | Fournisseurs | Secondes |
|---------|-------------|----------|
| Très rapide | ACME-DNS | 30 |
| Rapide | Cloudflare, Route53, PowerDNS, DuckDNS | 60 |
| Moyen | DigitalOcean, Linode, Google, ArvanCloud | 120 |
| Lent | Azure, Gandi, OVH | 180 |
| Très lent | Namecheap | 300 |

---

## Fonctionnalités de sécurité

- **Masquage des identifiants** dans l'interface Web et les réponses API
- **Permissions de fichiers sécurisées** (600) pour tous les fichiers d'identifiants
- **Validation du jeton API** avant la création de certificat
- **Support des variables d'environnement** pour les workflows CI/CD
- **Journalisation d'audit** pour toutes les opérations sur les fournisseurs DNS
- **Isolation des comptes** — les identifiants de chaque compte sont stockés séparément

---

## Architecture et guide développeur

### Classes principales

| Classe | Fichier | Objectif |
|--------|---------|----------|
| `DNSManager` | `modules/core/dns_providers.py` | Gestion de la configuration multi-comptes |
| `CertificateManager` | `modules/core/certificates.py` | Création de certificats avec fournisseurs DNS |
| `SettingsManager` | `modules/core/settings.py` | Persistance et migration des paramètres |
| `Utils` | `modules/core/utils.py` | Génération et validation des fichiers d'identifiants |

### Méthodes de stockage des identifiants

1. **Fichier de paramètres** (`data/settings.json`) — le plus courant
2. **Variables d'environnement** — pour CI/CD
3. **Fichiers de configuration temporaires** (`letsencrypt/config/[provider].ini`) — créés pendant les demandes de certificat, supprimés après

### Ajouter un nouveau fournisseur DNS

1. Ajoutez le plugin à `requirements.txt` : `certbot-dns-nouveaufournisseur`
2. Créez une fonction de configuration dans `modules/core/utils.py`
3. Ajoutez la définition des identifiants dans `utils.py`
4. Importez et gérez dans `modules/core/certificates.py`
5. Ajoutez à la liste des fournisseurs supportés dans `modules/core/settings.py`
6. Mettez à jour la documentation

Voir le [Guide d'architecture](./architecture.md) pour les détails d'implémentation complets.

---

## Dépannage

### Problèmes courants

| Erreur | Solution |
|--------|----------|
| "Fournisseur DNS non configuré" | Vérifiez que tous les identifiants requis sont fournis |
| "Échec de création du certificat" | Vérifiez les permissions DNS et la propriété du domaine |
| "Plugin non trouvé" | Exécutez `pip install -r requirements.txt` ou reconstruisez Docker |
| "Échec de détection du fournisseur" | Vérifiez le champ `dns_provider` dans les paramètres du domaine |

### Mode débogage

```bash
export FLASK_DEBUG=1
python app.py
```

### Tester la configuration du fournisseur

```bash
curl -X GET http://localhost:8000/api/settings/dns-providers \
  -H "Authorization: Bearer VOTRE_TOKEN_API"
```

---

## Guide de migration

### D'un fournisseur unique vers plusieurs fournisseurs

Les configurations existantes restent inchangées. Ajoutez simplement de nouveaux fournisseurs :

```json
{
  "dns_providers": {
    "cloudflare": {
      "api_token": "token_existant"
    },
    "vultr": {
      "api_key": "nouvelle_cle_api_vultr"
    }
  }
}
```

### Utiliser différents fournisseurs par certificat

```bash
# Cloudflare pour un domaine
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "dns_provider": "cloudflare"}'

# Route53 pour un autre
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer VOTRE_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{"domain": "test.org", "dns_provider": "route53"}'
```

---

<div align="center">

[← Retour à la documentation](./README.md) • [Installation →](./installation.md) • [Fournisseurs CA →](./ca-providers.md)

</div>
