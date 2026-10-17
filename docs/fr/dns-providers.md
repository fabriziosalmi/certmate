# Fournisseurs DNS

<!-- CERTMATE-TRANSLATED-FROM f2105fc570be338c -->

CertMate supporte une large gamme de fournisseurs DNS pour les défis Let's Encrypt DNS-01 via des plugins certbot individuels. La liste complète est dans le tableau ci-dessous.

---

## Fournisseurs supportés

| Fournisseur | Plugin | Identifiants requis | Catégorie | Disponibilité |
|-------------|--------|---------------------|-----------|---|
| **Cloudflare** | `certbot-dns-cloudflare` | Jeton API | Cloud majeur | **Stable** |
| **AWS Route53** | `certbot-dns-route53` | Clés d'accès ou chaîne d'identification AWS / rôle IAM | Cloud majeur | **Stable** |
| **Azure DNS** | Hook propre à CertMate (`azure-mgmt-dns`) | Service Principal | Cloud majeur | **Stable** |
| **Google Cloud DNS** | `certbot-dns-google` | Service Account JSON | Cloud majeur | **Stable** |
| **PowerDNS** | `certbot-dns-powerdns` | URL API, Clé API | Entreprise | **Installation séparée** |
| **EfficientIP SOLIDserver** | script personnalisé via API REST | Hôte, Identifiants API | Entreprise | **Stable** |
| **DNS Made Easy** | `certbot-dns-dnsmadeeasy` | Clé API, Secret Key | Entreprise | **Stable** |
| **NS1** | `certbot-dns-nsone` | Clé API | Entreprise | **Stable** |
| **DigitalOcean** | `certbot-dns-digitalocean` | Jeton API | Cloud | **Stable** |
| **Linode** (Akamai Connected Cloud) | `certbot-dns-linode` | Clé API | Cloud | **Stable** |
| **Akamai Edge DNS** | `certbot-plugin-edgedns` | EdgeGrid `.edgerc` (client_token, client_secret, access_token, host) | Entreprise | **Stable** |
| **Vultr** | `certbot-dns-vultr` | Clé API | Cloud | **Stable** |
| **Hetzner (DNS legacy)** | `certbot-dns-hetzner` | Jeton API | Cloud | **Stable** |
| **Hetzner Cloud** | `certbot-dns-hetzner-cloud` | Jeton API | Cloud | **Stable** |
| **Gandi** | `certbot-dns-gandi` | Jeton API | Registrar | **Stable** |
| **Namecheap** | `certbot-dns-namecheap` | Nom d'utilisateur, Clé API | Registrar | **Indisponible** |
| **Porkbun** | `certbot-dns-porkbun` | Clé API, Secret Key | Registrar | **Stable** |
| **GoDaddy** | `certbot-dns-godaddy` | Clé API, Secret | Registrar | **Stable** |
| **OVH** | `certbot-dns-ovh` | Identifiants API | Régional | **Stable** |
| **Infomaniak** | `certbot-dns-infomaniak` | Jeton API | Régional | **Stable** |
| **ArvanCloud** | `certbot-dns-arvancloud` | Clé API | Régional | **Stable** |
| **RFC2136** | `certbot-dns-rfc2136` | Serveur DNS, Clé TSIG | Protocole standard | **Stable** |
| **ACME-DNS** | _intégré_ (aucun plugin) | URL API, Nom d'utilisateur, Mot de passe, Sous-domaine | Spécialisé | **Stable** |
| **Hurricane Electric** | `certbot-dns-he-ddns` | Nom d'utilisateur, Mot de passe | DNS gratuit | **Image étendue** |
| **Dynu** | `certbot-dns-dynudns` | Jeton API | DNS dynamique | **Image étendue** |
| **DuckDNS** | `certbot-dns-duckdns` | Jeton de compte | DDNS gratuit (sans domaine requis) | **Stable** |
| **deSEC** | `certbot-dns-desec` | Jeton API | Gratuit, UE (DE), DNSSEC — déléguer NS à `ns1.desec.io` / `ns2.desec.org` | **Stable** |
| **Scaleway** | `certbot-dns-scaleway` | Clé secrète API | Cloud souverain UE (FR) — plugin communautaire (alpha), dans aucune image : voir [Disponibilité](#disponibilité) | **Installation séparée** |
| **Script personnalisé** | aucun (mode `--manual` du cœur de certbot) | Chemin du script auth hook (+ cleanup hook optionnel) | Apportez le vôtre | **Stable** |

### Disponibilité

La dernière colonne indique si l'image Docker peut utiliser le fournisseur telle quelle :

| Valeur | Signification |
| --- | --- |
| **Stable** | Le plugin est figé dans `requirements.txt`, il est donc dans l'image par défaut. |
| **Image étendue** | Figé dans `requirements-extended.txt`. Construire avec `--build-arg EXTRA_REQUIREMENTS=requirements-extended.txt`. |
| **Installation séparée** | Dans aucune image. Construire une image dérivée qui l'installe (ci-dessous), dans son propre environnement quand c'est indiqué. |
| **Indisponible** | Il n'existe aucun plugin utilisable pour la pile prise en charge. CertMate peut être configuré pour lui, mais l'émission échoue. |

`Namecheap` est l'indisponible : la seule version de `certbot-dns-namecheap` sur PyPI est la 1.0.0, une alpha pour Python 2.7-3.8 qui ne fonctionne pas avec certbot 2 sous Python 3.12. Pour les domaines Namecheap, utilisez ACME-DNS ou le script personnalisé.

`Scaleway` est une alpha (0.0.7, qui déclare la prise en charge de Python 2.7), et `PowerDNS` exige `dns-lexicon<=3.5.6`, en conflit avec le reste de l'ensemble étendu, d'où son propre environnement.

L'image n'a pas de pip : un plugin installé séparément va donc dans une image dérivée, qui remet pip pour sa propre construction seulement :

```dockerfile
FROM fabriziosalmi/certmate:latest
USER root
RUN /opt/venv/bin/python -m ensurepip && \
    /opt/venv/bin/python -m pip install --no-cache-dir certbot-dns-scaleway==0.0.7 && \
    /opt/venv/bin/python -m pip uninstall -y pip
USER certmate
```

Dans cette image, `certbot plugins` liste alors `dns-scaleway`.

Chaque fournisseur peut avoir plusieurs comptes, choisis par certificat ; voir [Support multi-comptes](#support-multi-comptes).

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
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "dns_provider": "cloudflare",
    "dns_providers": {
      "cloudflare": {
        "api_token": "your_cloudflare_token"
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
      "api_token": "your_cloudflare_api_token"
    }
  }
}
```

### AWS Route53

Les comptes existants continuent d'utiliser des clés d'accès par défaut. Pour
utiliser la chaîne d'identification AWS (un rôle de tâche EC2/ECS, EKS Pod
Identity ou IRSA), sélectionnez **AWS credentials / IAM role (no keys)** dans
Paramètres → Fournisseurs DNS, ou définissez `auth_mode` sur `iam_role` pour le
compte DNS Route53 :

```json
{"dns_providers": {"route53": {"accounts": {"default": {
  "auth_mode": "iam_role", "region": "eu-west-3"
}}}}}
```

Vous pouvez aussi définir `assume_role_arn` pour assumer un autre rôle disposant
des permissions DNS Route53. Cela fonctionne avec la chaîne d'identification AWS
comme avec des clés d'accès stockées comme identité source ; cette identité a
besoin de `sts:AssumeRole`, et le rôle cible doit lui faire confiance. CertMate
transmet des identifiants STS temporaires à Certbot pour chaque émission ou
renouvellement. Le mode alias DNS utilise la même identité.
En mode IAM, toute personne autorisée à modifier les paramètres DNS peut faire
utiliser par CertMate l'identité AWS de l'hôte et ses permissions Route53.
Sans `auth_mode`, le comportement actuel avec clés d'accès reste en vigueur.

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
      "subscription_id": "your_subscription_id",
      "resource_group": "your_resource_group",
      "tenant_id": "your_tenant_id",
      "client_id": "your_client_id",
      "client_secret": "your_client_secret"
    }
  }
}
```

Azure DNS n'est pas traité par un plugin certbot : CertMate écrit lui-même l'enregistrement du défi avec le SDK Azure, avec le même service principal. Le principal doit pouvoir lire et écrire les enregistrements TXT de la zone (le rôle `DNS Zone Contributor` sur le groupe de ressources suffit). Les certificats émis auparavant via `certbot-dns-azure` passent à cette méthode à leur prochain renouvellement, et il n'y a rien à modifier. L'attente avant la validation est le réglage de propagation du fournisseur (180 secondes par défaut).

### Google Cloud DNS

```json
{
  "dns_provider": "google",
  "dns_providers": {
    "google": {
      "project_id": "your_project_id",
      "service_account_key": "{ ... service account JSON ... }"
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
      "api_url": "https://your-powerdns-server:8081",
      "api_key": "your_powerdns_api_key"
    }
  }
}
```

### EfficientIP SOLIDserver

```json
{
  "dns_provider": "solidserver",
  "dns_providers": {
    "solidserver": {
      "host": "your-solidserver.example.com",
      "username": "user",
      "password": "password",
      "dns_name": "dns_name",
      "dnsview_name": "optional",
      "propagation_seconds": 120
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
      "api_key": "your_vultr_api_key"
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
      "api_key": "your_api_key",
      "secret_key": "your_secret_key"
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
      "api_key": "your_nsone_api_key"
    }
  }
}
```

### RFC2136

Pour BIND ou d'autres serveurs DNS compatibles RFC2136 (y compris **Technitium DNS Server**) :

```json
{
  "dns_provider": "rfc2136",
  "dns_providers": {
    "rfc2136": {
      "nameserver": "ns.example.com",
      "tsig_key": "mykey",
      "tsig_secret": "base64-encoded-secret",
      "tsig_algorithm": "HMAC-SHA512"
    }
  }
}
```

> **Technitium DNS** : activez Dynamic Updates dans Zone Options, créez une clé TSIG (par ex. `certmate-key` avec HMAC-SHA512), puis utilisez le secret généré dans la configuration ci-dessus.

### Hetzner (API DNS legacy)

> **Avis de dépréciation :** Hetzner a annoncé l'arrêt de l'API de sa console DNS pour mai 2025. Les nouveaux utilisateurs doivent utiliser le fournisseur **Hetzner Cloud** ci-dessous, et les configurations `hetzner` existantes doivent migrer vers `hetzner-cloud`. Voir la [page de statut Hetzner](https://status.hetzner.com/incident/c2146c42-6dd2-4454-916a-19f07e0e5a44) pour plus de détails.

```json
{
  "dns_provider": "hetzner",
  "dns_providers": {
    "hetzner": {
      "api_token": "your_hetzner_dns_api_token"
    }
  }
}
```

### Hetzner Cloud

Utilise la nouvelle [API Hetzner Cloud](https://docs.hetzner.cloud/reference/cloud) qui remplace la console DNS Hetzner dépréciée. C'est le fournisseur recommandé pour tous les utilisateurs Hetzner.

```json
{
  "dns_provider": "hetzner-cloud",
  "dns_providers": {
    "hetzner-cloud": {
      "api_token": "your_hetzner_cloud_api_token"
    }
  }
}
```

> Générez un jeton API Hetzner Cloud depuis la [Console Hetzner Cloud](https://console.hetzner.cloud/), dans la section des jetons API de votre projet. Le jeton nécessite les permissions DNS en lecture/écriture.

### Infomaniak

```json
{
  "dns_provider": "infomaniak",
  "dns_providers": {
    "infomaniak": {
      "api_token": "your_infomaniak_api_token"
    }
  }
}
```

> Obtenez le jeton API depuis Infomaniak Manager (section API avec le scope "Domain").

### Porkbun

```json
{
  "dns_provider": "porkbun",
  "dns_providers": {
    "porkbun": {
      "api_key": "your_porkbun_api_key",
      "secret_key": "your_porkbun_secret_key"
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
      "api_key": "your_godaddy_api_key",
      "secret": "your_godaddy_secret"
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
      "application_key": "your_app_key",
      "application_secret": "your_app_secret",
      "consumer_key": "your_consumer_key"
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
      "username": "your_he_username",
      "password": "your_he_password"
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
      "token": "your_dynu_api_token"
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
      "api_key": "your_arvancloud_api_key"
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
      "username": "your_acme_username",
      "password": "your_acme_password",
      "subdomain": "your_subdomain"
    }
  }
}
```

### DuckDNS (sans domaine requis)

DuckDNS fournit gratuitement des sous-domaines `<name>.duckdns.org` — le moyen
le plus simple d'obtenir un certificat de confiance publique quand vous ne
possédez pas de domaine. Cas d'usage typiques : homelabs, services
auto-hébergés, appareils IoT, tableaux de bord internes jusque-là bloqués sur
des certificats auto-signés.

1. Connectez-vous sur <https://www.duckdns.org/> (SSO Google / GitHub / Twitter / Reddit).
2. Choisissez un sous-domaine (par ex. `mybox` → `mybox.duckdns.org`).
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

Les wildcards comme `*.mybox.duckdns.org` sont supportés avec le même jeton.
DuckDNS ne stockant qu'un seul enregistrement TXT par domaine à la fois, une
seule exécution de certbot par sous-domaine DuckDNS est nécessaire — les
certificats SAN couvrant plusieurs sous-domaines DuckDNS ne sont pas supportés.

### Script personnalisé (apportez votre propre fournisseur)

Pour les fournisseurs DNS sans plugin certbot — Oracle Cloud (OCI), Total Uptime,
Netriplex, DNS interne, API d'appliance — pointez CertMate vers vos propres
scripts et il les pilote via le mode `--manual` du cœur de certbot. Aucune
installation de plugin requise.

**[Script DNS personnalisé](../custom-dns-script.md)** est le guide complet : les
règles sur les chemins et pourquoi elles sont strictes, l'environnement exact
avec lequel votre script est appelé, le cas wildcard plus apex, ce que le
renouvellement utilise, et un exemple détaillé.

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

certbot invoque l'auth hook une fois par défi de validation avec
l'[environnement manual-hook](https://eff-certbot.readthedocs.io/en/stable/using.html#hooks) standard :
`CERTBOT_DOMAIN` (le domaine en cours de validation) et `CERTBOT_VALIDATION`
(la valeur TXT). Le script doit créer l'enregistrement TXT
`_acme-challenge.$CERTBOT_DOMAIN` **et attendre qu'il se soit
propagé** — certbot valide immédiatement après le retour du hook.
Le cleanup hook optionnel s'exécute après la validation pour supprimer l'enregistrement.

Exemple détaillé pour OCI DNS (couvre [#285](https://github.com/fabriziosalmi/certmate/issues/285)). Notez qu'un certificat couvrant à la fois `example.com` et `*.example.com` produit DEUX défis de validation sur le même nom `_acme-challenge.example.com`, et que certbot exécute tous les auth hooks avant de valider — le hook doit donc AJOUTER au rrset TXT, jamais le remplacer (un simple `rrset update` effacerait le premier jeton avec le second) :

Cet exemple appelle la CLI `oci`, que l'image standard de CertMate ne
contient **pas** : l'étage d'exécution installe `bash`, `curl` et `tini`, et
rien d'autre. À vous de la fournir : une couche au-dessus de l'image, ou le
binaire et sa configuration montés dans le conteneur. Le hook s'exécute à
l'intérieur de CertMate, la CLI doit donc se trouver dans le PATH de
CertMate, pas dans celui de l'hôte.

```bash
#!/bin/sh
# /usr/local/bin/certmate-dns-auth.sh
set -eu
ZONE="example.com"
NAME="_acme-challenge.${CERTBOT_DOMAIN}"
# Fusionne le nouveau jeton de validation avec les enregistrements déjà présents sur le nom
# (les certificats apex + wildcard placent deux valeurs TXT sur le même nom).
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

- Les chemins doivent être **absolus**, les fichiers doivent exister, être
  **exécutables**, n'être modifiables ni par tous **ni par le groupe**
  (`chmod 755` ou plus strict), et ne pas contenir d'espaces ni de
  métacaractères shell (certbot exécute les hooks via le shell). Un hook en
  `chmod 775` — un mode courant pour un script appartenant à un groupe de
  déploiement — est refusé : tout membre de ce groupe pourrait réécrire ce que
  CertMate s'apprête à exécuter. Validé à l'émission et par l'endpoint API de
  test du fournisseur
  (`POST /api/web/certificates/test-provider`)
- Les scripts s'exécutent avec les privilèges de CertMate — même modèle de
  confiance que les deploy hooks : seuls les administrateurs peuvent les
  configurer, traitez-les comme faisant partie de votre déploiement
- Le paramètre `dns_propagation_seconds` de chaque fournisseur est exporté vers
  les scripts sous le nom `CERTMATE_DNS_PROPAGATION_SECONDS` (un champ
  `propagation_seconds` au niveau du compte le remplace)
- Les renouvellements utilisent les chemins des hooks configurés à ce moment-là,
  comme l'émission : déplacez un script, mettez à jour son chemin dans les
  Paramètres, et le renouvellement suivant l'utilise
- Les certificats wildcard fonctionnent (le hook reçoit chaque enregistrement de validation)

---

## Créer des certificats

### Utilisation du fournisseur par défaut

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Utilisation d'un fournisseur spécifique

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "vultr"
  }'
```

### Utilisation d'un compte spécifique

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
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

- **Séparation des environnements** : comptes de production, de staging et de DR
- **Multi-régions** : comptes différents pour les domaines US, UE, APAC
- **Isolation des permissions** : comptes admin, limités et CI/CD

### Ajouter plusieurs comptes

```bash
# Ajouter le compte de production
curl -X POST http://localhost:8000/api/dns/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "production",
    "config": {
      "name": "Production Environment",
      "description": "Main production Cloudflare account",
      "api_token": "cloudflare_production_token"
    }
  }'

# Ajouter le compte de staging
curl -X POST http://localhost:8000/api/dns/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "account_id": "staging",
    "config": {
      "name": "Staging Environment",
      "description": "Development and testing account",
      "api_token": "cloudflare_staging_token"
    }
  }'

# Définir production comme compte par défaut (il n'y a pas d'endpoint dédié :
# "set_as_default" accompagne les données du compte)
curl -X PUT http://localhost:8000/api/dns/cloudflare/accounts/production \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"set_as_default": true}'
```

### Gérer les comptes

```bash
# Lister tous les comptes d'un fournisseur
curl -X GET http://localhost:8000/api/dns/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Mettre à jour un compte
curl -X PUT http://localhost:8000/api/dns/cloudflare/accounts/staging \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "name": "Staging & Testing",
      "api_token": "new_staging_token"
    }
  }'

# Supprimer un compte
curl -X DELETE http://localhost:8000/api/dns/cloudflare/accounts/old-account \
  -H "Authorization: Bearer YOUR_API_TOKEN"
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
        "name": "Production Environment",
        "api_token": "***masked***"
      },
      "staging": {
        "name": "Staging Environment",
        "api_token": "***masked***"
      }
    },
    "route53": {
      "main-aws": {
        "name": "Main AWS Account",
        "access_key_id": "***masked***",
        "secret_access_key": "***masked***",
        "region": "us-east-1"
      }
    }
  }
}
```

### Rétrocompatibilité

Les configurations mono-compte existantes sont automatiquement migrées vers le format multi-comptes lors de la première utilisation. Aucun temps d'arrêt ni migration manuelle n'est nécessaire.

---

## DNS multi-maître et alias de domaine (délégation CNAME)

Lorsque votre domaine est géré par plusieurs fournisseurs DNS simultanément (configuration multi-maître), utilisez la **délégation CNAME** standard pour centraliser la validation DNS ACME sur un seul fournisseur.

### Le problème

Avec un DNS multi-maître (par ex. deSEC + gcore), vous ne pouvez configurer qu'un seul fournisseur DNS par demande de certificat, mais la validation ACME nécessite de créer des enregistrements TXT `_acme-challenge`.

### La solution

La validation par alias DNS fonctionne via la délégation CNAME. Let's Encrypt suit les chaînes CNAME pendant la validation DNS-01 ; CertMate écrit l'enregistrement TXT requis sur le nom de validation délégué.

1. **Créez un domaine de validation** chez un fournisseur de première classe supporté (par ex. `validation.example.org` sur Cloudflare, PowerDNS, Route53 ou ACME-DNS)
2. **Ajoutez des enregistrements CNAME** dans tous vos fournisseurs DNS, pointant vers le domaine de validation :
   ```dns
   _acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
   ```
3. **Demandez le certificat** en indiquant le fournisseur qui gère le domaine de validation :
   ```bash
   curl -X POST http://localhost:8000/api/certificates/create \
     -H "Authorization: Bearer YOUR_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{
       "domain": "example.com",
       "dns_provider": "cloudflare",
       "domain_alias": "validation.example.org"
     }'
   ```

   Quand `domain_alias` est défini avec un fournisseur supporté, CertMate utilise un hook DNS manuel de certbot pour créer l'enregistrement TXT sur `_acme-challenge.validation.example.org`. Le CNAME garantit que Let's Encrypt trouve cette valeur TXT en interrogeant `_acme-challenge.example.com`.

### Avantages

- Fonctionne quel que soit le fournisseur DNS qui répond à la requête
- Aucune synchronisation nécessaire entre les fournisseurs
- Fonctionne avec des fournisseurs que CertMate ne supporte pas nativement (deSEC, gcore)
- Les identifiants de l'API DNS sont limités au seul domaine de validation
- Implémenté pour les fournisseurs DNS de première classe de CertMate ; les fournisseurs génériques de repli sont rejetés tant que des adaptateurs d'alias dédiés n'existent pas

### Exemples par fournisseur

Cloudflare, PowerDNS et Route53 utilisent tous la même forme de requête :

```json
{
  "domain": "example.com",
  "dns_provider": "route53",
  "domain_alias": "validation.example.org"
}
```

Pour ACME-DNS, `domain_alias` doit correspondre exactement au `subdomain`/fulldomain ACME-DNS configuré. CertMate met à jour cet enregistrement ACME-DNS directement et ne tente aucun nettoyage, car ACME-DNS conserve la dernière valeur de validation.

Pour **RFC2136** (BIND, Technitium et autres serveurs à mise à jour dynamique), `domain_alias` écrit le TXT `_acme-challenge.<alias>` dans la zone de l'alias par une mise à jour dynamique signée TSIG, avec les mêmes `nameserver` / `tsig_key` / `tsig_secret` (et `tsig_algorithm` optionnel, HMAC-SHA512 par défaut) que l'émission normale. CertMate découvre la zone propriétaire à partir du SOA du serveur, de sorte qu'une seule clé TSIG peut servir plusieurs zones — y compris des domaines gérés à l'extérieur dont les propriétaires ont seulement ajouté le CNAME de délégation :

```json
{
  "domain": "external.example.com",
  "dns_provider": "rfc2136",
  "domain_alias": "internal.example.net"
}
```

### Certificats wildcard avec alias de domaine

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
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
# Vérifier la propagation du CNAME
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
CLOUDFLARE_API_TOKEN=your_token

# AWS Route53
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-1

# Azure
AZURE_SUBSCRIPTION_ID=your_subscription_id
AZURE_RESOURCE_GROUP=your_resource_group
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret

# Google Cloud
GOOGLE_PROJECT_ID=your_project_id
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json

# PowerDNS
POWERDNS_API_URL=https://your-powerdns-server:8081
POWERDNS_API_KEY=your_api_key
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
|---------|--------------|----------|
| Très rapide | ACME-DNS | 30 |
| Rapide | Cloudflare, Route53, PowerDNS, DuckDNS | 60 |
| Moyen | DigitalOcean, Linode, Google, ArvanCloud | 120 |
| Lent | Azure, Gandi, OVH | 180 |
| Très lent | Namecheap | 300 |

---

## Fonctionnalités de sécurité

- **Masquage des identifiants** dans l'interface Web et les réponses de l'API
- **Permissions de fichiers sécurisées** (600) pour tous les fichiers d'identifiants
- **Validation du jeton API** avant la création du certificat
- **Support des variables d'environnement** pour les workflows CI/CD
- **Journalisation d'audit** pour toutes les opérations sur les fournisseurs DNS
- **Isolation des comptes** — les identifiants de chaque compte sont stockés séparément

---

## Architecture et guide du développeur

### Classes principales

| Classe | Fichier | Rôle |
|--------|---------|------|
| `DNSManager` | `modules/core/dns_providers.py` | Gestion de la configuration multi-comptes |
| `CertificateManager` | `modules/core/certificates.py` | Création de certificats avec les fournisseurs DNS |
| `SettingsManager` | `modules/core/settings.py` | Persistance et migration des paramètres |
| `Utils` | `modules/core/utils.py` | Génération et validation des fichiers d'identifiants |

### Méthodes de stockage des identifiants

1. **Fichier de paramètres** (`data/settings.json`) — le plus courant
2. **Variables d'environnement** — pour le CI/CD
3. **Fichiers de configuration temporaires** (`letsencrypt/config/[provider].ini`) — créés pendant les demandes de certificat, supprimés ensuite

### Ajouter un nouveau fournisseur DNS

1. Ajoutez le plugin à `requirements.txt` : `certbot-dns-newprovider`
2. Créez une fonction de configuration dans `modules/core/utils.py`
3. Ajoutez la définition des identifiants dans `utils.py`
4. Importez-le et gérez-le dans `modules/core/certificates.py`
5. Ajoutez-le à la liste des fournisseurs supportés dans `modules/core/settings.py`
6. Mettez à jour la documentation

Voir le [Guide d'architecture](./architecture.md) pour tous les détails d'implémentation.

---

## Dépannage

### Problèmes courants

| Erreur | Solution |
|--------|----------|
| `DNS provider '<provider>' account '<id>' not configured` | Le compte indiqué par le certificat n'a pas d'identifiants enregistrés. Ajoutez-les dans les Paramètres, ou choisissez un compte qui existe |
| "Certificate creation failed" | Vérifiez les permissions DNS et la propriété du domaine |
| `The certbot plugin '<plugin>' is not installed` | Exécutez `pip install certbot-<plugin>`, ou reconstruisez l'image Docker avec `REQUIREMENTS_FILE=requirements.txt` |
| "Échec de la détection du fournisseur" | Vérifiez le champ `dns_provider` dans les paramètres du domaine |

### Mode débogage

```bash
# En lançant app.py directement : utilisez l'option. --log-level vaut INFO
# par défaut et l'emporte sur CERTMATE_LOG_LEVEL.
python app.py --log-level DEBUG

# Docker / gunicorn : définissez la variable d'environnement, par ex. dans .env
CERTMATE_LOG_LEVEL=DEBUG
```

### Tester la configuration du fournisseur

```bash
curl -X GET http://localhost:8000/api/settings/dns-providers \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

---

## Guide de migration

### D'un fournisseur unique à plusieurs fournisseurs

Les configurations existantes restent inchangées. Ajoutez simplement de nouveaux fournisseurs :

```json
{
  "dns_providers": {
    "cloudflare": {
      "api_token": "existing_token"
    },
    "vultr": {
      "api_key": "new_vultr_api_key"
    }
  }
}
```

### Utiliser des fournisseurs différents selon le certificat

```bash
# Cloudflare pour un domaine
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "dns_provider": "cloudflare"}'

# Route53 pour un autre
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "test.org", "dns_provider": "route53"}'
```

---

<div align="center">

[← Retour à la documentation](./README.md) • [Installation →](./installation.md) • [Fournisseurs CA →](./ca-providers.md)

</div>
