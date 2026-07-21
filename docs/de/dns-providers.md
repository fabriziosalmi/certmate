# DNS-Anbieter

CertMate unterstützt eine breite Palette von DNS-Anbietern für Let's Encrypt DNS-01-Challenges über individuelle certbot-Plugins. Die vollständige Liste befindet sich in der nachstehenden Tabelle.

---

## Unterstützte Anbieter

| Anbieter | Plugin | Erforderliche Zugangsdaten | Kategorie |
|---|---|---|---|
| **Cloudflare** | `certbot-dns-cloudflare` | API-Token | Großer Cloud-Anbieter |
| **AWS Route53** | `certbot-dns-route53` | Access Key, Secret Key | Großer Cloud-Anbieter |
| **Azure DNS** | `certbot-dns-azure` | Service Principal | Großer Cloud-Anbieter |
| **Google Cloud DNS** | `certbot-dns-google` | Service Account JSON | Großer Cloud-Anbieter |
| **PowerDNS** | `certbot-dns-powerdns` | API-URL, API-Schlüssel | Enterprise |
| **DNS Made Easy** | `certbot-dns-dnsmadeeasy` | API-Schlüssel, Secret Key | Enterprise |
| **NS1** | `certbot-dns-nsone` | API-Schlüssel | Enterprise |
| **DigitalOcean** | `certbot-dns-digitalocean` | API-Token | Cloud |
| **Linode (Akamai Connected Cloud)** | `certbot-dns-linode` | API-Schlüssel | Cloud |
| **Akamai Edge DNS** | `certbot-plugin-edgedns` | EdgeGrid `.edgerc` (client_token, client_secret, access_token, host) | Enterprise |
| **Vultr** | `certbot-dns-vultr` | API-Schlüssel | Cloud |
| **Hetzner (DNS legacy)** | `certbot-dns-hetzner` | API-Token | Cloud |
| **Hetzner Cloud** | `certbot-dns-hetzner-cloud` | API-Token | Cloud |
| **Gandi** | `certbot-dns-gandi` | API-Token | Registrar |
| **Namecheap** | `certbot-dns-namecheap` | Benutzername, API-Schlüssel | Registrar |
| **Porkbun** | `certbot-dns-porkbun` | API-Schlüssel, Secret Key | Registrar |
| **GoDaddy** | `certbot-dns-godaddy` | API-Schlüssel, Secret | Registrar |
| **OVH** | `certbot-dns-ovh` | API-Zugangsdaten | Regional |
| **Infomaniak** | `certbot-dns-infomaniak` | API-Token | Regional |
| **ArvanCloud** | `certbot-dns-arvancloud` | API-Schlüssel | Regional |
| **RFC2136** | `certbot-dns-rfc2136` | Nameserver, TSIG-Schlüssel | Standardprotokoll |
| **ACME-DNS** | `certbot-acme-dns` | API-URL, Benutzername, Passwort | Spezialisiert |
| **Hurricane Electric** | `certbot-dns-he-ddns` | Benutzername, Passwort | Kostenloses DNS |
| **Dynu** | `certbot-dns-dynudns` | API-Token | Dynamisches DNS |
| **DuckDNS** | `certbot-dns-duckdns` | Konto-Token | Kostenloses DDNS (ohne eigene Domain) |
| **deSEC** | `certbot-dns-desec` | API-Token | Kostenlos, EU (DE), DNSSEC — NS an `ns1.desec.io` / `ns2.desec.org` delegieren |
| **Scaleway** | `certbot-dns-scaleway` | Geheimer API-Schlüssel | Souveräne EU-Cloud (FR) — Community-Plugin (Alpha), separat installieren: `pip install certbot-dns-scaleway` |
| **Custom Script** | keines (certbot `--manual`) | Pfad zum Auth-Hook-Skript (+ optionaler Cleanup-Hook) | Eigene Lösung |

---

## Konfiguration

### Über die Weboberfläche

1. Navigieren Sie zu **Einstellungen**
2. Wählen Sie Ihren DNS-Anbieter aus dem Dropdown-Menü
3. Tragen Sie die erforderlichen Zugangsdaten ein
4. Einstellungen speichern

### Über die API

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

## Konfigurationsbeispiele je Anbieter

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

Für BIND oder andere RFC2136-kompatible DNS-Server (einschließlich **Technitium DNS Server**):

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

> **Technitium DNS**: Aktivieren Sie Dynamic Updates in den Zone-Optionen, legen Sie einen TSIG-Schlüssel an (z. B. `certmate-key` mit HMAC-SHA512) und verwenden Sie das generierte Secret in der obigen Konfiguration.

### Hetzner (legacy DNS API)

> **Abkündigungshinweis:** Die Hetzner-DNS-Konsolen-API wird im Mai 2025 abgeschaltet. Neue Nutzer sollten den **Hetzner Cloud**-Anbieter weiter unten verwenden. Bestehende Nutzer müssen vor dem Abschalttermin zu `hetzner-cloud` migrieren. Einzelheiten finden Sie auf der [Hetzner-Statusseite](https://status.hetzner.com/incident/c2146c42-6dd2-4454-916a-19f07e0e5a44).

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

Verwendet die neue [Hetzner Cloud API](https://docs.hetzner.cloud/reference/cloud), die die veraltete Hetzner-DNS-Konsole ersetzt. Dies ist der empfohlene Anbieter für alle Hetzner-Nutzer.

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

> Erzeugen Sie einen Hetzner Cloud API-Token in der [Hetzner Cloud Console](https://console.hetzner.cloud/) im Bereich API-Token Ihres Projekts. Der Token benötigt Lese- und Schreibrechte für DNS.

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

> Den API-Token erhalten Sie im Infomaniak Manager (Bereich API mit dem Scope „Domain").

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

### DuckDNS (ohne eigene Domain)

DuckDNS stellt kostenlose `<name>.duckdns.org`-Subdomains bereit — der einfachste Weg, ein öffentlich vertrauenswürdiges Zertifikat zu erhalten, wenn Sie keine eigene Domain besitzen. Typische Anwendungsfälle: Homelabs, selbst gehostete Dienste, IoT-Geräte, interne Dashboards, die bisher auf selbstsignierten Zertifikaten feststeckten.

1. Melden Sie sich auf <https://www.duckdns.org/> an (Google / GitHub / Twitter / Reddit SSO).
2. Wählen Sie eine Subdomain (z. B. `mybox` → `mybox.duckdns.org`).
3. Kopieren Sie den Konto-Token, der oben auf der Seite angezeigt wird.

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

Wildcards wie `*.mybox.duckdns.org` werden mit demselben Token unterstützt. Da DuckDNS pro Domain jeweils nur einen TXT-Eintrag speichert, ist pro DuckDNS-Subdomain genau ein certbot-Lauf erforderlich — SAN-Zertifikate, die mehrere DuckDNS-Subdomains umfassen, werden nicht unterstützt.

### Custom Script (eigene Lösung)

Für DNS-Anbieter ohne certbot-Plugin — Oracle Cloud (OCI), unternehmensinternes DNS, Appliance-APIs — verweisen Sie CertMate auf Ihre eigenen Skripte; CertMate steuert diese dann über certbots `--manual`-Modus. Eine Plugin-Installation ist nicht erforderlich.

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

certbot ruft den Auth-Hook einmal pro Validierungs-Challenge mit der standardmäßigen [manual-hook-Umgebung](https://eff-certbot.readthedocs.io/en/stable/using.html#hooks) auf: `CERTBOT_DOMAIN` (die zu validierende Domain) und `CERTBOT_VALIDATION` (der TXT-Wert). Das Skript muss den TXT-Eintrag `_acme-challenge.$CERTBOT_DOMAIN` anlegen **und warten, bis dieser propagiert ist** — certbot validiert unmittelbar nach Rückkehr des Hooks. Der optionale Cleanup-Hook wird nach der Validierung ausgeführt, um den Eintrag zu entfernen.

Praxisbeispiel für OCI DNS (behandelt [#285](https://github.com/fabriziosalmi/certmate/issues/285)). Beachten Sie: Ein Zertifikat, das sowohl `example.com` als auch `*.example.com` abdeckt, erzeugt ZWEI Validierungs-Challenges auf demselben Namen `_acme-challenge.example.com`; certbot führt alle Auth-Hooks aus, bevor es validiert — der Hook muss daher zum TXT-Rrset HINZUFÜGEN und es niemals ersetzen (ein einfaches `rrset update` würde den ersten Token mit dem zweiten überschreiben):

```bash
#!/bin/sh
# /usr/local/bin/certmate-dns-auth.sh
set -eu
ZONE="example.com"
NAME="_acme-challenge.${CERTBOT_DOMAIN}"
# Merge the new validation token with any records already on the name
# (apex + wildcard certs place two TXT values on the same name).
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

Voraussetzungen und Vertrauensmodell:

- Pfade müssen **absolut** sein, die Dateien müssen vorhanden und **ausführbar** sein, dürfen nicht world-writable sein und dürfen keine Leerzeichen oder Shell-Metazeichen enthalten (certbot führt Hooks über die Shell aus). Die Prüfung erfolgt bei der Ausstellung und über den Test-Provider-API-Endpoint (`POST /api/web/certificates/test-provider`)
- Skripte laufen mit den Berechtigungen von CertMate — dasselbe Vertrauensmodell wie bei deploy hooks: nur Administratoren können sie konfigurieren; behandeln Sie sie als Teil Ihres Deployments
- Die anbieterspezifische Einstellung `dns_propagation_seconds` wird den Skripten als `CERTMATE_DNS_PROPAGATION_SECONDS` exportiert (ein `propagation_seconds`-Feld auf Kontoebene überschreibt diesen Wert)
- Verlängerungen spielen die Hook-Pfade aus der certbot-Verlängerungskonfiguration erneut ab: halten Sie die Skripte unter einem stabilen Pfad (wenn Sie sie verschieben, stellen Sie das Zertifikat neu aus)
- Wildcard-Zertifikate funktionieren (der Hook erhält jeden Validierungseintrag)

---

## Zertifikate erstellen

### Mit dem Standard-Anbieter

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Mit einem bestimmten Anbieter

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "vultr"
  }'
```

### Mit einem bestimmten Konto

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

## Multi-Konto-Unterstützung

CertMate unterstützt mehrere Konten pro DNS-Anbieter für Enterprise-Umgebungen.

### Anwendungsfälle

- **Umgebungstrennung**: Produktions-, Staging- und DR-Konten
- **Multi-Region**: Unterschiedliche Konten für US-, EU- und APAC-Domains
- **Berechtigungsisolierung**: Admin-, eingeschränkte und CI/CD-Konten

### Mehrere Konten hinzufügen

```bash
# Produktionskonto hinzufügen
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

# Staging-Konto hinzufügen
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

# Produktion als Standardkonto festlegen (kein eigener Endpunkt:
# "set_as_default" wird mit den Kontodaten gesendet)
curl -X PUT http://localhost:8000/api/dns/cloudflare/accounts/production \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"set_as_default": true}'
```

### Konten verwalten

```bash
# Alle Konten eines Anbieters auflisten
curl -X GET http://localhost:8000/api/dns/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Ein Konto aktualisieren
curl -X PUT http://localhost:8000/api/dns/cloudflare/accounts/staging \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "name": "Staging & Testing",
      "api_token": "new_staging_token"
    }
  }'

# Ein Konto löschen
curl -X DELETE http://localhost:8000/api/dns/cloudflare/accounts/old-account \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

### Struktur der Multi-Konto-Konfiguration

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

### Abwärtskompatibilität

Bestehende Einzelkonto-Konfigurationen werden bei der ersten Verwendung automatisch in das Multi-Konto-Format migriert. Kein Ausfall und keine manuelle Migration erforderlich.

---

## Multi-Master-DNS und Domain-Alias (CNAME-Delegation)

Wenn Ihre Domain gleichzeitig von mehreren DNS-Anbietern verwaltet wird (Multi-Master-Setup), verwenden Sie die standardmäßige **CNAME-Delegation**, um die ACME-DNS-Validierung bei einem einzigen Anbieter zu zentralisieren.

### Das Problem

Bei Multi-Master-DNS (z. B. deSEC + gcore) kann pro Zertifikatsanfrage nur ein DNS-Anbieter konfiguriert werden, die ACME-Validierung erfordert jedoch das Anlegen von `_acme-challenge`-TXT-Einträgen.

### Die Lösung

Die DNS-Alias-Validierung funktioniert über CNAME-Delegation. Let's Encrypt folgt CNAME-Ketten während der DNS-01-Validierung; CertMate schreibt den erforderlichen TXT-Eintrag auf den delegierten Validierungsnamen.

1. **Erstellen Sie eine Validierungsdomain** bei einem unterstützten erstklassigen Anbieter (z. B. `validation.example.org` bei Cloudflare, PowerDNS, Route53 oder ACME-DNS)
2. **Fügen Sie CNAME-Einträge** in allen Ihren DNS-Anbietern hinzu, die auf die Validierungsdomain zeigen:
   ```dns
   _acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
   ```
3. **Fordern Sie das Zertifikat an** und geben Sie dabei den Anbieter an, der die Validierungsdomain verwaltet:
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

   Wenn `domain_alias` mit einem unterstützten Anbieter gesetzt ist, verwendet CertMate einen manuellen certbot-DNS-Hook, um den TXT-Eintrag unter `_acme-challenge.validation.example.org` zu erstellen. Der CNAME stellt sicher, dass Let's Encrypt diesen TXT-Wert findet, wenn es `_acme-challenge.example.com` abfragt.

### Vorteile

- Funktioniert unabhängig davon, welcher DNS-Anbieter die Abfrage bedient
- Keine Synchronisation zwischen Anbietern erforderlich
- Funktioniert mit Anbietern, die von CertMate nicht nativ unterstützt werden (deSEC, gcore)
- DNS-API-Zugangsdaten sind auf die Validierungsdomain beschränkt
- Implementiert für CertMate's erstklassige DNS-Anbieter; generische Fallback-Anbieter werden abgelehnt, bis dedizierte Alias-Adapter vorhanden sind

### Anbieterbeispiele

Cloudflare, PowerDNS und Route53 verwenden alle dieselbe Anfragestruktur:

```json
{
  "domain": "example.com",
  "dns_provider": "route53",
  "domain_alias": "validation.example.org"
}
```

Bei ACME-DNS muss `domain_alias` exakt mit der konfigurierten ACME-DNS-`subdomain`/Fulldomain übereinstimmen. CertMate aktualisiert diesen ACME-DNS-Eintrag direkt und versucht keine Bereinigung, da ACME-DNS immer den letzten Validierungswert speichert.

### Wildcard-Zertifikate mit Domain-Alias

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

Stellen Sie sicher, dass der CNAME vorhanden ist, bevor Sie das Zertifikat anfordern:

```dns
_acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
```

### Fehlerbehebung beim Domain-Alias

```bash
# CNAME-Propagation prüfen
dig @8.8.8.8 _acme-challenge.example.com CNAME +short
# Erwartet: _acme-challenge.validation.example.org.

# Nach der Zertifikatsanfrage den TXT-Eintrag auf der Validierungsdomain prüfen
dig _acme-challenge.validation.example.org TXT +short
# Erwartet: ein base64-kodierter ACME-Challenge-Token
```

---

## Umgebungsvariablen

Setzen Sie DNS-Anbieter-Zugangsdaten über Umgebungsvariablen für CI/CD-Workflows:

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

### Konfigurationspriorität (höchste bis niedrigste)

1. Umgebungsvariablen
2. Domainspezifische Einstellungen
3. Standard-Konto-Einstellungen
4. Globale Anbietereinstellung
5. Systemstandard (Cloudflare)

---

## DNS-Propagationszeiten

| Geschwindigkeit | Anbieter | Sekunden |
|----------------|----------|----------|
| Sehr schnell | ACME-DNS | 30 |
| Schnell | Cloudflare, Route53, PowerDNS, DuckDNS | 60 |
| Mittel | DigitalOcean, Linode, Google, ArvanCloud | 120 |
| Langsam | Azure, Gandi, OVH | 180 |
| Sehr langsam | Namecheap | 300 |

---

## Sicherheitsfunktionen

- **Maskierung von Zugangsdaten** in der Weboberfläche und in API-Antworten
- **Sichere Dateiberechtigungen** (600) für alle Zugangsdaten-Dateien
- **API-Token-Validierung** vor der Zertifikatserstellung
- **Unterstützung von Umgebungsvariablen** für CI/CD-Workflows
- **Audit-Logging** für alle DNS-Anbieter-Operationen
- **Kontoisolierung** — die Zugangsdaten jedes Kontos werden separat gespeichert

---

## Architektur und Entwicklerhandbuch

### Wichtige Klassen

| Klasse | Datei | Zweck |
|--------|-------|-------|
| `DNSManager` | `modules/core/dns_providers.py` | Verwaltung der Multi-Konto-Konfiguration |
| `CertificateManager` | `modules/core/certificates.py` | Zertifikatserstellung mit DNS-Anbietern |
| `SettingsManager` | `modules/core/settings.py` | Persistenz und Migration von Einstellungen |
| `Utils` | `modules/core/utils.py` | Generierung und Validierung von Zugangsdaten-Dateien |

### Methoden zur Speicherung von Zugangsdaten

1. **Einstellungsdatei** (`data/settings.json`) — am häufigsten verwendet
2. **Umgebungsvariablen** — für CI/CD
3. **Temporäre Konfigurationsdateien** (`letsencrypt/config/[provider].ini`) — werden während Zertifikatsanfragen erstellt und danach gelöscht

### Einen neuen DNS-Anbieter hinzufügen

1. Plugin zu `requirements.txt` hinzufügen: `certbot-dns-newprovider`
2. Konfigurationsfunktion in `modules/core/utils.py` erstellen
3. Zugangsdaten-Definition in `utils.py` hinzufügen
4. Importieren und verarbeiten in `modules/core/certificates.py`
5. Zur Liste der unterstützten Anbieter in `modules/core/settings.py` hinzufügen
6. Dokumentation aktualisieren

Vollständige Implementierungsdetails finden Sie im [Architekturhandbuch](./architecture.md).

---

## Fehlerbehebung

### Häufige Probleme

| Fehler | Lösung |
|--------|--------|
| "DNS provider not configured" | Stellen Sie sicher, dass alle erforderlichen Zugangsdaten angegeben sind |
| "Certificate creation failed" | DNS-Berechtigungen und Domain-Inhaberschaft prüfen |
| "Plugin not found" | `pip install -r requirements.txt` ausführen oder Docker neu erstellen |
| "Provider detection failing" | Das Feld `dns_provider` in den Domain-Einstellungen prüfen |

### Debug-Modus

```bash
export FLASK_DEBUG=1
python app.py
```

### Anbieterkonfiguration testen

```bash
curl -X GET http://localhost:8000/api/settings/dns-providers \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

---

## Migrationshandbuch

### Von einem einzelnen Anbieter zu mehreren Anbietern

Bestehende Konfigurationen bleiben unverändert. Fügen Sie einfach neue Anbieter hinzu:

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

### Verschiedene Anbieter je Zertifikat verwenden

```bash
# Cloudflare für eine Domain
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "dns_provider": "cloudflare"}'

# Route53 für eine andere
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "test.org", "dns_provider": "route53"}'
```

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [Installation →](./installation.md) • [CA-Anbieter →](./ca-providers.md)

</div>
