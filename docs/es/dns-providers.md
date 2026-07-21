# Proveedores DNS

CertMate soporta una amplia gama de proveedores DNS para los desafíos Let's Encrypt DNS-01 mediante plugins de certbot individuales. La lista completa se encuentra en la tabla a continuación.

---

## Proveedores soportados

| Proveedor | Plugin | Credenciales requeridas | Categoría |
|---|---|---|---|
| **Cloudflare** | `certbot-dns-cloudflare` | Token API | Cloud principal |
| **AWS Route53** | `certbot-dns-route53` | Access Key, Secret Key | Cloud principal |
| **Azure DNS** | `certbot-dns-azure` | Service Principal | Cloud principal |
| **Google Cloud DNS** | `certbot-dns-google` | Service Account JSON | Cloud principal |
| **PowerDNS** | `certbot-dns-powerdns` | URL API, Clave API | Empresa |
| **DNS Made Easy** | `certbot-dns-dnsmadeeasy` | Clave API, Secret Key | Empresa |
| **NS1** | `certbot-dns-nsone` | Clave API | Empresa |
| **DigitalOcean** | `certbot-dns-digitalocean` | Token API | Cloud |
| **Linode (Akamai Connected Cloud)** | `certbot-dns-linode` | Clave API | Cloud |
| **Akamai Edge DNS** | `certbot-plugin-edgedns` | EdgeGrid `.edgerc` (client_token, client_secret, access_token, host) | Empresa |
| **Vultr** | `certbot-dns-vultr` | Clave API | Cloud |
| **Hetzner (DNS legacy)** | `certbot-dns-hetzner` | Token API | Cloud |
| **Hetzner Cloud** | `certbot-dns-hetzner-cloud` | Token API | Cloud |
| **Gandi** | `certbot-dns-gandi` | Token API | Registrar |
| **Namecheap** | `certbot-dns-namecheap` | Nombre de usuario, Clave API | Registrar |
| **Porkbun** | `certbot-dns-porkbun` | Clave API, Secret Key | Registrar |
| **GoDaddy** | `certbot-dns-godaddy` | Clave API, Secret | Registrar |
| **OVH** | `certbot-dns-ovh` | Credenciales API | Regional |
| **Infomaniak** | `certbot-dns-infomaniak` | Token API | Regional |
| **ArvanCloud** | `certbot-dns-arvancloud` | Clave API | Regional |
| **RFC2136** | `certbot-dns-rfc2136` | Servidor DNS, Clave TSIG | Protocolo estándar |
| **ACME-DNS** | `certbot-acme-dns` | URL API, Nombre de usuario, Contraseña | Especializado |
| **Hurricane Electric** | `certbot-dns-he-ddns` | Nombre de usuario, Contraseña | DNS gratuito |
| **Dynu** | `certbot-dns-dynudns` | Token API | DNS dinámico |
| **DuckDNS** | `certbot-dns-duckdns` | Token de cuenta | DDNS gratuito (sin dominio propio) |
| **deSEC** | `certbot-dns-desec` | Token API | Gratuito, UE (DE), DNSSEC — delegar NS a `ns1.desec.io` / `ns2.desec.org` |
| **Scaleway** | `certbot-dns-scaleway` | Clave secreta API | Cloud soberano UE (FR) — plugin comunitario (alpha), instalar por separado: `pip install certbot-dns-scaleway` |
| **Script personalizado** | ninguno (certbot `--manual`) | Ruta del script auth (+ script cleanup opcional) | Trae el tuyo propio |

---

## Configuración

### Mediante la interfaz web

1. Ve a **Ajustes**
2. Selecciona tu proveedor DNS en el menú desplegable
3. Rellena las credenciales requeridas
4. Guarda los ajustes

### Mediante la API

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

## Ejemplos de configuración por proveedor

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

Para servidores DNS compatibles con RFC2136 (incluido **Technitium DNS Server**):

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

> **Technitium DNS**: Activa Dynamic Updates en Zone Options, crea una clave TSIG (p. ej. `certmate-key` con HMAC-SHA512) y utiliza el secreto generado en la configuración anterior.

### Hetzner (API DNS legacy)

> **Aviso de obsolescencia:** La API de la consola DNS de Hetzner será retirada en mayo de 2025. Los nuevos usuarios deben utilizar el proveedor **Hetzner Cloud** que aparece más abajo. Los usuarios existentes deben migrar a `hetzner-cloud` antes de la fecha de retirada. Consulta la [página de estado de Hetzner](https://status.hetzner.com/incident/c2146c42-6dd2-4454-916a-19f07e0e5a44) para más detalles.

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

Utiliza la nueva [API Hetzner Cloud](https://docs.hetzner.cloud/reference/cloud) que reemplaza la API DNS de Hetzner obsoleta. Este es el proveedor recomendado para todos los usuarios de Hetzner.

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

> Genera un token API de Hetzner Cloud desde la [Consola Hetzner Cloud](https://console.hetzner.cloud/) en la sección de tokens API de tu proyecto. El token necesita permisos de lectura/escritura sobre DNS.

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

> Obtén el token API desde Infomaniak Manager (sección API con scope "Domain").

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

### DuckDNS (sin dominio propio)

DuckDNS proporciona subdominios gratuitos `<nombre>.duckdns.org` — la forma más sencilla de obtener un certificado de confianza pública cuando no se posee un dominio propio. Casos de uso típicos: homelabs, servicios auto-alojados, dispositivos IoT, paneles internos que hasta ahora dependían de certificados autofirmados.

1. Inicia sesión en <https://www.duckdns.org/> (SSO de Google / GitHub / Twitter / Reddit).
2. Elige un subdominio (p. ej. `mybox` → `mybox.duckdns.org`).
3. Copia el token de cuenta que aparece en la parte superior de la página.

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

Los wildcards como `*.mybox.duckdns.org` están soportados con el mismo token. Dado que DuckDNS solo almacena un registro TXT por dominio a la vez, se requiere una única ejecución de certbot por subdominio DuckDNS — no se soportan certificados SAN que abarquen varios subdominios DuckDNS.

### Script personalizado (trae tu propio proveedor)

Para proveedores DNS sin plugin de certbot — Oracle Cloud (OCI), DNS interno, APIs de appliance — apunta CertMate a tus propios scripts y los ejecutará a través del modo `--manual` de certbot. No se requiere instalación de plugin alguno.

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

certbot invoca el auth hook una vez por cada desafío de validación con el entorno estándar de [manual-hook](https://eff-certbot.readthedocs.io/en/stable/using.html#hooks): `CERTBOT_DOMAIN` (el dominio que se valida) y `CERTBOT_VALIDATION` (el valor TXT). El script debe crear el registro TXT `_acme-challenge.$CERTBOT_DOMAIN` **y esperar a que se propague** — certbot valida inmediatamente tras el retorno del hook. El cleanup hook opcional se ejecuta después de la validación para eliminar el registro.

Ejemplo para OCI DNS (cubre [#285](https://github.com/fabriziosalmi/certmate/issues/285)). Ten en cuenta que un certificado que cubra tanto `example.com` como `*.example.com` produce DOS desafíos de validación sobre el mismo nombre `_acme-challenge.example.com`, y certbot ejecuta todos los auth hooks antes de validar — por tanto, el hook debe AÑADIR al rrset TXT, nunca reemplazarlo (una actualización simple del rrset eliminaría el primer token con el segundo):

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

Requisitos y modelo de confianza:

- Las rutas deben ser **absolutas**, los archivos deben existir, ser **ejecutables**, no tener permisos de escritura para todos los usuarios, y no contener espacios ni metacaracteres de shell (certbot ejecuta los hooks a través del shell). Se validan en el momento de la emisión y mediante el endpoint API de prueba (`POST /api/web/certificates/test-provider`)
- Los scripts se ejecutan con los privilegios de CertMate — el mismo modelo de confianza que los deploy hooks: solo los administradores pueden configurarlos; tratalos como parte de tu despliegue
- El ajuste `dns_propagation_seconds` por proveedor se exporta a los scripts como `CERTMATE_DNS_PROPAGATION_SECONDS` (un campo `propagation_seconds` a nivel de cuenta tiene prioridad sobre él)
- Las renovaciones replican las rutas de los hooks desde la configuración de renovación de certbot: mantén los scripts en una ruta estable (si los mueves, vuelve a emitir el certificado)
- Los certificados wildcard funcionan correctamente (el hook recibe cada registro de validación)

---

## Crear certificados

### Usando el proveedor por defecto

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com"}'
```

### Usando un proveedor específico

```bash
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "dns_provider": "vultr"
  }'
```

### Usando una cuenta específica

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

## Soporte multi-cuenta

CertMate soporta varias cuentas por proveedor DNS para entornos de empresa.

### Casos de uso

- **Separación de entornos**: Cuentas de producción, staging y DR
- **Multi-región**: Distintas cuentas para dominios US, UE, APAC
- **Aislamiento de permisos**: Cuentas de administrador, limitada y CI/CD

### Añadir varias cuentas

```bash
# Añadir cuenta de producción
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

# Añadir cuenta de staging
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

# Establecer producción por defecto (no hay un endpoint dedicado:
# "set_as_default" viaja con los datos de la cuenta)
curl -X PUT http://localhost:8000/api/dns/cloudflare/accounts/production \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"set_as_default": true}'
```

### Gestionar cuentas

```bash
# Listar todas las cuentas de un proveedor
curl -X GET http://localhost:8000/api/dns/cloudflare/accounts \
  -H "Authorization: Bearer YOUR_API_TOKEN"

# Actualizar una cuenta
curl -X PUT http://localhost:8000/api/dns/cloudflare/accounts/staging \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "name": "Staging & Testing",
      "api_token": "new_staging_token"
    }
  }'

# Eliminar una cuenta
curl -X DELETE http://localhost:8000/api/dns/cloudflare/accounts/old-account \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

### Estructura de configuración multi-cuenta

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

### Compatibilidad con versiones anteriores

Las configuraciones mono-cuenta existentes se migran automáticamente al formato multi-cuenta en el primer uso. No se requiere tiempo de inactividad ni migración manual.

---

## DNS multi-master y alias de dominio (delegación CNAME)

Cuando tu dominio está gestionado por varios proveedores DNS simultáneamente (configuración multi-master), utiliza la **delegación CNAME** estándar para centralizar la validación ACME DNS en un único proveedor.

### El problema

Con DNS multi-master (p. ej. deSEC + gcore), solo se puede configurar un proveedor DNS por solicitud de certificado, pero la validación ACME requiere crear registros TXT `_acme-challenge`.

### La solución

La validación por alias DNS funciona mediante delegación CNAME. Let's Encrypt sigue las cadenas CNAME durante la validación DNS-01; CertMate escribe el registro TXT requerido en el nombre de validación delegado.

1. **Crea un dominio de validación** en un proveedor soportado de primera clase (p. ej. `validation.example.org` en Cloudflare, PowerDNS, Route53 o ACME-DNS)
2. **Añade registros CNAME** en todos tus proveedores DNS apuntando al dominio de validación:
   ```dns
   _acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
   ```
3. **Solicita el certificado** especificando el proveedor que gestiona el dominio de validación:
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

   Cuando `domain_alias` está definido con un proveedor soportado, CertMate utiliza un hook DNS manual de certbot para crear el registro TXT en `_acme-challenge.validation.example.org`. El CNAME garantiza que Let's Encrypt encuentre ese valor TXT al consultar `_acme-challenge.example.com`.

### Ventajas

- Funciona independientemente del proveedor DNS que sirva la consulta
- No se necesita sincronización entre proveedores
- Compatible con proveedores no soportados nativamente por CertMate (deSEC, gcore)
- Las credenciales DNS se limitan exclusivamente al dominio de validación
- Implementado para los proveedores DNS de primera clase de CertMate; los proveedores genéricos son rechazados hasta que existan adaptadores de alias dedicados

### Ejemplos por proveedor

Cloudflare, PowerDNS y Route53 utilizan todos la misma forma de solicitud:

```json
{
  "domain": "example.com",
  "dns_provider": "route53",
  "domain_alias": "validation.example.org"
}
```

Para ACME-DNS, `domain_alias` debe coincidir exactamente con el `subdomain`/fulldomain de ACME-DNS configurado. CertMate actualiza ese registro ACME-DNS directamente y no intenta limpiarlo porque ACME-DNS almacena el último valor de validación.

### Certificados wildcard con alias de dominio

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

Asegúrate de que el CNAME esté en su lugar antes de solicitar el certificado:

```dns
_acme-challenge.example.com. 300 IN CNAME _acme-challenge.validation.example.org.
```

### Resolución de problemas con alias de dominio

```bash
# Verificar la propagación del CNAME
dig @8.8.8.8 _acme-challenge.example.com CNAME +short
# Esperado: _acme-challenge.validation.example.org.

# Tras solicitar un certificado, verificar el registro TXT en el dominio de validación
dig _acme-challenge.validation.example.org TXT +short
# Esperado: un token de desafío ACME codificado en base64
```

---

## Variables de entorno

Define las credenciales del proveedor DNS mediante variables de entorno para los flujos de trabajo CI/CD:

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

### Prioridad de configuración (de mayor a menor)

1. Variables de entorno
2. Ajustes específicos del dominio
3. Ajustes de la cuenta por defecto
4. Ajuste global del proveedor
5. Valor por defecto del sistema (Cloudflare)

---

## Tiempos de propagación DNS

| Velocidad | Proveedores | Segundos |
|-----------|-------------|----------|
| Muy rápido | ACME-DNS | 30 |
| Rápido | Cloudflare, Route53, PowerDNS, DuckDNS | 60 |
| Medio | DigitalOcean, Linode, Google, ArvanCloud | 120 |
| Lento | Azure, Gandi, OVH | 180 |
| Muy lento | Namecheap | 300 |

---

## Características de seguridad

- **Enmascaramiento de credenciales** en la interfaz web y en las respuestas de la API
- **Permisos de archivo seguros** (600) para todos los archivos de credenciales
- **Validación del token API** antes de la creación del certificado
- **Soporte de variables de entorno** para flujos de trabajo CI/CD
- **Registro de auditoría** para todas las operaciones sobre proveedores DNS
- **Aislamiento de cuentas** — las credenciales de cada cuenta se almacenan por separado

---

## Arquitectura y guía para desarrolladores

### Clases principales

| Clase | Archivo | Propósito |
|-------|---------|-----------|
| `DNSManager` | `modules/core/dns_providers.py` | Gestión de configuración multi-cuenta |
| `CertificateManager` | `modules/core/certificates.py` | Creación de certificados con proveedores DNS |
| `SettingsManager` | `modules/core/settings.py` | Persistencia y migración de ajustes |
| `Utils` | `modules/core/utils.py` | Generación y validación de archivos de credenciales |

### Métodos de almacenamiento de credenciales

1. **Archivo de ajustes** (`data/settings.json`) — el más habitual
2. **Variables de entorno** — para CI/CD
3. **Archivos de configuración temporales** (`letsencrypt/config/[provider].ini`) — creados durante las solicitudes de certificado, eliminados después

### Añadir un nuevo proveedor DNS

1. Añade el plugin a `requirements.txt`: `certbot-dns-newprovider`
2. Crea una función de configuración en `modules/core/utils.py`
3. Añade la definición de credenciales en `utils.py`
4. Importa y gestiona en `modules/core/certificates.py`
5. Añade a la lista de proveedores soportados en `modules/core/settings.py`
6. Actualiza la documentación

Consulta la [Guía de arquitectura](./architecture.md) para los detalles completos de implementación.

---

## Resolución de problemas

### Problemas frecuentes

| Error | Solución |
|-------|----------|
| "DNS provider not configured" | Verifica que se han proporcionado todas las credenciales requeridas |
| "Certificate creation failed" | Comprueba los permisos DNS y la propiedad del dominio |
| "Plugin not found" | Ejecuta `pip install -r requirements.txt` o reconstruye Docker |
| "Provider detection failing" | Comprueba el campo `dns_provider` en los ajustes del dominio |

### Modo de depuración

```bash
export FLASK_DEBUG=1
python app.py
```

### Probar la configuración del proveedor

```bash
curl -X GET http://localhost:8000/api/settings/dns-providers \
  -H "Authorization: Bearer YOUR_API_TOKEN"
```

---

## Guía de migración

### De un proveedor único a múltiples proveedores

Las configuraciones existentes permanecen sin cambios. Simplemente añade nuevos proveedores:

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

### Usar distintos proveedores por certificado

```bash
# Cloudflare para un dominio
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "example.com", "dns_provider": "cloudflare"}'

# Route53 para otro
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"domain": "test.org", "dns_provider": "route53"}'
```

---

<div align="center">

[← Volver a la documentación](./README.md) • [Instalación →](./installation.md) • [Proveedores CA →](./ca-providers.md)

</div>
