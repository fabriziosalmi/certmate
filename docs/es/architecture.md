# Arquitectura de CertMate

<!-- CERTMATE-TRANSLATED-FROM 16b7294196819288 -->

Este documento cubre la arquitectura completa de CertMate — tanto el sistema principal de certificados de servidor como el subsistema de certificados de cliente.

---

## Tabla de contenidos

- [Arquitectura del sistema principal](#arquitectura-del-sistema-principal)
- [Diagrama de alto nivel](#diagrama-de-alto-nivel)
- [Clases de gestión (Managers)](#clases-de-gestión-managers)
- [Flujo de creación de certificados](#flujo-de-creación-de-certificados)
- [Arquitectura de almacenamiento](#arquitectura-de-almacenamiento)
- [Estructura de configuración](#estructura-de-configuración)
- [Endpoints API](#endpoints-api)
- [Pila tecnológica](#pila-tecnológica)
- [Arquitectura de certificados de cliente](#arquitectura-de-certificados-de-cliente)

---

## Arquitectura del sistema principal

CertMate es un sistema modular y extensible de gestión de certificados SSL/TLS construido con Python/Flask. Admite múltiples proveedores CA, los proveedores DNS enumerados en [Proveedores DNS](./dns-providers.md) y backends de almacenamiento intercambiables.

**Datos clave:**
- **Lenguaje**: Python 3.12 (Flask, Flask-RESTX)
- **Almacenamiento**: Sistema de archivos local por defecto + 5 backends remotos (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical, S3-compatible)
- **Proveedores CA**: Let's Encrypt, ZeroSSL, Google Trust Services, DigiCert ACME, SSL.com, Actalis, Sectigo y cualquier otra CA ACME a través de la entrada CA privada; véase [Proveedores CA](./ca-providers.md)
- **Proveedores DNS**: Cloudflare, AWS Route53, Azure, Google, y más — véase [Proveedores DNS](./dns-providers.md) para la lista completa
- **API**: REST con Swagger/OpenAPI mediante Flask-RESTX
- **Tipos de certificados actuales**: TLS en el lado del servidor (DV, OV, EV)

---

## Diagrama de alto nivel

```
┌─────────────────────────────────────────────────────┐
│                 CertMate Application                │
│                                                     │
│  ┌───────────────────────────────────────────────┐  │
│  │             Web Layer (Flask)                 │  │
│  │  Dashboard   Settings   Help   Client Certs   │  │
│  └─────────────────────┬─────────────────────────┘  │
│                        ↓                            │
│  ┌───────────────────┐  ┌────────────────────────┐  │
│  │  REST API         │  │  Web Routes            │  │
│  │  /api/certificates│  │  /api/web/certificates │  │
│  │  /api/client-certs│  │  /client-certificates  │  │
│  └─────────┬─────────┘  └───────────┬────────────┘  │
│            └───────────┬────────────┘               │
│                        ↓                            │
│  ┌───────────────────────────────────────────────┐  │
│  │          Manager Layer (Business Logic)       │  │
│  │                                               │  │
│  │  CertificateManager    CAManager              │  │
│  │  DNSManager            StorageManager         │  │
│  │  AuthManager           SettingsManager        │  │
│  │  CacheManager          FileOperations         │  │
│  │  ClientCertManager     OCSPResponder          │  │
│  │  CRLManager            AuditLogger            │  │
│  └─────────────────────┬─────────────────────────┘  │
│                        ↓                            │
│  ┌───────────────────────────────────────────────┐  │
│  │          Execution Layer                      │  │
│  │  Certbot (server certs over ACME)             │  │
│  │  PrivateCA (client certs via direct signing)  │  │
│  └─────────────────────┬─────────────────────────┘  │
│                        ↓                            │
│  ┌───────────────────────────────────────────────┐  │
│  │          Storage Layer (Pluggable Backends)   │  │
│  │  Local FS │ Azure KV │ AWS SM │ Vault         │  │
│  │  Infisical │ S3-compatible                    │  │
│  └───────────────────────────────────────────────┘  │
│                                                     │
└─────────────────────────────────────────────────────┘

        ┌─────────────────────────────────────────┐
        │  Composition root — modules/factory.py  │
        │                                         │
        │  create_app() constructs every          │
        │  manager and REGISTERS the API and      │
        │  web layers onto the Flask app.         │
        └───┬──────────────┬──────────────┬───────┘
            │ constructs   │ registers    │ registers
            ▼              ▼              ▼
      Manager Layer   REST API      Web Routes
        (core/)        (api/)         (web/)
```

Todas las flechas apuntan hacia abajo. La raíz de composición se sitúa **por encima** de las tres capas
que compone, en `modules/factory.py`, de modo que `modules/core/` no importa ni
`modules/api/` ni `modules/web/`.

No siempre fue así. Hasta #668 la raíz vivía en `modules/core/factory.py` e
importaba las dos capas situadas por encima de ella: la única dependencia hacia arriba del sistema, dibujada
en este diagrama y defendida como una excepción deliberada. El argumento era
sólido hasta donde llegaba: una raíz de composición tiene que conocer lo que compone, y
las alternativas son una capa que construye sus propias dependencias o un
registro que oculta esa misma dependencia tras una indirección.

Lo que se le escapó al argumento es que la tercera opción es la barata. Una
raíz de composición no tiene por qué vivir *dentro* de una de las capas que
compone. Mover el archivo un directorio más arriba elimina la excepción en lugar de
documentarla, y el ciclo que la hacía parecer inevitable resultó ser
de una sola función: `api/client_certificates.py` importaba
`error_code_for_status` de vuelta desde la raíz, y derivar `NOT_FOUND` de 404
nunca debió estar ahí. Ahora está en `modules/core/http_errors.py`.

Una única excepción documentada es un diseño; aun así merece la pena comprobar si
tiene que serlo. `tests/test_the_layers_point_one_way.py` es lo que mantiene
cierto este párrafo.

---

## Clases de gestión (Managers)

```
CertMateApp (main application)
  ├── FileOperations          # E/S de archivos, copias de seguridad
  ├── SettingsManager         # Carga/guardado de settings.json
  ├── AuthManager             # Validación de tokens
  ├── CertificateManager      # Crear/renovar/info (certificados de servidor)
  ├── CAManager               # Configuración del proveedor CA, construcción de certbot
  ├── DNSManager              # Cuentas de proveedores DNS
  ├── CacheManager            # Caché de despliegue
  ├── StorageManager          # Abstracción de backends
  ├── ClientCertificateManager # Ciclo de vida de certificados de cliente
  ├── PrivateCAGenerator      # Gestión de la CA autofirmada
  ├── OCSPResponder           # Consultas de estado de certificados
  ├── CRLManager              # Generación de listas de revocación
  └── AuditLogger             # Seguimiento de operaciones
```

---

## Flujo de creación de certificados

### Certificados de servidor (mediante Certbot + ACME)

```
1. User submits: domain, email, DNS provider, CA provider
2. Validate inputs (domain format, email, provider existence)
3. Get CA config (ACME URL, EAB credentials if the CA requires them)
4. Get DNS config (account credentials from settings)
5. Create directory: certificates/{domain}/
6. Build certbot command:
   certbot certonly --non-interactive --agree-tos
     --server {acme_url}
     --email {email}
     --{dns_plugin} --{dns_plugin}-credentials {cred_file}
     --{dns_plugin}-propagation-seconds {timeout}
     --eab-kid/--eab-hmac-key (if required)
     -d {domain}
7. Create temporary DNS credentials file (600 permissions)
8. Execute certbot (30-minute timeout)
9. Resolve symlinks, copy cert files to domain root
10. Store via configured backend + create metadata.json
11. Clean up credentials file
```

### Certificados de cliente (mediante CA privada)

```
1. User submits: common_name, email, organization, cert_usage
2. Initialize or load existing CA (4096-bit RSA)
3. Generate CSR (or accept provided CSR)
4. Sign CSR with private CA
5. Store cert/key/csr files + metadata.json
6. Log in audit trail
```

---

## Arquitectura de almacenamiento

### Certificados de servidor

```
certificates/
  example.com/
    cert.pem          # Server certificate
    chain.pem         # Intermediate CA chain
    fullchain.pem     # cert + chain
    privkey.pem       # Private key (600 permissions)
    metadata.json     # Certificate metadata
```

### Certificados de cliente

```
data/certs/
  ca/
    ca.crt            # CA certificate
    ca.key            # CA private key (600 permissions)
    ca_metadata.json  # CA metadata
    crl.pem           # Certificate Revocation List
  client/
    api-mtls/         # Certificates by usage type
      cert-001/
        cert.crt
        cert.key
        cert.csr
        metadata.json
    vpn/
      cert-002/
        ...
```

### Backends de almacenamiento

Todos los backends implementan `CertificateStorageBackend`:

| Backend | Ubicación de almacenamiento |
|---------|----------------------------|
| **Sistema de archivos local** | `certificates/{domain}/` (por defecto) |
| **Azure Key Vault** | Secrets, objetos Certificate nativos, o ambos — véase más abajo |
| **AWS Secrets Manager** | AWS Secrets Manager |
| **HashiCorp Vault** | Vault KV v1/v2 |
| **Infisical** | Secrets de Infisical |
| **S3-compatible** | Cualquier API S3: MinIO/Ceph autoalojados, o Hetzner, Contabo, OVHcloud, Scaleway, Exoscale, Wasabi |

#### HashiCorp Vault — redirecciones

La petición a Vault transporta la clave privada y el token de Vault. CertMate
solo sigue una redirección dentro de la dirección con la que fue configurado (mismo esquema,
host y puerto) y **rechaza** una hacia otro host, o de https a http,
antes de enviar nada allí. Lo indica en el error, nombrando el host.

Un nodo standby que no reenvía las peticiones responde exactamente con una redirección
de ese tipo hacia el nodo activo. Con el reenvío de peticiones activado (el valor por defecto) eso nunca
ocurre. Si tu Vault funciona sin él, establece `vault_url` en el nodo activo, o en
un balanceador de carga que encamine hacia él.

#### Azure Key Vault — modos de almacenamiento

El backend de Azure Key Vault puede persistir los certificados como Secrets (por defecto), como objetos Certificate nativos, o ambos, controlado por `certificate_storage.azure_keyvault.storage_mode` en `settings.json`.

| Modo | Escribe Secrets | Escribe objeto Certificate | Cuándo usarlo |
|---|---|---|---|
| `secrets` (por defecto) | sí | no | Comportamiento retrocompatible. Cada `cert.pem` / `chain.pem` / `fullchain.pem` / `privkey.pem` y los metadatos se almacenan como Secrets independientes en Key Vault. |
| `certificate` | no | sí | Vincula directamente desde App Service, Application Gateway, Front Door, API Management, AKS Ingress, etc. El certificado + cadena + clave privada se importan como un único objeto `Certificate` PKCS12 con `issuer_name="Unknown"` para que Key Vault no intente renovarlo. |
| `both` | sí | sí | Configuraciones transitorias o con consumidores mixtos. Las lecturas prefieren siempre la ruta de Secrets (más económica). |

Una acción manual **Backfill Certificate objects** en el panel de ajustes de almacenamiento (`POST /api/storage/azure-keyvault/backfill-certificates`) importa un objeto Certificate para cada dominio que ya existe en el vault como Secret pero aún no tiene uno. Los objetos Certificate existentes se omiten. El endpoint acepta un parámetro de consulta opcional `?limit=N` para limitar el número de dominios procesados por llamada; los vaults grandes pueden paginar llamando repetidamente hasta que la respuesta indique `0` restantes.

##### Nota de seguridad — los objetos Certificate exponen la clave privada a través de la API Secrets

Cuando Key Vault importa un objeto Certificate PKCS12, también crea un **Secret** asociado con el mismo nombre cuyo valor es el PFX completo (incluida la clave privada). Esto es deliberado en Azure: es la forma documentada para que las extensiones de VM y App Service consuman el certificado, y cualquier principal con `Secrets/Get` en el vault puede por tanto descargar la clave privada — *el permiso `Get` sobre Certificates por sí solo no es suficiente para extraer la clave privada, pero `Secrets/Get` sí lo es*. Los operadores que ejecuten CertMate en modo `certificate` o `both` deben restringir `Secrets/Get` con cuidado y preferir Azure RBAC sobre las directivas de acceso al vault para un control más granular. Véase [Microsoft Learn — Certificados en Key Vault](https://learn.microsoft.com/azure/key-vault/certificates/about-certificates) para el modelo completo.

##### Permisos del Service Principal

| Modo | Permisos requeridos en el vault |
|---|---|
| `secrets` | Secrets `Get/Set/List/Delete` |
| `certificate` / `both` | Añade Certificates `Get/List/Import/Delete` y conserva Secrets `Get/List` (Key Vault expone el PFX importado, incluida la clave privada, únicamente a través del Secret con el mismo nombre que el objeto Certificate). |

---

## Estructura de configuración

Todos los ajustes se almacenan en `data/settings.json`:

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

### Tipo/tamaño de clave del certificado

Tres claves de primer nivel controlan la forma de la clave pública de los certificados recién emitidos:

| Clave | Valores | Se aplica cuando |
|---|---|---|
| `default_key_type` | `rsa` (por defecto) / `ecdsa` | siempre |
| `default_key_size` | `2048` (por defecto) / `3072` / `4096` | `default_key_type == "rsa"` |
| `default_elliptic_curve` | `secp256r1` (por defecto) / `secp384r1` | `default_key_type == "ecdsa"` |

Se admite una sobreescritura por certificado: cada entrada en `domains` puede llevar un `key_type` opcional más `key_size` (RSA) o `elliptic_curve` (ECDSA). Cuando la sobreescritura está presente tiene prioridad; en caso contrario se aplica el valor global por defecto. Los valores por defecto `rsa`/`2048` reflejan el valor implícito de certbot que CertMate emitía antes de que existiera este ajuste, por lo que las instalaciones actualizadas no verán ningún cambio a menos que el operador elija otro valor.

Las renovaciones siempre preservan la forma que estaba en vigor en el momento de la creación: certbot persiste `--key-type`, `--rsa-key-size` y `--elliptic-curve` en su propio `renewal/<domain>.conf` durante la primera emisión, y `certbot renew --cert-name <domain>` reutiliza esos valores automáticamente.

---

## Endpoints API

### Certificados de servidor

| Método | Endpoint | Propósito |
|--------|----------|-----------|
| GET | `/api/health` | Comprobación de salud |
| GET | `/api/certificates` | Listar todos los certificados |
| POST | `/api/certificates/create` | Crear nuevo certificado |
| GET | `/api/certificates/{domain}` | Obtener información del certificado |
| POST | `/api/certificates/{domain}/renew` | Renovar certificado |
| GET | `/api/certificates/{domain}/download` | Descarga: ZIP por defecto; `?file=<cert.pem\|chain.pem\|fullchain.pem\|privkey.pem\|combined.pem\|cert.pfx>` para un único archivo; `?format=json` para todos los PEM en línea |

### Certificados de cliente

| Método | Endpoint | Propósito |
|--------|----------|-----------|
| POST | `/api/client-certs/create` | Crear certificado |
| GET | `/api/client-certs` | Listar con filtros |
| GET | `/api/client-certs/{id}` | Obtener metadatos |
| GET | `/api/client-certs/{id}/download/{type}` | Descargar cert/clave/csr |
| POST | `/api/client-certs/{id}/revoke` | Revocar certificado |
| POST | `/api/client-certs/{id}/renew` | Renovar certificado |
| GET | `/api/client-certs/stats` | Estadísticas |
| POST | `/api/client-certs/batch` | Importación CSV por lotes |
| GET | `/api/ocsp/status/{serial}` | Estado OCSP |
| GET | `/api/crl/download/{format}` | Descargar CRL |

---

## Pila tecnológica

| Capa | Tecnologías |
|------|-------------|
| **Backend** | Python 3.12, Flask, Flask-RESTX, APScheduler, Certbot |
| **Frontend** | HTML5, Tailwind CSS, Vanilla JavaScript, Font Awesome |
| **SDKs Cloud** | Azure SDK, boto3, hvac, infisical-python |
| **Criptografía** | cryptography (OpenSSL), plugins de certbot |
| **Despliegue** | Docker, Docker Compose, Gunicorn, systemd |

---

## Limitaciones principales

1. **Solo Certbot para certificados de servidor**: emitidos por ACME y validados por DNS-01, por HTTP-01 (sin wildcards) o por una cuenta de Sectigo SCM que ya autoriza los nombres
2. **Almacenamiento de servidor centrado en el dominio**: un certificado por directorio de dominio
3. **Sin base de datos**: un único archivo JSON para la configuración
4. **Uso de claves en certificados de servidor**: sin control sobre las extensiones keyUsage/extendedKeyUsage

---

# Arquitectura de certificados de cliente

## Descripción general del sistema

```

 Web UI Layer 
 (/client-certificates web dashboard) 

 

 API Layer 
 (/api/client-certs, /api/ocsp, /api/crl) 
 (REST endpoints with Flask-RESTX) 

 

 Managers Layer 
 
 ClientCertificateManager (lifecycle + metadata) 
 OCSPResponder (certificate status queries) 
 CRLManager (revocation list generation) 
 AuditLogger (operation tracking) 
 SimpleRateLimiter (request throttling) 
 

 

 Core Modules Layer 
 
 PrivateCAGenerator (CA management) 
 CSRHandler (CSR validation & creation) 
 ClientCertificateManager (cert operations) 
 OCSPResponder (status responses) 
 CRLManager (revocation lists) 
 AuditLogger (logging) 
 RateLimitConfig/SimpleRateLimiter (limiting) 
 

 

 Cryptography & Storage Layer 
 
 Cryptography Library (OpenSSL) 
 File System Storage (data/certs/) 
 Storage Backends (Azure, AWS, Vault, etc) 
 

```

---

## Componentes principales

### 1. PrivateCAGenerator (`modules/core/private_ca.py`)

**Propósito**: Generar y gestionar la Autoridad de Certificación autofirmada

**Características clave**:
- Genera claves RSA de 4096 bits para la CA
- Período de validez de 10 años
- Certificados autofirmados con las extensiones adecuadas
- Funcionalidad de copia de seguridad y restauración de la CA
- Capacidad de firma de CRL

**Archivos creados**:
- `data/certs/ca/ca.crt` — Certificado CA (PEM)
- `data/certs/ca/ca.key` — Clave privada CA (PEM, permisos 0600)
- `data/certs/ca/ca_metadata.json` — Metadatos CA
- `data/certs/ca/crl.pem` — Lista de revocación de certificados

**Métodos principales**:
```python
initialize() # Inicializar o cargar la CA existente
sign_certificate_request() # Firmar un CSR
generate_crl() # Generar CRL a partir de números de serie revocados
get_crl_pem() # Obtener la CRL en formato PEM
```

---

### 2. CSRHandler (`modules/core/csr_handler.py`)

**Propósito**: Validar, analizar y crear solicitudes de firma de certificado

**Características clave**:
- Crear nuevos CSR con claves privadas (2048 o 4096 bits)
- Validar CSR codificados en PEM
- Extraer información del CSR (CN, Org, Email, SAN, etc.)
- Soporte para Subject Alternative Names (SAN)
- Guardar el CSR y los pares de claves en disco

**Métodos principales**:
```python
create_csr() # Crear nuevo CSR con clave privada
validate_csr_pem() # Validar y cargar CSR desde PEM
get_csr_info() # Extraer información de un CSR
save_csr_and_key() # Guardar CSR y clave en archivos
```

---

### 3. ClientCertificateManager (`modules/core/client_certificates.py`)

**Propósito**: Gestión completa del ciclo de vida de los certificados de cliente

**Características clave**:
- Crear certificados (firmados por CA o mediante CSR)
- Listar/filtrar certificados (por uso, estado, búsqueda)
- Revocar certificados con registro de auditoría
- Renovar certificados (mismo CN, nuevo número de serie)
- Planificación de renovación automática
- Almacenamiento de metadatos (JSON por certificado)
- Soporte para 30 000+ certificados simultáneos

**Estructura de almacenamiento**:
```
data/certs/client/
 api-mtls/ # Certificates for API mTLS
 cert-001/
 cert.crt
 cert.key
 cert.csr
 metadata.json
 vpn/ # Certificates for VPN
 cert-002/
 ...
 other/ # Other usage types
 ...
```

**Estructura de metadatos** (JSON):
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
 "extended_key_usage": ["clientAuth"],
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

**Métodos principales**:
```python
create_client_certificate() # Crear nuevo certificado
list_client_certificates() # Listar con filtros opcionales
get_certificate_metadata() # Obtener metadatos del certificado
get_certificate_file() # Obtener archivo cert/clave/csr
revoke_certificate() # Revocar con motivo
renew_certificate() # Renovar certificado
check_renewals() # Comprobación de renovaciones automáticas
get_statistics() # Obtener estadísticas de uso
```

---

### 4. OCSPResponder (`modules/core/ocsp_crl.py`)

**Propósito**: Proporcionar respuestas al protocolo de estado de certificado en línea (OCSP)

**Características clave**:
- Consultar el estado de un certificado (good/revoked/unknown)
- Generar respuestas OCSP
- Consultas de estado en tiempo real
- Soporte para múltiples tipos de estado

**Estados**:
- `good` — El certificado es válido
- `revoked` — El certificado ha sido revocado
- `unknown` — Certificado no encontrado

**Métodos principales**:
```python
get_cert_status() # Obtener el estado del certificado
generate_ocsp_response() # Generar respuesta OCSP
```

**Formato de respuesta**:
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

**Propósito**: Generar y distribuir listas de revocación de certificados

**Características clave**:
- Generar la CRL con todos los certificados revocados
- Distribuir en formatos PEM y DER
- Almacenar metadatos e información de la CRL
- Actualizaciones automáticas de la CRL

**Métodos principales**:
```python
get_revoked_serials() # Obtener números de serie de certificados revocados
update_crl() # Generar/actualizar la CRL
get_crl_pem() # Obtener la CRL en formato PEM
get_crl_der() # Obtener la CRL en formato DER
get_crl_info() # Obtener metadatos de la CRL
```

---

### 6. AuditLogger (`modules/core/audit.py`)

**Propósito**: Registrar todas las operaciones sobre certificados para cumplimiento normativo y depuración

**Características clave**:
- Registro en formato JSON
- Archivo de auditoría persistente
- Seguimiento de operaciones, usuarios y direcciones IP
- Consulta de entradas por recurso o período de tiempo

**Formato del registro**:
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

**Archivo de registro**: `logs/audit/certificate_audit.log`

**Métodos principales**:
```python
log_certificate_created() # Registrar la creación de certificado
log_certificate_revoked() # Registrar la revocación
log_certificate_renewed() # Registrar la renovación
log_certificate_downloaded() # Registrar las descargas
log_batch_operation() # Registrar operaciones por lotes
log_api_request() # Registrar peticiones API
get_recent_entries() # Obtener las últimas entradas de auditoría
```

---

### 7. Limitación de tasa (`modules/core/rate_limit.py`)

**Propósito**: Proteger la API contra abusos con limitación de la tasa de peticiones

**Configuración**:
- Por defecto: 100 req/min
- Creación de certificado: 30 req/min (costoso)
- Operaciones por lotes: 10 req/min (muy costoso)
- Estado OCSP: 200 req/min (económico)
- Descarga CRL: 60 req/min

**Clases principales**:
```python
RateLimitConfig # Contenedor de configuración
SimpleRateLimiter # Limitador en memoria
rate_limit_decorator # Decorador de endpoint Flask
```

**Respuesta al superar el límite**:
```json
{
 "error": "Rate limit exceeded",
 "message": "Too many requests. Please try again later.",
 "retry_after": 60
}
```

Estado HTTP: `429 Too Many Requests`

---

## Flujo de datos

### Flujo de creación de certificados

```
User/API Request
 ↓
ClientCertificateManager.create_client_certificate()
 Generate CSR (or accept provided CSR)
 Sign CSR with private CA
 Create metadata.json
 Store cert/key/csr files
 Log in audit trail
 Return cert data
 ↓
Response to User
```

### Flujo de revocación de certificados

```
User/API Request (revoke endpoint)
 ↓
ClientCertificateManager.revoke_certificate()
 Load certificate metadata
 Update revocation status
 Save updated metadata
 Log in audit trail
 Trigger CRL update
 Return success
 ↓
Response to User
```

### Flujo de consulta OCSP

```
Client OCSP Request (serial number)
 ↓
OCSPResponder.get_cert_status()
 Search certificate by serial
 Check revocation status
 Return status (good/revoked/unknown)
 ↓
OCSPResponder.generate_ocsp_response()
 Format OCSP response
 Add timestamps
 Return response
 ↓
Response to Client
```

---

## Arquitectura de almacenamiento

### Estructura de directorios

```
data/certs/
 ca/ # Certificate Authority
 ca.crt # CA certificate (public)
 ca.key # CA private key (0600)
 ca_metadata.json # CA metadata
 crl.pem # Certificate Revocation List

 client/ # Client certificates
 api-mtls/ # API mTLS certificates
 cert-001/
 cert.crt
 cert.key
 cert.csr
 metadata.json
 ...
 vpn/ # VPN certificates
 ...
 other/ # Other usage types
 ...

 crl/ # CRL storage
 (generated CRLs)
```

### Archivos de metadatos

Cada certificado tiene un archivo `metadata.json` que contiene:
- Identificación del certificado (CN, número de serie, huella digital)
- Información del sujeto (Org, email, ubicación)
- Fechas de validez
- Estado e historial de revocación
- Configuración de renovación
- Notas personalizadas

---

## Modelo de seguridad

### Protección de claves

- **Permisos de archivos**: 0600 (lectura/escritura solo para el propietario)
- **Formato de claves**: PEM en formato tradicional OpenSSL
- **Sin cifrado de claves**: las claves privadas se escriben sin cifrar, protegidas por los permisos de archivo indicados arriba; un backend de almacenamiento remoto guarda su copia con el cifrado en reposo que aplique ese servicio

### Firma de certificados

- **Algoritmo de firma**: SHA256withRSA
- **Tamaño de clave**: RSA de 4096 bits para la CA, 2048/4096 bits para clientes
- **Validez**: configurable (por defecto 1 año para certificados de cliente)

### Control de acceso

- **Autenticación**: Bearer token en todos los endpoints API
- **Autorización**: basada en tokens (puede ampliarse con roles)
- **Limitación de tasa**: protección por endpoint

### Registro de auditoría

- Todas las operaciones registradas con marca de tiempo
- Seguimiento del usuario y la dirección IP
- Archivo de registro de auditoría inmutable
- Consultable para cumplimiento normativo

---

## Escalabilidad

### Almacenamiento de certificados

- **Escalabilidad lineal**: almacenamiento basado en directorios
- **Capacidad**: probado con 30 000+ certificados
- **Rendimiento**: análisis de directorios O(n) eficientes

### Rendimiento de la API

- **Limitación de tasa**: evita el agotamiento de recursos
- **Instancia única**: un solo worker de gunicorn ejecuta la API y el planificador de renovaciones; véase [Disponibilidad y conmutación por error](#disponibilidad-y-conmutación-por-error)
- **Operaciones por lotes**: máximo 100 filas por solicitud (por encima, la API responde 400)

### Renovación automática

- **Programada**: a diario, los certificados de servidor entre las 01:00 y las 03:00 (las 02:00 con hasta una hora de desfase aleatorio en cualquier sentido), los certificados de cliente entre las 02:00 y las 04:00
- **Cuándo**: 30 días antes de la caducidad por defecto (`renewal_threshold_days`), un tercio de la vida útil antes de la caducidad para un certificado que dura menos de 60 días (la mitad si dura menos de 10 días), o donde lo sitúe la ventana de renovación de la CA (ARI); véase [la guía](./guide.md#cuando-se-renueva-un-certificado)
- **Tolerante a fallos**: continúa en caso de errores y registra para revisión

---

## Consideraciones de despliegue

### Requisitos mínimos

- Python 3.12
- 100 MB de espacio en disco para la CA y los certificados iniciales
- 50 MB para los registros de auditoría por cada millón de operaciones
- Huella de memoria reducida

### Recomendaciones para producción

- Usar un backend de almacenamiento (Azure, AWS, Vault, Infisical, S3-compatible) para que el material de los certificados sobreviva al nodo
- Habilitar el registro de auditoría para cumplimiento normativo
- Configurar la limitación de tasa en función de la carga
- Actualizaciones regulares de la CRL (diarias o en cada revocación)
- Hacer copia de seguridad de las claves CA y los metadatos con un archivo de recuperación ante desastres (`include_secrets=true` + `CERTMATE_BACKUP_PASSPHRASE`); la copia de seguridad por defecto, segura para compartir, deja fuera deliberadamente la clave de la CA
- Monitorizar los registros de auditoría en busca de actividad sospechosa

### Disponibilidad y conmutación por error

**CertMate no se ejecuta en varias instancias.** Su planificador de renovaciones
(APScheduler) corre dentro del proceso web y gunicorn usa un único worker a
propósito: una segunda réplica es un segundo planificador emitiendo y renovando
contra el mismo almacén de certificados — pedidos ACME duplicados y el límite de
tasa de la CA por certificados duplicados. El chart de Helm falla en tiempo de
plantilla si `replicaCount` no es `1`.


Cómo es, en cambio, la disponibilidad — **activo/en espera**:

1. Situar `DATA_DIR` en almacenamiento reconectable (un volumen de red o un
   sistema de archivos replicado). Ese es el estado que importa: ajustes,
   cadena de auditoría, CA privada y los certificados en sí.
2. Configurar un [backend de almacenamiento](#backends-de-almacenamiento)
   (Azure Key Vault, AWS Secrets Manager, Vault, Infisical, S3-compatible) para que el
   material de los certificados también viva con independencia del nodo.
3. Ejecutar **una** instancia. Ante un fallo, arrancar un reemplazo contra los
   mismos datos y apuntar el ingress hacia él. Perder una ventana de renovación
   no es urgente para un certificado de 90 días: la renovación empieza 30 días antes del vencimiento, así que
   una conmutación tiene semanas de margen. Sí lo es para los de corta duración: un certificado de 160 horas se renueva
   cuando le quedan unas 80 horas, así que una conmutación tiene días, no semanas.
4. Mantener [copias de recuperación ante desastres](./guide.md) con
   `CERTMATE_BACKUP_PASSPHRASE` establecida, para que una reconstrucción desde
   cero siga siendo posible aunque se pierda el volumen.

Quienes deben tener alta disponibilidad son los consumidores de los
certificados. CertMate emite y distribuye; no está en la ruta de las peticiones
de los servicios para los que emite, y que esté caído una hora no arrastra nada
más consigo.

---

## Puntos de integración

### Con el sistema principal de CertMate

- Usa los backends de almacenamiento existentes de CertMate
- Integrado en los managers de app.py
- Parte de la estructura API de Flask-RESTX
- Programado con APScheduler

### Sistemas externos

- Puede exportar certificados a través de la API
- Puede consultar el estado mediante OCSP
- Puede recuperar la CRL para validación
- Envía [notificaciones webhook](../webhooks.md) en los eventos de certificados y ejecuta [deploy hooks](./deploy-hooks.md)

---

## Extensibilidad futura

### Mejoras planificadas

1. **Protección con contraseña de la CA** — Cifrar las claves CA con contraseña
2. **Tokens hardware** — Soporte PKCS#11 para HSM

### Puntos de extensión

1. **Backends de almacenamiento** — Ya admite múltiples backends
2. **Destinos de auditoría** — Puede enviar registros de auditoría a sistemas externos
3. **Middleware API** — Añadir autenticación/autorización personalizada
4. **Sistema de notificaciones** — Integración con sistemas de alertas

---

## Monitorización y observabilidad

### Métricas clave

- Recuento de certificados (total, activos, revocados, próximos a caducar)
- Rendimiento de los endpoints API
- Infracciones de límite de tasa
- Volumen de registros de auditoría
- Tasa de éxito/fallo de las renovaciones automáticas

### Comprobaciones de salud

- Disponibilidad de la CA
- Funcionamiento del registro de auditoría
- Capacidad de respuesta del limitador de tasa
- Estado de generación de la CRL

---

<div align="center">

[← Volver a la documentación](./README.md) • [Inicio rápido →](./guide.md) • [Referencia API →](./api.md)

</div>
