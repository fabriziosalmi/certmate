# CertMate Certificados de Cliente - Referencia de API

## Descripción general

La API CertMate de gestión de certificados de cliente proporciona endpoints REST para una gestión completa de certificados con autenticación, limitación de tasa y registro de auditoría.

**URL base**: `http://localhost:5000/api`
**Autenticación**: Bearer Token (obligatoria en todos los endpoints)
**Content-Type**: `application/json`

---

## Autenticación

Todos los endpoints de la API requieren autenticación mediante Bearer token.

### Formato del encabezado

```
Authorization: Bearer TU_TOKEN
```

### Ejemplo de solicitud

```bash
curl -X GET http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TU_TOKEN" \
 -H "Content-Type: application/json"
```

---

## Limitación de tasa (Rate Limiting)

Los endpoints de la API tienen límites de tasa para prevenir abusos:

| Endpoint               | Límite | Por     |
| ---------------------- | ------ | ------- |
| General                | 100    | minuto  |
| Crear certificado      | 30     | minuto  |
| Operaciones por lotes  | 10     | minuto  |
| Estado OCSP            | 200    | minuto  |
| Descarga CRL           | 60     | minuto  |

### Respuesta al superar el límite

Cuando se supera el límite de tasa, recibirás:

```
HTTP 429 Too Many Requests

{
 "error": "Rate limit exceeded",
 "message": "Too many requests. Please try again later.",
 "retry_after": 60
}
```

---

## Endpoints

### Gestión de certificados

#### 1. Crear certificado

**Endpoint**: `POST /client-certs/create`

Crea un nuevo certificado de cliente.

**Solicitud**:
```json
{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true,
 "notes": "Production certificate"
}
```

**Parámetros**:
- `common_name` (obligatorio) — Asunto del certificado
- `email` (opcional) — Dirección de correo electrónico
- `organization` (opcional) — Nombre de la organización
- `organizational_unit` (opcional) — Nombre del departamento
- `cert_usage` (opcional) — Tipo de uso: `api-mtls`, `vpn`, o personalizado
- `days_valid` (opcional) — Validez en días (por defecto: 365)
- `generate_key` (opcional) — Generar clave privada (por defecto: true)
- `notes` (opcional) — Notas adicionales

**Respuesta** (201 Created):
```json
{
 "identifier": "cert-abc123",
 "common_name": "user@example.com",
 "serial_number": "12345678901234567890",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "cert_usage": "api-mtls",
 "status": "active"
}
```

**Ejemplo**:
```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365
 }'
```

---

#### 2. Listar certificados

**Endpoint**: `GET /client-certs`

Lista todos los certificados de cliente con filtrado opcional.

**Parámetros de consulta**:
- `usage` (opcional) — Filtrar por tipo de uso (p. ej., `api-mtls`)
- `revoked` (opcional) — Filtrar por estado (`true` o `false`)
- `search` (opcional) — Buscar en el nombre común

**Respuesta** (200 OK):
```json
{
 "certificates": [{
 "identifier": "cert-001",
 "common_name": "user1@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "created_at": "2024-10-30T18:00:00Z",
 "expires_at": "2025-10-30T18:00:00Z",
 "revoked": false,
 "status": "active"
 },
 {
 "identifier": "cert-002",
 "common_name": "user2@example.com",
 "organization": "ACME Corp",
 "cert_usage": "vpn",
 "created_at": "2024-10-29T18:00:00Z",
 "expires_at": "2025-10-29T18:00:00Z",
 "revoked": true,
 "status": "revoked"
 }
 ],
 "total": 2
}
```

**Ejemplos**:
```bash
# Listar todos los certificados
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtrar por tipo de uso
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Listar solo los revocados
curl "http://localhost:5000/api/client-certs?revoked=true" \
 -H "Authorization: Bearer TOKEN"

# Buscar por nombre común
curl "http://localhost:5000/api/client-certs?search=user1" \
 -H "Authorization: Bearer TOKEN"
```

---

#### 3. Obtener detalles de un certificado

**Endpoint**: `GET /client-certs/<identifier>`

Obtiene los metadatos completos de un certificado.

**Respuesta** (200 OK):
```json
{
 "type": "client_certificate",
 "identifier": "cert-001",
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "organizational_unit": "Engineering",
 "serial_number": "12345678901234567890",
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
 "renewal_threshold_days": 30
 }
}
```

**Ejemplo**:
```bash
curl http://localhost:5000/api/client-certs/cert-001 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 4. Descargar archivos de un certificado

**Endpoint**: `GET /client-certs/<identifier>/download/<type>`

Descarga el certificado, la clave privada o el archivo CSR.

**Parámetros**:
- `identifier` — ID del certificado
- `type` — Tipo de archivo: `crt`, `key`, o `csr`

**Respuesta** (200 OK):
- Content-Type: `application/octet-stream`
- Archivo adjunto con nombre apropiado

**Ejemplos**:
```bash
# Descargar el certificado
curl http://localhost:5000/api/client-certs/cert-001/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o certificate.crt

# Descargar la clave privada
curl http://localhost:5000/api/client-certs/cert-001/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o private.key

# Descargar el CSR
curl http://localhost:5000/api/client-certs/cert-001/download/csr \
 -H "Authorization: Bearer TOKEN" \
 -o request.csr
```

---

#### 5. Revocar un certificado

**Endpoint**: `POST /client-certs/<identifier>/revoke`

Revoca un certificado con un motivo opcional.

**Solicitud** (opcional):
```json
{
 "reason": "compromised"
}
```

**Respuesta** (200 OK):
```json
{
 "message": "Certificate revoked: cert-001",
 "revoked_at": "2024-10-30T18:15:00Z",
 "reason": "compromised"
}
```

**Ejemplo**:
```bash
curl -X POST http://localhost:5000/api/client-certs/cert-001/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "reason": "compromised"
 }'
```

---

#### 6. Renovar un certificado

**Endpoint**: `POST /client-certs/<identifier>/renew`

Renueva un certificado (mismo CN, nuevo número de serie).

**Respuesta** (201 Created):
```json
{
 "identifier": "cert-001-renewed",
 "common_name": "user@example.com",
 "serial_number": "98765432109876543210",
 "created_at": "2024-10-30T18:20:00Z",
 "expires_at": "2025-10-30T18:20:00Z",
 "status": "active"
}
```

**Ejemplo**:
```bash
curl -X POST http://localhost:5000/api/client-certs/cert-001/renew \
 -H "Authorization: Bearer TOKEN"
```

---

#### 7. Obtener estadísticas

**Endpoint**: `GET /client-certs/stats`

Obtiene estadísticas de uso de los certificados.

**Respuesta** (200 OK):
```json
{
 "total": 100,
 "active": 85,
 "revoked": 15,
 "expiring_soon": 8,
 "by_usage": {
 "api-mtls": 60,
 "vpn": 35,
 "other": 5
 },
 "created_count": 100,
 "renewal_enabled": 92
}
```

**Ejemplo**:
```bash
curl http://localhost:5000/api/client-certs/stats \
 -H "Authorization: Bearer TOKEN"
```

---

#### 8. Importación por lotes de certificados

**Endpoint**: `POST /client-certs/batch`

Crea múltiples certificados a partir de datos CSV en una sola solicitud.

**Solicitud**:
```json
{
 "headers": ["common_name", "email", "organization", "cert_usage", "days_valid"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp", "api-mtls", "365"],
 ["user2@example.com", "user2@example.com", "ACME Corp", "vpn", "365"],
 ["user3@example.com", "user3@example.com", "ACME Corp", "api-mtls", "365"]
 ]
}
```

**Respuesta** (201 Created):
```json
{
 "total": 3,
 "successful": 3,
 "failed": 0,
 "errors": [],
 "certificates": [{
 "identifier": "cert-batch-001",
 "common_name": "user1@example.com"
 },
 {
 "identifier": "cert-batch-002",
 "common_name": "user2@example.com"
 },
 {
 "identifier": "cert-batch-003",
 "common_name": "user3@example.com"
 }
 ]
}
```

**Ejemplo**:
```bash
curl -X POST http://localhost:5000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "headers": ["common_name", "email", "organization"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
 ["user2@example.com", "user2@example.com", "ACME Corp"]
 ]
 }'
```

---

### OCSP & CRL

#### 9. Consulta de estado OCSP

**Endpoint**: `GET /ocsp/status/<serial_number>`

Consulta el estado de un certificado mediante OCSP.

**Respuesta** (200 OK):
```json
{
 "response_status": "successful",
 "certificate_status": "good|revoked|unknown",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z",
 "next_update": null,
 "responder_name": "CertMate OCSP Responder"
}
```

**Ejemplo**:
```bash
curl http://localhost:5000/api/ocsp/status/12345678 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 10. Distribución de la CRL

**Endpoint**: `GET /crl/download/<format_type>`

Descarga la lista de revocación de certificados (CRL).

**Parámetros**:
- `format_type` — `pem`, `der`, o `info`

**Respuesta**:
- Para `pem` y `der`: Archivo adjunto
- Para `info`: JSON con metadatos de la CRL

**Ejemplos**:
```bash
# Descargar la CRL en formato PEM
curl http://localhost:5000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Descargar la CRL en formato DER
curl http://localhost:5000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Obtener información de la CRL
curl http://localhost:5000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

**Respuesta de información de la CRL**:
```json
{
 "status": "available",
 "issuer": "CN=CertMate CA, O=CertMate",
 "last_update": "2024-10-30T18:00:00Z",
 "next_update": "2024-10-31T18:00:00Z",
 "revoked_count": 5,
 "revoked_serials": [12345678,
 87654321
 ]
}
```

---

#### 11. Descargar archivos de certificado de dominio

**Endpoint**: `GET /certificates/<domain>/download`

Descarga los archivos de certificado para un dominio específico. Por defecto, este endpoint devuelve un archivo ZIP con todos los componentes del certificado. Se puede solicitar un archivo concreto mediante el parámetro de consulta `file`. También está disponible el modo JSON para la automatización que necesite todos los PEM en una sola respuesta.

**Parámetros**:
- `domain` (Path) — El nombre de dominio asociado al certificado.
- `file` (Query, opcional) — Especifica un único archivo a descargar.
  - Valores admitidos: `fullchain.pem`, `privkey.pem`, `combined.pem`
- `format` (Query, opcional) — Establece en `json` para devolver todos los archivos del certificado en un objeto JSON.

**Respuesta** (200 OK):
- **Por defecto**: `application/zip` (un archivo ZIP con todos los archivos PEM)
- **Con parámetro `file`**: `application/x-pem-file` (el contenido sin procesar del archivo solicitado)
- **Con `format=json`**: `application/json` con `domain`, `cert_pem`, `chain_pem`, `fullchain_pem` y `private_key_pem`

La forma JSON es el formato de automatización preferido para Ansible, Salt o cualquier otro cliente que desee escribir los archivos PEM directamente.

**Ejemplos**:

```bash
# Descargar todos los archivos como archivo ZIP
curl http://localhost:5000/api/certificates/example.com/download \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.zip

# Descargar solo el archivo fullchain.pem
curl "http://localhost:5000/api/certificates/example.com/download?file=fullchain.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o fullchain.pem

# Descargar solo la clave privada
curl "http://localhost:5000/api/certificates/example.com/download?file=privkey.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o privkey.pem

# Descargar el bundle completo de certificados en JSON
curl "http://localhost:5000/api/certificates/example.com/download?format=json" \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.json

```

---

#### 12. Reemitir un certificado de dominio (editar la configuración)

**Endpoint**: `POST /certificates/<domain>/reissue`

Edita la configuración de un certificado y lo reemite en su lugar — permite ampliar o eliminar entradas SAN sin necesidad de eliminar y volver a crear. Los campos omitidos conservan los valores con los que se emitió el certificado (leídos desde sus metadatos), por lo que la configuración de DNS/alias/CA no es necesario volver a introducirla. El certificado actual sigue sirviéndose hasta que la reemisión tenga éxito. La forma de la clave se preserva salvo cambio explícito (no se envían indicadores de clave y certbot conserva la clave de la cadena de certificados).

**Cuerpo de la solicitud** (todos los campos son opcionales):
```json
{
  "san_domains": ["www.example.com", "api.example.com"],
  "domain_alias": "",
  "async": true
}
```

- `san_domains`: conjunto de reemplazo de los SAN — omitir para conservar, `[]` para eliminar todos los SAN
- `domain_alias`: omitir para conservar, `""` para borrar
- `dns_provider`, `account_id`, `ca_provider`, `challenge_type`: omitir para conservar
- `key_type`/`key_size`/`elliptic_curve`: omitir para conservar la forma de clave existente
- `async`: diferir la emisión a un job en segundo plano (202 + ID del job, consultar `GET /certificates/jobs/<job_id>`)

**Respuesta** (200 OK, o 202 Accepted con `async`): message, domain, dns_provider, ca_provider, duration.

**Errores**: 404 cuando no existe ningún certificado para el dominio (usar create), 403 scope, 400 validación, 409 operación en curso, 422 fallo de certbot (el certificado anterior sigue en vigor).

**Ejemplo**:
```bash
curl -X POST http://localhost:5000/api/certificates/example.com/reissue \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"san_domains": ["www.example.com", "api.example.com"]}'
```

---

## Gestión de errores

### Formato de respuesta de error

```json
{
 "error": "Error message",
 "code": "ERROR_CODE",
 "status": 400
}
```

### Códigos de estado HTTP habituales

| Código | Significado          | Ejemplo                           |
| ------ | -------------------- | --------------------------------- |
| 200    | Éxito                | Certificado listado               |
| 201    | Creado               | Certificado creado                |
| 400    | Solicitud incorrecta | Campo obligatorio ausente         |
| 401    | No autorizado        | Token inválido o ausente          |
| 404    | No encontrado        | El certificado no existe          |
| 429    | Demasiadas solicitudes | Límite de tasa superado         |
| 500    | Error del servidor   | Error interno                     |
| 503    | Servicio no disponible | OCSP/CRL no disponible          |

### Ejemplo de error

```bash
curl http://localhost:5000/api/client-certs/invalid-id \
 -H "Authorization: Bearer TOKEN"

# Respuesta
{
 "error": "Certificate not found: invalid-id",
 "code": 404,
 "status": 404
}
```

---

## Registro de auditoría

Las operaciones del ciclo de vida de los certificados y los cambios de configuración y control de acceso se registran en un log de auditoría. Esto incluye las rutas críticas del ciclo de vida — creaciones, renovaciones, reemisiones, despliegues y activaciones/desactivaciones de renovación automática, tanto exitosas como fallidas, así como las **renovaciones no supervisadas (planificadas)** — cada una atribuida al actor que la realizó y al disparador que la causó.

### Formato del log

El log de auditoría se escribe en `logs/audit/certificate_audit.log`. Cada línea es una línea de log Python estándar cuyo mensaje es la entrada de auditoría en JSON:

```
2026-06-15 18:00:00 - certmate.audit - INFO - {"timestamp": "...", ...}
```

Para extraer el JSON, divide cada línea por el literal ` - INFO - ` y analiza el resto. Ten en cuenta las dos bases temporales: el prefijo de marca de tiempo de la línea es la hora **local** del servidor, mientras que el campo `timestamp` del JSON está en **UTC** (ISO-8601). Síguela en tiempo real con:

```bash
tail -f logs/audit/certificate_audit.log
```

### Estructura de la entrada

```json
{
  "timestamp": "2026-06-15T18:00:00.000000+00:00",
  "operation": "renew",
  "resource_type": "certificate",
  "resource_id": "api.example.com",
  "status": "success",
  "user": "api_key:renew-bot",
  "ip_address": "10.0.0.9",
  "details": {"force": false},
  "error": null,
  "actor": {
    "kind": "agent",
    "id": "9f2c…",
    "label": "api_key:renew-bot",
    "token_prefix": "cm_1a2b",
    "agent_session": "sess-9f2"
  },
  "trigger": {"cause": "agent"}
}
```

- **`actor.kind`** — `user` (una sesión humana / inicio de sesión OIDC), `api_token` (una clave de API o el token Bearer global heredado), `agent` (una clave de API marcada explícitamente como agente IA/MCP — ver más abajo), `scheduler` (un job de renovación no supervisado), o `system`. Se deriva **únicamente de la identidad autenticada**.
- **`actor.id` / `token_prefix`** — el ID de clave de API estable y el prefijo del token que hay detrás de la acción (ausente para el token Bearer global heredado, que no puede distinguirse por llamante — se prefieren las claves con scope).
- **`actor.agent_session` / `agent_id`** — los valores de los encabezados `X-CertMate-Agent-Session` / `X-CertMate-Agent-Id` proporcionados por el cliente (el servidor MCP los envía). Son una **afirmación meramente informativa**: se registran para correlación pero nunca modifican `actor.kind`, por lo que un llamante que no sea agente no puede forjar una atribución de tipo `agent`.
- **`trigger.cause`** — `manual`, `api`, `agent`, `scheduled_renewal`, o `event`; para las renovaciones planificadas, `trigger.job_id` identifica el job.

Para que las acciones de un agente queden registradas como `actor.kind="agent"`, crea una clave de API con scope y `is_agent: true` (una casilla en Ajustes → Claves de API, o `is_agent` en `POST /api/keys`) y apunta el servidor MCP hacia ella. Consulta la [guía MCP](./mcp.md).

### Lectura del log de auditoría mediante la API

`GET /api/activity?limit=N` devuelve las entradas más recientes (admin/visor, limitado a 500).

### Prueba de integridad (cadena de hash)

Junto al log legible por humanos, cada entrada se añade a una **cadena de hash** SHA-256 a prueba de manipulaciones en `data/audit/certificate_audit.chain.jsonl`. Cada registro es `{seq, entry, prev_hash, hash}` donde `hash` se compromete con la entrada y el hash del registro anterior, y `seq` es un contador sin huecos — por lo que cualquier modificación, eliminación o reordenación por parte de alguien que no pueda recalcular toda la cadena es detectable y localizable. Está activada por defecto; desactívala con `CERTMATE_AUDIT_CHAIN=0`.

**Verificación desde la API:** `GET /api/audit/verify` (admin) devuelve el resultado del verificador y HTTP `200` cuando está íntegra o `409` cuando está rota:

```json
{"ok": true, "count": 128, "first_seq": 0, "last_seq": 127, "head_hash": "5ee1…", "reason": "intact"}
```

**Verificación fuera del servidor:** el verificador autónomo solo depende de la biblioteca estándar de Python, por lo que un auditor puede ejecutarlo sin instalar ni confiar en CertMate:

```bash
python -m modules.core.audit_verify data/audit/certificate_audit.chain.jsonl
# OK: audit chain intact (128 entries, seq 0..127)
# or: FAIL: audit chain broken at seq 42: hash mismatch at seq 42: entry was modified
```

Código de salida `0` íntegra, `1` rota (con el `seq` y el motivo implicados), `2` archivo ausente o ilegible.

### Bundle de exportación firmado (verificable por terceros)

La instancia posee una clave de firma Ed25519, persistida en `data/.audit_signing_key` (generada en el primer arranque, `0600`; sobreescribe con `AUDIT_SIGNING_KEY_FILE` para mantenerla fuera del servidor). Su identidad pública se expone en `GET /api/audit/public-key` (admin): `{algorithm, public_key_pem, fingerprint}`. El extremo de la cadena se firma en checkpoints periódicos (`certificate_audit.checkpoints.jsonl`).

`GET /api/audit/export` (admin, opcional `?from_seq`/`?to_seq`) devuelve un bundle firmado y autoverificable — `{manifest, entries, bundle_signature}`. El manifiesto fija la huella de la instancia, la clave pública, el rango de `seq` y el `head_hash`; la firma cubre el manifiesto canónico, que (a través de `head_hash`) se compromete transitivamente con cada entrada. Un auditor lo verifica **fuera del servidor** sin ejecutar ni confiar en CertMate, pudiendo fijar la clave de forma externa:

```bash
python -m modules.core.audit_verify --bundle bundle.json --pubkey instance.pem
# OK: audit bundle intact and signed (128 entries, seq 0..127; signed by 0m2V5lDmnkPWOUHX)
```

El verificador comprueba la estructura de la cadena, que el manifiesto coincide con las entradas, la firma Ed25519 y que la huella coincide con la clave pública (fijada opcionalmente).

> **Honestidad del modelo de amenaza.** La cadena y la firma detectan cualquier modificación interior, eliminación o reordenación, y vinculan una exportación a la clave pública de esta instancia — para cualquiera que no posea la clave de firma. **No vinculan** al operador, que posee la clave y podría refirmar una cadena reescrita, y el truncamiento por la cola solo se detecta comparando exportaciones a lo largo del tiempo (una exportación posterior con menos entradas) o con un checkpoint externo. Limitar completamente al operador requiere enviar los checkpoints firmados a un sumidero externo de solo adición — un anclaje externo opcional, una funcionalidad prevista que aún no se ha implementado. Consulta [compliance.md](./compliance.md).

---

## Tipos de certificados

### API mTLS

Para la autenticación de clientes de API mediante TLS mutuo.

```
cert_usage: "api-mtls"
```

### VPN

Para la autenticación de clientes VPN.

```
cert_usage: "vpn"
```

### Tipos de uso personalizados

Puedes usar cualquier cadena de texto como tipo de uso personalizado:

```
cert_usage: "custom-application"
```

---

## Buenas prácticas

### Seguridad

1. **Protege tu token**
   - Mantén los tokens en secreto
   - Rota los tokens con regularidad
   - Usa HTTPS en producción

2. **Gestión de certificados**
   - Activa la renovación automática
   - Monitoriza las fechas de expiración
   - Revisa los logs de auditoría con regularidad
   - Revoca inmediatamente los certificados comprometidos

3. **Limitación de tasa**
   - Respeta los límites de tasa
   - Implementa backoff exponencial
   - Usa operaciones por lotes cuando sea posible

### Rendimiento

1. **Usa las operaciones por lotes**
   - Importa varios certificados a la vez
   - Reduce las llamadas a la API
   - Mejor gestión de errores

2. **Filtra los resultados**
   - Usa parámetros de consulta
   - Filtra por uso o estado
   - Reduce la transferencia de datos

3. **Usa caché cuando sea apropiado**
   - Almacena en caché los metadatos de los certificados
   - Refresca periódicamente
   - Comprueba la expiración localmente

---


---

<div align="center">

[← Volver a la documentación](./README.md) • [Inicio rápido →](./guide.md) • [Arquitectura →](./architecture.md)

</div>
