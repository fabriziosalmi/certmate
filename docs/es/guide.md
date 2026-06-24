# CertMate Certificados de Cliente - Guía de uso

## Primeros pasos

### Instalación

```bash
# 1. Instalar las dependencias
pip install -r requirements.txt

# 2. Ejecutar CertMate
python app.py

# 3. Abrir el panel de control
# Navega a: http://localhost:5000/client-certificates
```

### Primeros pasos

1. **Generar la CA** — Creada automáticamente en el primer arranque
2. **Acceder al panel de control** — Ve a `/client-certificates`
3. **Crear un certificado** — Usa el formulario web o la API
4. **Descargar los archivos** — Obtén el certificado, la clave y el CSR

---

## Panel de control web

### Funcionalidades del panel de control

**URL**: `http://localhost:5000/client-certificates`

#### Panel de estadísticas
- Total de certificados
- Número de activos
- Número de revocados
- Desglose por tipo de uso

#### Tabla de certificados
- Lista todos los certificados
- Búsqueda por nombre común
- Filtro por tipo de uso
- Filtro por estado
- Ordenación por fecha de creación

#### Formulario de creación de certificado

**Campos del formulario**:
- Nombre común (obligatorio)
- Dirección de correo electrónico
- Organización
- Unidad organizativa
- Tipo de uso (VPN, API-mTLS, etc.)
- Días de validez (por defecto: 365)
- Generar clave (casilla de verificación)
- Notas

**Ejemplo**:
```
Common Name: user@example.com
Email: user@example.com
Organization: ACME Corp
Usage Type: api-mtls
Days Valid: 365
```

#### Importación CSV por lotes

1. Haz clic en la pestaña "Importación masiva"
2. Prepara un archivo CSV con las cabeceras:
 ```
 common_name,email,organization,cert_usage,days_valid
 user1@example.com,user1@example.com,ACME Corp,api-mtls,365
 user2@example.com,user2@example.com,ACME Corp,vpn,365
 ```
3. Arrastra y suelta o haz clic para subir el archivo
4. Revisa la vista previa
5. Haz clic en "Importar"

---

## Tareas habituales

### Crear un certificado individual

#### Mediante el panel de control web

1. Ve a `/client-certificates`
2. Rellena el formulario "Crear certificado"
3. Haz clic en "Crear"
4. El certificado aparece en la tabla

#### Mediante la API

```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
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

---

### Descargar los archivos de un certificado

#### Mediante el panel de control web

1. Localiza el certificado en la tabla
2. Haz clic en el icono de descarga ()
3. Selecciona el tipo de archivo:
 - **CRT** — Certificado (público)
 - **KEY** — Clave privada (mantener en secreto)
 - **CSR** — Solicitud de firma de certificado

#### Mediante la API

```bash
# Descargar el certificado
curl http://localhost:5000/api/client-certs/CERT_ID/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o my-cert.crt

# Descargar la clave
curl http://localhost:5000/api/client-certs/CERT_ID/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o my-key.key
```

---

### Revocar un certificado

#### Mediante el panel de control web

1. Localiza el certificado en la tabla
2. Haz clic en el botón "Revocar" ()
3. Introduce el motivo de revocación (opcional)
4. Confirma

#### Mediante la API

```bash
curl -X POST http://localhost:5000/api/client-certs/CERT_ID/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "reason": "compromised"
 }'
```

**Motivos de revocación**:
- `compromised` — La clave ha sido comprometida
- `superseded` — Reemplazado por un nuevo certificado
- `unspecified` — Revocación general
- Cualquier motivo personalizado

---

### Renovar un certificado

#### Mediante el panel de control web

1. Localiza el certificado en la tabla
2. Haz clic en el botón "Renovar" ()
3. Confirma la renovación

#### Mediante la API

```bash
curl -X POST http://localhost:5000/api/client-certs/CERT_ID/renew \
 -H "Authorization: Bearer TOKEN"
```

**Nota**: La renovación crea un nuevo certificado con:
- El mismo nombre común
- Un nuevo número de serie
- Una nueva fecha de expiración
- El ID original actualizado

---

### Listar y filtrar certificados

#### Mediante el panel de control web

1. Ve a la tabla de certificados
2. Usa el cuadro de búsqueda para el nombre común
3. Usa el menú desplegable "Tipo de uso" para filtrar
4. Usa el menú desplegable "Estado" (Activo/Revocado)
5. Haz clic en "Aplicar filtros"

#### Mediante la API

```bash
# Listar todos
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtrar por uso
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Filtrar por estado
curl "http://localhost:5000/api/client-certs?revoked=false" \
 -H "Authorization: Bearer TOKEN"

# Buscar
curl "http://localhost:5000/api/client-certs?search=user@" \
 -H "Authorization: Bearer TOKEN"
```

---

### Comprobar el estado de un certificado (OCSP)

#### Mediante la API

```bash
curl http://localhost:5000/api/ocsp/status/SERIAL_NUMBER \
 -H "Authorization: Bearer TOKEN"
```

**Respuesta**:
```json
{
 "certificate_status": "good",
 "certificate_serial": 12345678,
 "this_update": "2024-10-30T18:00:00Z"
}
```

---

### Obtener la lista de revocación (CRL)

#### Descargar la CRL

```bash
# Formato PEM
curl http://localhost:5000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Formato DER
curl http://localhost:5000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl
```

#### Obtener información de la CRL

```bash
curl http://localhost:5000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

---

## Operaciones por lotes

### Formato CSV

```csv
common_name,email,organization,cert_usage,days_valid
user1@example.com,user1@example.com,ACME Corp,api-mtls,365
user2@example.com,user2@example.com,ACME Corp,vpn,365
user3@example.com,user3@example.com,ACME Corp,api-mtls,730
```

### Columnas obligatorias

- `common_name` — Sujeto del certificado (obligatorio)

### Columnas opcionales

- `email` — Dirección de correo electrónico
- `organization` — Nombre de la organización
- `organizational_unit` — Nombre del departamento
- `cert_usage` — Tipo de uso
- `days_valid` — Vigencia en días

### Mediante el panel de control web

1. Ve a la pestaña "Importación masiva"
2. Sube el archivo CSV
3. Revisa la vista previa
4. Haz clic en "Importar todo"

### Mediante la API

```bash
curl -X POST http://localhost:5000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "headers": ["common_name", "email", "organization"],
 "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
 ["user2@example.com", "user2@example.com", "ACME Corp"],
 ["user3@example.com", "user3@example.com", "ACME Corp"]
 ]
 }'
```

### Resultados de la importación

Devuelve los contadores de éxito/error:
```json
{
 "total": 3,
 "successful": 3,
 "failed": 0,
 "errors": [],
 "certificates": [{"identifier": "cert-batch-001", "common_name": "user1@example.com"},
 {"identifier": "cert-batch-002", "common_name": "user2@example.com"},
 {"identifier": "cert-batch-003", "common_name": "user3@example.com"}
 ]
}
```

---

## Tipos de uso de los certificados

### API mTLS

Para la autenticación mutua TLS de clientes API.

```
Usage Type: api-mtls
Typical Validity: 1 year (365 days)
```

### VPN

Para la autenticación de clientes VPN.

```
Usage Type: vpn
Typical Validity: 1-2 years (365-730 days)
```

### Tipos personalizados

Puedes crear certificados para cualquier uso personalizado:

```
Usage Type: custom-application
Usage Type: internal-service
Usage Type: mobile-app
```

---

## Renovación automática

### Configuración

- **Comprobación**: Diariamente a las 3 AM
- **Umbral**: 30 días antes de la expiración
- **Acción**: Renovación automática si está activada

### Activar la renovación automática

La renovación automática está activada por defecto. Para comprobar el estado:

```bash
curl http://localhost:5000/api/client-certs/CERT_ID \
 -H "Authorization: Bearer TOKEN"
```

Busca:
```json
{
 "renewal": {
 "renewal_enabled": true,
 "renewal_threshold_days": 30
 }
}
```

### Comportamiento de la renovación

Cuando se renueva automáticamente:
- Se crea un nuevo certificado
- Mismo CN (nombre común)
- Nuevo número de serie
- Nueva fecha de expiración
- El ID original permanece igual
- El certificado antiguo es reemplazado

---

## Resolución de problemas

### Problemas habituales

#### Fallo en la creación del certificado

**Error**: `Failed to create certificate`

**Soluciones**:
1. Comprueba que el nombre común es válido
2. Verifica que todos los campos obligatorios están rellenos
3. Comprueba que la CA está inicializada
4. Revisa los logs para más detalles

#### Fallo en la descarga del archivo

**Error**: `File not found`

**Soluciones**:
1. Verifica que el ID del certificado existe
2. Comprueba el tipo de archivo (crt, key, csr)
3. Asegúrate de que el certificado no ha sido eliminado
4. Comprueba el espacio en disco

#### Límite de solicitudes superado

**Error**: `HTTP 429 Too Many Requests`

**Soluciones**:
1. Espera antes de reintentar
2. Usa operaciones por lotes
3. Implementa backoff exponencial
4. Comprueba el límite para tu endpoint

### Consulta de logs

Ver los logs de la aplicación:
```bash
tail -f logs/certmate.log
```

Ver los logs de auditoría:
```bash
tail -f logs/audit/certificate_audit.log
```

---

## Buenas prácticas de seguridad

### Claves privadas

- **NUNCA** compartas tus claves privadas
- **NUNCA** hagas commit de claves en git
- Almacena las claves de forma segura
- Usa permisos de archivo 0600

### Certificados

- Monitoriza las fechas de expiración
- Renueva antes de que expiren
- Revoca inmediatamente los certificados comprometidos
- Conserva los logs de auditoría para el cumplimiento normativo

### Tokens de API

- Rota los tokens regularmente
- Usa HTTPS en producción
- No escribas los tokens directamente en el código
- Usa variables de entorno

### Revocación

Revoca siempre cuando:
- La clave esté comprometida
- El certificado sea reemplazado
- Un usuario abandone la organización
- El servicio sea dado de baja

---

## Consejos de rendimiento

### Para lotes grandes

Usa operaciones por lotes en lugar de creaciones individuales:
```bash
# Bien: Una solicitud para 1000 certificados
POST /api/client-certs/batch

# Mal: 1000 solicitudes para 1000 certificados
POST /api/client-certs/create × 1000
```

### Para el filtrado

Filtra en el lado del servidor:
```bash
# Bien: El servidor filtra
GET /api/client-certs?usage=api-mtls

# Mal: El cliente filtra todo
GET /api/client-certs
```

### Para la monitorización

Usa el endpoint de estadísticas:
```bash
GET /api/client-certs/stats
```

---

## Soporte

### Documentación

- [Referencia de API](./api.md) — Todos los endpoints
- [Arquitectura](./architecture.md) — Diseño del sistema
- [Notas de versión](../RELEASE_NOTES.md) — Historial de versiones

### Pruebas

Consulta `test_e2e_complete.py` para ejemplos de uso.

---

<div align="center">

[← Volver a la documentación](./README.md) • [Referencia de API →](./api.md) • [Arquitectura →](./architecture.md)

</div>
