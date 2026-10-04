# CertMate Certificados de Cliente - Guía de uso

<!-- CERTMATE-TRANSLATED-FROM 88bb16eb976577c4 -->

## Descripción general

CertMate Certificados de Cliente es una solución completa y lista para producción para la gestión de certificados de cliente con:

- **CA autofirmada** — Genere y gestione su propia Autoridad de Certificación
- **Gestión completa del ciclo de vida** — Cree, renueve, revoque y supervise certificados de cliente
- **OCSP & CRL** — Estado de los certificados en tiempo real y listas de revocación
- **Panel de control web** — Interfaz intuitiva para la gestión de certificados
- **API REST** — API completa para la automatización
- **Operaciones por lotes** — Importe certificados de cliente por CSV (máximo 100 filas por solicitud)
- **Registro de auditoría** — Seguimiento de todas las operaciones para el cumplimiento normativo
- **Limitación de tasa** — Protección integrada contra el abuso

---


## Primeros pasos

### Instalación

```bash
# 1. Instalar las dependencias
pip install -r requirements.txt

# 2. Ejecutar CertMate
python app.py

# 3. Abrir el panel de control
# Navega a: http://localhost:8000/client-certificates
```

### Primeros pasos

1. **Generar la CA** — Creada automáticamente en el primer arranque
2. **Acceder al panel de control** — Ve a `/client-certificates`
3. **Crear un certificado** — Usa el formulario web o la API
4. **Descargar los archivos** — Obtén el certificado, la clave y el CSR

---

## Panel de control web

### Funcionalidades del panel de control

**URL**: `http://localhost:8000/client-certificates`

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
curl -X POST http://localhost:8000/api/client-certs/create \
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
curl http://localhost:8000/api/client-certs/CERT_ID/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o my-cert.crt

# Descargar la clave
curl http://localhost:8000/api/client-certs/CERT_ID/download/key \
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
curl -X POST http://localhost:8000/api/client-certs/CERT_ID/revoke \
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
curl -X POST http://localhost:8000/api/client-certs/CERT_ID/renew \
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
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtrar por uso
curl "http://localhost:8000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Filtrar por estado
curl "http://localhost:8000/api/client-certs?revoked=false" \
 -H "Authorization: Bearer TOKEN"

# Buscar
curl "http://localhost:8000/api/client-certs?search=user@" \
 -H "Authorization: Bearer TOKEN"
```

---

### Comprobar el estado de un certificado (OCSP)

#### Mediante la API

```bash
curl http://localhost:8000/api/ocsp/status/SERIAL_NUMBER \
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
curl http://localhost:8000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Formato DER
curl http://localhost:8000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl
```

#### Obtener información de la CRL

```bash
curl http://localhost:8000/api/crl/download/info \
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
curl -X POST http://localhost:8000/api/client-certs/batch \
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

- **Comprobación**: Diariamente. Los certificados de cliente entre las 02:00 y
  las 04:00; los certificados de servidor, cuya regla describe el resto de esta
  sección, entre las 01:00 y las 03:00 (cada ronda a su hora, con hasta una
  hora de desfase aleatorio en cualquier sentido)
- **Umbral**: 30 días antes de la expiración (`renewal_threshold_days`), cuando
  no supera la mitad de la vida del certificado; vea abajo
- **Acción**: Renovación automática si está activada

### Cuando se renueva un certificado

Decide una sola regla, y la respuesta del certificado la lleva:
`needs_renewal` pasa a verdadero en `renews_at`, el instante en que el barrido
lo renueva (`GET /api/certificates/<domain>`, desde el contrato de API 2.40).
CertMate toma la decision y le dice a certbot que renueve; la compuerta propia
de certbot ya no interviene, asi que una actualizacion de certbot no puede
cambiar cuando renueva CertMate.

- **El umbral**, cuando no supera la mitad de la vida: 30 dias de un
  certificado de 90, como siempre, o 45 si fija 45.
- **Si no, la vida**: un tercio de ella, o la mitad para un certificado que
  vive menos de 10 dias. 30 dias no significan nada para un certificado de 45,
  asi que se renueva cuando le quedan 15; uno de 160 horas cuando le quedan
  unos 3.
- **La ventana de la CA**, cuando publico una para este certificado (abajo):
  antes o despues que el umbral.

Para un certificado de 90 dias con los 30 por defecto, las renovaciones ocurren
cuando siempre ocurrieron.

### Cuando la CA no coincide con el umbral (ARI)

El umbral es la opinion de CertMate, y es la misma para cada
certificado y cada CA. Desde la [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html)
una CA puede publicar la suya, por certificado: un endpoint `renewalInfo` que
responde con una ventana durante la cual quiere que ese certificado se
sustituya. Let's Encrypt ofrece uno, en produccion y en staging. step-ca todavia
no (0.30.2, medido; vea smallstep/certificates#2162), asi que en una step-ca
privada decide solo el umbral y el panel del certificado dice que la CA no
publica ninguna ventana.

El barrido de renovacion TLS pregunta, para cada certificado, y la ventana
decide en ambas direcciones. **Adelanta** una renovacion: asi se entera una
instancia de un reemplazo masivo — una emision erronea, un intermedio
comprometido, una decision del CA/Browser Forum — dias antes de que llegue la
revocacion, en lugar de cuando el certificado deja de funcionar. Y **pospone**
una que el umbral habria hecho, hasta el punto de la ventana que pidio la CA.

**Un aplazamiento tiene un suelo.** Una ventana nunca retiene un certificado
cuando le queda una sexta parte de su vida (15 dias de 90, 7,5 de 45, alrededor
de uno de 160 horas), ni mas alla del final de la propia ventana, asi que una
CA que se equivoca, o una ventana caducada, no puede empujar un certificado
hacia la expiracion. Cada ausencia — una CA que no publica `renewalInfo`, un
endpoint inalcanzable, una respuesta mal formada, un certificado autofirmado
sin Authority Key Identifier con el que nombrarlo — no deja ninguna ventana, y
decide el umbral. La ventana se guarda en disco, asi que un aplazamiento dura
de un barrido al siguiente.

Dentro de la ventana CertMate elige un punto, derivado del propio
identificador del certificado, asi que la eleccion es la misma en cada barrido
y dos certificados no caen en el mismo instante. Para eso existe la ventana:
una CA no quiere que todos sus clientes renueven a la vez.

El resumen del barrido los cuenta como `ari_advanced` y `ari_postponed`, de
modo que una renovacion que su configuracion no explica, o una que no hace,
sea atribuible.

El panel de detalle del certificado muestra lo que dijo la CA en el ultimo
barrido, bajo **CA renewal window**: la ventana, el instante dentro de ella en
que CertMate renueva, y el enlace explicativo de la CA cuando lo dio. Cuando no
hay ventana dice que ausencia es: la CA no publica ninguna, la CA no respondio
en la ultima comprobacion, o el certificado no se puede nombrar en ARI. El
mismo registro se devuelve como `renewal_info` en `GET /api/certificates/<domain>`.
Se lee de lo que guardo el barrido, asi que abrir el panel nunca envia una
peticion a la CA. Justo despues de una renovacion dice "Not checked yet" hasta
que el siguiente barrido pregunte por el nuevo certificado.

Ponga `"ari_enabled": false` en `settings.json` para desactivarlo; esta activado
por defecto y cuesta un GET no autenticado por certificado y barrido, mas uno
por CA y hora para el directorio.

### Un umbral de mas de 30 dias

Antes de la version 2.40.0 CertMate pedia a certbot renovar sin forzarlo, y la
compuerta propia de certbot solo renovaba dentro de los 30 dias previos a la
expiracion, asi que un `renewal_threshold_days` de 45 se comportaba como 30. La
version 2.40.0 forzo las renovaciones que un umbral de mas de 30 dias daba por
pendientes, y desde el contrato de API 2.40 se fuerza toda renovacion que
decide CertMate: un umbral de 45 renueva un certificado de 90 dias 45 dias
antes de su expiracion. Una renovacion que el umbral adelanta respecto a la
regla de la vida llega con dos protecciones:

- **Como maximo `early_renewals_per_sweep` por barrido** (por defecto 10, entre
  1 y 50). Subir el umbral en muchos certificados reparte las renovaciones
  anticipadas en varias noches en lugar de enviar todos los pedidos a la CA en
  una sola. El resumen las cuenta como `early_forced`, y las que quedan para el
  siguiente barrido como `early_deferred`.
- **Un certificado mas joven que una semana, o que un tercio de su vida, nunca
  se renueva por adelantado.** Un umbral por encima de la mitad de la vida ya no
  cuenta (decide la vida), asi que esta proteccion es la ultima defensa ante un
  certificado cuyas fechas no cuadran.

Un certificado que necesita atencion por otro motivo, una clave servida que
falta o no coincide, no se fuerza: se repara desde su linaje sin una clave
nueva.

### Activar la renovación automática

La renovación automática está activada por defecto. Para comprobar el estado:

```bash
curl http://localhost:8000/api/client-certs/CERT_ID \
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

El cuerpo indica qué límite se alcanzó. `"code": "ISSUANCE_QUEUE_FULL"` significa
que hay demasiados trabajos de certificados en cola o en ejecución: reintenta cuando
terminen algunos, o aumenta `CERTMATE_ISSUANCE_QUEUE_LIMIT` /
`CERTMATE_ISSUANCE_WORKERS`. El límite de la API y el de intentos de inicio de
sesión devuelven ambos `retry_after` en segundos.

### Consulta de logs

Ver los logs de la aplicación (CertMate escribe en stdout):
```bash
docker logs -f certmate
```

Solo existe un archivo de log si defines `CERTMATE_LOG_FILE` (p. ej.
`CERTMATE_LOG_FILE=/app/logs/certmate.log`); entonces haz `tail -f` de esa ruta.

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
- [Notas de versión](../../RELEASE_NOTES.md) — Historial de versiones

### Pruebas

Consulta `test_e2e_complete.py` para ejemplos de uso.

---

<div align="center">

[← Volver a la documentación](./README.md) • [Referencia de API →](./api.md) • [Arquitectura →](./architecture.md)

</div>
