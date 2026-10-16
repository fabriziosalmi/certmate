# Servidor MCP (Model Context Protocol) de CertMate

<!-- CERTMATE-TRANSLATED-FROM 8ff9ffe2c5fe3b5b -->

CertMate incluye un servidor MCP (Model Context Protocol) integrado escrito en Node.js. Esto permite a los asistentes de IA agentivos (como Claude o Gemini) inspeccionar el estado de los certificados, disparar renovaciones, solicitar diagnósticos e interactuar directamente con la API de CertMate.

## Funcionalidades y herramientas

El servidor MCP de CertMate expone las siguientes herramientas a los asistentes de IA:

**Inventario y estado**
1. **`certmate_list_certificates`** — Lista todos los certificados gestionados por la instancia activa de CertMate (con fecha de expiración, estado y dominios).
2. **`certmate_get_certificate`** — Detalle completo de un dominio: estado, días hasta la expiración, SANs, proveedor DNS/CA, flag de renovación automática. Úsalo para decidir si un certificado necesita renovarse.
3. **`certmate_get_activity`** — Registro de actividad reciente/auditoría para diagnosticar qué cambió o falló.
4. **`certmate_diagnostics`** — Instantánea de diagnóstico completa y saneada.
5. **`certmate_get_settings`** — Ajustes globales y configuración, con los valores secretos enmascarados.

**Operaciones del ciclo de vida**
6. **`certmate_create_certificate`** — Solicita un nuevo certificado TLS para un dominio (proveedor DNS, account y CA opcionales). El servidor siempre pide la emisión asíncrona, por lo que devuelve un `job_id` (HTTP 202) que hay que consultar.
7. **`certmate_renew_certificate`** — Renueva un certificado existente si CertMate lo considera pendiente según su política de renovación; uno que aún no lo está queda como está, y el job informa `renewed: false`. También es asíncrono: devuelve un `job_id`.
8. **`certmate_get_job`** — Consulta un job asíncrono de creación/renovación/actualización por `job_id` hasta que su estado sea `succeeded` o `failed` (`queued` y `running` no son estados finales).
9. **`certmate_set_auto_renew`** — Activa o desactiva la renovación automática para un único dominio.
10. **`certmate_deploy_certificate`** — Ejecuta manualmente todos los deploy hooks configurados para un dominio.
11. **`certmate_download_certificate`** — Devuelve el material del certificado de un dominio en JSON (fullchain, key, chain) para que un agente pueda desplegarlo en otro lugar.

**Proveedores**
12. **`certmate_list_dns_providers`** — Proveedores DNS compatibles y configurados en esta instancia.
13. **`certmate_list_dns_accounts`** — Cuentas de proveedores DNS configuradas (credenciales enmascaradas); usa el ID de una cuenta devuelta como `account_id` al crear un certificado. **Requiere `admin`.**

**Edición y eliminación**
14. **`certmate_update_certificate`** — Cambia en el sitio la cobertura de un certificado existente reemitiéndolo: sustituye el conjunto de SAN y/o el alias DNS-01. El dominio principal es la identidad del certificado y no se puede cambiar aquí. Devuelve un `job_id`.
15. **`certmate_delete_certificate`** — **Destructivo e irreversible.** Elimina los archivos del certificado del disco y el dominio de los ajustes. **Requiere `admin`.**
16. **`certmate_get_certificate_file`** — Devuelve un único archivo de certificado como PEM sin procesar, listo para pegar, en lugar de envuelto en JSON. `cert.pem`, `chain.pem` y `fullchain.pem` los puede leer un `viewer`; `privkey.pem`, `combined.pem` y `cert.pfx` contienen material de clave y requieren `operator`.

## Roles

Dale al agente el token más restringido que le permita hacer su trabajo, y ten en cuenta que algunas herramientas
necesitan más que el resto:

| Herramienta | Rol mínimo |
|---|---|
| todo lo que figura en Inventario y estado salvo los diagnósticos (`certmate_get_settings` devuelve los secretos enmascarados), `certmate_list_dns_providers`, `certmate_get_certificate_file` para `cert.pem` / `chain.pem` / `fullchain.pem` | `viewer` |
| `certmate_create_certificate`, `certmate_renew_certificate`, `certmate_get_job`, `certmate_set_auto_renew`, `certmate_update_certificate`, `certmate_download_certificate`, `certmate_get_certificate_file` para `privkey.pem` / `combined.pem` / `cert.pfx` | `operator` |
| `certmate_diagnostics` | `admin` |
| **`certmate_deploy_certificate`** | **`admin`** |
| **`certmate_list_dns_accounts`** | **`admin`** |
| **`certmate_delete_certificate`** | **`admin`** |

El deploy y el listado de cuentas son los que sorprenden: ambos leen o actúan sobre credenciales
almacenadas, por lo que ambos son `admin` en el lado del servidor, aunque un agente que
solo renueva se conformaría en otro caso con `operator`. Un agente con alcance de operator
al que se le pida «elige una cuenta y emite» recibirá un 403 en la consulta de la cuenta: pasa
el `account_id` en el prompt, o dale deliberadamente un token admin.

## Puesta en marcha y configuración

### Requisitos previos
- Node.js (>= 20 — `mcp/package.json` declara `engines.node: ">=20.0.0"`)
- npm

### Instalación
Navega al directorio `mcp/` del repositorio de CertMate e instala las dependencias:
```bash
cd mcp
npm install
```

### Variables de entorno
El servidor MCP se comunica con la API REST de CertMate y requiere dos variables de entorno:
- `CERTMATE_URL` — La URL de tu instancia de CertMate (por defecto: `http://localhost:8000`).
- `CERTMATE_TOKEN` — Un token Bearer de API válido con los permisos de rol adecuados (normalmente `operator` o `admin`). Para un agente auditable, usa una clave marcada como clave de agente (ver [Atribución de auditoría](#atribución-de-auditoría)).

Opcionales:
- `CERTMATE_AGENT_SESSION` — Sobreescribe el ID de sesión por proceso que el servidor envía en cada llamada (`X-CertMate-Agent-Session`), de modo que una ejecución pueda correlacionarse con el ID de un orquestador externo. Se genera un UUID nuevo por proceso si no se define.
- `CERTMATE_AGENT_ID` — Una etiqueta para este despliegue de agente (`X-CertMate-Agent-Id`, por defecto `certmate-mcp-server`).

### Ejemplo de integración (configuración de Claude Desktop)
Para añadir el servidor MCP de CertMate a Claude Desktop, agrega lo siguiente a tu archivo de configuración (normalmente en `~/Library/Application Support/Claude/claude_desktop_config.json` en macOS o `%APPDATA%\Claude\claude_desktop_config.json` en Windows):

```json
{
  "mcpServers": {
    "certmate": {
      "command": "node",
      "args": ["/absolute/path/to/certmate/mcp/index.js"],
      "env": {
        "CERTMATE_URL": "http://localhost:8000",
        "CERTMATE_TOKEN": "your_secure_bearer_token"
      }
    }
  }
}
```

### Otros clientes MCP (Gemini, etc.)

El servidor habla MCP estándar sobre stdio, por lo que cualquier cliente que soporte MCP funciona
de la misma manera: apúntalo a `node /absolute/path/to/certmate/mcp/index.js` y define las
dos variables de entorno. Nada en el servidor es específico de Claude.

## Operar CertMate con un agente de IA (tareas programadas)

La mayoría de los asistentes de primer nivel ya soportan **tareas programadas** (Claude, Gemini y
otros). Combina esto con este servidor MCP y obtendrás un «guardián de certificados»
autónomo: describes la política en lenguaje natural con condiciones explícitas, el
modelo se programa a sí mismo, y en cada ejecución usa las herramientas anteriores para aplicar la
política. El patrón es agnóstico al modelo: cualquier cosa que pueda ejecutar un prompt guardado según un
calendario y llamar a herramientas MCP funcionará.

### El bucle que ejecuta el agente

1. `certmate_list_certificates` (o `certmate_get_certificate` por dominio) para leer `days_left` / estado.
2. Decide según tu condición, p. ej. *renovar cuando `days_left < 14`*.
3. `certmate_renew_certificate` para cada dominio pendiente.
4. Cada renovación devuelve un `job_id`; llama a `certmate_get_job` hasta que informe `succeeded` / `failed`. Un certificado que CertMate aún no considera pendiente termina con éxito con `renewed: false`: no se ha emitido nada.
5. Ante un fallo, expónlo. Un job de renovación o reemisión fallido también emite `certificate_failed`, por lo que los canales de notificación propios de CertMate (email, Slack, Discord, Telegram, ntfy, Gotify) lo notifican en cualquier caso. Dos excepciones: un job que falló porque otra operación ya tenía el dominio (`error_code: DOMAIN_OPERATION_IN_PROGRESS`) no lo emite, y tampoco lo emite una creación asíncrona fallida, así que para esos casos la señal es el propio informe del agente.

### Ejemplos de prompts programados

> **Diario, 08:00** — "Usando las herramientas MCP de CertMate, lista todos los certificados. Para cualquiera
> con `days_left < 14`, llama a `certmate_renew_certificate`, luego consulta
> `certmate_get_job` hasta que termine. Responde con un resumen de una línea por dominio e
> indica cualquier fallo."

> **Semanal** — "Llama a `certmate_get_activity` y `certmate_diagnostics`. Resume
> cualquier anomalía (renovaciones fallidas, certificados expirados, planificador detenido) en tres
> puntos. Si no hay nada incorrecto, indícalo."

> **Bajo demanda** — "Emite un certificado para `shop.example.com` usando `certmate_list_dns_providers`
> para elegir un proveedor configurado y `certmate_list_dns_accounts` para el ID de cuenta,
> luego supervisa el job hasta su finalización."

Como las condiciones viven en el prompt, puedes ajustar la política (umbral,
dominios, qué hacer ante un fallo) sin tocar ningún código. Dale al agente un
token con el alcance exacto de lo que debe hacer: `operator` para renovar, `admin`
solo si tiene que ejecutar deploy hooks, listar cuentas DNS, eliminar certificados o leer diagnósticos.

## Seguridad

1. **Protección del token** — El servidor MCP requiere un `CERTMATE_TOKEN` válido. Envía este token en la cabecera `Authorization` de cada petición a la API de CertMate. El `CERTMATE_URL` por defecto es `http://localhost:8000` en claro; cuando CertMate se ejecuta en otro host, usa una URL `https://`, o el token atravesará la red en texto plano.
2. **Mínimo privilegio** — Limita el token a lo que el agente necesita. Un guardián de renovaciones programadas necesita `operator`; reserva los tokens `admin` para agentes que deban ejecutar deploy hooks, listar cuentas DNS, eliminar certificados o extraer diagnósticos. Revoca el token para cortar el acceso del agente de inmediato.
3. **Compatibilidad con saneamiento de logs** — Herramientas como `certmate_diagnostics` recuperan datos después de que el saneador de logs haya eliminado las credenciales sensibles, protegiendo claves y tokens de filtrarse en contextos LLM.

## Atribución de auditoría

Para que el registro de auditoría pueda distinguir las acciones de un agente de las de un operador humano,
dale al servidor MCP una **clave API dedicada y marcada como agente** en lugar del token Bearer
global heredado:

1. En CertMate, ve a **Ajustes → Claves API**, crea una clave y marca **Clave de agente
   de IA** (o envía `"is_agent": true` a `POST /api/keys`). Dale el rol mínimo que necesite
   y, para una clave `viewer` u `operator`, limítala con `allowed_domains`. Una
   clave `admin` no se puede limitar por dominio: el servidor la rechaza con un 400.
2. Define esa clave como `CERTMATE_TOKEN` para el servidor MCP.

Cada acción sobre certificados que realice el agente quedará registrada con
`actor.kind="agent"`, el ID estable de la clave y el `X-CertMate-Agent-Session`
por proceso que envía el servidor, así que más adelante puedes mostrar exactamente qué
cambios en certificados realizó un agente de IA, bajo qué identidad y agrupados por ejecución.
El token Bearer global heredado reduce a cada llamante a `api_user` sin ID
de clave y se registra como `api_token`, no como `agent`. La cabecera de sesión de agente es una
declaración informativa y por sí sola nunca promueve a un llamante a `agent`.

Los registros resultantes forman parte de la cadena de auditoría a prueba de manipulaciones; ver
[Registro de auditoría](./api.md#registro-de-auditoría) y [compliance.md](./compliance.md).
