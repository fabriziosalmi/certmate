# Deploy Hooks

<!-- CERTMATE-TRANSLATED-FROM 380a402d93da0cfb -->
<!-- CERTMATE-STALE-TRANSLATION -->
> **Esta traducción no está actualizada.** La versión en inglés ([`docs/deploy-hooks.md`](../deploy-hooks.md)) se ha modificado desde entonces y es la de referencia. En caso de discrepancia, prevalece el documento en inglés.

Cierra [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Los deploy hooks son comandos shell cortos que CertMate ejecuta **después** de emitir, renovar o revocar un certificado. En CertMate solo se pueden revocar certificados de cliente (`POST /api/client-certs/<id>/revoke`); un certificado de servidor no tiene revocación, así que para él no se ejecuta ningún hook. Úsalos para recargar servicios, enviar el nuevo certificado a un load balancer, publicar una notificación o cualquier otra acción necesaria tras una ejecución exitosa de certbot.

Esta guía cubre:

1. [Qué es un hook](#qué-es-un-hook)
2. [Configuración de hooks (UI + JSON)](#configuración-de-hooks)
3. [Variables de entorno pasadas a tu comando](#variables-de-entorno-pasadas-a-tu-comando)
4. [Disparo manual](#disparo-manual)
5. [Modelo de seguridad: por qué algunos comandos son rechazados](#modelo-de-seguridad)
6. [Recetas comunes](#recetas-comunes)
7. [Auditoría, historial y depuración](#auditoría-historial-y-depuración)

---

## Qué es un hook

Un hook es un objeto JSON con cinco campos:

| Campo | Tipo | Requerido | Notas |
|---|---|---|---|
| `id` | string | sí | Identificador estable (un UUID es válido; la UI genera uno automáticamente). Usado por `/api/deploy/test/<id>`. |
| `name` | string | sí | Etiqueta mostrada en la UI y en el registro de auditoría. |
| `command` | string | sí | Un único comando shell (`sh -c`). Máximo 1024 caracteres. Ver [seguridad](#modelo-de-seguridad). |
| `enabled` | boolean | no | Por defecto `true`. Los hooks desactivados se omiten durante el disparo automático pero pueden probarse manualmente. |
| `timeout` | integer | no | Segundos. Valor por defecto 30, limitado al `MAX_TIMEOUT` del sistema (actualmente 300). |
| `on_events` | string array | no | Subconjunto de `["created", "renewed", "revoked"]`. Si está ausente al guardar la configuración, se fija en `["created", "renewed"]`: `revoked` hay que elegirlo, para que añadir un hook no empiece a ejecutar comandos en revocaciones para las que nadie lo escribió. Un hook escrito a mano en `settings.json` no se normaliza nunca: sin `on_events` no se ejecuta en ningún evento del certificado, aunque sí con una activación manual. |

Los hooks se ubican bajo dos claves en `deploy_hooks`:

- **`global_hooks`** — se disparan para todos los dominios. Ideal para "recargar nginx tras cualquier cambio de certificado".
- **`domain_hooks`** — indexados por nombre de dominio exacto. Ideal para "enviar el certificado del LB de `api.example.com` a S3 tras la renovación de ese certificado específico".

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "global_hooks": [
      {
        "id": "5f8...",
        "name": "Reload nginx",
        "command": "curl -fsS -X POST https://lb.internal/api/reload",
        "enabled": true,
        "timeout": 30,
        "on_events": ["created", "renewed"]
      }
    ],
    "domain_hooks": {
      "api.example.com": [
        {
          "id": "9b1...",
          "name": "Push to LB",
          "command": "/opt/scripts/push-cert-to-lb.sh",
          "enabled": true,
          "timeout": 120,
          "on_events": ["renewed"]
        }
      ]
    }
  }
}
```

Si `enabled` a nivel superior es `false`, ningún hook se ejecuta en los eventos de certificado. Las pruebas manuales (`POST /api/deploy/test/<id>`) siguen funcionando — útil para iterar sobre un hook antes de activar el interruptor principal.

---

## Configuración de hooks

### Mediante la UI

`Ajustes → Deploy Hooks`. Activa o desactiva el interruptor **Habilitado**, luego añade hooks globales o por dominio. Cada fila incluye:

- nombre + comando + timeout + casillas de verificación de eventos
- un botón **Test** (ejecuta el hook contra el dominio sintético `test.example.com` con `CERTMATE_EVENT=manual`)
- interruptor de activación/desactivación
- eliminar

Guarda los ajustes para conservar los cambios.

### Mediante la API

```bash
# Leer la configuración actual
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Reemplazar la configuración (escritura completa del documento — pasa todo el diccionario deploy_hooks)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

El POST reemplaza todo el bloque `deploy_hooks`; combina los cambios en el cliente si quieres conservar las entradas existentes.

---

## Variables de entorno pasadas a tu comando

Cada invocación define estas variables en el entorno del proceso del hook:

| Variable | Valor de ejemplo |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (solo intermediarios, sin el certificado hoja — para destinos que requieren la cadena como archivo separado) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` |
| `CERTMATE_DRY_RUN` | Se establece a `1` solo durante un dry-run; ausente en caso contrario. |

Tu comando puede referenciar estas variables como `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"`, etc. Los valores se pasan por entorno, no por interpolación de cadenas, por lo que las comillas funcionan igual que en cualquier shell normal.

El hook se ejecuta como el usuario del proceso CertMate (en la imagen Docker: `certmate`, UID/GID 1000:1000) dentro del contenedor. Todo lo que hagas con `cp`, `curl`, `ssh`, etc. debe ser accesible desde allí.

---

## Disparo manual

Dos formas de disparar un hook fuera del ciclo de vida normal del certificado:

### Test por hook (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Ejecuta únicamente el hook con ese `id`, contra el dominio sintético `test.example.com`, con `CERTMATE_EVENT=manual`. Omite el filtro `on_events` — útil para comprobar "¿funciona realmente este comando?".

### Ejecutar todos los hooks de un dominio (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Dispara todos los hooks globales y específicos del dominio habilitados para `api.example.com` con `CERTMATE_EVENT=manual`, ignorando `on_events`. Devuelve un resumen estructurado:

```jsonc
{
  "ok": true,
  "total": 3,
  "succeeded": 2,
  "failed": 1,
  "results": [
    {"hook_name": "Reload nginx", "exit_code": 0, "duration_ms": 142, ...},
    ...
  ]
}
```

Esto es lo que invoca el botón **Ejecutar Deploy Hooks Ahora** en el panel de detalles del certificado.

---

## Modelo de seguridad

Los hooks son ejecución de código arbitrario por diseño — esa es la funcionalidad. Para limitar el radio de impacto, el campo command se valida **en el momento de guardar y de nuevo en tiempo de ejecución** (defensa en profundidad) y se rechaza si contiene:

### Patrones shell bloqueados

| Patrón | Motivo |
|---|---|
| `` ` `` (backticks) | sustitución de comando |
| `$(...)` | sustitución de comando |
| `${...}` | expansión de parámetro (la expansión de variables de entorno está permitida — solo se bloquea la forma `${...}`) |
| `&&` / `\|\|` | encadenamiento lógico |
| `;` | separador de instrucciones |
| `\|` | pipe |
| `\r` / `\n` | saltos de línea (evita que `sh -c` los interprete como `;`) |
| `> /` (redirección a ruta absoluta) | evita sobreescribir archivos del sistema |
| `<<` | here-doc |
| `eval`, `source`, `.` (el atajo de source, con cualquier argumento) | builtins del shell que cargan código arbitrario |

Si necesitas alguno de estos elementos, coloca la lógica en un archivo script dentro del contenedor e invoca el script directamente:

```sh
/opt/scripts/deploy.sh
```

### Referencias de archivos bloqueadas

Las referencias a los archivos sensibles de CertMate se rechazan de plano (sin distinción de mayúsculas/minúsculas):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`, `private*key`, `.pem`

Así, `cat $CERTMATE_FULLCHAIN_PATH` es válido (la variable la expande el shell y la cadena literal `.pem` no aparece en `command`), pero `cat /app/data/settings.json` se rechazaría al guardar.

### Qué está permitido

- **Comandos simples**: `curl -fsS https://lb.internal/api/reload`, `openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates`
- **Peticiones curl (webhooks)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Expansión de variables en argumentos**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **Payloads JSON con `$VAR` (sin `${}`)**: `curl -d '{"domain":"$CERTMATE_DOMAIN"}' ...`
- **Invocaciones de script único**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Si un comando que antes podías guardar ahora produce `Command blocked at runtime: contains dangerous shell metacharacters`, consulta las notas de la versión — el validador se endureció en v2.4.0 y se relajó ligeramente en v2.4.1+.

---

## Dónde se ejecuta un hook

**Dentro del contenedor de CertMate**, como el proceso que emitió el certificado — no en el host de Docker, ni en la máquina que quieres recargar.

Es lo primero que hay que entender antes de escribir un hook, y los ejemplos de esta página lo tenían mal. `systemctl reload haproxy` parece recargar tu balanceador. No lo hace: se ejecuta en un contenedor sin systemd, sin haproxy y sin nginx, y termina con 127 — *not found* — que es lo que [#856](https://github.com/fabriziosalmi/certmate/issues/856) reportó para `scp`.

Lo que la imagen publicada contiene de verdad, para un hook:

| | |
|---|---|
| **presentes** | `sh`, `bash`, `curl`, `openssl` |
| **ausentes** | `ssh`, `scp`, `sftp`, `rsync`, `jq`, `nginx`, `systemctl`, `haproxy`, y todo lo demás |

La lista es corta a propósito: la etapa de runtime instala tres paquetes, y el Dockerfile explica por qué — cada paquete añadido es superficie que hay que parchear y escanear ([#403](https://github.com/fabriziosalmi/certmate/issues/403)).

### Tres formas de actuar sobre una máquina que no es esta

**Pedírselo por la red.** Casi todo lo que merece recargarse tiene una API, y `curl` está.

**Construir tu propia imagen.** La de CertMate es una base como cualquier otra:

```
FROM fabriziosalmi/certmate:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
USER certmate
```

**Montar un script.** Un hook puede llamar a cualquier ruta del contenedor — pero sigue ejecutándose en el contenedor, de modo que lo que invoque también tiene que estar ahí dentro.

---

## Recetas comunes

Se ejecutan en la imagen tal como se publica. Cada una se verifica contra ella.

### Enviar a un webhook de Slack

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Avisar a otra cosa de que el certificado cambió

```sh
curl -fsS -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" --data-binary "@$CERTMATE_FULLCHAIN_PATH" https://lb.internal/api/certs/$CERTMATE_DOMAIN
```

`-f` importa: sin él, `curl` termina con 0 incluso ante un error HTTP, y el hook informa de éxito para un despliegue que no ocurrió.

### Comprobar qué se emitió

```sh
openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -subject -dates
```

### Ejecutar un script propio

```sh
/opt/scripts/deploy.sh
```

Montado en el contenedor y escrito para lo que el contenedor tiene.
---

## Auditoría, historial y depuración

### Feed de actividad

`GET /api/deploy/history?limit=50` y la pestaña **Actividad** de la UI muestran las últimas N ejecuciones de hooks con: nombre del hook, dominio, evento, código de salida, duración, stdout/stderr (truncados a 4096 bytes cada uno) y marca de tiempo.

### Consola de depuración

Ajustes → Deploy Hooks dispone de una consola de depuración (botón de alternancia en la esquina inferior derecha) que muestra en tiempo real los eventos `loadConfig` / `saveConfig` / `testHook` en el lado del cliente. Útil para iterar sobre la UI.

### Registro de auditoría

Cada ejecución de un hook escribe una entrada `operation: deploy_hook` en el registro de auditoría con el estado `success`/`failure` más el nombre del hook, el código de salida y la duración. Visible en la pestaña Actividad y en `/api/audit`.

### Fallos comunes

| Síntoma | Causa probable |
|---|---|
| `Hook not found` | El ID del hook en la solicitud de prueba no coincide con ningún hook en la configuración guardada (la UI estaba desactualizada o el hook acaba de eliminarse). Recarga la página. |
| `Command blocked at runtime` | Uno de los [patrones bloqueados](#patrones-shell-bloqueados) pasó el guardado. Mueve la lógica problemática a un archivo script. |
| `exit code 127` | Comando no encontrado dentro del contenedor (p. ej., `nginx` no está en `$PATH`). Usa rutas absolutas o instala el binario en la imagen. |
| `timeout after 30s` | El hook tardó más que su `timeout`. Auméntalo (máximo 300 s) o mueve el trabajo a un script en segundo plano. |
| `Deploy hooks disabled` | `deploy_hooks.enabled` es `false`. Activa el interruptor principal en Ajustes. |
| `No hooks configured for <domain>` | Se intenta ejecutar hooks para un dominio sin hooks globales Y sin entrada en `domain_hooks[<domain>]`. Añade un hook (o llama a `/api/deploy/test/<id>` para uno específico). |

---

## Ver también

- [`modules/core/deployer.py`](../../modules/core/deployer.py) — implementación
- [`modules/web/settings_routes.py`](../../modules/web/settings_routes.py) — endpoints `/api/deploy/*`
- [`templates/partials/settings_deploy.html`](../../templates/partials/settings_deploy.html) — partial de UI
- [`static/js/settings-deploy.js`](../../static/js/settings-deploy.js) — componente Alpine

---

<div align="center">

[← Volver a la documentación](./README.md)

</div>
