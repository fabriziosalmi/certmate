# Deploy Hooks

Cierra [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Los deploy hooks son comandos shell cortos que CertMate ejecuta **después** de emitir, renovar o revocar un certificado. Úsalos para recargar servicios, enviar el nuevo certificado a un load balancer, publicar una notificación o cualquier otra acción necesaria tras una ejecución exitosa de certbot.

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
| `on_events` | string array | no | Subconjunto de `["created", "renewed", "revoked"]`. Si está ausente, el hook se ejecuta en los tres eventos. |

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
        "command": "/usr/sbin/nginx -s reload",
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
| `eval`, `source`, `. /` | builtins del shell que cargan código arbitrario |

Si necesitas alguno de estos elementos, coloca la lógica en un archivo script dentro del contenedor e invoca el script directamente:

```sh
/opt/scripts/deploy.sh
```

### Referencias de archivos bloqueadas

Las referencias a los archivos sensibles de CertMate se rechazan de plano (sin distinción de mayúsculas/minúsculas):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`, `private*key`, `.pem`

Así, `cat $CERTMATE_FULLCHAIN_PATH` es válido (la variable la expande el shell y la cadena literal `.pem` no aparece en `command`), pero `cat /app/data/settings.json` se rechazaría al guardar.

### Qué está permitido

- **Comandos simples**: `/usr/sbin/nginx -s reload`, `systemctl reload haproxy`
- **Peticiones curl (webhooks)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Expansión de variables en argumentos**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **Payloads JSON con `$VAR` (sin `${}`)**: `curl -d '{"domain":"$CERTMATE_DOMAIN"}' ...`
- **Invocaciones de script único**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Si un comando que antes podías guardar ahora produce `Command blocked at runtime: contains dangerous shell metacharacters`, consulta las notas de la versión — el validador se endureció en v2.4.0 y se relajó ligeramente en v2.4.1+.

---

## Recetas comunes

### Recargar nginx (global, todos los eventos)

```sh
/usr/sbin/nginx -t && /usr/sbin/nginx -s reload
```

(Nota: `&&` está bloqueado. Envuelve esto en un script: `/opt/scripts/reload-nginx.sh`.)

### Recargar haproxy

```sh
systemctl reload haproxy
```

### Enviar a un webhook de Slack

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Sincronizar el certificado con un host remoto

(Envuelve en un script — no se permiten `;`, `&&` en línea.)

```sh
/opt/scripts/sync-cert.sh
```

Donde `sync-cert.sh` es:

```sh
#!/bin/sh
set -eu
scp "$CERTMATE_FULLCHAIN_PATH" "$CERTMATE_KEY_PATH" deploy@lb:/etc/ssl/$CERTMATE_DOMAIN/
ssh deploy@lb 'systemctl reload haproxy'
```

### Omitir hooks durante un dry-run

En tu script:

```sh
[ -n "${CERTMATE_DRY_RUN:-}" ] && { echo "dry run, skipping"; exit 0; }
```

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
