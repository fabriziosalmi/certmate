# Deploy Hooks

<!-- CERTMATE-TRANSLATED-FROM 0d31dc7a82589489 -->

Cierra [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Los deploy hooks son comandos shell cortos que CertMate ejecuta **después** de emitir, renovar o revocar un certificado. Úsalos para recargar servicios, enviar el nuevo certificado a un load balancer, publicar una notificación o cualquier otra acción que deba realizarse a continuación de una ejecución exitosa de certbot.

> **Sobre `revoked`.** En CertMate solo se pueden revocar certificados de cliente — `POST /api/client-certs/<id>/revoke` —, así que es entonces cuando se ejecuta un hook `revoked`, con `CERTMATE_DOMAIN` establecido en el identificador del certificado de cliente. No existe ninguna operación de revocación para un certificado de servidor, así que para él no se ejecuta ningún hook.

Esta guía cubre:

1. [Qué es un hook](#qué-es-un-hook)
2. [Configuración de hooks (UI + JSON)](#configuración-de-hooks)
3. [Variables de entorno pasadas a tu comando](#variables-de-entorno-pasadas-a-tu-comando)
4. [Ventanas de mantenimiento](#ventanas-de-mantenimiento)
5. [Disparo manual](#disparo-manual)
6. [Modelo de seguridad: por qué algunos comandos son rechazados](#modelo-de-seguridad)
7. [Dónde se ejecuta un hook](#dónde-se-ejecuta-un-hook)
8. [Recetas comunes](#recetas-comunes)
9. [Auditoría, historial y depuración](#auditoría-historial-y-depuración)
10. [Destinos de despliegue tipados](#destinos-de-despliegue-tipados)

---

## Qué es un hook

Un hook es un objeto JSON con estos campos:

| Campo | Tipo | Requerido | Notas |
|---|---|---|---|
| `id` | string | sí | Identificador estable (un UUID es válido; la UI genera uno automáticamente). Usado por `/api/deploy/test/<id>`. |
| `name` | string | sí | Etiqueta mostrada en la UI y en el registro de auditoría. |
| `command` | string | sí | Un único comando shell (`sh -c`). Máximo 1024 caracteres. Ver [seguridad](#modelo-de-seguridad). |
| `enabled` | boolean | no | Por defecto `true`. Los hooks desactivados se omiten durante el disparo automático, pero pueden seguir probándose manualmente. |
| `timeout` | integer | no | Segundos. Valor por defecto 30, limitado al `MAX_TIMEOUT` del sistema (actualmente 300). |
| `on_events` | string array | no | Subconjunto de `["created", "renewed", "revoked"]`. Si está ausente al guardar la configuración, se fija en `["created", "renewed"]` — `revoked` hay que elegirlo expresamente, para que añadir un hook no empiece a ejecutar comandos en revocaciones para las que nadie lo escribió. Un hook escrito a mano en `settings.json` no se normaliza nunca, así que sin `on_events` no se ejecuta en ningún evento del certificado; sí se ejecuta con un disparo manual. |
| `window` | object | no | Una [ventana de mantenimiento](#ventanas-de-mantenimiento). Si está ausente, el hook se ejecuta en cuanto se emite o se renueva el certificado — el comportamiento que todos los hooks han tenido hasta ahora. |

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
        "name": "Tell the load balancer",
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

Si `enabled` a nivel superior es `false`, ningún hook se ejecuta en los eventos de certificado. Las ejecuciones de prueba por hook (`POST /api/deploy/test/<id>`) siguen funcionando — útil para iterar sobre un hook antes de activar el interruptor principal. Ejecutar todos los hooks de un dominio (`POST /api/certificates/<domain>/deploy`) no funciona: se rechaza mientras el interruptor está desactivado.

---

## Configuración de hooks

### Mediante la UI

`Settings → Deploy Hooks`. Activa el interruptor **Enabled** y luego añade hooks globales o por dominio. Cada fila incluye:

- nombre + comando + timeout + casillas de verificación de eventos
- un botón **Test** (ejecuta el hook contra el dominio sintético `test.example.com` con `CERTMATE_EVENT=test` y `CERTMATE_DRY_RUN=1`)
- interruptor de activación/desactivación
- eliminar

Guarda los ajustes para conservar los cambios.

### Mediante la API

```bash
# Leer la configuración actual
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Escribir la configuración (las claves de nivel superior que envías reemplazan las guardadas)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

El POST combina en el nivel superior de `deploy_hooks`: cada clave que envías (`enabled`, `global_hooks`, `domain_hooks`, `targets`) reemplaza por completo el valor guardado, y una clave que omites se conserva tal como estaba. Así, enviar `global_hooks` reemplaza la lista entera; para añadir un hook, lee la lista, añade el hook al final y envíala de vuelta. Una lista vacía explícita vacía esa clave.

---

## Variables de entorno pasadas a tu comando

Cada invocación define estas variables en el entorno del proceso del hook:

| Variable | Valor de ejemplo |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` — **no se define** para un [certificado a partir de CSR](../csr-only-certificates.md), cuya clave permanece en el dispositivo |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (solo intermediarios, sin el certificado hoja — para destinos que requieren la cadena como archivo separado) |
| `CERTMATE_TAGS` | `loadbalancer,env:prod` — las [etiquetas](./api.md) del certificado, separadas por comas y en minúsculas; **vacía** cuando no tiene ninguna, y siempre definida, de modo que un hook puede contar con ella (desde el contrato de API 2.33) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` (Deploy Now) / `test` (test por hook). `renewed` también sigue a la [sustitución de un certificado externo](../api.md#replace-an-external-certificate) mediante subida. |
| `CERTMATE_DRY_RUN` | Se establece en `1` solo para un test por hook (`/api/deploy/test/<id>`, el botón **Test**); ausente en caso contrario, también para Deploy Now. El comando se ejecuta igualmente; es solo una señal que tu script puede comprobar. |

Las rutas están bajo el directorio de certificados de CertMate: `/app/certificates` en la imagen Docker, o donde apunte `CERTMATE_CERT_DIR`.

Tu comando puede referenciar estas variables como `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"`, etc. Los valores se pasan por entorno, no por interpolación de cadenas, por lo que las comillas funcionan igual que en cualquier shell normal.

El hook se ejecuta como el usuario del proceso CertMate (en la imagen Docker: `certmate`, UID/GID 1000:1000) dentro del contenedor. Todo lo que hagas con `cp`, `curl`, `ssh`, etc. debe ser accesible desde allí.

---

## Ventanas de mantenimiento

Cierra [#632](https://github.com/fabriziosalmi/certmate/issues/632).

Un certificado se renueva cuando le toca, y ese es un momento que nadie ha elegido: el barrido de renovación se ejecuta a las 02:00 con una hora de jitter, y solo para los certificados que esa noche están dentro del umbral. El hook se ejecutaba entonces inmediatamente. Para un hook que reinicia una base de datos o recarga un load balancer, eso es una interrupción del servicio a una hora impredecible.

Una `window` separa las dos cosas. El certificado se sigue renovando cuando le toca — eso lo determina la caducidad y no es negociable —, pero el **despliegue** se retiene hasta la próxima vez que la ventana esté abierta.

```jsonc
"window": {
  "start": "02:00",          // obligatorio, HH:MM en formato de 24 horas
  "end": "04:00",            // obligatorio, exclusivo
  "days": ["sat", "sun"],    // opcional; omitir o dejar vacío para todos los días
  "timezone": "Europe/Rome"  // nombre IANA opcional, UTC por defecto
}
```

El mismo campo funciona en los destinos de despliegue tipados, que suele ser donde lo quieres: el rollout de un secret de Kubernetes es exactamente el tipo de despliegue que corresponde a una ventana de mantenimiento.

### Cuáles son las reglas

- **`end` es exclusivo.** `02:00`–`04:00` y `04:00`–`06:00` son adyacentes, no se solapan.
- **Una ventana puede cruzar la medianoche**, y pertenece al día en que **empieza**. Una ventana `22:00`–`04:00` en `["fri"]` está abierta a las 02:00 del sábado por la mañana. Leerla al revés te obligaría, sin avisarte, a marcar también el sábado.
- **`start` y `end` no pueden ser iguales.** Eso se lee igual de bien como "siempre abierta" que como "nunca abierta", así que se rechaza en lugar de adivinarlo. Usa `00:00`–`23:59` para un día entero.
- **La zona horaria es un nombre IANA** (`Europe/Rome`, `America/New_York`), validado al guardar. Una errata se rechaza en ese momento en lugar de retener en silencio todos los despliegues para una ventana que nunca se abre.
- **El horario de verano lo gestiona la zona, no la aritmética.** El día del cambio de primavera, una ventana `02:00`–`04:00` de Roma se abre a las 03:00 locales, porque 02:00–02:59 no existe; el día de otoño está abierta durante las dos pasadas de 02:00–02:59.

### Qué ocurre mientras un despliegue está retenido

La cola vive en `data/pending_deploys.json` y sobrevive a un reinicio — la ventana suele estar a horas de distancia.

- Una segunda renovación antes de que se abra la ventana **no** encola un segundo despliegue. El hook lee el certificado del disco cuando se ejecuta, así que una única ejecución diferida publica siempre el más reciente.
- Si el hook se elimina o se desactiva, o si los deploy hooks se desactivan por completo, el despliegue encolado se **descarta** en el siguiente vaciado de la cola. Tu configuración actual dice que no se ejecute.
- Si eliminas la ventana, el despliegue se libera en el siguiente vaciado de la cola en lugar de esperar una vez más.
- **Deploy Now consume el despliegue que estaba esperando.** Si el hook (o el destino tipado) que ejecutas a mano tiene éxito, se elimina su entrada encolada para ese dominio: el certificado ya se ha entregado, y ejecutarlo de nuevo cuando se abra la ventana sería un segundo despliegue no anunciado. Si la ejecución manual **falla**, la entrada se queda, de modo que el despliegue de la ventana es el reintento. Una renovación que ocurre *mientras* Deploy Now se está ejecutando conserva su entrada, porque ese certificado es más reciente que el que leyó la ejecución manual. Los dos nunca ejecutan el mismo despliegue a la vez: si la ventana se abre mientras Deploy Now está ejecutando un hook, la ejecución programada lo omite y el siguiente tick lo encuentra o bien entregado o bien todavía pendiente; y si la ejecución programada ya está dentro del hook cuando pulsas el botón, Deploy Now espera a que termine y luego se ejecuta. Aun así, un despliegue encolado que no quieres solo se puede eliminar desactivando o eliminando el hook (entonces se descarta en el siguiente vaciado de la cola).
- Un hook que falla dentro de su ventana **no** se vuelve a encolar. Se registra en el historial como cualquier otro fallo; volver a encolarlo lo reintentaría cada minuto mientras la ventana siguiera abierta.
- Un despliegue que sigue esperando después de siete días se registra como advertencia. No es un límite — esperar es precisamente la funcionalidad —, pero una semana significa que la ventana no se ha abierto ni una sola vez, lo que suele indicar que los días o la zona horaria no son los que pretendías.

Los despliegues retenidos por una ventana son invisibles en todas las demás partes: el certificado se renovó, el historial no muestra nada y nada falló. `GET /api/deploy/pending` los lista junto con la ventana que esperan y cuándo se abre la próxima vez.

```bash
curl -H "Authorization: Bearer $TOKEN" https://certmate.local/api/deploy/pending
```

```json
[
  {
    "kind": "hook", "id": "6f0…", "domain": "api.example.com",
    "event": "renewed", "queued_at": "2026-09-08T13:12:04+00:00",
    "window": "02:00-04:00 Europe/Rome (sat, sun)",
    "next_run": "2026-09-12T00:00:00+00:00", "orphaned": false
  }
]
```

### Qué ignora la ventana

**Deploy Now** la ignora. Pulsarlo es elegir este momento; retener el despliegue hasta las 02:00 haría que el botón no hiciera nada visible. Lo que entrega no se vuelve a entregar: consulta *Qué ocurre mientras un despliegue está retenido*. La ventana se ignora igualmente en `POST /api/deploy/test/<id>`, que nunca toca la cola.

---

## Disparo manual

Dos formas de disparar un hook fuera del ciclo de vida normal del certificado:

### Test por hook (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Ejecuta únicamente el hook con ese `id`, contra el dominio sintético `test.example.com` (o el `domain` indicado en un cuerpo JSON), con `CERTMATE_EVENT=test` y `CERTMATE_DRY_RUN=1`. El comando se ejecuta de verdad. Omite el filtro `on_events`, el propio indicador `enabled` del hook y el interruptor principal — útil para comprobar "¿funciona realmente este comando?".

### Ejecutar todos los hooks de un dominio (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Dispara todos los hooks globales y específicos del dominio que estén habilitados (y todos los destinos de despliegue tipados que coincidan) para `api.example.com` con `CERTMATE_EVENT=manual`, ignorando `on_events`. Se rechaza mientras el interruptor principal está desactivado. Devuelve un resumen estructurado:

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

Esto es lo que invoca el botón **Run deploy hooks now** (icono de play, sección Deployment del panel de detalles del certificado).

---

## Modelo de seguridad

Los hooks son ejecución de código arbitrario por diseño — esa es la funcionalidad. Para mantener acotado el radio de impacto, el campo command se valida **en el momento de guardar y de nuevo en tiempo de ejecución** (defensa en profundidad) y se rechaza si contiene:

### Patrones shell bloqueados

| Patrón | Motivo |
|---|---|
| `` ` `` (backticks) | sustitución de comando |
| `$(...)` | sustitución de comando |
| `${...}` | expansión de parámetro. `$VAR` está permitido, y también `${CERTMATE_NAME}` con la llave de cierre justo después del nombre; cualquier otra forma `${...}`, incluida `${CERTMATE_DOMAIN:-x}`, se bloquea |
| `&&` / `\|\|` | encadenamiento lógico |
| `;` | separador de instrucciones |
| `\r` / `\n` | saltos de línea (para que `sh -c` no pueda interpretarlos como `;`) |
| `> /` (redirección a ruta absoluta) | evita sobrescribir archivos del sistema |
| `<<` | here-doc |
| `eval`, `source`, `.` (el atajo de source, con cualquier argumento) | builtins del shell que cargan código arbitrario |

Dos cosas que parecen pertenecer a esa lista están permitidas a propósito (#115): un pipe simple, para posprocesado como `curl ... | grep -q ok` (ambos lados deben ser un comando que la imagen incluya — `jq` no es uno de ellos), y una redirección a una ruta relativa (`> out.txt`). Solo se bloquea la redirección a una ruta absoluta.

Si necesitas alguno de esos elementos, coloca la lógica en un archivo script dentro del contenedor e invoca el script directamente:

```sh
/opt/scripts/deploy.sh
```

### Referencias de archivos bloqueadas

Un comando que nombra uno de los propios archivos sensibles de CertMate se rechaza (sin distinción de mayúsculas/minúsculas):

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`

Los archivos del certificado no están en la lista: instalar el certificado y su clave (`privkey.pem`, `$CERTMATE_KEY_PATH`) es el trabajo normal de un hook. `cat /app/data/settings.json` se rechaza al guardar.

La comprobación reconoce esos nombres **tal como están escritos**. Detiene un hook que nombra uno de esos archivos por error. No detiene un comando que llega al mismo archivo sin escribir su nombre: un glob (`settings*`), un comodín `?` o un nombre partido por comillas (`settings"."json`) pasan. Es una protección contra accidentes, no una frontera de seguridad. Solo un admin puede guardar o ejecutar un hook, y un admin que puede guardar un hook ya puede ejecutar cualquier comando como CertMate. Lo mismo vale para los patrones de shell de arriba.

### Enviar la clave privada desde un hook

Un hook puede enviar la clave a una URL: `CERTMATE_KEY_PATH` no está en la lista de bloqueados y `curl` está en la imagen, así que `curl --data-binary @"$CERTMATE_KEY_PATH" …` se guarda sin problemas. CertMate no examina lo que un comando así hace con la clave. Las comprobaciones te corresponden a ti:

- usa `https://`, nunca `http://`: la clave cruzaría la red en claro;
- no añadas `-k`/`--insecure`, que desactiva la comprobación de que el servidor es el que pretendías;
- no añadas `-L`/`--location`, que repite la petición, clave incluida, en cualquier dirección que indique la respuesta;
- no dejes que el comando imprima en la salida lo que responde el servidor: la salida del hook se conserva en el historial, y el registro de auditoría no se puede editar.

Para Kubernetes usa en su lugar el [destino tipado](#destinos-de-despliegue-tipados), que cumple las tres primeras por ti.

### Qué está permitido

- **Comandos simples**: `curl -fsS https://lb.internal/api/reload`, `openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates`
- **Peticiones POST con curl (webhooks)**: `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Expansión de variables en argumentos**: `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **Payloads JSON con `$VAR`**: `curl -H "Content-Type: application/json" -d "{\"domain\":\"$CERTMATE_DOMAIN\"}" ...`. El cuerpo tiene que ir entre comillas dobles: dentro de comillas simples el shell nunca expande `$CERTMATE_DOMAIN`, y el receptor recibe el texto literal.
- **Invocaciones de script único**: `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Si un comando que antes podías guardar ahora produce `Command blocked at runtime: contains dangerous shell metacharacters`, consulta las notas de la versión — el validador se endureció en v2.4.0 y se relajó ligeramente en v2.4.1+.

---

## Dónde se ejecuta un hook

**Dentro del contenedor de CertMate**, como el proceso que emitió el certificado — no en el host de Docker, ni en la máquina que quieres recargar.

Es lo único que hay que tener claro antes de escribir un hook, y los ejemplos de esta página lo tenían mal. Un comando como `systemctl reload haproxy` parece recargar tu load balancer. No lo hace: se ejecuta en un contenedor que no tiene systemd, ni haproxy, ni nginx, y termina con 127 — `not found` —, que es lo que [#856](https://github.com/fabriziosalmi/certmate/issues/856) reportó para `scp`.

Lo que la imagen publicada contiene de verdad, para que un hook lo use:

| | |
|---|---|
| **presentes** | `sh`, `bash`, `curl`, `openssl` |
| **ausentes** | `ssh`, `scp`, `sftp`, `rsync`, `jq`, `nginx`, `systemctl`, `haproxy`, y todo lo demás |

Esa lista es corta a propósito. La etapa de runtime instala tres paquetes, y el Dockerfile explica por qué: cada paquete añadido es superficie que hay que parchear y escanear ([#403](https://github.com/fabriziosalmi/certmate/issues/403)). No es un descuido, así que un hook tiene que funcionar con lo que hay — o llegar a algo que tenga más.

`tests/test_a_hook_runs_where_certmate_runs.py` comprueba los ejemplos de abajo contra la imagen, para que esta tabla no pueda volver a desviarse de ella.

### Tres formas de actuar sobre una máquina que no es esta

**Pedírselo por la red.** Casi todo lo que merece la pena recargar tiene una API, y `curl` está presente. Este es el patrón que funciona sin ningún cambio.

**Construir tu propia imagen.** La imagen de CertMate es una base como cualquier otra:

```
FROM fabriziosalmi/certmate:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
USER certmate
```

Ahora `scp` está ahí, junto con lo que hayas añadido, y parchear esa superficie te corresponde a ti en lugar de a todos.

**Montar un script y sus dependencias.** Un hook puede llamar a cualquier ruta del contenedor, así que un script montado con bind mount funciona — pero sigue ejecutándose en el contenedor, de modo que todo lo que invoque también tiene que estar ahí dentro.

---

## Recetas comunes

Estas se ejecutan en la imagen tal como se publica. Cada una se comprueba contra ella.

### Enviar a un webhook de Slack

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Avisar a otra cosa de que el certificado cambió

Cualquier cosa con una API HTTP — un load balancer, un endpoint de gestión de configuración, tu propio pequeño agente junto al servicio:

```sh
curl -fsS -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" --data-binary "@$CERTMATE_FULLCHAIN_PATH" https://lb.internal/api/certs/$CERTMATE_DOMAIN
```

`-f` importa: sin él, `curl` termina con 0 ante un error HTTP, y el hook informa de éxito para un despliegue que no ocurrió.

### Comprobar qué se emitió antes de enviarlo

```sh
openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -subject -dates
```

### Ejecutar un script propio

```sh
/opt/scripts/deploy.sh
```

Montado en el contenedor y escrito para lo que el contenedor tiene. Usa un script siempre que necesites `;` o `&&` — el campo command rechaza ambos, y el script es, de todos modos, donde debe estar esa lógica.

### Actuar solo sobre algunos certificados

Etiqueta un certificado (`PATCH /api/certificates/<domain>` con `tags`, o **Edit** en su panel de detalles) y un único hook global puede decidir, certificado por certificado, si actuar. `CERTMATE_TAGS` está siempre definida, separada por comas y en minúsculas, y una etiqueta solo contiene letras, dígitos y `. _ - : /`, así que es seguro usarla sin comillas. En tu script:

```sh
echo ",$CERTMATE_TAGS," | grep -q ',loadbalancer,' || exit 0
```

Las comas de los extremos son lo que hace exacta la coincidencia: sin ellas, `loadbalancer` también coincidiría con una etiqueta llamada `loadbalancer-old`.

### Omitir el trabajo real durante una ejecución de Test

En tu script (la variable solo la define el **Test** por hook):

```sh
[ -n "${CERTMATE_DRY_RUN:-}" ] && { echo "dry run, skipping"; exit 0; }
```

---

## Auditoría, historial y depuración

### Feed de actividad

`GET /api/deploy/history?limit=50` y la pestaña **Activity** de la UI muestran las últimas N ejecuciones de hooks con: nombre del hook, dominio, evento, código de salida, duración, stdout/stderr (truncados a 4096 bytes cada uno) y marca de tiempo.

### Consola de depuración

Ajustes → Deploy Hooks dispone de una consola de depuración (botón de alternancia en la esquina inferior derecha) que muestra en tiempo real los eventos `loadConfig` / `saveConfig` / `testHook` en el lado del cliente. Útil para iterar sobre la UI.

### Registro de auditoría

Cada ejecución de un hook escribe una entrada `operation: deploy_hook` en el registro de auditoría con el estado `success`/`failure` más el nombre del hook, el código de salida y la duración. Visible en la pestaña Activity y en `/api/audit`.

### Fallos comunes

| Síntoma | Causa probable |
|---|---|
| `Hook <id> is no longer in settings...` | El ID del hook en la solicitud de prueba no coincide con ningún hook de la configuración guardada: la página está desactualizada, el hook acaba de eliminarse o su comando se rechazó al guardar. Recarga la página. |
| `Command blocked at runtime` | Uno de los [patrones bloqueados](#patrones-shell-bloqueados) pasó el guardado. Mueve la lógica problemática a un archivo script. |
| `exit code 127` | Comando no encontrado dentro del contenedor (p. ej., `nginx` no está en `$PATH`). Usa rutas absolutas o instala el binario en la imagen. |
| `timeout after 30s` | El hook tardó más que su `timeout`. Auméntalo (máximo 300 s) o mueve el trabajo a un script en segundo plano. |
| `Deploy hooks are disabled. Enable them in Settings → Deploy.` | `deploy_hooks.enabled` es `false` y ejecutaste todos los hooks de un dominio. Activa el interruptor principal en Ajustes. |
| `No enabled hooks or deploy targets configured for <domain>...` | Se intentan ejecutar los hooks de un dominio sin ningún hook global habilitado, sin ninguna entrada habilitada en `domain_hooks[<domain>]` y sin ningún destino tipado para él. Añade un hook (o llama a `/api/deploy/test/<id>` para uno específico). |

---

## Destinos de despliegue tipados

Un **destino de despliegue tipado** es una alternativa declarativa a un shell hook para un destino habitual, de modo que no tengas que montar a mano `kubectl` + credenciales. Los destinos viven bajo `deploy_hooks.targets` y se disparan en los mismos puntos del ciclo de vida que los hooks (emisión + cada renovación, y despliegue manual), con el mismo aislamiento de fallos — un destino que falla queda en el log y en la auditoría y lanza la alerta `deploy_hook_failed`, pero nunca bloquea la operación sobre el certificado.

El primer destino tipado es **Kubernetes Secret**: escribe los `fullchain.pem` / `privkey.pem` renovados en un Secret `kubernetes.io/tls` mediante Server-Side Apply (un único create-or-update idempotente).

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "targets": [
      {
        "id": "prod-web-tls",
        "name": "Publish to prod web Secret",
        "type": "kubernetes-secret",
        "enabled": true,
        "on_events": ["created", "renewed"],
        "domains": ["example.com"],          // vacío/omitido = todos los dominios gestionados
        "config": {
          "secret_name": "example-tls",
          "namespace": "web",
          // Opción A — hablar directamente con el API server:
          "api_server": "https://10.0.0.1:6443",
          "token": "<service-account bearer token>",
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",  // opcional; si no, las CA del sistema
          "verify_ssl": true
          // Opción B — ejecutándose dentro del clúster: establece "in_cluster": true en su lugar,
          // y el API server, el token, la CA y el namespace por defecto se leen de la
          // service account montada.
        }
      }
    ]
  }
}
```

Configúralo mediante `POST /api/deploy/config` (el mismo endpoint solo para admin que el de los shell hooks). El token de la service account que se use debe tener un alcance limitado a `patch`/`create` sobre Secrets en el namespace de destino.

> **Seguridad:** la configuración de despliegue es solo para admin y — como un secreto incrustado en un shell hook — el `token` de Kubernetes se guarda en los ajustes y se devuelve a los admins en `GET /api/deploy/config`. Mantén el alcance del token al mínimo.

Un destino envía la clave privada a la dirección con la que está configurado, así que se respetan dos cosas:

- **No se siguen las redirecciones.** Una redirección repetiría la petición, clave incluida, en cualquier dirección que indique la respuesta. Un `3xx` del API server se notifica como un fallo que lo dice (sin la dirección que indicaba); apunta `api_server` a la dirección que responde directamente.
- **Lo que vuelve nunca se copia en los registros.** La respuesta a una petición fallida se muestra al operador, y también acaba en el registro de auditoría, en el historial de despliegues y en la alerta de fallo. El registro de auditoría es una cadena de hash y no se puede editar después, así que a la respuesta se le quitan el bearer token y la clave (como PEM, escapada en JSON, en base64, codificada en URL, o una línea de ella) antes de acortarla y guardarla.

`verify_ssl: false` se sigue aceptando para un clúster con un certificado que no puedes verificar. Desactiva la comprobación de que el servidor es el que configuraste, así que úsalo solo en una red que controles.

### Destino webhook: entregar el certificado y, opcionalmente, la clave

Un **webhook de notificación** (Ajustes → Notificaciones) *anuncia* una renovación, y lo que comunica llega a alertas, correo y logs. Nunca lleva la clave privada ([webhooks.md](../webhooks.md)). El **destino webhook** *entrega*: envía el certificado y la cadena y, si la plantilla lo pide, la clave privada, a un endpoint HTTPS que tú elegiste, normalmente un appliance o un servicio con una API de subida. Son cosas distintas con reglas distintas, así que este es un destino de despliegue y no otro placeholder del webhook de notificación.

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "targets": [
      {
        "id": "lb-cert",
        "name": "Upload to the load balancer",
        "type": "webhook",
        "enabled": true,
        "domains": ["shop.example.com"],      // obligatorio: nunca "todos los dominios" por defecto
        "on_events": ["created", "renewed"],
        "config": {
          "url": "https://lb.internal:8443/api/certificate",
          "method": "POST",                   // POST, PUT o PATCH
          "payload_template": "{\"name\": \"{{domain}}\", \"cert\": \"{{fullchain}}\", \"key\": \"{{privkey_pkcs8}}\"}",
          "auth_type": "bearer", "auth_token": "<token>",   // none | bearer | basic | header
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",     // o "pin_sha256": "<fingerprint>"
          "allow_internal": true,             // el destino está en una red privada
          "acknowledge_key_delivery_to": "lb.internal"      // necesario porque la plantilla nombra la clave
        }
      }
    ]
  }
}
```

**En la UI.** Ajustes → Deploy → **Deploy Targets** lista todos los destinos y edita los de tipo webhook: nombre, dominios (obligatorio), eventos, URL, método, autenticación, secreto de firma, cómo se verifica el servidor, un interruptor de red privada, timeout e intentos, y el payload con las variables como botones. Las variables de clave están en rojo, y añadir una es lo que activa la confirmación descrita más abajo. **Preview what would be sent** llama al endpoint de vista previa descrito más abajo y muestra la dirección de destino con su puerto, cómo se verifica el servidor, los archivos que lee una entrega, las cabeceras (con las credenciales enmascaradas) y el cuerpo renderizado con un certificado y una clave de ejemplo. Una vista previa desaparece en cuanto cambia el formulario, así que lo que hay en pantalla es siempre lo que se guardaría.

Si el payload nombra una variable de clave privada, el formulario muestra un recuadro rojo con el host de destino y mantiene **Save target** desactivado hasta que hayas escrito ese host. A un destino ya confirmado para su host no se le vuelve a preguntar cuando lo renombras o cambias sus dominios; un host distinto vuelve a preguntar e indica para qué host se había confirmado. Guardar escribe solo `targets`, a partir de la lista que tiene el servidor en ese momento con solo este destino cambiado, de modo que no puede sobrescribir una edición hecha mediante la API entre medias, y deja los demás tipos de destino (secrets de Kubernetes) exactamente como están. Allí aparecen en la lista, y se editan mediante la API. La página nunca envía un consentimiento: lo escribe el servidor.

**Variables de plantilla.** El payload es JSON que escribes tú. Un placeholder dentro de una cadena se inserta escapado, de modo que un PEM (que tiene saltos de línea) no puede romper el JSON.

| Variable | Qué es |
|---|---|
| `{{cert}}`, `{{fullchain}}`, `{{chain}}` | el certificado, el certificado con su cadena, la cadena sola (PEM) |
| `{{privkey_pkcs8}}` | la clave privada como PKCS#8 (`BEGIN PRIVATE KEY`) |
| `{{privkey_traditional}}` | la clave privada como PKCS#1 para RSA (`BEGIN RSA PRIVATE KEY`) o SEC1 para EC (`BEGIN EC PRIVATE KEY`). Un tipo de clave sin esa forma, como Ed25519, se rechaza con un mensaje, no se sustituye en silencio |
| `{{event}}`, `{{domain}}`, `{{timestamp}}`, `{{certificate_sha256}}` | el evento, el nombre del certificado, la hora y el SHA-256 del certificado hoja |

No hay un `privkey` a secas: las dos grafías hacen visible la elección, y una errata en un nombre se rechaza al guardar en lugar de no enviar nada en silencio. Un nombre que no está en esta tabla se rechaza.

**Enviar la clave es una decisión sobre un destino.** Si la plantilla nombra una variable de clave privada, el guardado debe llevar `config.acknowledge_key_delivery_to` con el valor del host de `url`. El servidor registra entonces quién lo confirmó y cuándo (`delivery_consent`, devuelto por `GET /api/deploy/config`); nunca se lee de lo que envías. Si después cambias el host, la confirmación deja de aplicarse: el destino se niega a enviar hasta que se vuelva a dar, y un guardado sin ella se rechaza. Cada confirmación queda en el registro de auditoría.

**Cómo se verifica el servidor.** Siempre. Por defecto, contra el almacén del sistema. Con `ca_cert`, solo contra esa CA (sustituye al almacén del sistema). Con `pin_sha256`, contra la huella SHA-256 exacta del propio certificado del servidor, para un appliance que se firma a sí mismo: indica la huella (se admiten los dos puntos), no el certificado. No hay ningún ajuste que desactive la verificación, y la URL debe ser `https://`.

**Adónde puede enviar.** El host se resuelve una vez, se comprueba cada dirección, y la conexión va a esa dirección. Una dirección de loopback, link-local o de metadatos de la nube nunca es un destino. Un destino en una red privada necesita `allow_internal: true` **en este destino**, lo cual es deliberado y más acotado que un interruptor para toda la instancia. No se siguen las redirecciones: un `3xx` es un fallo que lo dice.

**Qué hace cuando algo va mal.** Un error de red, o un estado `408`, `425`, `429`, `500`, `502`, `503` o `504`, se reintenta con backoff hasta `attempts` (3 por defecto, como máximo 5). Cualquier otro estado no: un `4xx` dice que la petición es incorrecta, y volver a enviar una clave para que te lo vuelvan a decir no ayuda a nadie. Cada entrega lleva una `Idempotency-Key` que es la misma para los reintentos de una entrega y para el mismo certificado enviado de nuevo, y distinta para el siguiente certificado, de modo que un receptor puede distinguir una repetición de una entrega nueva. Con `signing_secret` el cuerpo se firma en `X-CertMate-Signature`, como en el webhook de notificación.

**Qué se registra y qué no.** Un resultado es un estado y una frase que nombra el host: nunca la dirección, la query, las cabeceras, el cuerpo que enviaste ni el cuerpo con el que respondió el receptor, que puede repetir lo que se le envió. Una entrega que llevaba la clave privada queda marcada en el registro de auditoría: adónde fue (`key_sent_to`), para qué dominio, la huella del certificado, el estado y los intentos, y nunca la clave. Un reset después del handshake TLS se registra como posiblemente enviado, porque no se puede distinguir de uno anterior al handshake.

**No hay "enviar una prueba" para un destino que envía la clave**, a propósito. Una prueba que entregara una clave a un appliance que acepta subidas la instalaría en lugar de la real. Usa en su lugar la **vista previa** ([`POST /api/deploy/targets/preview`](./api.md)): renderiza la petición contra un certificado y una clave de ejemplo, no lee ningún archivo y no envía nada. Para entregar de verdad una vez, usa [*Ejecutar todos los hooks de un dominio*](#ejecutar-todos-los-hooks-de-un-dominio-admin) (admin), que es una acción explícita.

**Contra qué protege y contra qué no.**

| Protege contra | No protege contra |
|---|---|
| Que la clave vaya a un host que no confirmaste, también después de editar la URL | Un receptor comprometido o que registra lo que se le envía: tiene la clave en cuanto la recibe. Algunas plataformas de automatización guardan cada cuerpo de petición en un historial de ejecuciones; no apuntes a una de ellas un destino que lleve la clave |
| Que una redirección, una respuesta DNS de rebinding o una dirección de metadatos lleven la petición a otro sitio | Un administrador: cualquiera que pueda guardar esta configuración ya puede escribir un [shell hook](#enviar-la-clave-privada-desde-un-hook) que envíe la clave, sin ninguna de las comprobaciones anteriores |
| Enviar por HTTP plano, o a un servidor que nadie ha verificado | Mantener la clave fuera de las copias de seguridad y los logs del propio receptor |
| Que la respuesta del receptor lleve la clave al registro de auditoría | |
| | Las credenciales del propio destino: `auth_token`, `auth_password` y `signing_secret` se guardan en `settings.json` (modo `0600`) y `GET /api/deploy/config` las devuelve a un administrador, exactamente igual que el token de un destino Kubernetes. El formulario las muestra como campos de contraseña. Dale al receptor un token que solo pueda hacer esto |

No incluido en esta versión: un bundle como subida de archivo o PKCS#12, y cabeceras de petición personalizadas distintas de la de autenticación. Di qué necesita un receptor.

#### Recibirlo en n8n

Comprobado con n8n 2.41.4 con un certificado real, un nodo Webhook y el payload de abajo; los tres pasos son lo que hubo que hacer, no lo que es cierto en general de n8n.

```json
{"domain": "{{domain}}", "event": "{{event}}",
 "certificates": {"cert": "{{cert}}", "key": "{{privkey_pkcs8}}", "rsa_key": "{{privkey_traditional}}",
                  "fullchain": "{{fullchain}}", "intermediate": "{{chain}}"}}
```

1. **n8n tiene que responder por HTTPS.** Un n8n por defecto escucha en HTTP plano, y un destino lo rechaza (`url must be https://`). Pon delante un terminador TLS, o dale a n8n un certificado propio con `N8N_PROTOCOL=https`, `N8N_SSL_KEY=/path/key.pem` y `N8N_SSL_CERT=/path/cert.pem`. Para un certificado que n8n firmó él mismo, establece `pin_sha256` en el destino con su huella: solo los dígitos, no la etiqueta. El comando `openssl x509 -in cert.pem -noout -fingerprint -sha256` imprime `SHA256 Fingerprint=AA:BB:...`; pega lo que sigue al `=`, porque el campo rechaza la etiqueta. Si n8n está en una dirección privada, establece también `allow_internal: true` en el destino.
2. **El nodo Webhook:** HTTP Method `POST`, un Path como `certmate`, Respond *Immediately*, y publica el workflow. El destino debe llamar a la URL de **producción** (`https://host:5678/webhook/certmate`), no a la de prueba.
3. **Qué recibe el nodo.** `$json.body` es el payload que escribiste, así que el ejemplo de arriba da `{{ $json.body.certificates.fullchain }}` y así sucesivamente, como una cadena PEM multilínea normal. Las cabeceras están en `$json.headers`: `x-certmate-event`, `idempotency-key` (la misma para un reintento de una entrega, de modo que un workflow puede ignorar una repetición) y `user-agent: CertMate-Deploy/1`. En la comprobación, cada certificado llegó idéntico al archivo, la clave PKCS#8 idéntica a `privkey.pem`, y la clave en la forma tradicional (`RSA PRIVATE KEY` o `EC PRIVATE KEY`) era la clave del certificado, tanto para un certificado RSA como para uno EC.

**n8n guarda lo que recibe.** Con su configuración por defecto, n8n almacenó cada cuerpo de petición en su propia base de datos, y en la comprobación la clave privada se podía leer de esos datos de ejecución. Trata la base de datos de n8n y sus copias de seguridad como si contuvieran la clave, o deja las variables de clave fuera de un destino n8n y obtén la clave de otra forma. Configurar el workflow para que no guarde las ejecuciones **no** se comportó como se esperaba en la misma comprobación (las ejecuciones se quedaron en estado `running` con sus datos), así que no confíes en ese ajuste sin mirar lo que guarda tu propia instancia. Este es el caso al que se refiere la tabla de arriba con "algunas plataformas de automatización guardan cada cuerpo de petición en un historial de ejecuciones".

---

## Ver también

- [`modules/core/deployer.py`](../../modules/core/deployer.py) — implementación
- [`modules/core/deploy_targets.py`](../../modules/core/deploy_targets.py) — destinos de despliegue tipados
- [`modules/web/settings_routes.py`](../../modules/web/settings_routes.py) — endpoints `/api/deploy/*`
- [`templates/partials/settings_deploy.html`](../../templates/partials/settings_deploy.html) — partial de UI
- [`static/js/settings-deploy.js`](../../static/js/settings-deploy.js) — componente Alpine
