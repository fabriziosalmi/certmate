# Construcción y despliegue con Docker

<!-- CERTMATE-TRANSLATED-FROM b3c7a928998dc93e -->

Esta guía cubre la construcción, el despliegue y la ejecución de CertMate en Docker — incluyendo soporte multiplataforma para ARM y AMD64.

---

## En producción con Docker Compose

La forma más corta de ejecutar CertMate en producción: un solo archivo, la imagen publicada, nada que compilar y ningún repositorio que clonar.

```bash
mkdir certmate && cd certmate
curl -fsSLO https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/docker-compose.yml
printf 'API_BEARER_TOKEN=%s\nSECRET_KEY=%s\nCERTMATE_BACKUP_PASSPHRASE=%s\n' \
  "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" "$(openssl rand -hex 32)" > .env
chmod 600 .env
docker compose up -d
```

Abre `http://127.0.0.1:8000`. La primera página crea la cuenta de administrador y pide el `API_BEARER_TOKEN` del archivo `.env` para autorizarla. Conserva `.env`: contiene el token que usan los clientes de la API, la clave que firma las sesiones y la frase de contraseña sin la cual una copia de seguridad no puede restaurar esta instancia.

Qué hace el archivo:

- **Fija la imagen** de la última versión. La copia en `main` se actualiza con cada versión. Para quedarte en una versión, define `CERTMATE_VERSION=X.Y.Z` en `.env`.
- **Guarda todo en volúmenes con nombre** (`certificates`, `data`, `logs`, `backups`). Docker los crea con la propiedad que CertMate necesita, así que no hay que hacer ningún `chown`. `docker compose down` los conserva; `down -v` los elimina.
- **Escucha solo en 127.0.0.1.** Para el acceso remoto, pon un proxy inverso delante y define `BEHIND_PROXY=true`. Definir `CERTMATE_BIND=0.0.0.0` lo publica en todas las interfaces. `CERTMATE_PORT` cambia el puerto del host.
- **Se niega a arrancar sin `API_BEARER_TOKEN` y `SECRET_KEY`**, en lugar de generar valores que cambiarían cada vez que se recrea el contenedor.

Variables opcionales para `.env`: `CLOUDFLARE_TOKEN` (crea una cuenta DNS de Cloudflare en el primer arranque), `LETSENCRYPT_EMAIL`, `BEHIND_PROXY`.

**Actualización:** descarga de nuevo el archivo (o cambia `CERTMATE_VERSION`) y luego ejecuta `docker compose pull && docker compose up -d`.

El `docker-compose.yml` en la raíz del repositorio construye la imagen desde el código fuente y está pensado para el desarrollo.

---

## Portainer

En Portainer, despliega el [paquete compose de producción](#en-producción-con-docker-compose) como stack directamente desde este repositorio:

1. **Stacks → Add stack**, llámalo `certmate` y elige **Repository**.
2. URL del repositorio `https://github.com/fabriziosalmi/certmate`, referencia `refs/heads/main`, ruta del compose `deploy/docker-compose.yml`.
3. En **Environment variables** añade `API_BEARER_TOKEN`, `SECRET_KEY` y `CERTMATE_BACKUP_PASSPHRASE`, cada uno con un valor aleatorio largo, como la salida de `openssl rand -hex 32`. Opcionalmente, añade `CERTMATE_PORT`, `CERTMATE_BIND` o `CLOUDFLARE_TOKEN`.
4. **Deploy the stack.**

Sin las dos variables obligatorias el despliegue falla e indica cuál falta (`required variable API_BEARER_TOKEN is missing a value`), en lugar de arrancar con claves que cambiarían en cada redespliegue. Para actualizar, usa **Pull and redeploy** en el stack: los volúmenes con nombre, y con ellos los certificados y los ajustes, se conservan.

Verificado en Portainer CE 2.45: un stack sin las variables se rechaza con ese mensaje; con ellas arranca sano, el token autoriza la API, y un pull and redeploy recrea el contenedor con los datos intactos.

---

## Inicio rápido

### Pull y ejecución

Las imágenes se publican en Docker Hub como `fabriziosalmi/certmate`. Las versiones posteriores a v2.42.0 también se publican, con las mismas etiquetas, en GHCR como `ghcr.io/fabriziosalmi/certmate`, lo que evita los límites de descarga anónima de Docker Hub: usa cualquiera de los dos nombres a continuación.

```bash
# Docker selecciona automáticamente la arquitectura correcta
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_data:/app/data \
  -v certmate_certificates:/app/certificates \
  fabriziosalmi/certmate:latest
```

### Construcción y ejecución local

```bash
docker build -t certmate:latest .
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  -v certmate_logs:/app/logs \
  certmate:latest
```

---

## Seguridad

El proceso de construcción garantiza que no se incluya ningún secreto en la imagen:

- `.dockerignore` excluye todos los archivos `.env` y los datos sensibles
- Las variables de entorno se proporcionan en **tiempo de ejecución**, no en tiempo de construcción
- Solo se incluyen los archivos de aplicación esenciales
- Las imágenes pueden publicarse de forma segura en registros públicos

### Verificar la ausencia de secretos en la imagen

```bash
docker history certmate:latest
docker inspect certmate:latest | grep -i env
docker run --rm certmate:latest find / -name "*.env" 2>/dev/null
```

---

## Configuración en tiempo de ejecución

### Opción 1: Archivo de entorno

Crea un archivo `.env` en tu host (no dentro de la imagen Docker):

```bash
SECRET_KEY=your-super-secret-key-here
# SECRET_KEY_FILE=/run/secrets/secret_key  # Alternative: takes precedence over SECRET_KEY
# Define API_BEARER_TOKEN antes de exponer en una red una instancia aún sin
# configurar: hasta que exista el primer admin, una instancia sin token ofrece la
# configuración inicial sin autenticación a cualquiera que pueda alcanzarla. Si está
# definido, pégalo una vez en la pantalla de primer inicio para crear el admin.
API_BEARER_TOKEN=your-api-bearer-token-here
# API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token  # Alternative: takes precedence over API_BEARER_TOKEN
CLOUDFLARE_TOKEN=your-cloudflare-api-token
CERTMATE_LOG_LEVEL=INFO
```

```bash
docker run -d --name certmate \
  --env-file .env \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  -v certmate_logs:/app/logs \
  certmate:latest
```

### Opción 2: Variables de entorno directas

```bash
docker run -d --name certmate \
  -e SECRET_KEY="your-secret-key" \
  # -e SECRET_KEY_FILE="/run/secrets/secret_key" \  # Alternative: takes precedence over SECRET_KEY
  -e API_BEARER_TOKEN="your-api-bearer-token" \
  # -e API_BEARER_TOKEN_FILE="/run/secrets/api_bearer_token" \  # Alternative: takes precedence over API_BEARER_TOKEN
  -e CLOUDFLARE_TOKEN="your-api-token" \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  certmate:latest
```

### Referencia de variables de entorno

| Variable | Requerida | Descripción |
|----------|-----------|-------------|
| `SECRET_KEY` | No | Clave secreta de Flask para las sesiones (se genera automáticamente si no se define) |
| `SECRET_KEY_FILE` | No | Ruta a un archivo que contiene la clave secreta de Flask (tiene prioridad sobre `SECRET_KEY`). Si está definida y el archivo no se puede leer o está vacío, CertMate se niega a arrancar: un secreto que no se ha podido montar es un error de configuración, y generar una clave en su lugar cerraría la sesión de todos los usuarios, en cada reinicio, con sesiones firmadas por una clave que no has elegido tú. |
| `API_BEARER_TOKEN` | No (autogenerado) | Token de autenticación de la API. Se genera automáticamente si no se define, pero defínelo antes de exponer en red una instancia aún sin configurar; cuando está definido, pégalo una vez en la pantalla de primer inicio para crear el admin. **Este valor es el que manda:** si difiere del token ya almacenado, el almacenado se reemplaza al arrancar y deja de funcionar. Eso es lo que hace que añadir o rotar la variable en una instalación existente surta efecto — antes, la exigencia del token se basaba en este valor mientras la autenticación seguía comprobando el antiguo, y la pantalla de primer inicio pedía un token que luego rechazaba |
| `API_BEARER_TOKEN_FILE` | No | Ruta a un archivo que contiene el bearer token de la API (tiene prioridad sobre `API_BEARER_TOKEN`) |
| `CERTMATE_LOG_LEVEL` | No | `INFO` (por defecto), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | **Defínela si quieres copias de seguridad automáticas desde las que poder restaurar** | Cifra en reposo las copias de seguridad unificadas (`.zip.enc`, PBKDF2-SHA256 + Fernet), y es lo que hace que las copias automáticas sean *completas* — con ella pueden restaurar esta instancia, sin ella mantienen sus credenciales enmascaradas y no pueden. Se requiere la misma frase de contraseña para restaurarlas, y CertMate nunca la guarda por ti. Guárdala en un lugar distinto de la máquina que contiene las copias de seguridad |
| `CLOUDFLARE_TOKEN` | No | Token de API de la cuenta DNS predeterminada de Cloudflare. Route53 normalmente utiliza las credenciales configuradas en Ajustes → Proveedores DNS, pero cuando su cuenta selecciona explícitamente `auth_mode: iam_role`, Certbot utiliza la cadena de credenciales AWS del contenedor (incluidos los roles IAM). |

Consulta la [Guía de instalación](./installation.md#variables-de-entorno) para ver la lista completa.

### Mantener los tokens DNS fuera de `settings.json`

Los tokens de los proveedores DNS configurados desde la interfaz se guardan en
`settings.json`, que es el archivo que se respalda, se copia y se monta. En su
lugar, cualquier campo de credencial puede **indicar** dónde vive su valor:
`api_token_file` con una ruta, o `api_token_env` con el nombre de una variable,
del mismo modo que funciona `API_BEARER_TOKEN_FILE`. El valor se lee cuando se
ejecuta certbot y nunca se vuelve a escribir. El `client_secret` de OIDC acepta
el mismo par. Consulta
[SECURITY.md](https://github.com/fabriziosalmi/certmate/blob/main/SECURITY.md#keeping-credentials-out-of-settingsjson).

---

## Docker Compose

### Configuración básica

```yaml
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    container_name: certmate
    ports:
      - "127.0.0.1:8000:8000"  # solo localhost; pon un proxy inverso delante para el acceso externo
    environment:
      - SECRET_KEY=${SECRET_KEY:-}
      # - SECRET_KEY_FILE=${SECRET_KEY_FILE:-}  # Alternative: path to a file containing the secret key
      - API_BEARER_TOKEN=${API_BEARER_TOKEN:-}
      # - API_BEARER_TOKEN_FILE=${API_BEARER_TOKEN_FILE:-}  # Alternative: path to a file containing the bearer token
      - CERTMATE_LOG_LEVEL=${CERTMATE_LOG_LEVEL:-INFO}
    volumes:
      - certmate_certificates:/app/certificates
      - certmate_data:/app/data
      - certmate_logs:/app/logs
      - certmate_backups:/app/backups
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  certmate_certificates:
  certmate_data:
  certmate_logs:
  certmate_backups:
```

```bash
# Iniciar con el archivo .env en el mismo directorio
docker compose up -d

# O especificar un archivo de entorno diferente
docker compose --env-file /path/to/.env up -d
```

---

## Podman (Quadlet, rootless) y OpenShift

### Quadlet: CertMate como servicio systemd

[`deploy/podman/certmate.container`](../../deploy/podman/certmate.container) es una unidad Quadlet: Podman la convierte en un servicio systemd. Ejecuta la imagen publicada con volúmenes con nombre, el puerto solo en loopback, los secretos como secretos de Podman, un healthcheck y soporte para `podman auto-update`.

En rootless, con tu propio usuario:

```bash
# Los tres secretos, creados una vez. Nunca aparecen en un archivo.
for s in certmate-api-token certmate-secret-key certmate-backup-passphrase; do
  openssl rand -hex 32 | tr -d '\n' | podman secret create "$s" -
done

mkdir -p ~/.config/containers/systemd
curl -fsSL -o ~/.config/containers/systemd/certmate.container \
  https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/podman/certmate.container
systemctl --user daemon-reload
systemctl --user start certmate

# Mantenerlo en marcha sin una sesión iniciada, e iniciarlo al arrancar.
sudo loginctl enable-linger "$USER"
```

En rootful, en cambio: coloca el archivo en `/etc/containers/systemd/`, crea los secretos como root y luego ejecuta `sudo systemctl daemon-reload && sudo systemctl start certmate`.

Abre `http://127.0.0.1:8000`. La primera página crea la cuenta de administrador y pide el token de la API: `podman secret inspect --showsecret certmate-api-token --format '{{.SecretData}}'`.

Verificado en Fedora 44 con Podman 5.8, rootful y rootless: el servicio arranca sano, el token autoriza la API y vuelve tras un reinicio (en rootless mediante lingering).

### UID arbitrarios (Podman rootless, OpenShift)

La imagen se ejecuta por defecto como el usuario no root `1000`, pero también sigue el patrón de **UID arbitrario** de OpenShift: los directorios en los que se escribe en tiempo de ejecución (`/app/data`, `/app/certificates`, `/app/logs`, `/app/backups`) pertenecen al **grupo 0 (grupo root)** y tienen escritura para el grupo + setgid. Un proceso del contenedor que se ejecute con *cualquier* UID perteneciente al grupo 0 — que es como Podman rootless y OpenShift lanzan los contenedores — puede por tanto crear y renombrar archivos sin un `chown -R 1000:1000` manual de los volúmenes. Los archivos secretos que escribe la aplicación (la clave privada de la CA, la clave de firma de auditoría, los archivos de credenciales DNS, `.secret_key`) se crean siempre con `0600`, solo para el propietario, así que los directorios con escritura para el grupo nunca exponen una clave. (Incidencia [#380](https://github.com/fabriziosalmi/certmate/issues/380).)

### Volúmenes con nombre

Un **volumen con nombre** nuevo hereda los permisos de grupo 0 de la imagen con Podman rootful y con Docker. Con Podman **rootless** no siempre: medido en Podman 5.8, la raíz del volumen `backups`, cuyo directorio en la imagen no está vacío, siguió siendo propiedad de root, y CertMate se negó a arrancar con *"Required directories are not writable"*. Añade `:U`, que entrega cada volumen al usuario del contenedor:

```bash
podman run -d --name certmate \
  -p 127.0.0.1:8000:8000 \
  -v certmate_data:/app/data:U \
  -v certmate_certificates:/app/certificates:U \
  -v certmate_logs:/app/logs:U \
  -v certmate_backups:/app/backups:U \
  docker.io/fabriziosalmi/certmate:latest
```

### Bind mounts (directorios del host)

Un bind mount conserva la propiedad del directorio del **host**, que oculta los permisos de la imagen. Da una vez permiso de escritura al grupo 0 sobre los directorios del host y luego ejecuta:

```bash
# Crear los directorios del host con escritura para el grupo 0 (cualquier UID del grupo 0 puede escribir)
mkdir -p ./{data,certificates,logs,backups}
chgrp -R 0 ./{data,certificates,logs,backups}
chmod -R g+rwX ./{data,certificates,logs,backups}

podman run -d --name certmate \
  -p 8000:8000 \
  -v ./data:/app/data \
  -v ./certificates:/app/certificates \
  -v ./logs:/app/logs \
  -v ./backups:/app/backups \
  docker.io/fabriziosalmi/certmate:latest
```

Como alternativa, deja que podman corrija la propiedad por ti con la opción de montaje `:U` (hace un chown recursivo del origen para que coincida con el UID/GID del contenedor):

```bash
podman run -d --name certmate \
  -p 8000:8000 \
  -v ./data:/app/data:U \
  -v ./certificates:/app/certificates:U \
  -v ./logs:/app/logs:U \
  -v ./backups:/app/backups:U \
  docker.io/fabriziosalmi/certmate:latest
```

### podman-compose rootless

```yaml
services:
  certmate:
    image: docker.io/fabriziosalmi/certmate:latest
    ports:
      - "8000:8000"
    volumes:
      - certmate_data:/app/data:U
      - certmate_certificates:/app/certificates:U
      - certmate_logs:/app/logs:U
      - certmate_backups:/app/backups:U
    restart: unless-stopped

volumes:
  certmate_data:
  certmate_certificates:
  certmate_logs:
  certmate_backups:
```

Si el arranque se interrumpe con *"Required directories are not writable by the CertMate
process"*, el montaje no tiene permiso de escritura para el usuario del contenedor — añade `:U` al
volumen o, para un bind mount, aplica el `chgrp 0 … && chmod g+rwX …` de arriba.

> **Kubernetes / OpenShift:** no hace falta ningún cambio. Define
> `spec.securityContext.fsGroup: 0` (o confía en la SCC restringida por defecto,
> que ya asigna un UID arbitrario en el grupo 0) y los volúmenes montados
> pasan a tener escritura para el grupo 0 automáticamente.

---

## Actualización

CertMate guarda su estado persistente en `/app/data` (`settings.json`, los usuarios
admin, la `.secret_key` autogenerada, la clave de firma de auditoría y la base de datos
del planificador) y `/app/certificates`. Ese estado sobrevive a una actualización
porque esas rutas se montan desde fuera del contenedor, como en todos los ejemplos
de esta página, y **no** se guardan en la imagen: actualizar consiste en descargar una
imagen más reciente y recrear el contenedor con los mismos montajes, y tu configuración,
tus certificados y tu inicio de sesión se conservan.

Las copias de seguridad se escriben en `/app/backups`. La sección Inicio rápido de arriba
no lo monta, así que una copia hecha ahí se pierde con el contenedor cuando este se
elimina: descárgala antes, o monta también `/app/backups`, como hace el ejemplo de abajo.

```bash
# Recomendado: haz antes una copia de seguridad (Ajustes → Backup, o la API)

# Docker Compose
docker compose pull          # descarga la nueva imagen
docker compose up -d         # recrea el contenedor (data/ + certificates/ persisten)

# docker run simple: detener/eliminar y volver a ejecutar con los MISMOS montajes
# con los que lo iniciaste. Son los volúmenes con nombre del Inicio rápido, más uno
# para las copias de seguridad; si lo iniciaste con bind mounts, usa tus rutas del host.
docker pull fabriziosalmi/certmate:latest
docker rm -f certmate
docker run -d --name certmate --env-file .env -p 127.0.0.1:8000:8000 \
  -v certmate_data:/app/data -v certmate_certificates:/app/certificates \
  -v certmate_backups:/app/backups \
  fabriziosalmi/certmate:latest
```

Las migraciones del formato de los ajustes se ejecutan automáticamente al arrancar. En producción,
fija una etiqueta de versión (p. ej. `fabriziosalmi/certmate:2.19`) en lugar de `:latest` para que
una nueva descarga no te sorprenda con una actualización no deseada — la construcción multiplataforma
publica las etiquetas `MAJOR`, `MAJOR.MINOR` y `MAJOR.MINOR.PATCH`.

---

## Construcciones multiplataforma

CertMate soporta imágenes Docker multiplataforma para las arquitecturas ARM y AMD64.

### Arquitecturas soportadas

| Plataforma | Descripción | Casos de uso habituales |
|------------|-------------|-------------------------|
| `linux/amd64` | Intel/AMD 64-bit | La mayoría de servidores cloud, equipos de escritorio |
| `linux/arm64` | ARM 64-bit | Apple Silicon, instancias cloud ARM |
| `linux/arm/v7` | ARM 32-bit v7 | Raspberry Pi 3+ — **no publicada**: se puede construir a demanda (ver más abajo), las imágenes de las versiones son amd64 + arm64 |

### Docker Buildx manual

```bash
# Crear y usar el builder buildx
docker buildx create --name certmate-builder --use

# Construir para múltiples plataformas
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest .

# Construir y publicar
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:latest --push .

# Construir solo para la plataforma actual
docker build -t certmate:latest .

# Etiquetar una versión y publicarla
docker buildx build --platform linux/amd64,linux/arm64 \
  -t USERNAME/certmate:v1.0.0 -t USERNAME/certmate:latest --push .

# Raspberry Pi 3+ (linux/arm/v7, no publicada)
docker buildx build --platform linux/arm/v7 -t USERNAME/certmate:armv7 --push .
```

### Requisitos previos para el modo multiplataforma

```bash
# Verificar el soporte de buildx
docker buildx version
docker buildx inspect --bootstrap

# Activar la emulación QEMU (si es necesario)
docker run --privileged --rm tonistiigi/binfmt --install all
```

### Forzar una plataforma específica

```bash
# Forzar AMD64 (p. ej., en Apple Silicon para pruebas)
docker run --platform linux/amd64 --rm \
  --env-file .env -p 8000:8000 certmate:latest

# Detección automática (recomendado)
docker run --rm --env-file .env -p 8000:8000 certmate:latest
```

---

## Publicar en Docker Hub

```bash
# Iniciar sesión
docker login

# Etiquetar y publicar
docker build -t USERNAME/certmate:latest .
docker push USERNAME/certmate:latest

# Con etiqueta de versión
docker build -t USERNAME/certmate:v1.0.0 .
docker push USERNAME/certmate:v1.0.0
```

---

## Integración CI/CD

### GitHub Actions

Secrets requeridos:
- `DOCKERHUB_USER`
- `DOCKERHUB_TOKEN`

```bash
# Activación manual con plataformas personalizadas
gh workflow run docker-multiplatform.yml \
  -f platforms="linux/amd64,linux/arm64,linux/arm/v7" \
  -f push_to_registry=true
```

---

## Consejos para producción

1. **Usa gestión de secretos**: Docker secrets, Kubernetes secrets o un gestor de secretos
2. **Activa TLS**: Ejecuta detrás de un proxy inverso con terminación TLS
3. **Monitoriza los recursos**: Define límites de CPU y memoria
4. **Haz copias de seguridad de los volúmenes**: Realiza backups periódicos de los volúmenes de certificados y datos
5. **Actualiza con regularidad**: Mantén la imagen actualizada con los parches de seguridad
6. **Usa el caché de capas** para construcciones más rápidas:
   ```bash
   docker buildx build --cache-from type=registry,ref=USERNAME/certmate:cache .
   ```

---

## Resolución de problemas

### El contenedor no arranca

```bash
docker logs certmate
docker exec certmate env
```

### El health check falla

```bash
docker logs certmate
docker exec certmate curl -v http://localhost:8000/health
```

### Problemas de permisos

```bash
docker exec certmate ls -la /app/certificates
docker exec certmate ls -la /app/data
```

### Problemas de construcción multiplataforma

| Error | Solución |
|-------|----------|
| "multiple platforms not supported for docker driver" | `docker buildx create --name multiplatform --use` |
| "exec format error" | `docker run --privileged --rm tonistiigi/binfmt --install all` |
| Construcciones no nativas lentas | Normal debido a la emulación; usa GitHub Actions para producción |
| No se puede cargar la imagen multiplataforma en Docker local | Usa `--load` con una sola plataforma para pruebas locales |

---

## Tamaños de imagen

Tamaños típicos por arquitectura:
- **AMD64**: ~200-300 MB
- **ARM64**: ~200-300 MB
- **ARM v7**: ~180-250 MB

---

<div align="center">

[← Volver a la documentación](./README.md) • [Instalación →](./installation.md) • [Arquitectura →](./architecture.md)

</div>
