# Construcción y despliegue con Docker

Esta guía cubre la construcción, el despliegue y la ejecución de CertMate en Docker — incluyendo soporte multiplataforma para ARM y AMD64.

---

## Inicio rápido

### Pull y ejecución

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
API_BEARER_TOKEN=your-api-bearer-token-here
# API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token  # Alternative: takes precedence over API_BEARER_TOKEN
CLOUDFLARE_API_TOKEN=your-cloudflare-api-token
LOG_LEVEL=INFO
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
  -e CLOUDFLARE_API_TOKEN="your-api-token" \
  -p 8000:8000 \
  -v certmate_certificates:/app/certificates \
  -v certmate_data:/app/data \
  certmate:latest
```

### Referencia de variables de entorno

| Variable | Requerida | Descripción |
|----------|-----------|-------------|
| `SECRET_KEY` | No | Clave secreta de Flask para las sesiones (se genera automáticamente si no se define) |
| `SECRET_KEY_FILE` | No | Ruta a un archivo que contiene la clave secreta de Flask (tiene prioridad sobre `SECRET_KEY`) |
| `API_BEARER_TOKEN` | No (autogenerado) | Token de autenticación de la API. Se genera automáticamente si no se define, pero defínelo antes de exponer en red una instancia aún sin configurar; cuando está definido, pégalo una vez en la pantalla de primer inicio para crear el admin |
| `API_BEARER_TOKEN_FILE` | No | Ruta a un archivo que contiene el bearer token de la API (tiene prioridad sobre `API_BEARER_TOKEN`) |
| `LOG_LEVEL` | No | `INFO` (por defecto), `DEBUG`, `WARNING`, `ERROR` |
| `CERTMATE_BACKUP_PASSPHRASE` | No | Cuando se define, las copias de seguridad unificadas se cifran en reposo (`.zip.enc`, PBKDF2-SHA256 + Fernet). Se requiere la misma frase de contraseña para restaurarlas. Sin definir = copias de seguridad en texto claro `.zip` (comportamiento heredado) |
| `CLOUDFLARE_API_TOKEN` | No | Token del proveedor DNS de Cloudflare |
| `AWS_ACCESS_KEY_ID` | No | Clave de acceso de AWS Route53 |
| `AWS_SECRET_ACCESS_KEY` | No | Clave secreta de AWS Route53 |

Consulta la [Guía de instalación](./installation.md#environment-variables) para ver la lista completa.

---

## Docker Compose

### Configuración básica

```yaml
version: '3.8'

services:
  certmate:
    image: fabriziosalmi/certmate:latest
    container_name: certmate
    ports:
      - "8000:8000"
    environment:
      - SECRET_KEY=${SECRET_KEY:-}
      # - SECRET_KEY_FILE=${SECRET_KEY_FILE:-}  # Alternative: path to a file containing the secret key
      - API_BEARER_TOKEN=${API_BEARER_TOKEN:-}
      # - API_BEARER_TOKEN_FILE=${API_BEARER_TOKEN_FILE:-}  # Alternative: path to a file containing the bearer token
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    volumes:
      - certmate_certificates:/app/certificates
      - certmate_data:/app/data
      - certmate_logs:/app/logs
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
```

```bash
# Iniciar con el archivo .env en el mismo directorio
docker-compose up -d

# O especificar un archivo de entorno diferente
docker-compose --env-file /path/to/.env up -d
```

---

## Construcciones multiplataforma

CertMate soporta imágenes Docker multiplataforma para las arquitecturas ARM y AMD64.

### Arquitecturas soportadas

| Plataforma | Descripción | Casos de uso habituales |
|------------|-------------|-------------------------|
| `linux/amd64` | Intel/AMD 64-bit | La mayoría de servidores cloud, equipos de escritorio |
| `linux/arm64` | ARM 64-bit | Apple Silicon, instancias cloud ARM |
| `linux/arm/v7` | ARM 32-bit v7 | Raspberry Pi 3+ |
| `linux/arm/v6` | ARM 32-bit v6 | Raspberry Pi 1, Zero |

### Scripts de construcción

```bash
# Construir solo para la plataforma actual
./build-docker.sh

# Construir para múltiples plataformas (ARM64 + AMD64)
./build-docker.sh -m

# Construir y publicar en Docker Hub
./build-docker.sh -m -p -r YOUR_DOCKERHUB_USERNAME

# Script dedicado multiplataforma
./build-multiplatform.sh -r USERNAME -v v1.0.0 -p

# Construir para Raspberry Pi
./build-multiplatform.sh --platforms linux/arm/v7 -r USERNAME -p
```

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
- `DOCKERHUB_USERNAME`
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
2. **Activa TLS**: Ejecuta detrás de un reverse proxy con terminación TLS
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
