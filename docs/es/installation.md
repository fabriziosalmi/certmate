# Guía de instalación

Esta guía cubre todos los métodos de instalación y despliegue de CertMate.

---

## Requisitos previos

- Python 3.9 o superior
- pip (gestor de paquetes de Python)
- Docker (opcional, para el despliegue en contenedor)

---

## Método 1: Instalación directa

### 1. Clonar el repositorio

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
```

### 2. Crear el entorno virtual

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# o
.\venv\Scripts\activate   # Windows
```

### 3. Instalar las dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar el entorno

Cree un archivo `.env`:

```bash
cp .env.example .env
# Edite .env con sus ajustes
```

### 5. Iniciar la aplicación

```bash
python app.py
```

---

## Método 2: Instalación con Docker

### Con Docker Compose (recomendado)

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker-compose up -d
```

### Con Docker Build

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker build -t certmate .
docker run -p 8000:8000 --env-file .env -v ./certificates:/app/certificates certmate
```

> Para el despliegue avanzado con Docker, incluyendo builds multiplataforma, consulte la [Guía de Docker](./docker.md).

---

## Dependencias del sistema

### Ubuntu / Debian

```bash
sudo apt update
sudo apt install python3-dev python3-venv build-essential libssl-dev libffi-dev
```

### CentOS / RHEL / Rocky

```bash
sudo yum install python3-devel gcc openssl-devel libffi-devel
```

### macOS

```bash
brew install python3 openssl libffi
```

---

## Configuración del proveedor DNS

Tras la instalación, configure las credenciales de su proveedor DNS. Consulte la [Guía de proveedores DNS](./dns-providers.md) para instrucciones detalladas.

Configuración rápida para los proveedores más habituales:

### Cloudflare

1. Vaya al [Panel de Cloudflare](https://dash.cloudflare.com/profile/api-tokens)
2. Cree un nuevo token de API con permisos `Zone:DNS:Edit`
3. Añada el token en los ajustes de CertMate

### AWS Route53

1. Cree un usuario IAM con permisos de Route53
2. Genere claves de acceso
3. Añada las credenciales en los ajustes de CertMate

### Azure DNS

1. Cree un Service Principal
2. Asigne el rol DNS Zone Contributor
3. Configure los detalles de la suscripción en los ajustes de CertMate

### Google Cloud DNS

1. Cree una cuenta de servicio con el rol DNS Administrator
2. Descargue el archivo de clave JSON
3. Impórtelo en los ajustes de CertMate

---

## Variables de entorno

```bash
# Autenticación de la API (se genera automáticamente si no se define ninguna)
# Opción A: valor directo
API_BEARER_TOKEN=su_token_seguro
# Opción B: ruta a un archivo que contiene el token (tiene precedencia sobre API_BEARER_TOKEN)
API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token

# Clave secreta de sesión de Flask (se genera automáticamente si no se define ninguna)
# Opción A: valor directo
SECRET_KEY=su_clave_secreta_flask
# Opción B: ruta a un archivo que contiene la clave (tiene precedencia sobre SECRET_KEY)
SECRET_KEY_FILE=/run/secrets/secret_key

# Reverse proxy — establezca 'true' cuando CertMate esté detrás de Nginx,
# HAProxy, Traefik, Cloudflare, etc. Sin esto, request.remote_addr
# resuelve a la IP del proxy en cada petición, lo que colapsa la
# limitación de tasa por cliente en un único bucket.
BEHIND_PROXY=true

# Cifrado de backups en reposo (opcional, recomendado).
# Cuando se define, los backups unificados se escriben como archivos
# .zip.enc cifrados (derivación de clave PBKDF2-SHA256 + Fernet/AES)
# en lugar de .zip en texto claro. Los backups incluyen cada clave
# privada de certificado; sin esto, un archivo de backup exfiltrado
# supone un compromiso total de las claves.
CERTMATE_BACKUP_PASSPHRASE=elija-una-frase-de-paso-larga-y-aleatoria

# Proveedores DNS (elija uno o varios)
CLOUDFLARE_TOKEN=su_token_cloudflare
AWS_ACCESS_KEY_ID=su_access_key_aws
AWS_SECRET_ACCESS_KEY=su_secret_key_aws
AZURE_SUBSCRIPTION_ID=su_subscription_azure
AZURE_TENANT_ID=su_tenant_azure
AZURE_CLIENT_ID=su_client_azure
AZURE_CLIENT_SECRET=su_secret_azure
GOOGLE_PROJECT_ID=su_proyecto_gcp
POWERDNS_API_URL=https://su-powerdns:8081
POWERDNS_API_KEY=su_clave_powerdns
```

### Orden de resolución

| Variable | Prioridad |
|----------|-----------|
| `API_BEARER_TOKEN_FILE` | La más alta — si está definida, `API_BEARER_TOKEN` nunca se lee |
| `API_BEARER_TOKEN` | Se usa solo cuando `API_BEARER_TOKEN_FILE` está ausente |
| *(generado)* | Fallback cuando ninguna está definida o el valor no supera la validación |
| `SECRET_KEY_FILE` | La más alta — si está definida, `SECRET_KEY` nunca se lee |
| `SECRET_KEY` | Se usa solo cuando `SECRET_KEY_FILE` está ausente |
| *(generado + persistido)* | Se escribe en `data/.secret_key` para que las sesiones sobrevivan a los reinicios |

> **Consejo para Docker Secrets**: Use `API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token` y `SECRET_KEY_FILE=/run/secrets/secret_key` con Docker Swarm o los secrets de Kubernetes para evitar poner valores sensibles en variables de entorno.

---

## Despliegue en producción

### Detrás de un reverse proxy

Si CertMate está detrás de un reverse proxy (Nginx, HAProxy, Traefik, Cloudflare, Kubernetes Ingress) — que es la forma recomendada de ejecutarlo para la terminación TLS — establezca `BEHIND_PROXY=true` en el entorno del contenedor. Esto activa el middleware `ProxyFix` de Werkzeug para que los siguientes elementos confíen en las cabeceras `X-Forwarded-*` de su proxy:

- `request.remote_addr` resuelve a la IP original del cliente en lugar de la IP del proxy. La limitación de tasa, las entradas del registro de auditoría y las advertencias de "intento de token de API inválido desde X" pasan a ser por cliente en lugar de por proxy.
- El esquema / host / prefijo del proxy se respetan, lo que mantiene la corrección de las URLs generadas y los scopes de las cookies.

```yaml
# Fragmento de docker-compose.yml
services:
  certmate:
    image: fabriziosalmi/certmate:latest
    environment:
      BEHIND_PROXY: "true"
    volumes:
      - ./data:/app/data
```

**Cuándo NO activarlo.** Si expone CertMate directamente a la red sin ningún proxy delante, deje `BEHIND_PROXY` sin definir. Con esta opción activada, cualquiera que pueda alcanzar el listener podría falsificar `X-Forwarded-For` y eludir los límites de tasa por cliente. El proxy es el límite de confianza.

Su proxy debe, por supuesto, reenviar las cabeceras. Ejemplo con Nginx:

```nginx
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

#### Ejemplo: Zion (gateway TLS en Rust + WAF)

[Zion](https://github.com/fabriziosalmi/zion) es un reverse proxy Rust de alto rendimiento con un WAF integrado — una buena opción delante de CertMate cuando se desea terminación TLS 1.3 y filtrado de peticiones en el edge. CertMate permanece en HTTP plano en la red interna; Zion termina el TLS y reenvía.

`zion.toml`:

```toml
[server]
listen_http  = "0.0.0.0:8080"
listen_https = "0.0.0.0:8443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"
key_path  = "/etc/ssl/zion/tls.key"
min_version = "1.3"
alpn = ["h2", "http/1.1"]

[upstream.backend]
url = "http://certmate:8000"

[[route]]
path = "/"
upstream = "backend"

[[route]]
path = "/{*rest}"
upstream = "backend"
```

`docker-compose.yml`:

```yaml
services:
  certmate:
    image: certmate:latest
    environment:
      BEHIND_PROXY: "true"
    expose:
      - "8000"
    volumes:
      - ./data:/app/data

  zion:
    image: zion:latest
    depends_on:
      - certmate
    environment:
      ZION_CONFIG: /etc/zion/zion.toml
    volumes:
      - ./zion.toml:/etc/zion/zion.toml:ro
      - ./certs:/etc/ssl/zion:ro
    ports:
      - "443:8443"
      - "80:8080"
```

Mantenga `BEHIND_PROXY=true` en el servicio CertMate: Zion añade `X-Forwarded-For`, lo que hace que la limitación de tasa por cliente, las entradas de auditoría y las advertencias de fallo de autenticación resuelvan a la IP real del cliente en lugar de la de Zion.

### Usar Gunicorn

```bash
pip install gunicorn
gunicorn --bind 0.0.0.0:8000 --workers 4 --threads 8 app:app
```

### Usar systemd

Cree `/etc/systemd/system/certmate.service`:

```ini
[Unit]
Description=CertMate Gestor de Certificados SSL
After=network.target

[Service]
Type=simple
User=certmate
WorkingDirectory=/opt/certmate
Environment=PATH=/opt/certmate/venv/bin
ExecStart=/opt/certmate/venv/bin/gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

### Backup y restauración

```bash
# Crear un backup
curl -X POST http://localhost:8000/api/backups/create \
  -H "Authorization: Bearer SU_TOKEN_API"

# Listar los backups
curl http://localhost:8000/api/backups \
  -H "Authorization: Bearer SU_TOKEN_API"

# Restaurar un backup
curl -X POST http://localhost:8000/api/backups/restore \
  -H "Authorization: Bearer SU_TOKEN_API" \
  -H "Content-Type: application/json" \
  -d '{"name": "backup_20240101_120000.zip"}'
```

---

## Resolución de problemas

### Conflictos de versiones de plugins DNS

Si encuentra conflictos de versiones, use estas versiones específicas:

```txt
certbot==4.1.1
certbot-dns-cloudflare==4.1.1
certbot-dns-route53==4.1.1
certbot-dns-azure==2.6.1
certbot-dns-google==4.1.1
certbot-dns-powerdns==0.2.1
```

### Comandos de validación

```bash
# Comprobar los plugins de certbot
certbot plugins --text

# Verificar que el servicio está en funcionamiento
curl -X GET http://localhost:8000/api/health
```

### Errores comunes

| Error | Solución |
|-------|----------|
| `ModuleNotFoundError` | Ejecute `pip install -r requirements.txt` |
| `Port already in use` | Cambie el puerto en las variables de entorno |
| `certbot not found` | Instale certbot: `pip install certbot` |
| `Permission denied` | Compruebe los permisos en `/app/data` y `/app/certificates` |
| `Token API inválido` | Verifique `API_BEARER_TOKEN` en su archivo `.env` |

### Modo de depuración

```bash
export FLASK_DEBUG=1
python app.py
```

### Restricción del tráfico saliente (hardening de egress)

CertMate establece conexiones salientes hacia las autoridades de certificación ACME, las APIs de proveedores DNS, el almacenamiento de objetos y los webhooks de notificación a través de HTTP(S), además de SMTP para las notificaciones por email. Puede restringir y auditar el tráfico **HTTP(S)** enrutándolo a través de un **forward proxy** y denegando a CertMate cualquier otra ruta hacia internet.

Los clientes HTTP(S) de CertMate (`requests`, `certbot`, entrega de webhooks vía `urllib`, `boto3`) respetan las variables de entorno estándar `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`, por lo que no se requieren cambios en el código. **SMTP es la excepción:** las notificaciones por email usan `smtplib`, que abre una conexión TCP directa y **no** consulta las variables de proxy HTTP. En una red de egress restringida, permita directamente el `host:port` de su relay SMTP (regla de firewall / NetworkPolicy), o use un canal de notificación webhook en lugar del email.

Ejemplo con [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager), un forward proxy autoalojado basado en Squid con WAF, DNS sinkhole y — desde v3.9.0 — una **lista de permitidos de egress default-deny** integrada (solo los destinos explícitamente aprobados son alcanzables; todo lo demás se deniega):

```yaml
services:
  certmate:
    image: certmate:latest
    environment:
      HTTP_PROXY:  "http://proxy:3128"
      HTTPS_PROXY: "http://proxy:3128"
      NO_PROXY:    "localhost,127.0.0.1"
    networks:
      - egress            # CertMate solo puede alcanzar el proxy en esta red
networks:
  egress:
    internal: true        # sin gateway: CertMate no tiene internet directo
```

Colocar CertMate en una red `internal` (sin gateway) compartida con el proxy hace del proxy su **único** camino hacia el exterior. El tráfico saliente se convierte en un único punto de control auditable: permita los destinos que CertMate realmente necesita (su CA, proveedor DNS, almacenamiento de objetos, endpoints de notificación) y deniegue el resto.

**Kubernetes:** una `NetworkPolicy` de egress default-deny que solo permite tráfico hacia el Service del proxy, más las variables de entorno `HTTP(S)_PROXY` en el Deployment.

**systemd:** `Environment=HTTPS_PROXY=...` en la unidad, más reglas de firewall en el host que restringen el egress al proxy.

### Ubicación de almacenamiento del directorio de datos

CertMate utiliza E/S de archivos bloqueante estándar de Python para todo lo que se encuentra bajo `data/` (ajustes, certificados, registro de auditoría, almacenamiento SQLite del planificador). Se recomienda encarecidamente el disco local.

Si monta `data/` en un sistema de archivos de red (NFS, SMB), tenga en cuenta que:

- Un servidor NFS bloqueado puede detener las lecturas de archivos de Python indefinidamente sin timeout integrado. El worker de renovación, el escritor del registro de auditoría y la sonda /health se bloquearán todos en el mismo punto de montaje.
- El modo journal WAL de SQLite requiere semánticas de bloqueo que NFS no siempre proporciona. CertMate registra una advertencia si tuvo que recurrir a un modo journal más débil; la corrección se preserva, pero la concurrencia disminuye.

Si NFS es inevitable, monte con `soft,timeo=30,retrans=3` (o el equivalente de su distribución) para que las E/S fallen rápidamente en lugar de bloquearse ante un servidor caído.

### Usar Gunicorn

```bash
gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
```

### Usar systemd

Cree `/etc/systemd/system/certmate.service`:

```ini
[Unit]
Description=CertMate Gestor de Certificados SSL
After=network.target

[Service]
Type=simple
User=certmate
WorkingDirectory=/opt/certmate
Environment=PATH=/opt/certmate/venv/bin
ExecStart=/opt/certmate/venv/bin/gunicorn --bind 0.0.0.0:8000 --workers 4 app:app
Restart=always

[Install]
WantedBy=multi-user.target
```

Active e inicie:

```bash
sudo systemctl enable certmate
sudo systemctl start certmate
```

### Usar Docker en producción

```yaml
version: '3.8'
services:
  certmate:
    build: .
    ports:
      - "8000:8000"
    environment:
      - API_BEARER_TOKEN=${API_BEARER_TOKEN}
      - CLOUDFLARE_TOKEN=${CLOUDFLARE_TOKEN}
    volumes:
      - ./certificates:/app/certificates
      - ./data:/app/data
    restart: unless-stopped
```

---

## Resolución de problemas

### Instalación manual de dependencias

Si la instalación automática falla, instale los proveedores DNS individualmente:

```bash
# Núcleo de certbot
pip install certbot==4.1.1

# Cloudflare
pip install certbot-dns-cloudflare==4.1.1

# AWS Route53
pip install certbot-dns-route53==4.1.1 boto3==1.35.76

# Azure DNS
pip install certbot-dns-azure==2.6.1 azure-identity==1.19.0 azure-mgmt-dns==8.1.0

# Google Cloud DNS
pip install certbot-dns-google==4.1.1 google-cloud-dns==0.35.0

# PowerDNS
pip install certbot-dns-powerdns==0.2.1
```

> La mayoría de los plugins DNS requieren Certbot 4.1.1. El plugin de Azure tiene versionado independiente (2.6.1) y PowerDNS es un plugin más reciente (0.2.1).

### Comandos de validación

```bash
# Comprobar los plugins de certbot
certbot plugins --text

# Verificar que el servicio está en funcionamiento
curl -X GET http://localhost:8000/api/health
```

### Errores comunes

| Error | Solución |
|-------|----------|
| `ModuleNotFoundError` | Ejecute `pip install -r requirements.txt` |
| `Port already in use` | Cambie el puerto en las variables de entorno |
| `certbot not found` | Instale certbot: `pip install certbot` |
| `Permission denied` | Compruebe los permisos en `/app/data` y `/app/certificates` |
| `Token API inválido` | Verifique `API_BEARER_TOKEN` en su archivo `.env` |

### Modo de depuración

```bash
export FLASK_DEBUG=1
python app.py
```

---

## Soporte

Si encuentra algún problema:

1. Revise los registros en busca de errores específicos
2. Verifique las credenciales de su proveedor DNS
3. Consulte la [Guía de proveedores DNS](./dns-providers.md) para la resolución de problemas específicos del proveedor
4. Consulte la [Guía de pruebas](./testing.md) para ejecutar diagnósticos

---

<div align="center">

[← Volver a la documentación](./README.md) • [Proveedores DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
