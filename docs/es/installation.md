# Guía de instalación

<!-- CERTMATE-TRANSLATED-FROM 5c5bff50936e6742 -->

Esta guía cubre todos los métodos de instalación y despliegue de CertMate.

---

## Servidor Linux con systemd

La forma recomendada en un host Linux sin Docker. Verificada en Debian 12, Ubuntu 24.04 y Rocky Linux 9; usa `apt` o `dnf`, así que Fedora, RHEL y Alma Linux siguen el mismo camino.

```bash
curl -fsSL https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/install.sh | sudo sh
```

Qué hace:

- instala `curl`, `tar`, `gzip` y `openssl` solo si faltan;
- descarga la última versión en `/opt/certmate`, propiedad de root y de solo lectura para el servicio;
- obtiene con [uv](https://docs.astral.sh/uv/) un Python 3.12 independiente en `/opt/certmate` e instala `requirements.lock`, el mismo conjunto fijado con el que se construye la imagen del contenedor. No se usa el Python del sistema, por eso funcionan también las distribuciones con un Python más antiguo, como Debian 12 y RHEL 9;
- crea el usuario de sistema `certmate`, propietario solo de `certificates`, `data`, `backups`, `logs` y `letsencrypt`;
- escribe `/etc/certmate/certmate.env` con `API_BEARER_TOKEN`, `SECRET_KEY` y `CERTMATE_BACKUP_PASSPHRASE` generados, solo si el archivo no existe;
- instala e inicia el servicio systemd `certmate`, escuchando en `127.0.0.1:8000`.

Abre `http://127.0.0.1:8000`. La primera página crea la cuenta de administrador y pide el token: `sudo grep API_BEARER_TOKEN /etc/certmate/certmate.env`.

- **Una versión concreta:** `curl -fsSL …/install.sh | sudo sh -s -- --version X.Y.Z`. Las versiones hasta v2.42.0 son anteriores al instalador y se rechazan.
- **Actualización:** ejecuta de nuevo el mismo comando. Se reemplazan el código y el virtualenv; certificados, datos, copias de seguridad y `certmate.env` se conservan.
- **Escuchar en otra dirección:** define `CERTMATE_BIND` en `/etc/certmate/certmate.env` (por ejemplo `0.0.0.0:8000`, o mantén el loopback detrás de un proxy inverso y define `BEHIND_PROXY=true`), y luego `sudo systemctl restart certmate`.
- **Registros:** `journalctl -u certmate`.
- **SELinux:** el instalador aún no se ha verificado con SELinux en modo enforcing. Si el servicio no arranca en un host así, el journal dirá por qué; avísanos.

### Configurarlo a mano

[`deploy/install.sh`](../../deploy/install.sh) es un script POSIX corto, y la lista de arriba es todo lo que hace, así que es la referencia para una configuración manual. Lo que una configuración manual debe respetar:

- la unidad es [`certmate.service`](../../certmate.service) de este repositorio, instalada como `/etc/systemd/system/certmate.service`. Sus comentarios explican cada línea: `PATH` conserva los directorios del sistema para que los hooks de despliegue puedan ejecutarse, un solo worker porque las sesiones y el limitador de inicios de sesión viven en un solo proceso, `GUNICORN_TIMEOUT=300` porque DNS-01 espera la propagación;
- ejecuta gunicorn desde `/opt/certmate/venv` como el usuario `certmate`, aislado con `ProtectSystem=strict`. Las únicas rutas escribibles son `certificates`, `data`, `backups`, `logs` y `letsencrypt` bajo `/opt/certmate`, y las cinco deben existir antes de que el servicio arranque;
- lee `/etc/certmate/certmate.env`, donde el instalador escribe `API_BEARER_TOKEN`, `SECRET_KEY` y `CERTMATE_BACKUP_PASSPHRASE`, con propietario `root:certmate` y modo `0640`. Un token de menos de 32 caracteres, o un marcador de posición, se rechaza al arrancar. Sin `CERTMATE_BACKUP_PASSPHRASE`, las copias de seguridad automáticas no pueden restaurar la instancia;
- después de cambiar `certmate.env`, usa `systemctl restart`: `reload` solo envía una señal a gunicorn y no vuelve a leer el archivo.

---

## Una VM en la nube con cloud-init

Para una VM nueva en cualquier proveedor que acepte user data (Hetzner, DigitalOcean, AWS, Azure, GCP, OpenStack, Proxmox): pega [`deploy/cloud-init/certmate.yaml`](../../deploy/cloud-init/certmate.yaml) en el campo "user data" o "cloud-init" de la VM al crearla ([archivo sin formato](https://raw.githubusercontent.com/fabriziosalmi/certmate/main/deploy/cloud-init/certmate.yaml)). Instala Docker, descarga el [paquete compose de producción](docker.md#en-producción-con-docker-compose), genera los secretos en la VM en `/srv/certmate/.env` (modo 600, nunca en el user data) e inicia CertMate.

CertMate escucha en `127.0.0.1:8000` dentro de la VM. Accede con un túnel SSH, `ssh -L 8000:127.0.0.1:8000 <user>@<vm>`, y luego abre `http://127.0.0.1:8000`. La primera página crea la cuenta de administrador y pide el token: `sudo grep API_BEARER_TOKEN /srv/certmate/.env`.

Verificado en la imagen cloud de Ubuntu 24.04: cloud-init termina en `done`, CertMate está sano pocos minutos después del arranque y vuelve tras un reinicio.

---

## Requisitos previos

- Python 3.12
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
source venv/bin/activate  # En Windows: venv\Scripts\activate
```

### 3. Instalar las dependencias

```bash
pip install -r requirements.txt
```

### 4. Configurar el entorno

Crea un archivo `.env`:

```bash
cp .env.example .env
# Edita .env con tus ajustes
```

### 5. Iniciar la aplicación

```bash
python app.py
```

---

## Método 2: Instalación con Docker

### Con Docker Compose (recomendado)

Descarga el paquete de producción y arráncalo: un solo archivo, la imagen publicada, sin clonar ni compilar. Los comandos y lo que hace cada ajuste están en [Docker: En producción con Docker Compose](docker.md#en-producción-con-docker-compose).

### Con Docker Build

```bash
git clone https://github.com/fabriziosalmi/certmate.git
cd certmate
docker build -t certmate .
docker run -p 8000:8000 --env-file .env -v ./certificates:/app/certificates certmate
```

> Para el despliegue avanzado con Docker, incluyendo builds multiplataforma, consulta la [Guía de Docker](./docker.md).

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

Tras la instalación, configura las credenciales de tu proveedor DNS. Consulta la [Guía de proveedores DNS](./dns-providers.md) para ver las instrucciones de configuración detalladas de cada proveedor soportado.

Configuración rápida para los proveedores más habituales:

### Cloudflare

1. Ve al [Panel de Cloudflare](https://dash.cloudflare.com/profile/api-tokens)
2. Crea un nuevo token de API con permisos `Zone:DNS:Edit`
3. Añade el token en los ajustes de CertMate

### AWS Route53

1. Concede permisos DNS de Route53 a un rol IAM asociado al host/pod, o a un usuario IAM.
2. En los ajustes de CertMate → Proveedores DNS, selecciona **AWS credentials / IAM role** para usar la cadena de credenciales de AWS, o introduce las claves de acceso del usuario.
3. Opcionalmente, establece **Assume role ARN** si la identidad de origen puede asumir otro rol de Route53. Consulta [Proveedores DNS](./dns-providers.md#aws-route53).

### Azure DNS

1. Crea un Service Principal
2. Asigna el rol DNS Zone Contributor
3. Configura los detalles de la suscripción en los ajustes de CertMate

### Google Cloud DNS

1. Crea una cuenta de servicio con el rol DNS Administrator
2. Descarga el archivo de clave JSON
3. Súbelo en los ajustes de CertMate

---

## Variables de entorno

```bash
# Autenticación de la API (se genera automáticamente si no se define ninguna)
# Opción A: valor directo
API_BEARER_TOKEN=your_secure_token_here
# Opción B: ruta a un archivo que contiene el token (tiene prioridad sobre API_BEARER_TOKEN)
API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token

# Clave secreta de sesión de Flask (se genera automáticamente si no se define ninguna)
# Opción A: valor directo
SECRET_KEY=your_flask_secret_key
# Opción B: ruta a un archivo que contiene la clave (tiene prioridad sobre SECRET_KEY)
SECRET_KEY_FILE=/run/secrets/secret_key

# Proxy inverso: defínelo a 'true' cuando CertMate esté detrás de Nginx,
# HAProxy, Traefik, Cloudflare, etc. Sin esto, request.remote_addr
# resuelve a la IP del proxy en cada petición, lo que colapsa la limitación
# de tasa por cliente en un único bucket. Consulta la sección "Detrás de un
# proxy inverso" en Despliegue en producción para más detalles.
BEHIND_PROXY=true

# Cifrado de las copias de seguridad en reposo (opcional, recomendado).
# Cuando se define, las copias de seguridad unificadas se escriben como archivos
# .zip.enc cifrados (derivación de clave PBKDF2-SHA256 + Fernet/AES) en lugar de .zip en claro.
# Una copia de recuperación ante desastres (include_secrets=true) incluye cada
# clave privada de certificado y cada credencial, así que sin esto una
# copia exfiltrada supone un compromiso total; la copia por defecto, segura para compartir,
# no lleva ninguna de las dos. La misma frase de contraseña
# debe estar presente para restaurar. Solo por entorno, a propósito: una frase guardada
# en settings.json acabaría ella misma dentro de copias de seguridad en claro.
CERTMATE_BACKUP_PASSPHRASE=choose-a-long-random-passphrase

# Proveedor DNS. Cloudflare es el único proveedor que se lee del entorno:
# este token configura la cuenta de Cloudflare predeterminada. Route53, Azure,
# Google Cloud DNS, PowerDNS y los demás se configuran en Ajustes -> Proveedores DNS
# o a través de la API; AWS_*, AZURE_* y variables similares aquí no tienen efecto.
CLOUDFLARE_TOKEN=your_cloudflare_token
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

> **Consejo para Docker Secrets**: Usa `API_BEARER_TOKEN_FILE=/run/secrets/api_bearer_token` y `SECRET_KEY_FILE=/run/secrets/secret_key` con Docker Swarm o los secrets de Kubernetes para evitar poner valores sensibles en variables de entorno.

---

## Despliegue en producción

### Detrás de un proxy inverso

Si CertMate está detrás de un proxy inverso (Nginx, HAProxy, Traefik,
Cloudflare, Kubernetes Ingress) — que es la forma recomendada de ejecutarlo
para la terminación TLS — define `BEHIND_PROXY=true` en el entorno del
contenedor. Esto activa el middleware `ProxyFix` de Werkzeug para que los
siguientes elementos confíen en las cabeceras `X-Forwarded-*` de tu proxy:

- `request.remote_addr` resuelve a la IP original del cliente en lugar de
  la IP del proxy. La limitación de tasa, las entradas del registro de
  auditoría y las advertencias de "intento de token de API inválido desde X"
  pasan a ser por cliente en lugar de por proxy.
- Se respetan las cabeceras de esquema / host / prefijo del proxy, lo que
  mantiene correctas las URLs generadas y los ámbitos de las cookies.

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

**Cuándo NO activarlo.** Si expones CertMate directamente a la red sin
ningún proxy delante, deja `BEHIND_PROXY` sin definir. Con esta opción
definida, cualquiera que pueda alcanzar el listener podría falsificar
`X-Forwarded-For` y eludir los límites de tasa por cliente. El proxy es el
límite de confianza.

Tu proxy debe, por supuesto, reenviar las cabeceras. Ejemplo con Nginx:

```nginx
proxy_set_header Host              $host;
proxy_set_header X-Real-IP         $remote_addr;
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
```

#### El perfil nginx incluido

`docker-compose.yml` incluye un servicio `nginx` opcional (`--profile nginx`)
que termina TLS delante de CertMate. Su configuración **no** se versiona
como `nginx.conf` — ese archivo es tuyo y está en gitignore — sino como
`nginx.conf.example`, el mismo patrón que `.env.example` / `.env`:

```bash
cp nginx.conf.example nginx.conf
# edita nginx.conf: sustituye cada <your-domain> en ssl_certificate / ssl_certificate_key
docker compose --profile nginx up -d
```

Copia **antes** de `up`: si `nginx.conf` no existe en el host cuando se crea
el bind mount, Docker lo crea como un *directorio* vacío y nginx no arranca.
Si actualizas desde una versión en la que `nginx.conf` estaba versionado:
tu copia editada se queda en su sitio (git ahora la ignora); compárala con el
nuevo `nginx.conf.example` tras un pull para incorporar los cambios de upstream.

#### Ejemplo: Zion (gateway TLS en Rust + WAF)

[Zion](https://github.com/fabriziosalmi/zion) es un proxy inverso TLS en Rust
de alto rendimiento con un WAF integrado — una buena opción delante de CertMate
cuando quieres terminación TLS 1.3 y filtrado de peticiones en el edge. CertMate
permanece en HTTP plano en la red interna; Zion termina el TLS y reenvía.

`zion.toml`:

```toml
[server]
listen_http  = "0.0.0.0:8080"
listen_https = "0.0.0.0:8443"

[tls]
cert_path = "/etc/ssl/zion/tls.crt"   # tu certificado, o usa el ACME de Zion (--features acme)
key_path  = "/etc/ssl/zion/tls.key"
min_version = "1.3"
alpn = ["h2", "http/1.1"]

[upstream.backend]
url = "http://certmate:8000"

# Catch-all hacia el backend. La ruta explícita "/" es inofensiva y documenta
# la intención; las versiones recientes de Zion también registran "/" automáticamente para un catch-all en la raíz.
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
    image: certmate:latest          # la imagen publicada, o tu build local
    environment:
      BEHIND_PROXY: "true"          # confiar en las cabeceras X-Forwarded-* de Zion
    expose:
      - "8000"                       # solo interno; no se publica en el host
    volumes:
      - ./data:/app/data

  zion:
    image: zion:latest              # la imagen publicada, o tu build local
    depends_on:
      - certmate
    environment:
      ZION_CONFIG: /etc/zion/zion.toml
    volumes:
      - ./zion.toml:/etc/zion/zion.toml:ro
      - ./certs:/etc/ssl/zion:ro
    ports:
      - "443:8443"                   # 443 del host -> listener HTTPS de Zion
      - "80:8080"                    # 80 del host  -> listener HTTP de Zion
```

Mantén `BEHIND_PROXY=true` en el servicio CertMate: Zion añade
`X-Forwarded-For`, lo que hace que la limitación de tasa por cliente, las entradas
de auditoría y las advertencias de fallo de autenticación resuelvan a la IP real
del cliente en lugar de a la de Zion.

> **`/metrics` lo sirve Zion, no se reenvía.** Zion expone su propio endpoint
> de Prometheus en `/metrics` (series `zion_*` para el proxy), que oculta el
> `/metrics` de CertMate. Recógelos por separado: el `/metrics` de Zion desde dentro
> de la red del host / clúster (Zion lo restringe a IP de origen privadas y devuelve
> 403 a los clientes públicos), y las métricas `certmate_*` de CertMate directamente
> contra el `certmate:8000` interno con un Bearer token de admin (consulta
> [`monitoring/`](../../monitoring/) para el dashboard y la configuración de scrape).

### Restricción del tráfico saliente (hardening de egress)

CertMate establece conexiones salientes hacia las autoridades de certificación ACME,
las APIs de proveedores DNS, el almacenamiento de objetos y los webhooks de
notificación a través de HTTP(S), además de SMTP para las notificaciones por email.
Puedes restringir y auditar el tráfico **HTTP(S)** enrutándolo a través de un
**forward proxy** y denegando a CertMate cualquier otra ruta hacia internet.

Los clientes HTTP(S) de CertMate (`requests`, `certbot`, entrega de webhooks vía
`urllib`, `boto3`) respetan las variables de entorno estándar `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`,
por lo que no se requieren cambios en el código. Las sondas TLS también:
la comprobación del estado de despliegue, el barrido del inventario, el endpoint
`POST /api/probe`, la comprobación de cabeceras HSTS y la de TLS 1.0/1.1 encauzan
todas su tramo TCP con HTTP CONNECT, y la descarga OCSP/CRL para la revocación — que
es HTTP en claro — pasa por `HTTP_PROXY`. Un destino que resuelve a una dirección
privada o de loopback se contacta siempre de forma directa, porque ningún proxy de
salida lo sirve.

**Dos cosas no pasan por el proxy:**

- **SMTP.** Las notificaciones por email usan `smtplib`, que abre una conexión
  TCP directa y **no** consulta las variables de proxy HTTP. Permite directamente
  el `host:port` de tu relay SMTP (regla de firewall / NetworkPolicy), o usa
  un canal de notificación webhook en lugar del email.
- **WHOIS.** La comprobación de caducidad del registro recurre a WHOIS en el puerto 43
  para los TLD sin RDAP, y un proxy HTTP no puede transportar ese protocolo. RDAP —
  que es HTTPS, y es lo que responden la mayoría de los TLD — sí pasa por el proxy.
  Permite el puerto 43 hacia los registros que necesites, o deja que esos TLD informen
  `unavailable`.

Ejemplo con [Secure Proxy Manager](https://github.com/fabriziosalmi/secure-proxy-manager),
un forward proxy autoalojado basado en Squid con WAF, DNS sinkhole y — desde
v3.9.0 — una **lista de permitidos de egress default-deny** integrada (solo los
destinos explícitamente aprobados son alcanzables; todo lo demás se deniega):

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
  # La pila de Secure Proxy Manager proporciona el servicio `proxy` en :3128.
  # Conecta ese proxy TANTO a la red `egress` (para que CertMate pueda alcanzarlo)
  # COMO a una segunda red no interna (para que el propio proxy llegue a
  # internet). El proxy pasa a ser entonces la única salida de CertMate.
networks:
  egress:
    internal: true        # sin gateway: CertMate no tiene internet directo
```

Colocar CertMate en una red `internal` (sin gateway) compartida con el proxy
hace del proxy su **único** camino hacia el exterior. El tráfico saliente se
convierte en un único punto de control auditable: permite los destinos que CertMate
realmente necesita (tu CA, proveedor DNS, almacenamiento de objetos, endpoints de
notificación) y deniega el resto; los destinos expresados como IP literal se bloquean
en el proxy en lugar de aceptarse a ciegas. Si usas delegación DNS-alias / CNAME,
permite también `cloudflare-dns.com` — CertMate resuelve esos CNAME por DoH.

Con Secure Proxy Manager v3.9.0+ es un modo integrado y no un ejercicio manual
de ACL: activa **Default-deny egress** en Settings y rellena la
**Egress Allowlist** con los destinos que CertMate necesita. Cada entrada es un
dominio o una IP/CIDR (clasificada automáticamente), y el endpoint `/api/egress-allowlist`
permite gestionar la lista desde IaC. Una lista de permitidos inicial representativa:

- el host de la API de tu CA ACME — p. ej. `acme-v02.api.letsencrypt.org` (más
  `acme-staging-v02.api.letsencrypt.org` si emites contra staging), o el
  endpoint de la CA que hayas configurado;
- el host de la API de tu proveedor DNS — varía según el proveedor (por ejemplo
  `api.cloudflare.com`);
- el endpoint de tu almacenamiento de objetos, si la copia de seguridad externa está activada;
- el host de tus notificaciones — el endpoint del webhook, Gotify, ntfy o Telegram, si
  se usa;
- `cloudflare-dns.com`, si usas delegación DNS-alias / CNAME (resuelta por
  DoH, como arriba).

Todo lo demás se deniega en el proxy, así que una configuración errónea o una
dependencia comprometida no puede exfiltrar datos en silencio hacia un host
arbitrario. Para HTTPS la lista de permitidos compara el host de la petición
`CONNECT`, así que funciona sin interceptación TLS.

- **Kubernetes:** una `NetworkPolicy` de egress default-deny que solo permite tráfico
  hacia el Service del proxy, más las variables de entorno `HTTP(S)_PROXY` en el Deployment.
- **systemd:** `Environment=HTTPS_PROXY=...` en la unidad, más reglas de firewall en el
  host que restringen el egress al proxy.

**Inspección del contenido HTTPS (opcional, avanzado).** Un forward proxy solo ve el
SNI / host / IP de una conexión HTTPS — permitir o denegar por destino funciona con eso
sin descifrar. Si además activas la interceptación TLS (SSL-bump) en el proxy para
inspeccionar el *contenido* saliente, CertMate debe **confiar en la CA de interceptación
del proxy**: apunta `REQUESTS_CA_BUNDLE` (y `SSL_CERT_FILE`) a un bundle que la
incluya, o añádela al almacén de confianza del sistema del contenedor. **Excluye
(`splice`) los endpoints ACME de la interceptación** — no quieres hacer MITM a la
conexión con tu autoridad de certificación, y algunos endpoints fijan certificados.
Esto no es TLS mutuo; es una confianza unidireccional en una CA privada.

### Ubicación de almacenamiento del directorio de datos

CertMate utiliza E/S de archivos bloqueante estándar de Python para todo lo que se
encuentra bajo `data/` (ajustes, certificados, registro de auditoría, almacenamiento
SQLite del planificador). Se recomienda encarecidamente el disco local.

Si montas `data/` en un sistema de archivos de red (NFS, SMB), ten en cuenta que:

- Un servidor NFS bloqueado puede detener las lecturas de archivos de Python
  indefinidamente sin timeout integrado. El worker de renovación, el escritor del
  registro de auditoría y la sonda /health se bloquearán todos en el mismo punto de montaje.
- El modo journal WAL de SQLite requiere semánticas de bloqueo que NFS no siempre
  proporciona. CertMate registra una advertencia si tuvo que recurrir a un modo
  journal más débil; la corrección se preserva, pero la concurrencia disminuye.

Si NFS es inevitable, monta con `soft,timeo=30,retrans=3` (o el equivalente de tu
distribución) para que las E/S fallen rápidamente en lugar de bloquearse ante un
servidor caído, y revisa el registro de la aplicación tras el primer arranque en busca de
la advertencia de que tuvo que abandonar el modo WAL (stdout, o el archivo indicado en
`CERTMATE_LOG_FILE` si has definido uno).

### Usar Gunicorn

```bash
gunicorn --bind 0.0.0.0:8000 --workers 1 --threads 8 --timeout 300 app:app
```

### Usar systemd

Usa el instalador, o la unidad del repositorio a mano: consulta [Servidor Linux con systemd](#servidor-linux-con-systemd).

### Usar Docker en producción

```yaml
services:
  certmate:
    build: .
    ports:
      - "127.0.0.1:8000:8000"  # solo localhost; el proxy inverso es lo que da a la red
    environment:
      - API_BEARER_TOKEN=${API_BEARER_TOKEN}
      - CLOUDFLARE_TOKEN=${CLOUDFLARE_TOKEN}
    volumes:
      - ./certificates:/app/certificates
      - ./data:/app/data
      - ./logs:/app/logs
      - ./backups:/app/backups
    restart: unless-stopped
```

---

## Resolución de problemas

### Conflictos de versiones de plugins DNS

Instala desde el archivo requirements que distribuye CertMate. Ese conjunto se
resuelve, se construye y se arranca en CI en cada ejecución; una lista montada a
mano no.

```bash
pip install -r requirements.txt            # todos los proveedores incluidos
pip install -r requirements-minimal.txt    # solo certbot + Cloudflare
pip install -r requirements-extended.txt   # más proveedores, sobre minimal
pip install -r requirements-aws.txt        # Route53, sobre cualquiera de los dos
```

> Esta página publicaba su propia lista de versiones, que se había desviado
> hasta `certbot==4.1.1` en los cinco idiomas mientras el proyecto estaba fijado
> a `2.10.0`. El proyecto ahora usa certbot `5.8.0` (incidencia #103).
>
> Corregir esos números no basta, y por eso la lista se ha eliminado en lugar de
> actualizarse. Lo que mantiene unida la pila no son las versiones de los
> plugins, sino que certbot, `acme`, `josepy`, los plugins oficiales,
> `cryptography` y `pyopenssl` encajen entre sí: certbot y `acme` 5.8.0 exigen
> `cryptography>=47`, y pyOpenSSL 26.4.0 exige `>=49,<51`. Montado a mano, un pin
> acaba fuera de esa ventana; el archivo que CertMate incluye es el conjunto que
> se resuelve, se construye y se arranca en la CI. Véase SECURITY.md, "Known
> dependency constraint".
>
> `certbot-dns-powerdns` necesita su propio entorno: requiere
> `dns-lexicon<=3.5.6` mientras que los plugins de Linode, OVH, RFC2136,
> DNSMadeEasy y NS1 requieren `>=3.14.1`, y pip no puede satisfacer ambos.

### Instalación manual de dependencias

Si un proveedor concreto no se instala, añádelo sobre una base que funcione en
lugar de montar una a mano:

```bash
pip install -r requirements-minimal.txt    # primero la base que funciona
pip install -r requirements-aws.txt        # Route53 + boto3
pip install -r requirements-gcp.txt        # Google Cloud DNS
pip install -r requirements-azure.txt      # Azure DNS
```

Cada archivo lleva las versiones que su plugin necesita, y CI resuelve todas las
combinaciones en cada ejecución — incluida la comprobación de que certbot no se
sale de su pin.

### Comandos de validación

```bash
# Comprobar los plugins de certbot
certbot plugins --text

# Verificar que el servicio está en funcionamiento
curl -X GET http://localhost:8000/api/health
```

---

## Soporte

Si encuentras algún problema:

1. Revisa los registros en busca de errores específicos
2. Verifica las credenciales de tu proveedor DNS
3. Consulta la [Guía de proveedores DNS](./dns-providers.md) para la resolución de problemas específicos del proveedor
4. Consulta la [Guía de pruebas](./testing.md) para ejecutar diagnósticos

---

<div align="center">

[← Volver a la documentación](./README.md) • [Proveedores DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
