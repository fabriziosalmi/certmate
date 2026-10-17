# Documentación de CertMate

<!-- CERTMATE-TRANSLATED-FROM bc6b854a04bbb77b -->

Bienvenido a la documentación de CertMate. Esta carpeta contiene guías completas para todas las funcionalidades.

---

## Navegación rápida

### Primeros pasos
- **[Guía de instalación](./installation.md)** — Configuración, dependencias, despliegue en producción
- **[Guía de Docker](./docker.md)** — Builds de Docker, multiplataforma, Docker Compose
- **[Notas de Kubernetes](./kubernetes.md)** — Recursos de producción, dimensionamiento OOM, parches de runtime
- **[Configuración](../configuration.md)** — cada variable de entorno, su valor por defecto y lo que cambia *(en inglés)*

### Funcionalidades principales
- **[Proveedores DNS](./dns-providers.md)** — proveedores soportados, multi-cuenta, alias de dominio
- **[Script DNS personalizado](../custom-dns-script.md)** — cualquier proveedor sin plugin, gobernado por tus propios hooks *(en inglés)*
- **[Proveedores CA](./ca-providers.md)** — Let's Encrypt, DigiCert, CA privada
- **[Certificados de cliente](./guide.md)** — Ciclo de vida de certificados de cliente, panel web, operaciones por lotes
- **[Servidor MCP (Model Context Protocol)](./mcp.md)** — Servidor Node.js independiente para integraciones con agentes de IA

### Referencia
- **[Referencia de API](./api.md)** — Documentación completa de la API REST
- **[Arquitectura](./architecture.md)** — Diseño del sistema, componentes, flujo de datos
- **[Guía de pruebas](./testing.md)** — Framework de pruebas, CI/CD, cobertura
- **[Descubrimiento e inventario de certificados](../discovery-inventory.md)** — descubrimiento por sonda/CT-log, inventario, adopción, preparación criptográfica *(en inglés)*
- **[Deploy hooks](./deploy-hooks.md)** — hooks posteriores a la emisión: configuración, pruebas, redacción de la salida, ventanas de mantenimiento
- **[Certificados a partir de CSR](../csr-only-certificates.md)** — emisión y renovación cuando la clave privada permanece en el dispositivo *(en inglés)*
- **[Webhooks](../webhooks.md)** — webhooks genéricos: plantillas de payload, autenticación, verificación de firma *(en inglés)*
- **[Cumplimiento](./compliance.md)** — cadena de auditoría, atribución de acciones, postura NIS2/eIDAS
- **[Copias de seguridad y recuperación](../backup.md)** — los dos tipos de archivo, copias fuera del host, restauración, contraseña de administrador perdida *(en inglés)*
- **[Sondas de despliegue](./probes.md)** — comprobar que el certificado renovado se sirve de verdad
- **[Inicio de sesión único (OIDC)](../sso.md)** — inicio de sesión con OpenID Connect, asignación de roles, aprovisionamiento *(en inglés)*
- **[Almacenamiento de certificados](../storage.md)** — backends de almacenamiento, qué necesita cada uno, migración entre ellos *(en inglés)*
- **[Monitorización](../monitoring.md)** — endpoints de salud, métricas de Prometheus, logs, canales de notificación *(en inglés)*
- **[Solución de problemas](../troubleshooting.md)** — fallos comunes, registro de depuración, cómo informar de un error *(en inglés)*

---

## Documentación por audiencia

### Para nuevos usuarios

1. **[Instalación](./installation.md)** — Poner en marcha CertMate
2. **[Proveedores DNS](./dns-providers.md)** — Configurar tu proveedor DNS
3. **[Guía de certificados de cliente](./guide.md)** — Crear tu primer certificado

### Para desarrolladores

1. **[Referencia de API](./api.md)** — Todos los endpoints con ejemplos
2. **[Arquitectura](./architecture.md)** — Funcionamiento interno y diseño
3. **[Guía de pruebas](./testing.md)** — Cómo escribir y ejecutar pruebas

### Para administradores

1. **[Despliegue con Docker](./docker.md)** — Configuración de Docker para producción
2. **[Notas de Kubernetes](./kubernetes.md)** — Dimensionamiento de pods en producción y parches operativos
3. **[Proveedores CA](./ca-providers.md)** — Configurar autoridades de certificación
4. **[Proveedores DNS](./dns-providers.md#soporte-multi-cuenta)** — Configuración empresarial multi-cuenta

---

## Descripción general de funcionalidades

### Certificados de servidor
- **Todos los proveedores DNS soportados** para los desafíos DNS-01 de Let's Encrypt (ver [Proveedores DNS](./dns-providers.md) para la lista completa)
- **Múltiples proveedores CA**: Let's Encrypt, DigiCert, CA privada
- **Soporte multi-cuenta** por proveedor DNS
- **Backends de almacenamiento intercambiables**: Local, Azure Key Vault, AWS Secrets Manager, HashiCorp Vault, Infisical, S3-compatible
- **Renovación automática** con umbrales configurables
- **Soporte Docker** con builds multiplataforma (ARM64 + AMD64)
- **Log Sanitizer** — Elimina automáticamente tokens de API, claves privadas y credenciales sensibles de los logs de CertMate
- **Zombie Certificate Scanner** — Sonda multihilo que pregunta si los nombres de tus certificados gestionados siguen resolviendo y respondiendo
- **Servidor MCP (Model Context Protocol)** — Servidor Node.js independiente para integrarse con asistentes de IA agénticos

### Certificados de cliente
- **CA autofirmada** con claves RSA de 4096 bits
- **Gestión completa del ciclo de vida** — crear, renovar, revocar, supervisar
- **OCSP & CRL** — estado en tiempo real y listas de revocación
- **Panel web** en `/client-certificates`
- **Operaciones por lotes** — importar certificados de cliente en bloque mediante CSV (hasta 100 filas por solicitud)
- **Registro de auditoría** y **limitación de peticiones**

---

## Referencia rápida de endpoints de la API

| Método | Endpoint                                 | Descripción                   |
| ------ | ---------------------------------------- | ----------------------------- |
| POST   | `/api/client-certs/create`               | Crear certificado             |
| GET    | `/api/client-certs`                      | Listar certificados           |
| GET    | `/api/client-certs/<id>`                 | Obtener metadatos             |
| GET    | `/api/client-certs/<id>/download/<type>` | Descargar cert/clave/csr      |
| POST   | `/api/client-certs/<id>/revoke`          | Revocar certificado           |
| POST   | `/api/client-certs/<id>/renew`           | Renovar certificado           |
| GET    | `/api/client-certs/stats`                | Obtener estadísticas          |
| POST   | `/api/client-certs/batch`                | Importación CSV por lotes     |
| GET    | `/api/ocsp/status/<serial>`              | Estado OCSP                   |
| GET    | `/api/crl/download/<format>`             | Descargar CRL                 |

Ver la [Referencia de API](./api.md#endpoints) para la documentación completa.

---

## Pruebas

Todas las funcionalidades están exhaustivamente probadas:

```bash
# Ejecutar pruebas
# La suite de UI dirige Playwright contra un servidor vivo y no puede
# compartir proceso con el resto; e2e necesita una instancia en marcha.
# La misma selección que usan `make test` y scripts/release.sh.
pytest -v --tb=short -m "not ui and not e2e"
```

La cobertura de pruebas incluye:
- Operaciones de CA
- Operaciones de CSR
- Ciclo de vida de certificados
- Filtrado y búsqueda
- Operaciones por lotes
- OCSP & CRL
- Auditoría y limitación de peticiones

---

## Funcionalidades de seguridad

- **RSA de 4096 bits** para claves de CA
- **Algoritmo de firma** SHA256
- **Autenticación** por Bearer token
- **Limitación de peticiones** en todos los endpoints
- **Registro de auditoría** de todas las operaciones
- **Permisos de archivo** 0600 para claves privadas

---

## Rendimiento

- Soporta **más de 30.000 certificados simultáneos**
- Consultas **multi-filtro** eficientes
- Planificación de **renovación automática**
- **Operaciones por lotes** con seguimiento de errores

---

## ¿Necesitas ayuda?

1. **¿Problemas de instalación?** → Ver la [sección de instalación](./guide.md#instalación)
2. **¿Preguntas sobre la API?** → Ver la [Referencia de API](./api.md)
3. **¿Preguntas sobre la arquitectura?** → Ver el [documento de arquitectura](./architecture.md)
4. **¿Otra cosa?** → Abre un [issue](https://github.com/fabriziosalmi/certmate/issues)

---

## Estructura de archivos

<!-- Checked by tests/test_docs_navigation.py: this listing must match
     what is actually on disk. It used to omit six pages. -->

```
docs/es/
  README.md           this file — documentation index  <- you are here
  THEME_MIGRATION.md  one-off theme migration record
  api.md              complete REST API reference
  architecture.md     system architecture
  ca-providers.md     certificate authorities
  compliance.md       audit chain, attribution, NIS2/eIDAS
  deploy-hooks.md     post-issuance deploy hooks
  dns-providers.md    DNS providers, multi-account, domain alias
  docker.md           Docker build and deployment
  guide.md            client-certificate user guide
  index.md            client-certificate landing page
  installation.md     installation and setup
  kubernetes.md       Kubernetes production notes and Helm chart
  mcp.md              MCP server for AI agents
  probes.md           deployment probes
  testing.md          test framework and CI/CD
```

---

## Itinerario de aprendizaje

**Principiante** → [Empezar aquí](./guide.md) → [Primeros pasos](./guide.md)

**Desarrollador** → [Referencia de API](./api.md) → [Arquitectura](./architecture.md)

**Avanzado** → [Documentación de API completa](./api.md) → [Detalles de arquitectura](./architecture.md)

---

## Enlaces importantes

- **Panel web**: `http://localhost:8000/client-certificates`
- **Documentación de API**: `http://localhost:8000/docs/`
- **Comprobación de salud**: `http://localhost:8000/health`
- **Registros de auditoría**: `logs/audit/certificate_audit.log`

---

## Estado de las pruebas

Aquí no hay un marcador de pruebas mantenido a mano. Una tabla de recuentos de pruebas queda obsoleta al día siguiente de escribirse — esta decía `27/27` cuando la suite ya pasaba de dos mil.

La señal de referencia es la CI en `main`: las insignias al principio del [README del proyecto](../../README.md) y el mínimo de cobertura impuesto en [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml).

---

## Ejemplos rápidos

### Crear un certificado mediante la API

```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365
 }'
```

### Listar certificados

```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer YOUR_TOKEN"
```

### Descargar un certificado

```bash
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o certificate.crt
```

Ver la [Guía de API](./api.md) para más ejemplos.

---

## Licencia

CertMate está publicado bajo la licencia MIT. Ver el archivo LICENSE en el repositorio.

---

## ¿Preguntas o problemas?

- Consulta la página de documentación correspondiente
- Revisa los archivos de prueba para ver ejemplos de uso
- Consulta la [Referencia de API](./api.md) para detalles sobre los endpoints

---

---

**Versión actual**: 2.50.1

<div align="center">

[Inicio](../../README.md) • [Documentación](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
