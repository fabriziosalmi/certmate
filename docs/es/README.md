# Documentación de CertMate

Bienvenido a la documentación de CertMate. Esta carpeta contiene guías completas para todas las funcionalidades.

---

## Navegación rápida

### Primeros pasos
- **[Guía de instalación](./installation.md)** — Configuración, dependencias, despliegue en producción
- **[Guía de Docker](./docker.md)** — Builds de Docker, multiplataforma, Docker Compose
- **[Notas de Kubernetes](./kubernetes.md)** — Recursos de producción, dimensionamiento OOM, parches de runtime

### Funcionalidades principales
- **[Proveedores DNS](./dns-providers.md)** — Proveedores soportados, multi-cuenta, alias de dominio
- **[Proveedores CA](./ca-providers.md)** — Let's Encrypt, DigiCert, CA privada
- **[Certificados de cliente](./guide.md)** — Ciclo de vida de certificados de cliente, panel web, operaciones por lotes
- **[Servidor MCP (Model Context Protocol)](./mcp.md)** — Servidor Node.js independiente para integraciones con agentes de IA

### Referencia
- **[Referencia de API](./api.md)** — Documentación completa de la API REST
- **[Arquitectura](./architecture.md)** — Diseño del sistema, componentes, flujo de datos
- **[Guía de pruebas](./testing.md)** — Framework de pruebas, CI/CD, cobertura

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
2. **[Notas de Kubernetes](./kubernetes.md)** — Dimensionamiento de pods y parches operativos
3. **[Proveedores CA](./ca-providers.md)** — Configurar autoridades de certificación
4. **[Proveedores DNS](./dns-providers.md#multi-account-support)** — Configuración empresarial multi-cuenta

---

## Descripción general de funcionalidades

### Certificados de servidor
- **Más de dos docenas de proveedores DNS** para los desafíos DNS-01 de Let's Encrypt (ver [Proveedores DNS](./dns-providers.md) para la lista completa)
- **Múltiples proveedores CA**: Let's Encrypt, DigiCert, CA privada
- **Soporte multi-cuenta** por proveedor DNS
- **Backends de almacenamiento intercambiables**: Local, Azure Key Vault, AWS, Vault, Infisical
- **Renovación automática** con umbrales configurables
- **Soporte Docker** con builds multiplataforma (ARM64 + AMD64)
- **Log Sanitizer** — Elimina automáticamente tokens de API, claves privadas y credenciales sensibles de los logs de CertMate
- **Zombie Certificate Scanner** — Escáner de sistema de archivos multihilo para identificar y limpiar certificados huérfanos
- **Servidor MCP (Model Context Protocol)** — Servidor Node.js independiente para integrarse con asistentes de IA agénticos

### Certificados de cliente
- **CA autofirmada** con claves RSA de 4096 bits
- **Gestión completa del ciclo de vida** — crear, renovar, revocar, supervisar
- **OCSP & CRL** — estado en tiempo real y listas de revocación
- **Panel web** en `/client-certificates`
- **Operaciones por lotes** — importar entre 100 y 30.000 certificados mediante CSV
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
python -m pytest tests/ -v
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

## Estructura de archivos

```
docs/
  README.md            ← Estás aquí
  index.md             ← Página de inicio de certificados de cliente
  installation.md      ← Instalación y configuración
  kubernetes.md        ← Notas de producción de Kubernetes
  dns-providers.md     ← Proveedores DNS y multi-cuenta
  ca-providers.md      ← Proveedores de autoridad de certificación
  docker.md            ← Build y despliegue con Docker
  testing.md           ← Framework de pruebas y CI/CD
  guide.md             ← Guía de usuario de certificados de cliente
  api.md               ← Referencia de API completa
  architecture.md      ← Arquitectura del sistema
```

---

## Itinerario de aprendizaje

**Principiante** → [Empezar aquí](./index.md) → [Primeros pasos](./guide.md)

**Desarrollador** → [Referencia de API](./api.md) → [Arquitectura](./architecture.md)

**Avanzado** → [Documentación de API completa](./api.md) → [Detalles de arquitectura](./architecture.md)

---

## Enlaces importantes

- **Panel web**: `http://localhost:8000/client-certificates`
- **Documentación de API**: `http://localhost:8000/docs/`
- **Comprobación de salud**: `http://localhost:8000/health`
- **Registros de auditoría**: `logs/audit/certificate_audit.log`

---

## Panel de estado

| Componente          | Estado       | Pruebas   |
| ------------------- | ------------ | --------- |
| Fundación CA        | Listo        | 3/3       |
| Gestor CSR          | Listo        | 3/3       |
| Gestor de cert.     | Listo        | 8/8       |
| Filtrado            | Listo        | 3/3       |
| Operaciones por lotes | Listo      | 2/2       |
| OCSP/CRL            | Listo        | 5/5       |
| Auditoría/Limitación | Listo       | 3/3       |
| **Total**           | **Listo**    | **27/27** |

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

<div align="center">

[Inicio](../README.md) • [Documentación](./) • [GitHub](https://github.com/fabriziosalmi/certmate)

</div>
