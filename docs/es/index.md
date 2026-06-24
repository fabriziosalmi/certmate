# CertMate - Certificados de Cliente

<div align="center">

![CertMate](https://img.shields.io/badge/CertMate-Certificados%20de%20Cliente-blue?style=for-the-badge)
![Estado](https://img.shields.io/badge/Estado-Listo%20para%20Producción-green?style=for-the-badge)

**Gestión completa de certificados de cliente para CertMate**

[Documentación](#documentación) • [Inicio rápido](#inicio-rápido) • [Referencia API](./api.md) • [Arquitectura](./architecture.md)

</div>

---

## Descripción general

CertMate Certificados de Cliente es una solución completa y lista para producción para la gestión de certificados de cliente con:

- **CA autofirmada** — Genere y gestione su propia Autoridad de Certificación
- **Gestión completa del ciclo de vida** — Cree, renueve, revoque y supervise certificados de cliente
- **OCSP & CRL** — Estado de los certificados en tiempo real y listas de revocación
- **Panel de control web** — Interfaz intuitiva para la gestión de certificados
- **API REST** — API completa para la automatización
- **Operaciones por lotes** — Importe entre 100 y 30.000 certificados mediante CSV
- **Registro de auditoría** — Seguimiento de todas las operaciones para el cumplimiento normativo
- **Limitación de tasa** — Protección integrada contra el abuso

---

## Funcionalidades

### Fase 1: Fundación CA
- **PrivateCAGenerator**: CA autofirmada con claves RSA de 4096 bits, validez de 10 años
- **CSRHandler**: Valide, cree y analice solicitudes de firma de certificado
- **Almacenamiento seguro**: Permisos de archivo adecuados (0600) para las claves privadas

### Fase 2: Motor de certificados de cliente
- **Ciclo de vida completo**: Cree, liste, filtre, revoque y renueve certificados
- **Consultas multi-filtro**: Búsqueda por tipo de uso, estado de revocación, nombre común
- **Renovación automática**: Verificaciones diarias programadas para certificados próximos a vencer
- **Soporte para más de 30k certificados**: Almacenamiento por directorio para escalabilidad lineal
- **Gestión de metadatos**: Seguimiento de CN, email, organización, uso y fechas de expiración

### Fase 3: Interfaz de usuario y funcionalidades avanzadas
- **Panel de control web**: Interfaz de gestión adaptable con modo oscuro
- **Respondedor OCSP**: Consulte el estado de los certificados en tiempo real
- **Gestor CRL**: Genere y distribuya listas de revocación (PEM/DER)
- **API REST**: 10 endpoints en 3 espacios de nombres para automatización completa
- **Operaciones por lotes**: Importe certificados desde archivos CSV

### Fase 4: Mejoras rápidas
- **Registro de auditoría**: Seguimiento de todas las operaciones sobre certificados con información de usuario/IP
- **Limitación de tasa**: Límites configurables por endpoint con valores predeterminados razonables
- **Listo para integración**: Ambos gestores disponibles en la aplicación para uso inmediato

---

## Inicio rápido

### Instalación

```bash
pip install -r requirements.txt
python app.py
```

El servidor se iniciará en `http://localhost:8000`

### Uso básico

#### 1. Acceder al panel de control web
```
Navegue a: http://localhost:8000/client-certificates
```

#### 2. Crear un certificado mediante la API
```bash
curl -X POST http://localhost:8000/api/client-certs/create \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
 "common_name": "user@example.com",
 "email": "user@example.com",
 "organization": "ACME Corp",
 "cert_usage": "api-mtls",
 "days_valid": 365,
 "generate_key": true
 }'
```

#### 3. Listar certificados
```bash
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer YOUR_TOKEN"
```

#### 4. Descargar archivos de certificado
```bash
curl http://localhost:8000/api/client-certs/USER_ID/download/crt \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o user.crt

curl http://localhost:8000/api/client-certs/USER_ID/download/key \
 -H "Authorization: Bearer YOUR_TOKEN" \
 -o user.key
```

---

## Documentación

### Documentación principal

- **[Guía de instalación](./installation.md)** — Configuración, dependencias, despliegue
- **[Notas de Kubernetes](./kubernetes.md)** — Dimensionamiento de pods y resolución de problemas OOM
- **[Proveedores DNS](./dns-providers.md)** — Proveedores soportados, multi-cuenta, alias de dominio
- **[Proveedores CA](./ca-providers.md)** — Let's Encrypt, Actalis, DigiCert, CA privada
- **[Guía de Docker](./docker.md)** — Construcciones Docker, multi-plataforma, Compose
- **[Guía de pruebas](./testing.md)** — Framework de pruebas, CI/CD, cobertura
- **[Referencia API](./api.md)** — Documentación completa de la API REST con ejemplos
- **[Arquitectura](./architecture.md)** — Diseño del sistema, componentes y flujo de datos
- **[Guía de usuario](./guide.md)** — Guía paso a paso para las tareas más habituales

### Enlaces rápidos

- [Endpoints API](./api.md#endpoints) — Todos los endpoints disponibles
- [Tipos de certificado](./api.md#certificate-types) — VPN, API mTLS, etc.
- [Limitación de tasa](./api.md#rate-limiting) — Límites predeterminados y configuración
- [Registro de auditoría](./api.md#audit-logging) — Comprensión de las trazas de auditoría

---

## Pruebas

Todas las funcionalidades han sido probadas de forma exhaustiva:

```bash
python -m pytest tests/ -v
```

### Cobertura de pruebas
- Operaciones CA (3 pruebas)
- Operaciones CSR (3 pruebas)
- Ciclo de vida de certificados (8 pruebas)
- Filtrado y búsqueda (3 pruebas)
- Operaciones por lotes (2 pruebas)
- OCSP y CRL (5 pruebas)
- Auditoría y limitación de tasa (3 pruebas)

---

## Resumen de endpoints API

| Método | Endpoint                                 | Propósito                              |
| ------ | ---------------------------------------- | -------------------------------------- |
| `POST` | `/api/client-certs/create`               | Crear un nuevo certificado             |
| `GET`  | `/api/client-certs`                      | Listar certificados con filtros        |
| `GET`  | `/api/client-certs/<id>`                 | Obtener metadatos de un certificado    |
| `GET`  | `/api/client-certs/<id>/download/<type>` | Descargar cert/key/csr                 |
| `POST` | `/api/client-certs/<id>/revoke`          | Revocar un certificado                 |
| `POST` | `/api/client-certs/<id>/renew`           | Renovar un certificado                 |
| `GET`  | `/api/client-certs/stats`                | Obtener estadísticas                   |
| `POST` | `/api/client-certs/batch`                | Importación CSV por lotes              |
| `GET`  | `/api/ocsp/status/<serial>`              | Consulta de estado OCSP                |
| `GET`  | `/api/crl/download/<format>`             | Descargar la CRL (PEM/DER)             |

---

## Arquitectura

El sistema está construido con una arquitectura modular por capas:

```

 Interfaz Web y API REST
 (/client-certificates, /api/*)

 Recursos API y gestores
 (OCSP, CRL, Audit, Limitación de tasa)

 Módulos principales
 (Gestión de certificados, CSR, CA, Almacenamiento)

 Criptografía y almacenamiento
 (OpenSSL, Sistema de archivos, Backends)

```

Consulte la [Documentación de arquitectura](./architecture.md) para información detallada.

---

## Seguridad

### Solidez criptográfica
- **CA**: Claves RSA de 4096 bits, validez de 10 años
- **Certificados de cliente**: RSA de 2048 o 4096 bits (configurable)
- **Firmas**: SHA256
- **Almacenamiento de claves**: Permisos 0600 en sistemas Unix

### Control de acceso
- **Autenticación mediante token Bearer** en todos los endpoints API
- **Limitación de tasa**: Límites configurables por endpoint
- **Registro de auditoría**: Todas las operaciones registradas con información de usuario/IP

### Cumplimiento normativo
- Seguimiento de metadatos de certificados
- Traza de auditoría de revocaciones
- Registros de operaciones persistentes
- Soporte para consultas de cumplimiento

---

## Rendimiento

La implementación está optimizada para:
- **Escalabilidad**: El almacenamiento por directorio soporta más de 30k certificados simultáneos
- **Velocidad**: Consultas multi-filtro eficientes
- **Fiabilidad**: Programación automática de renovaciones
- **Capacidad de respuesta**: JavaScript asíncrono en la interfaz web

---

## Soporte

Para preguntas o incidencias:
1. Consulte la [Guía de usuario](./guide.md)
2. Consulte la [Documentación API](./api.md)
3. Consulte la sección [Arquitectura](./architecture.md)
4. Revise los casos de prueba en `test_e2e_complete.py`

---

## Licencia

Consulte el archivo LICENSE en el repositorio

---

## Versión

**Versión actual**: 2.3.0
**Estado**: Listo para producción

---

<div align="center">

[Documentación](.) • [Licencia](../LICENSE)

</div>
