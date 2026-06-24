# Proveedores de autoridad de certificación (CA)

CertMate soporta múltiples proveedores de autoridad de certificación, permitiéndote elegir la CA más adecuada a tus necesidades.

---

## Proveedores CA soportados

### Let's Encrypt (predeterminado)

- **Tipo**: Certificados SSL gratuitos y automatizados
- **Tipos de certificados**: Domain Validation (DV)
- **Soporte Wildcard**: Sí
- **EAB requerido**: No
- **Ideal para**: Desarrollo, pequeñas empresas, proyectos personales

**Configuración:**
- **Email**: Requerido para las notificaciones de certificado

### Let's Encrypt (Staging)

- **Tipo**: Certificados de prueba del entorno de staging de Let's Encrypt
- **Tipos de certificados**: Domain Validation (DV) — NO reconocidos por los navegadores
- **Soporte Wildcard**: Sí
- **EAB requerido**: No
- **Ideal para**: Validar la configuración DNS, el despliegue y la renovación sin consumir los límites de producción

El staging es una entrada de autoridad de certificación independiente (desde v2.12.0), no un indicador por certificado: selecciónala como CA al crear un certificado, o establécela como CA predeterminada durante las pruebas. El email recurre al de la cuenta de Let's Encrypt cuando se deja vacío. Convertir un certificado de staging a producción requiere una reemisión con la CA de producción.

### DigiCert ACME

- **Tipo**: Certificados SSL de nivel empresarial
- **Tipos de certificados**: DV, OV, EV
- **Soporte Wildcard**: Sí
- **EAB requerido**: Sí
- **Ideal para**: Entornos empresariales, aplicaciones comerciales

**Requisitos de configuración:**
- **URL del directorio ACME**: `https://acme.digicert.com/v2/acme/directory`
- **EAB Key ID**: Proporcionado por DigiCert
- **EAB HMAC Key**: Proporcionada por DigiCert
- **Email**: Requerido para las notificaciones de certificado

### Actalis

- **Tipo**: Certificados DV gratuitos de 90 días de una CA europea (italiana)
- **Tipos de certificados**: Domain Validation (DV)
- **Soporte Wildcard**: No (no disponible vía ACME)
- **EAB requerido**: Sí
- **Ideal para**: Usuarios de la UE que buscan una alternativa europea a Let's Encrypt, entornos del ecosistema eIDAS

**Requisitos de configuración:**
- **URL del directorio ACME**: `https://acme-api.actalis.com/acme/directory` (fija, preconfigurada)
- **EAB Key ID**: Desde tu área de cliente de Actalis
- **EAB HMAC Key**: Desde tu área de cliente de Actalis
- **Email**: Requerido para las notificaciones de certificado

**Límites del plan gratuito:**
- Solo certificados de dominio único — una solicitud con entradas SAN es rechazada con
  `Your account only grants single-domain 90-days DV certificates`
- Validez de 90 días
- Sin certificados wildcard (los planes SAN de pago cubren hasta 5 nombres de host)

### CA privada

- **Tipo**: Autoridad de certificación interna/corporativa
- **Tipos de certificados**: Privados/Internos
- **Soporte Wildcard**: Sí (depende de la implementación de la CA)
- **EAB requerido**: Opcional
- **Ideal para**: Redes internas, entornos corporativos, sistemas aislados

**Software compatible:**
- [step-ca](https://smallstep.com/docs/step-ca/)
- [Boulder](https://github.com/letsencrypt/boulder)
- [Pebble](https://github.com/letsencrypt/pebble)
- Otras CAs privadas compatibles con ACME

**Uso de una CA pública ACME a través de la entrada CA privada:**

La entrada CA privada es también la vía de escape genérica para cualquier CA ACME sin una entrada dedicada en CertMate: apúntala a la URL del directorio de la CA y, si la CA exige vinculación de cuenta, rellena el EAB Key ID y HMAC Key opcionales. Por ejemplo, Actalis funciona tanto a través de su entrada dedicada (recomendado) como como CA privada con:

- **URL del directorio ACME**: `https://acme-api.actalis.com/acme/directory`
- **EAB Key ID / HMAC Key**: desde el área de cliente de Actalis
- **Certificado CA**: dejar vacío (raíces de confianza pública)

---

## Configuración

### Mediante la interfaz web

1. Ve a **Ajustes**
2. Desplázate hasta **Proveedores de autoridad de certificación (CA)**
3. Selecciona tu proveedor CA predeterminado
4. Configura los campos requeridos
5. Haz clic en **Probar conexión CA** para verificar
6. Guarda los ajustes

### CA predeterminada vs. CA por certificado

Establece una CA predeterminada para todos los nuevos certificados. Puedes sobrescribirla por certificado durante la creación:

1. Ve a la página **Certificados**
2. Selecciona la CA deseada en el desplegable **Autoridad de certificación**
3. Continúa con la creación del certificado

### Mediante la API

```bash
# Create certificate with specific CA
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "ca_provider": "digicert"
  }'

# Test CA connection
curl -X POST http://localhost:8000/api/settings/test-ca-provider \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_provider": "digicert",
    "config": {
      "acme_url": "https://acme.digicert.com/v2/acme/directory",
      "eab_kid": "your_key_id",
      "eab_hmac": "your_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

Algunos proveedores CA (como DigiCert y Actalis) requieren External Account Binding para vincular tu cliente ACME a tu cuenta de CA.

### ¿Qué es EAB?

- **Key ID**: Un identificador único para tu cuenta
- **HMAC Key**: Una clave secreta utilizada para firmar las solicitudes

### Obtener credenciales EAB

**DigiCert:**
1. Inicia sesión en tu cuenta de DigiCert
2. Ve a los ajustes ACME
3. Genera o recupera tu EAB Key ID y HMAC Key

**Actalis:**
1. Registra una cuenta gratuita en [actalis.com](https://www.actalis.com/)
2. En el área de cliente, abre **Manage with ACME**
3. Recupera el KID y la clave HMAC en **ACME Credentials**

**CA privada:**
- **step-ca**: EAB puede habilitarse/deshabilitarse por provisioner
- **Boulder**: Generalmente requiere EAB para producción
- Consulta la documentación de tu CA privada para los requisitos específicos

---

## Confianza del certificado SSL

### CAs públicas (Let's Encrypt, DigiCert)

Los certificados son reconocidos automáticamente por los navegadores y sistemas operativos.

### CAs privadas

Para que los certificados de CA privada sean reconocidos:
1. Instala el certificado raíz de la CA en los sistemas cliente
2. Configura las aplicaciones para una confianza personalizada
3. Importa el certificado raíz en los almacenes de confianza de los navegadores

Opcionalmente puedes proporcionar el certificado raíz de la CA en CertMate para la verificación de la cadena de confianza durante la creación del certificado.

---

## Resolución de problemas

### Let's Encrypt
- **Certificado no reconocido tras la emisión**: Comprueba si el certificado fue emitido por la CA de staging — selecciona la entrada de producción "Let's Encrypt" y vuelve a emitir
- **Límite de peticiones alcanzado**: Cambia a la entrada CA "Let's Encrypt (Staging)" durante las pruebas
- **Email válido**: Asegúrate de que el formato del email es correcto

### DigiCert
- **Credenciales EAB inválidas**: Verifica la Key ID y la HMAC Key
- **Cuenta no autorizada**: Asegúrate de que ACME está habilitado en tu cuenta de DigiCert
- **URL ACME incorrecta**: Verifica la URL del directorio con el soporte de DigiCert

### Actalis
- **`Your account only grants single-domain 90-days DV certificates`**: El plan gratuito rechaza las solicitudes SAN/multi-dominio — emite un certificado por nombre de host o actualiza el plan
- **Credenciales EAB inválidas**: Recupera credenciales nuevas desde el área de cliente en Manage with ACME
- **Wildcard rechazado**: Los certificados wildcard no están disponibles vía ACME en Actalis

### CA privada
- **URL ACME inaccesible**: Comprueba la conectividad de red
- **Certificado CA inválido**: Verifica el formato PEM y la validez
- **EAB mismatch**: Comprueba si EAB es requerido por tu CA

### General
- Asegúrate de que el proveedor DNS está correctamente configurado
- Verifica la propiedad del dominio y la propagación DNS
- Comprueba las reglas del firewall para el puerto ACME (normalmente 443)

---

## Migración entre CAs

1. **Los nuevos certificados** utilizan la nueva CA predeterminada
2. **Los certificados existentes** continúan usando su CA original hasta la renovación
3. **Migración forzada**: Renueva manualmente para cambiar a la nueva CA

**Buenas prácticas:**
- Prueba la nueva configuración de CA antes de establecerla como predeterminada
- Planifica la migración durante ventanas de mantenimiento
- Mantén copias de seguridad de los certificados existentes
- Monitoriza la validez tras la migración

---

## Consideraciones de seguridad

- Las claves HMAC EAB no se muestran tras guardar
- Las claves privadas se generan localmente y nunca se transmiten
- Usa HTTPS para todas las comunicaciones con la CA
- Considera el uso de VPN para el acceso a la CA privada

---

## Recursos

### Let's Encrypt
- [Documentación](https://letsencrypt.org/docs/)
- [Límites de peticiones](https://letsencrypt.org/docs/rate-limits/)
- [Entorno de staging](https://letsencrypt.org/docs/staging-environment/)

### DigiCert
- [Documentación ACME](https://docs.digicert.com/certificate-tools/acme-user-guide/)
- [Configuración de cuenta](https://docs.digicert.com/certificate-tools/acme-user-guide/acme-account-setup/)

### Actalis
- [Cómo habilitar ACME](https://guide.actalis.com/ssl/activation/acme)
- [FAQ ACME](https://guide.actalis.com/faq/SSL/ACME)

### CA privada
- [Documentación de step-ca](https://smallstep.com/docs/step-ca/)
- [Proyecto Boulder](https://github.com/letsencrypt/boulder)
- [Servidor de prueba Pebble](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Volver a la documentación](./README.md) • [Proveedores DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
