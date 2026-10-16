# Proveedores de autoridad de certificación (CA)

<!-- CERTMATE-TRANSLATED-FROM b5fbaa66b65585c0 -->

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
- **Email**: Contacto de la cuenta ACME (ver [Email de la cuenta](#email-de-la-cuenta))

**Perfiles:** `classic` (90 días, el predeterminado), `tlsserver` (45 días) y
`shortlived` (160 horas), en producción y en staging. Un certificado solicita uno
con `acme_profile`, y una cuenta CA puede indicar uno predeterminado para los certificados
creados con ella; ver [Perfiles ACME](../api.md#acme-profiles). En el dashboard: **ACME
Profile** en las opciones avanzadas del formulario de creación (Edit & Reissue se abre con el
perfil del propio certificado), y **Default ACME profile** en el formulario de la cuenta CA. El
panel del certificado muestra su perfil y cuándo se renueva.

### Let's Encrypt (Staging)

- **Tipo**: Certificados de prueba del entorno de staging de Let's Encrypt
- **Tipos de certificados**: Domain Validation (DV) — NO reconocidos por los navegadores
- **Soporte Wildcard**: Sí
- **EAB requerido**: No
- **Ideal para**: Validar la configuración DNS, el despliegue y la renovación sin consumir los límites de producción

El staging es una entrada de autoridad de certificación independiente (desde v2.12.0), no un indicador por certificado:
selecciónala como CA al crear un certificado, o establécela como CA predeterminada durante
las pruebas. El email recurre al de la cuenta de Let's Encrypt cuando se deja vacío.
Convertir un certificado de staging a producción requiere una reemisión con la CA de producción.

### ZeroSSL

- **Tipo**: Certificados DV gratuitos de 90 días
- **Tipos de certificados**: Domain Validation (DV)
- **Soporte Wildcard**: Sí
- **EAB requerido**: Sí

**Requisitos de configuración:**
- **URL del directorio ACME**: `https://acme.zerossl.com/v2/DV90` (fija, preconfigurada)
- **EAB Key ID**: Desde el ZeroSSL Developer Dashboard
- **EAB HMAC Key**: Desde el ZeroSSL Developer Dashboard
- **Email**: Contacto de la cuenta ACME (ver [Email de la cuenta](#email-de-la-cuenta))

### Google Trust Services

- **Tipo**: Certificados DV gratuitos
- **Tipos de certificados**: Domain Validation (DV)
- **Soporte Wildcard**: Sí
- **EAB requerido**: Sí

**Requisitos de configuración:**
- **URL del directorio ACME**: `https://dv.acme-v02.api.pki.goog/directory` (fija, preconfigurada)
- **EAB Key ID**: Desde tu proyecto de Google Cloud
- **EAB HMAC Key**: Desde tu proyecto de Google Cloud
- **Email**: Contacto de la cuenta ACME (ver [Email de la cuenta](#email-de-la-cuenta))

### DigiCert ACME

- **Tipo**: Certificados SSL de nivel empresarial
- **Tipos de certificados**: DV, OV, EV
- **Soporte Wildcard**: Sí
- **EAB requerido**: Sí
- **Ideal para**: Entornos empresariales, aplicaciones comerciales

**Requisitos de configuración:**
- **URL del directorio ACME**: `https://one.digicert.com/mpki/api/v1/acme/v2/directory`
  — la predeterminada, y **regional**. Una cuenta fuera de la región predeterminada tiene
  su propia URL de directorio, que se muestra en CertCentral; introdúcela aquí y la emisión la
  usa. Si la dejas en el valor predeterminado, se usa el predeterminado. Debe ser `https`.
- **EAB Key ID**: Proporcionado por DigiCert
- **EAB HMAC Key**: Proporcionada por DigiCert
- **Email**: Contacto de la cuenta ACME (ver [Email de la cuenta](#email-de-la-cuenta))

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
- **Email**: Contacto de la cuenta ACME (ver [Email de la cuenta](#email-de-la-cuenta))

**Límites del plan gratuito:**
- Solo certificados de dominio único — una solicitud con entradas SAN es rechazada con
  `Your account only grants single-domain 90-days DV certificates`
- Validez de 90 días
- Sin certificados wildcard (los planes SAN de pago cubren hasta 5 nombres de host)

### SSL.com

- **Tipo**: Certificados comerciales
- **Tipos de certificados**: DV, OV, EV
- **Soporte Wildcard**: Sí
- **EAB requerido**: Sí

**Requisitos de configuración:**
- **URL del directorio ACME**: `https://acme.ssl.com/sslcom-dv-rsa` (fija, preconfigurada)
- **EAB Key ID**: Proporcionado por SSL.com
- **EAB HMAC Key**: Proporcionada por SSL.com
- **Email**: Contacto de la cuenta ACME (ver [Email de la cuenta](#email-de-la-cuenta))

### Sectigo

- **Tipo**: CA ACME pública/comercial a través de Sectigo Certificate Manager (SCM)
- **Tipos de certificados**: DV, OV (según la cuenta/perfil de SCM seleccionado)
- **Soporte Wildcard**: Sí, cuando lo permite la cuenta/perfil de SCM
- **EAB requerido**: Sí
- **URL del directorio ACME**: Copia la URL HTTPS de los detalles de la cuenta ACME en SCM; es específica de cada cuenta
- **EAB Key ID / KID y HMAC Key**: Cópialos de los detalles de la cuenta ACME en SCM
- **Email**: Contacto de la cuenta ACME (ver [Email de la cuenta](#email-de-la-cuenta))

Configuración de prueba de ejemplo (la URL es **solo un ejemplo**, no un endpoint universal):

```json
{
  "ca_provider": "sectigo",
  "config": {
    "acme_url": "https://acme.sectigo.com/v2/OV",
    "eab_kid": "your-sectigo-key-id",
    "eab_hmac": "your-sectigo-hmac-key",
    "email": "admin@example.com"
  }
}
```

Para varias cuentas, configura `ca_providers.sectigo.accounts` en los ajustes,
con cada cuenta con sus propios `acme_url`, `eab_kid`, `eab_hmac` y `email`.
Selecciona una cuenta con `ca_account_id` en la API de creación de certificados; si se
omite, CertMate usa `default_ca_accounts.sectigo` o la primera cuenta configurada.
La renovación reutiliza la cuenta CA registrada. DNS-01 (incluido Custom Script) y
HTTP-01 siguen disponibles; puede que SCM ya haya autorizado el dominio solicitado.
Para una cuenta de SCM que ya autoriza **todos** los nombres solicitados, selecciona
**Sectigo → Sectigo (already authorized in SCM)** como tipo de desafío
del certificado. CertMate no configura validación DNS ni HTTP en ese modo, y se puede
solicitar un wildcard si esa cuenta/perfil de SCM lo autoriza. Certbot
usa su autenticador manual con un hook que no publica nada solo para satisfacer su
requisito de funcionamiento no interactivo: cuando la CA devuelve autorizaciones ACME válidas,
el hook nunca se llama. Si SCM devuelve una autorización pendiente, el hook
no publica ningún material de validación, por lo que CertMate no puede satisfacerla en este modo.
Usa DNS-01 o HTTP-01 cuando los nombres no estén ya autorizados. En la
renovación, SCM debe seguir autorizando los nombres para esa cuenta.
Este modo solo está disponible cuando Sectigo se selecciona explícitamente como CA.
Las configuraciones de Sectigo existentes bajo CA privada siguen funcionando sin cambios.

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
3. Haz clic en **Add CA Account**, elige la CA y ponle nombre a la cuenta (letras,
   dígitos, puntos, guiones y guiones bajos)
4. Configura los campos requeridos
5. Haz clic en **Probar conexión CA** para comprobar los campos
6. Haz clic en **Save Account**

**Probar conexión CA** solo contacta con la CA en el caso de una CA privada: obtiene la
URL del directorio ACME (usando el certificado CA, si se ha indicado uno). Para cualquier otra
CA comprueba que los campos requeridos estén rellenados (y, para DigiCert, que
las credenciales EAB no sean inverosímilmente cortas) sin contactar con la CA, por lo que una
prueba superada no demuestra que las credenciales funcionen. Eso lo demuestra la primera emisión.

### Email de la cuenta

Certbot usa el email de la cuenta CA seleccionada para las nuevas emisiones, y recurre
al ajuste global `email` cuando esa cuenta no tiene ninguno. El email global
sigue siendo obligatorio para la emisión. Cambiar el email de una cuenta no actualiza una
cuenta ACME ya registrada por Certbot; usa `certbot update_account` para
ese cambio de contacto.

### CA predeterminada vs. CA por certificado

Ajustes → Proveedores CA lista las cuentas CA (por ejemplo, dos emails de Let's Encrypt
o dos cuentas de Sectigo SCM). **Add CA Account** abre el formulario de la cuenta;
**Edit** lo vuelve a abrir. Selecciona **Default for this CA** en una cuenta por proveedor;
**Make global default** elige además el proveedor usado para los nuevos certificados.
Las configuraciones existentes de una sola cuenta se conservan como la cuenta `default`
cuando se añade otra cuenta. Eliminar una cuenta deja intactas las demás cuentas
de esa CA; cambia la predeterminada o reemite los certificados que usan esa cuenta antes de
eliminarla.

Establece una CA predeterminada para todos los nuevos certificados. Puedes sobrescribirla por certificado durante la creación:

1. Ve a la página **Certificados**
2. Selecciona la CA deseada en el desplegable **Autoridad de certificación**
3. Continúa con la creación del certificado

Si la CA elegida no tiene ninguna configuración guardada (o la cuenta CA solicitada no
existe), la solicitud se **rechaza**. Emitir desde una CA distinta no
sustituye a la que pediste: era posible pedir DigiCert y
recibir un certificado de Let's Encrypt con un `201`, y pedir a una CA privada
un nombre interno y que ese nombre acabara publicado en un certificado público. El
rechazo indica la CA que falta.

Let's Encrypt es la excepción, y solo porque los valores predeterminados de certbot son su
configuración: una solicitud para ella se completa sin nada guardado, y una solicitud
de staging se queda en staging.

La columna **CA** de la página Certificados indica la autoridad con la que se emitió cada
certificado; el mismo valor es `ca_provider` en la respuesta de la API y en los
metadatos del certificado. Los certificados emitidos antes de que CertMate registrara la CA
muestran `—` en lugar de una suposición.

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
      "acme_url": "https://one.digicert.com/mpki/api/v1/acme/v2/directory",
      "eab_kid": "your_key_id",
      "eab_hmac": "your_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis y Sectigo requieren External Account Binding para vincular tu cliente ACME a tu cuenta de CA.

### ¿Qué es EAB?

- **Key ID**: Un identificador único para tu cuenta
- **HMAC Key**: Una clave secreta utilizada para firmar las solicitudes

### Obtener credenciales EAB

**DigiCert:**
1. Inicia sesión en tu cuenta de DigiCert
2. Ve a los ajustes ACME
3. Genera o recupera tu EAB Key ID y HMAC Key

**ZeroSSL:**
- Genera las credenciales EAB en el ZeroSSL Developer Dashboard

**Actalis:**
1. Registra una cuenta gratuita en [actalis.com](https://www.actalis.com/)
2. En el área de cliente, abre **Manage with ACME**
3. Recupera el KID y la clave HMAC en **ACME Credentials**

**CA privada:**
- **step-ca**: EAB puede habilitarse/deshabilitarse por provisioner
- Consulta la documentación de tu CA privada para los requisitos específicos

---

## Confianza del certificado SSL

### CAs públicas (Let's Encrypt, ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis, Sectigo)

Los certificados son reconocidos automáticamente por los navegadores y sistemas operativos (salvo los del staging de Let's Encrypt).

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

### Sectigo
- **Credenciales EAB inválidas**: Comprueba el KID y el HMAC con los detalles de la cuenta ACME de SCM seleccionada
- **Identificador/dominio no autorizado**: Comprueba que el dominio está autorizado para la cuenta ACME de SCM y la organización seleccionadas
- **Endpoint ACME incorrecto**: Comprueba que la URL del directorio configurada coincide exactamente con la URL que proporciona SCM para esa cuenta

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
2. **Los certificados existentes** se quedan en la CA con la que se emitieron: la renovación ejecuta
   `certbot renew` contra la CA original, también en una renovación manual o forzada
3. **Mover un certificado a otra CA**: reemítelo con la nueva CA
   (`POST /api/certificates/<domain>/reissue` con `ca_provider`; ver la
   [referencia de la API](./api.md))

**Buenas prácticas:**
- Prueba la nueva configuración de CA antes de establecerla como predeterminada
- Planifica la migración durante ventanas de mantenimiento
- Mantén copias de seguridad de los certificados existentes
- Monitoriza la validez tras la migración

---

## Consideraciones de seguridad

- Las claves HMAC EAB no se muestran tras guardar
- Las claves privadas se generan localmente y nunca se envían a la CA (un backend de almacenamiento remoto o un destino de despliegue que configures sí las recibe)
- Usa una URL de directorio ACME `https://` para una CA privada
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

### Sectigo
- [Entender los endpoints ACME de SCM](https://docs.sectigo.com/scm/scm-administrator/understanding-acme-endpoints.html)
- [Añadir cuentas ACME en SCM](https://docs.sectigo.com/scm/scm-administrator/adding-acme-accounts.html)

### CA privada
- [Documentación de step-ca](https://smallstep.com/docs/step-ca/)
- [Proyecto Boulder](https://github.com/letsencrypt/boulder)
- [Servidor de prueba Pebble](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Volver a la documentación](./README.md) • [Proveedores DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
