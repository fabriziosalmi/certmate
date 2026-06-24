# Sondas de Despliegue (Probes)

Las sondas verifican que sus certificados son accesibles en la red realizando un handshake TLS en vivo contra el servidor desplegado.

## Configuración

Configure las sondas por dominio en **Ajustes → Sondas de despliegue**.

| Campo | Descripción |
|---|---|
| Dominio | El dominio del certificado a sondear |
| Puerto | Puerto TCP (por defecto: 443 para HTTPS/TLS, 587 para SMTP STARTTLS) |
| Protocolo | `HTTPS/TLS` — handshake HTTPS estándar, `TLS` — TLS sin HTTP, `SMTP STARTTLS` — SMTP con actualización a TLS |

El protocolo y el puerto se almacenan en el `metadata.json` del certificado bajo las claves `deployment_protocol` y `deployment_port`.

## Funcionamiento

### Sonda backend

1. El backend lee el puerto y el protocolo configurados en los metadatos del certificado.
2. Se abre una conexión socket y se realiza un handshake TLS.
3. La huella digital del certificado servido se compara con la del certificado almacenado localmente.
4. El resultado (accesible, desplegado, coincidencia de certificado) se almacena en caché durante 5 minutos (configurable).

### Sonda de navegador (fallback)

Cuando la sonda backend indica que el servidor es inaccesible **y** el protocolo es `HTTPS/TLS`, se activa una sonda de respaldo en el lado del navegador mediante `fetch(..., { mode: 'no-cors' })`. Esto permite verificar la accesibilidad incluso cuando el backend no puede conectarse (p. ej., segmentación de red).

Para los protocolos `TLS` y `SMTP STARTTLS`, la sonda de navegador se **omite** porque los navegadores no pueden realizar conexiones TLS sin HTTP ni SMTP. El estado del navegador muestra "No verificado".

### Caché

| Capa | Duración | Omisión |
|---|---|---|
| Backend (memoria) | 300 s (por defecto) | Parámetro `?refresh=1` |
| Frontend (memoria) | 300 s | `forceRefresh=true` (botón Verificar sonda) |

## API

### Verificar el estado de despliegue

```
GET /api/certificates/<domain>/deployment-status
GET /api/certificates/<domain>/deployment-status?refresh=1
```

Devuelve:

| Campo | Tipo | Descripción |
|---|---|---|
| domain | string | El dominio sondeado |
| deployed | boolean | Si se sirvió un certificado |
| reachable | boolean | Si el servidor respondió |
| certificate_match | boolean/null | Si el certificado servido coincide con el almacenado |
| method | string | Protocolo utilizado (`https-tls`, `tls`, `smtp-starttls`) |
| port | integer | Puerto TCP sondeado |
| protocol | string | Igual que method |
| error | string | Mensaje de error si la sonda falló |
| browser | object | Resultado de la sonda de navegador (solo HTTPS) |

### Configurar una sonda

```
PATCH /api/certificates/<domain>
```

```json
{ "deployment_port": 444, "deployment_protocol": "https-tls" }
```

Establecer a `null` para eliminar la configuración de la sonda:

```json
{ "deployment_port": null, "deployment_protocol": null }
```
