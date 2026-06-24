# Notas de producción en Kubernetes

Esta guía recoge la configuración de dimensionamiento base para CertMate cuando se ejecuta detrás de un Ingress/HTTPRoute de Kubernetes y utiliza un backend de certificados remoto como Azure Key Vault.

## Recursos recomendados

CertMate ejecuta gunicorn junto con subprocesos certbot en el mismo contenedor. Durante la creación o renovación de certificados, certbot y los plugins DNS pueden añadir temporalmente un pico de memoria considerable. Con Azure Key Vault en modo `both`, listar los certificados también realiza llamadas remotas, por lo que límites muy reducidos pueden convertir operaciones rutinarias en reinicios por OOM.

Utiliza esta configuración base para los pods de producción que gestionan decenas de certificados:

```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 1536Mi
env:
  - name: CERTMATE_CERT_INFO_CACHE_TTL
    value: "60"
  - name: GUNICORN_TIMEOUT
    value: "300"
```

Para el modo de fallo específico en el que un pod con `memory: 512Mi` se reinicia durante la creación de un certificado, aumenta primero el límite de memoria. La ruta de código ahora evita los subprocesos `openssl` de la vista de lista anterior, utiliza lecturas ligeras de información de certificado de Azure Key Vault y excluye los directorios temporales e históricos de certbot de las copias de seguridad rutinarias, pero certbot sigue necesitando margen durante la emisión de certificados.

## Ejemplo de aplicación del patch

```bash
kubectl -n certificate-management patch deployment certmate --type='strategic' -p '
spec:
  template:
    spec:
      containers:
        - name: certmate
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: "1"
              memory: 1536Mi
          env:
            - name: CERTMATE_CERT_INFO_CACHE_TTL
              value: "60"
            - name: GUNICORN_TIMEOUT
              value: "300"
'
```

Verifica el motivo del siguiente reinicio tras aplicar el patch:

```bash
kubectl -n certificate-management describe pod -l app=certmate | grep -A6 "Last State"
kubectl -n certificate-management top pod -l app=certmate
```

## Número de réplicas

Ejecuta `replicas: 1` a menos que todas las rutas mutables (`/app/data`, `/app/certificates`, `/app/backups`, `/app/logs`) estén respaldadas por almacenamiento seguro para escritores concurrentes y hayas validado el comportamiento del planificador/renovación con múltiples pods. Azure Key Vault puede almacenar los certificados de forma remota, pero CertMate sigue conservando localmente los ajustes, metadatos, copias de seguridad y el estado de ejecución.

## El badge de estado de despliegue muestra "Backend: Unreachable"

*Actualizado el 2026-05-25 (ver [#263](https://github.com/fabriziosalmi/certmate/issues/263)).*

El badge de estado de despliegue en el panel de control es un indicador de salud opcional y **no afecta** a la emisión, renovación ni descarga de certificados. El propio proceso de CertMate abre una conexión TLS directa a `<domain>:443` y compara la huella digital del certificado servido con la almacenada:

- **Deployed** — el handshake fue exitoso y la huella digital coincide.
- **Wrong Cert** — el handshake fue exitoso pero se sirve un certificado diferente.
- **Unreachable** — el pod no pudo abrir una conexión TLS al dominio.

En Kubernetes, **Unreachable para cada certificado es lo esperado** cuando el pod de CertMate no puede conectarse directamente a tu IP pública/Ingress. Causas frecuentes:

- El dominio resuelve a una IP pública/Ingress que no es enrutable desde dentro del pod (hairpin/NAT o DNS split-horizon).
- Una `NetworkPolicy` de egreso bloquea el puerto 443 saliente.
- TLS está terminado por tu controlador Ingress o por un balanceador de carga externo, por lo que no existe ningún endpoint al que CertMate pueda conectarse directamente.
- La sonda es simplemente lenta y supera el presupuesto predeterminado de 3 segundos.

Si el destino es accesible pero lento, aumenta el presupuesto de la sonda:

```yaml
env:
  - name: CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
    value: "10"   # accepts 1–30 seconds; default is 3
```

De lo contrario, el badge puede ignorarse con seguridad en una topología Ingress/Kubernetes — los certificados se emiten y sirven correctamente aunque CertMate no pueda sondearlos por sí mismo.

---

<div align="center">

[← Volver a la documentación](./README.md) • [Guía de Docker →](./docker.md)

</div>
