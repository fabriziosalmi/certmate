# CertMate en Kubernetes

<!-- CERTMATE-TRANSLATED-FROM c0ef74162bfa4e87 -->

Instala CertMate con su chart de Helm, directamente o a través de Argo CD o Flux, y después dimensiónalo para producción. El README del propio chart documenta todos los valores: [charts/certmate/README.md](../../charts/certmate/README.md).

## Instalar con Helm

El chart se publica en GHCR como artefacto OCI en cada release, por lo que no hay paso `helm repo add` (Helm 3.8+). Su versión es la versión de CertMate: sin `--version`, Helm toma la más reciente, y `--version X.Y.Z` fija una concreta.

Crea primero el Secret, para que la instancia conserve el mismo token y la misma clave de sesión entre reinicios:

```bash
kubectl create namespace certmate
kubectl -n certmate create secret generic certmate-secrets \
  --from-literal=API_BEARER_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=CERTMATE_BACKUP_PASSPHRASE="$(openssl rand -hex 32)"

helm install certmate oci://ghcr.io/fabriziosalmi/charts/certmate \
  --namespace certmate \
  --set secrets.existingSecret=certmate-secrets

kubectl -n certmate port-forward svc/certmate 8000:8000
```

Abre `http://127.0.0.1:8000`. La primera página crea la cuenta de administrador y pide el `API_BEARER_TOKEN` guardado en el Secret (`kubectl -n certmate get secret certmate-secrets -o jsonpath='{.data.API_BEARER_TOKEN}' | base64 -d`). Añade `CLOUDFLARE_TOKEN` al mismo Secret para inicializar una cuenta DNS de Cloudflare; los demás proveedores DNS se configuran en la interfaz web.

Actualiza con `helm upgrade certmate oci://ghcr.io/fabriziosalmi/charts/certmate --namespace certmate --reuse-values`. Para Ingress, persistencia y copias de seguridad, consulta el README del chart.

## GitOps con Argo CD

El Secret anterior se crea una sola vez, fuera de Git. Después:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: certmate
  namespace: argocd
spec:
  project: default
  source:
    repoURL: ghcr.io/fabriziosalmi/charts
    chart: certmate
    targetRevision: "2.*"
    helm:
      valuesObject:
        secrets:
          existingSecret: certmate-secrets
  destination:
    server: https://kubernetes.default.svc
    namespace: certmate
  syncPolicy:
    automated: {}
```

`repoURL` no lleva el prefijo `oci://`: Argo CD recibe por separado la ruta del registro y el nombre del chart. `2.*` sigue las nuevas releases 2.x; indica una versión exacta para fijar una concreta.

## GitOps con Flux

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: certmate
  namespace: certmate
spec:
  interval: 1h
  url: oci://ghcr.io/fabriziosalmi/charts/certmate
  ref:
    semver: "2.x"
  layerSelector:
    mediaType: application/vnd.cncf.helm.chart.content.v1.tar+gzip
    operation: copy
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: certmate
  namespace: certmate
spec:
  interval: 1h
  chartRef:
    kind: OCIRepository
    name: certmate
  values:
    secrets:
      existingSecret: certmate-secrets
```

`semver: "2.x"` sigue las nuevas releases 2.x; usa `tag: X.Y.Z` para fijar una concreta.

Estos tres métodos se comprobaron en un clúster k3s 1.31, con Helm 4.1, Argo CD 3.5 y Flux (source-controller 1.9): cada uno instala el chart y la instancia informa de que está sana.

---

# Notas de producción

Esta parte recoge la configuración de dimensionamiento base para CertMate cuando se ejecuta detrás de un Ingress/HTTPRoute de Kubernetes y utiliza un backend de certificados remoto como Azure Key Vault.

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

Con el chart de Helm, define lo mismo en tu archivo de valores. El límite de memoria predeterminado del chart es 512Mi, que, como explica el párrafo siguiente, es demasiado bajo para la emisión bajo carga:

```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 1536Mi
extraEnv:
  - name: CERTMATE_CERT_INFO_CACHE_TTL
    value: "60"
```

Para el modo de fallo específico en el que un pod con `memory: 512Mi` se reinicia durante la creación de un certificado, aumenta primero el límite de memoria. La ruta de código ahora evita los subprocesos `openssl` de la vista de lista anterior, utiliza lecturas ligeras de información de certificado de Azure Key Vault y excluye los directorios temporales e históricos de certbot de las copias de seguridad rutinarias, pero certbot sigue necesitando margen durante la emisión de certificados.

## Ejemplo de patch del Deployment

Para un Deployment que no está gestionado por el chart de Helm (el chart etiqueta sus pods con `app.kubernetes.io/name=certmate`, no con `app=certmate`). Con el chart, usa en su lugar los valores anteriores.

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

Ejecuta `replicas: 1`. CertMate ejecuta su planificador de renovación de certificados **dentro del proceso**, por lo que cada pod (y cada worker de gunicorn) lanza la comprobación de renovación de forma independiente. Con más de un escritor, esto significa pedidos ACME duplicados y el límite de tasa de certificados duplicados de la CA, además de condiciones de carrera sobre los ajustes locales, los metadatos, las copias de seguridad y el estado de ejecución que CertMate conserva incluso cuando los certificados residen en un backend remoto (Azure Key Vault, Vault, S3).

Un `flock` local del host (`/app/data/.renewal.lock`) evita renovaciones duplicadas cuando varios workers/contenedores comparten el **mismo** volumen de datos en un único host, pero **no** coordina pods en volúmenes/nodos distintos. Por tanto, aumenta el número de réplicas solo si todas las rutas mutables (`/app/data`, `/app/certificates`, `/app/backups`, `/app/logs`) son un único volumen compartido por todos los pods Y has validado el comportamiento de la renovación; de lo contrario, mantén un único escritor y, para la disponibilidad, pon delante una única instancia activa en lugar de escalar este Deployment.

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

De lo contrario, el badge puede ignorarse con seguridad en una topología Ingress/Kubernetes: los certificados se emiten y sirven correctamente aunque CertMate no pueda sondearlos por sí mismo.
