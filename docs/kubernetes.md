# CertMate on Kubernetes

Install CertMate with its Helm chart, directly or through Argo CD or Flux, then size it for production. The chart's own README covers every value: [charts/certmate/README.md](../charts/certmate/README.md).

## Install with Helm

The chart is published to GHCR as an OCI artifact on every release, so there is no `helm repo add` step (Helm 3.8+). Its version is the CertMate version: without `--version` Helm takes the newest, and `--version X.Y.Z` pins one.

Create the Secret first, so the instance keeps the same token and session key across restarts:

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

Open `http://127.0.0.1:8000`. The first page creates the administrator account and asks for the `API_BEARER_TOKEN` stored in the Secret (`kubectl -n certmate get secret certmate-secrets -o jsonpath='{.data.API_BEARER_TOKEN}' | base64 -d`). Add `CLOUDFLARE_TOKEN` to the same Secret to bootstrap a Cloudflare DNS account; other DNS providers are configured in the web UI.

Upgrade with `helm upgrade certmate oci://ghcr.io/fabriziosalmi/charts/certmate --namespace certmate --reuse-values`. For Ingress, persistence and backups, see the chart README.

## GitOps with Argo CD

The Secret above is created once, outside Git. Then:

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

`repoURL` has no `oci://` prefix: Argo CD takes the registry path and the chart name separately. `2.*` follows new 2.x releases; set an exact version to pin one.

## GitOps with Flux

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

`semver: "2.x"` follows new 2.x releases; use `tag: X.Y.Z` to pin one.

These three were checked on a k3s 1.31 cluster, with Helm 4.1, Argo CD 3.5 and Flux (source-controller 1.9): each one installs the chart and the instance reports healthy.

---

# Production notes

This part captures the production sizing baseline for CertMate when it runs
behind a Kubernetes Ingress/HTTPRoute and uses a remote certificate backend
such as Azure Key Vault.

## Recommended Resources

CertMate runs gunicorn plus certbot subprocesses in the same container. During
certificate creation or renewal, certbot and DNS plugins can temporarily add a
large memory spike. With Azure Key Vault in `both` mode, listing certificates
also performs remote calls, so very small limits can turn routine operations
into OOM restarts.

Use this baseline for production pods that manage dozens of certificates:

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

With the Helm chart, set the same in your values file. The chart's default memory limit is 512Mi, which the next paragraph explains is too small for issuance under load:

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

For the specific failure mode where a pod with `memory: 512Mi` restarts while
creating a certificate, raise the memory limit first. The code path now avoids
the previous list-view `openssl` subprocesses, uses lightweight Azure Key Vault
certificate-info reads, and excludes certbot scratch/history directories from
routine backups, but certbot still needs headroom while issuing certificates.

## Deployment Patch Example

For a Deployment that is not managed by the Helm chart (the chart labels its pods `app.kubernetes.io/name=certmate`, not `app=certmate`). With the chart, use the values above instead.

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

Verify the next restart reason after applying:

```bash
kubectl -n certificate-management describe pod -l app=certmate | grep -A6 "Last State"
kubectl -n certificate-management top pod -l app=certmate
```

## Replica Count

Run `replicas: 1`. CertMate runs its certificate-renewal scheduler **in
process**, so every pod (and every gunicorn worker) fires the renewal check
independently. With more than one writer this means duplicate ACME orders and
the CA's duplicate-certificate rate limit — plus races on the local settings,
metadata, backups, and runtime state that CertMate keeps even when certificates
live in a remote backend (Azure Key Vault, Vault, S3).

A host-local `flock` (`/app/data/.renewal.lock`) prevents duplicate renewal
when multiple workers/containers share the **same** data volume on one host,
but it does **not** coordinate pods on separate volumes/nodes. So only raise
the replica count if every mutable path (`/app/data`, `/app/certificates`,
`/app/backups`, `/app/logs`) is a single volume shared by all pods AND you have
validated renewal behavior — otherwise keep one writer and, for availability,
front a single active instance rather than scaling this Deployment.

## Deployment Status Badge Shows "Backend: Unreachable"

*Updated 2026-05-25 (see [#263](https://github.com/fabriziosalmi/certmate/issues/263)).*

The deployment-status badge on the dashboard is an optional health indicator and
does **not** affect issuance, renewal, or download. CertMate's own process opens
a plain TLS connection to `<domain>:443` and compares the served certificate's
fingerprint against the stored one:

- **Deployed** — handshake succeeded and the fingerprint matches.
- **Wrong Cert** — handshake succeeded but a different certificate is served.
- **Unreachable** — the pod could not open a TLS connection to the domain at all.

On Kubernetes, **Unreachable for every certificate is expected** whenever the
CertMate pod cannot dial your public/ingress IP point-to-point. Common causes:

- The domain resolves to a public/ingress IP that is not routable from inside
  the pod (hairpin/NAT or split-horizon DNS).
- An egress `NetworkPolicy` blocks outbound 443.
- TLS is terminated by your ingress controller or an external load balancer, so
  there is no endpoint CertMate can reach directly.
- The probe is simply slow and exceeds the default 3-second budget.

If the target is reachable but slow, raise the probe budget:

```yaml
env:
  - name: CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
    value: "10"   # accepts 1–30 seconds; default is 3
```

Otherwise the badge is safe to ignore in an ingress/Kubernetes topology — the
certificates are issued and served correctly even when CertMate cannot probe
them itself.
