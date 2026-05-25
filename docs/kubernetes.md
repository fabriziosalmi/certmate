# Kubernetes Production Notes

This guide captures the production sizing baseline for CertMate when it runs
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

For the specific failure mode where a pod with `memory: 512Mi` restarts while
creating a certificate, raise the memory limit first. The code path now avoids
the previous list-view `openssl` subprocesses, uses lightweight Azure Key Vault
certificate-info reads, and excludes certbot scratch/history directories from
routine backups, but certbot still needs headroom while issuing certificates.

## Deployment Patch Example

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

Run `replicas: 1` unless all mutable paths (`/app/data`, `/app/certificates`,
`/app/backups`, `/app/logs`) are backed by storage that is safe for concurrent
writers and you have validated scheduler/renewal behavior for multiple pods.
Azure Key Vault can store certificates remotely, but CertMate still keeps local
settings, metadata, backups, and runtime state.

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
