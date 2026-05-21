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
