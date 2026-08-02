# CertMate Helm chart

Run [CertMate](https://github.com/fabriziosalmi/certmate) in Kubernetes.

```bash
helm install certmate oci://ghcr.io/fabriziosalmi/charts/certmate \
  --namespace certmate --create-namespace
kubectl -n certmate port-forward svc/certmate 8000:8000
```

The chart is published as an OCI artifact to GHCR on every release, so there
is no `helm repo add` step — Helm 3.8 and later pull `oci://` URLs directly.
It lives under `charts/` rather than beside the container image, because a
chart and an image in one OCI repository would fight over the same tags.

Or from a checkout, which is the same chart:

```bash
helm install certmate ./charts/certmate --namespace certmate --create-namespace
```

**The chart version is the CertMate version.** `--version 2.25.0` gets the
chart that deploys CertMate 2.25.0. There is no second number to reconcile,
deliberately: every independent version copy in this repository has drifted at
least once.

## What this chart deliberately will not do

**It renders exactly one replica, and refuses anything else.** CertMate's
scheduler (APScheduler) runs inside the web process and gunicorn runs a single
worker on purpose. A second replica is a second scheduler issuing and renewing
against the same certificate store, and a second writer on a ReadWriteOnce
volume. `--set replicaCount=2` fails at template time with that explanation
rather than deploying something that looks healthy and quietly double-renews.

Scale the resources, not the replicas.

**It will not run without persistent storage.** Issued certificates, the
settings store, the certificate inventory and the tamper-evident audit chain
all live on disk. Disabling persistence without supplying
`persistence.existingClaim` fails at template time.

**The volume outlives the release.** The PVC carries
`helm.sh/resource-policy: keep`, so `helm uninstall` leaves your certificates
alone. Removing them is a deliberate `kubectl delete pvc`.

The rollout strategy is `Recreate` rather than `RollingUpdate`: a
ReadWriteOnce volume cannot be mounted by the new pod while the old one holds
it, so a rolling update would deadlock. Expect a few seconds of downtime on
upgrade.

## Secrets

`values.yaml` is not a secret store. For anything committed to git, create the
Secret yourself and point the chart at it:

```yaml
secrets:
  existingSecret: certmate-secrets
```

with keys such as `API_BEARER_TOKEN`, `SECRET_KEY` and whatever DNS provider
credentials you use (`CLOUDFLARE_TOKEN`, …). Everything in that Secret is
exposed to the container as environment variables.

Left empty, CertMate generates what it can on first boot — fine for a trial,
not for something you want to reproduce. With nothing supplied the chart
creates no Secret at all and mounts no environment from one, rather than
wiring up an empty object that looks like configuration.

The `secretRef` is **not** marked optional. If `existingSecret` names a Secret
that does not exist, the pod fails to start and says so, instead of coming up
without its credentials and turning a typo into a runtime mystery.

### Rotating an external Secret

The chart adds a checksum annotation so that changing values it *owns*
restarts the pod. It cannot do that for `existingSecret`: the chart does not
own that object, and reading it would require `lookup`, which returns nothing
during `helm template` and makes rendering depend on the live cluster —
breaking dry runs and GitOps diffs.

So after rotating an external Secret, restart the deployment yourself:

```bash
kubectl -n certmate rollout restart deployment/certmate
```

or run a controller that does it for you, such as
[stakater/Reloader](https://github.com/stakater/Reloader).

## Common values

| key | default | note |
|---|---|---|
| `image.tag` | chart `appVersion` | pin a digest for production |
| `persistence.size` | `2Gi` | certificates, inventory, audit chain, backups |
| `persistence.existingClaim` | `""` | bring your own volume |
| `env.behindProxy` | `true` | correct when traffic arrives via Ingress |
| `env.gunicornTimeout` | `300` | raise for slow DNS providers |
| `ingress.enabled` | `false` | |
| `secrets.existingSecret` | `""` | strongly preferred over inline values |

## OpenShift

The image's writable trees are group 0 with setgid, so an arbitrary assigned
UID works. Clear the values that would fight the SCC:

```bash
helm install certmate ./charts/certmate \
  --set podSecurityContext.runAsUser=null \
  --set podSecurityContext.fsGroup=null
```

## Where this fits

If everything needing TLS is an in-cluster Ingress, **cert-manager** is the
right tool and we say so in the
[deployment guide](https://www.certmate.org/deploy/kubernetes). CertMate earns
its place when certificates also have to reach things that are not Ingresses —
load balancers, appliances, hosts outside the cluster — and when you want one
inventory, audit trail and expiry view across all of them.
