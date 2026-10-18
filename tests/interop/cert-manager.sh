#!/usr/bin/env bash
# cert-manager against CertMate's ACME server (#476), on a Kubernetes cluster.
#
# Measured on OrbStack's cluster (orbctl start k8s), which runs the images of
# the local Docker engine; another cluster needs the CertMate image loaded
# into it, or CERTMATE_IMAGE set to one it can pull. The cluster's CoreDNS
# must import /etc/coredns/custom/*.server from an optional coredns-custom
# ConfigMap (k3s and OrbStack do), which is where the test zone goes.
#
# Installs cert-manager and ingress-nginx from their release manifests,
# checked against the SHA-256 they were measured with. ingress-nginx is
# retired upstream; it is here because cert-manager's http-01 Ingress solver
# drives it with no setup, and only for this test. Then CertMate and a TLS
# front in their own namespace, ACME on and an EAB key through the admin
# API, an Issuer with that key and the front's certificate as caBundle, and
# one Certificate for web.lab.internal, which a zone of its own points at
# the ingress controller. The checks: the Certificate is Ready, its leaf
# chains to /acme/root, and where cert-manager placed its renewal.
#
# Usage: tests/interop/cert-manager.sh   (KUBE_CONTEXT, default orbstack)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${INTEROP_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/certmate-cert-manager.XXXXXX")}
CONTEXT=${KUBE_CONTEXT:-orbstack}
NS=certmate-interop
CERTMATE_IMAGE=${CERTMATE_IMAGE:-certmate:interop}
NGINX_IMAGE=nginx@sha256:892bb2152464f0c5d8972593a5f5afaf8054552580b699d95f8ff4af08c2d33d

CERT_MANAGER_URL=https://github.com/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml
CERT_MANAGER_SHA256=e03b668ec8675214af6b0a671699d088f2601fa3878e0dbe1b41d3feafd1879f
INGRESS_URL=https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.15.1/deploy/static/provider/cloud/deploy.yaml
INGRESS_SHA256=502fddca66b09c20dd48b6d0a792a9671cd663a3a0d2a8bda5ae990d13b6c5b2

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
result() { printf 'RESULT %s\n' "$*" | tee -a "$WORK/results.txt"; }
k() { kubectl --context "$CONTEXT" "$@"; }
# As root: on Linux the image's own user cannot write $WORK, which belongs to
# whoever runs this (run.sh met it on GitHub's runner; OrbStack's mounts on
# macOS hide it).
py() { docker run --rm -i --user 0:0 -v "$WORK:/w" --entrypoint /opt/venv/bin/python "$CERTMATE_IMAGE" - "$@"; }
mkdir -p "$WORK"
: > "$WORK/results.txt"

fetch() {  # $1 url, $2 sha256, $3 file: download once, refuse on a different digest
    [ -f "$WORK/$3" ] || curl -sfL -o "$WORK/$3" "$1"
    local got
    got=$(shasum -a 256 "$WORK/$3" | cut -d' ' -f1)
    [ "$got" = "$2" ] || { log "$3 has sha256 $got, not $2: refusing to apply it"; exit 1; }
}

if [ "$CERTMATE_IMAGE" = certmate:interop ]; then
    log "building CertMate from $REPO"
    docker build -q -t certmate:interop "$REPO" >/dev/null
fi

log "cert-manager v1.21.2 and ingress-nginx v1.15.1"
fetch "$CERT_MANAGER_URL" "$CERT_MANAGER_SHA256" cert-manager.yaml
fetch "$INGRESS_URL" "$INGRESS_SHA256" ingress-nginx.yaml
k apply -f "$WORK/cert-manager.yaml" >/dev/null
k apply -f "$WORK/ingress-nginx.yaml" >/dev/null
k -n cert-manager wait --for=condition=Available deployment --all --timeout=300s >/dev/null
k -n ingress-nginx wait --for=condition=Available deployment/ingress-nginx-controller --timeout=300s >/dev/null

log "a fresh namespace, and web.lab.internal pointed at the ingress controller"
k delete namespace "$NS" --ignore-not-found --wait=true >/dev/null
INGRESS_IP=$(k -n ingress-nginx get svc ingress-nginx-controller -o jsonpath='{.spec.clusterIP}')
k apply -f - >/dev/null <<EOF
apiVersion: v1
kind: ConfigMap
metadata: {name: coredns-custom, namespace: kube-system}
data:
  lab.server: |
    lab.internal:53 {
        hosts {
            $INGRESS_IP web.lab.internal
        }
    }
EOF
k -n kube-system rollout restart deployment coredns >/dev/null
k -n kube-system rollout status deployment coredns --timeout=120s >/dev/null

log "CertMate and its TLS front"
py <<'PY'
import datetime, secrets
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
names = ['acme.certmate-interop.svc', 'acme.certmate-interop.svc.cluster.local']
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
now = datetime.datetime.now(datetime.UTC)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
open('/w/front.crt', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
open('/w/front.key', 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
open('/w/token', 'w').write(secrets.token_urlsafe(32))
PY
k create namespace "$NS" >/dev/null
k -n "$NS" create secret generic certmate-token --from-file=token="$WORK/token" >/dev/null
k -n "$NS" create secret tls front-tls --cert="$WORK/front.crt" --key="$WORK/front.key" >/dev/null
k apply -f - >/dev/null <<EOF
apiVersion: apps/v1
kind: Deployment
metadata: {name: certmate, namespace: $NS}
spec:
  replicas: 1
  selector: {matchLabels: {app: certmate}}
  template:
    metadata: {labels: {app: certmate}}
    spec:
      containers:
      - name: certmate
        image: $CERTMATE_IMAGE
        imagePullPolicy: IfNotPresent
        env:
        - {name: API_BEARER_TOKEN, valueFrom: {secretKeyRef: {name: certmate-token, key: token}}}
        - {name: BEHIND_PROXY, value: "true"}
        ports: [{containerPort: 8000}]
        readinessProbe: {httpGet: {path: /health, port: 8000}, periodSeconds: 3}
---
apiVersion: v1
kind: Service
metadata: {name: certmate, namespace: $NS}
spec:
  selector: {app: certmate}
  ports: [{port: 8000, targetPort: 8000}]
---
apiVersion: v1
kind: ConfigMap
metadata: {name: front-conf, namespace: $NS}
data:
  nginx.conf: |
    events {}
    http {
        server {
            listen 443 ssl;
            ssl_certificate     /certs/tls.crt;
            ssl_certificate_key /certs/tls.key;
            location / {
                proxy_pass http://certmate.$NS.svc.cluster.local:8000;
                proxy_set_header Host \$host;
                proxy_set_header X-Forwarded-Proto https;
                proxy_set_header X-Forwarded-Host \$host;
            }
        }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: acme, namespace: $NS}
spec:
  replicas: 1
  selector: {matchLabels: {app: acme}}
  template:
    metadata: {labels: {app: acme}}
    spec:
      containers:
      - name: front
        image: $NGINX_IMAGE
        ports: [{containerPort: 443}]
        volumeMounts:
        - {name: conf, mountPath: /etc/nginx/nginx.conf, subPath: nginx.conf}
        - {name: certs, mountPath: /certs}
      volumes:
      - {name: conf, configMap: {name: front-conf}}
      - {name: certs, secret: {secretName: front-tls}}
---
apiVersion: v1
kind: Service
metadata: {name: acme, namespace: $NS}
spec:
  selector: {app: acme}
  ports: [{port: 443, targetPort: 443}]
EOF
k -n "$NS" rollout status deployment certmate --timeout=300s >/dev/null
k -n "$NS" rollout status deployment acme --timeout=120s >/dev/null

POD=$(k -n "$NS" get pod -l app=certmate -o jsonpath='{.items[0].metadata.name}')
TOKEN=$(cat "$WORK/token")
api() {
    k -n "$NS" exec "$POD" -- curl -sf -X "$1" -H "Authorization: Bearer $TOKEN" \
        -H 'Content-Type: application/json' "http://localhost:8000$2" --data "$3" 2>/dev/null
}
log "turning ACME on and issuing an EAB key through the admin API"
api PATCH /api/acme/server '{"enabled": true}' >/dev/null
api POST /api/acme/eab-keys '{"kid": "cert-manager", "allowed_identifiers": ["*.lab.internal"], "note": "cert-manager interop"}' \
    > "$WORK/eab.json"
k -n "$NS" exec "$POD" -- curl -sf -H 'X-Forwarded-Proto: https' -H "X-Forwarded-Host: acme.$NS.svc" \
    http://localhost:8000/acme/root > "$WORK/root.pem" 2>/dev/null

py <<'PY' > "$WORK/issuer.yaml"
import base64, json
eab = json.load(open('/w/eab.json'))
open('/w/hmac', 'w').write(eab['hmac_key'])
print(f'''apiVersion: cert-manager.io/v1
kind: Issuer
metadata: {{name: certmate-acme, namespace: certmate-interop}}
spec:
  acme:
    server: https://acme.certmate-interop.svc/acme/directory
    caBundle: {base64.b64encode(open('/w/front.crt', 'rb').read()).decode()}
    email: ops@lab.internal
    privateKeySecretRef: {{name: certmate-acme-account}}
    externalAccountBinding:
      keyID: {eab['kid']}
      keySecretRef: {{name: certmate-eab, key: secret}}
    solvers:
    - http01:
        ingress:
          ingressClassName: nginx
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {{name: web, namespace: certmate-interop}}
spec:
  secretName: web-tls
  dnsNames: [web.lab.internal]
  issuerRef: {{name: certmate-acme, kind: Issuer}}
''')
PY
k -n "$NS" create secret generic certmate-eab --from-file=secret="$WORK/hmac" >/dev/null

log "the Issuer and a Certificate for web.lab.internal"
started=$(date +%s)
k apply -f "$WORK/issuer.yaml" >/dev/null
k -n "$NS" wait --for=condition=Ready issuer/certmate-acme --timeout=120s >/dev/null
k -n "$NS" wait --for=condition=Ready certificate/web --timeout=300s >/dev/null
result "cert-manager: Certificate Ready in $(( $(date +%s) - started )) s"
result "cert-manager: $(k -n "$NS" get certificate web -o jsonpath='notBefore={.status.notBefore} notAfter={.status.notAfter} renewalTime={.status.renewalTime}')"
k -n "$NS" get secret web-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > "$WORK/web.crt"
# Assigned first: inside another command's arguments, a failed check would not
# stop the run (bash ignores the status of that command substitution).
chained=$(py <<'PY'
from cryptography import x509
root = x509.load_pem_x509_certificate(open('/w/root.pem', 'rb').read())
chain = x509.load_pem_x509_certificates(open('/w/web.crt', 'rb').read())
chain[0].verify_directly_issued_by(root)
names = chain[0].extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
print(f'cert-manager: the secret holds {len(chain)} certificate, chained to the ACME root, names={names}')
PY
)
result "$chained"
log "results in $WORK/results.txt"
