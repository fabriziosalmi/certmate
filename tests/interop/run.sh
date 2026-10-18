#!/usr/bin/env bash
# ACME interoperability run for CertMate's ACME server (#476).
#
# Builds CertMate from this checkout, puts nginx in front of it with a
# throwaway TLS certificate (RFC 8555 section 6.1 wants HTTPS; BEHIND_PROXY
# keeps the scheme), turns ACME on and issues an EAB key through the admin
# API, as an operator would. Then each client, in a container of its own on
# the same Docker network under its own name, registers with the EAB key,
# answers http-01 with its standalone server, gets a certificate, is asked
# to renew at once (to read its renewal rule against the default validity),
# and revokes it. The checks run with CertMate's own Python: the leaf chains
# to /acme/root, and /acme/crl lists what was revoked.
#
# Needs Docker, the images pinned below, and nothing on the host but bash.
# Usage: tests/interop/run.sh [lego|acmesh ...]   (default: every client)
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
WORK=${INTEROP_WORK:-$(mktemp -d "${TMPDIR:-/tmp}/certmate-interop.XXXXXX")}
NET=certmate-interop
DIRECTORY=https://acme.lab.internal/acme/directory
CLIENTS=${*:-lego acmesh}

# Pinned by digest: lego 5.5.2 and acme.sh 3.1.5, the releases this was measured with.
LEGO_IMAGE=goacme/lego@sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd
ACMESH_IMAGE=neilpang/acme.sh@sha256:05a6a9e0276e148b3671c9f599bab098559a2d2a09e5811d44db9fe1da87d416
NGINX_IMAGE=nginx@sha256:892bb2152464f0c5d8972593a5f5afaf8054552580b699d95f8ff4af08c2d33d

log() { printf '%s %s\n' "$(date -u +%H:%M:%S)" "$*"; }
result() { printf 'RESULT %s\n' "$*" | tee -a "$WORK/results.txt"; }

stop() {
    docker rm -f certmate-interop acme-front >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
}
trap stop EXIT
stop
mkdir -p "$WORK/certs" "$WORK/lego" "$WORK/acmesh"
: > "$WORK/results.txt"
docker network create "$NET" >/dev/null

log "building CertMate from $REPO"
docker build -q -t certmate:interop "$REPO" >/dev/null

py() { docker run --rm -i -v "$WORK:/w" --entrypoint /opt/venv/bin/python certmate:interop - "$@"; }

log "a throwaway TLS certificate for the front"
py <<'PY'
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'acme.lab.internal')])
now = datetime.datetime.now(datetime.UTC)
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('acme.lab.internal')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256()))
open('/w/certs/front.pem', 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
open('/w/certs/front.key', 'wb').write(key.private_bytes(serialization.Encoding.PEM,
                                                         serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
PY
chmod 644 "$WORK/certs/front.key"

TOKEN=$(py <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)
docker run -d --name certmate-interop --network "$NET" \
    -e API_BEARER_TOKEN="$TOKEN" -e BEHIND_PROXY=true certmate:interop >/dev/null
docker run -d --name acme-front --network "$NET" --network-alias acme.lab.internal \
    -v "$HERE/front.conf:/etc/nginx/nginx.conf:ro" -v "$WORK/certs:/certs:ro" "$NGINX_IMAGE" >/dev/null

for _ in $(seq 1 90); do
    docker exec certmate-interop curl -sf http://localhost:8000/health >/dev/null 2>&1 && break
    sleep 2
done
docker exec certmate-interop curl -sf http://localhost:8000/health >/dev/null

api() {
    local args=(-sf -X "$1" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json')
    [ -n "${3:-}" ] && args+=(--data "$3")
    docker exec certmate-interop curl "${args[@]}" "http://localhost:8000$2"
}
public() {  # an /acme/ resource as the front would hand it over: https, by name
    docker exec certmate-interop curl -sf -H 'X-Forwarded-Proto: https' \
        -H 'X-Forwarded-Host: acme.lab.internal' "http://localhost:8000$1"
}

log "turning ACME on and issuing an EAB key through the admin API"
api PATCH /api/acme/server '{"enabled": true}' >/dev/null
api POST /api/acme/eab-keys '{"kid": "interop", "allowed_identifiers": ["*.lab.internal"], "note": "interop run"}' \
    > "$WORK/eab.json"
KID=$(py <<'PY'
import json
print(json.load(open('/w/eab.json'))['kid'])
PY
)
HMAC=$(py <<'PY'
import json
print(json.load(open('/w/eab.json'))['hmac_key'])
PY
)
public /acme/root > "$WORK/root.pem"

check_leaf() {  # $1 client, $2 leaf path inside $WORK
    py "$1" "$2" <<'PY'
import sys
from cryptography import x509
client, leaf_path = sys.argv[1], sys.argv[2]
root = x509.load_pem_x509_certificate(open('/w/root.pem', 'rb').read())
leaf = x509.load_pem_x509_certificates(open('/w' + leaf_path, 'rb').read())[0]
leaf.verify_directly_issued_by(root)
days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds() / 86400
names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
print(f'{client} issued: chains to the ACME root, names={names}, lifetime={days:.3f} days, serial={leaf.serial_number:x}')
PY
}

in_crl() {  # $1 client, $2 leaf path inside $WORK
    public /acme/crl > "$WORK/crl.der"
    py "$1" "$2" <<'PY'
import sys
from cryptography import x509
client, leaf_path = sys.argv[1], sys.argv[2]
root = x509.load_pem_x509_certificate(open('/w/root.pem', 'rb').read())
crl = x509.load_der_x509_crl(open('/w/crl.der', 'rb').read())
leaf = x509.load_pem_x509_certificates(open('/w' + leaf_path, 'rb').read())[0]
assert crl.is_signature_valid(root.public_key())
entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
print(f'{client} revoked: in the signed CRL={entry is not None}')
PY
}

run_lego() {
    lego() {
        docker run --rm --network "$NET" --network-alias lego.lab.internal \
            -e LEGO_CA_CERTIFICATES=/certs/front.pem -v "$WORK/certs:/certs:ro" -v "$WORK/lego:/data" \
            "$LEGO_IMAGE" "$@"
    }
    local common=(--server "$DIRECTORY" --path /data --log.format text)
    log "lego: register with EAB and issue for lego.lab.internal over http-01"
    lego run "${common[@]}" --eab --eab.kid "$KID" --eab.hmac "$HMAC" --email ops@lab.internal \
        --accept-tos --domains lego.lab.internal --http --no-random-sleep > "$WORK/lego-issue.log" 2>&1
    local leaf
    leaf=$(cd "$WORK" && find lego -name 'lego.lab.internal.crt' | head -1)
    result "$(check_leaf lego "/$leaf")"
    log "lego: asked to renew at once, with its default rule"
    lego run "${common[@]}" --eab --eab.kid "$KID" --eab.hmac "$HMAC" --email ops@lab.internal \
        --accept-tos --domains lego.lab.internal --http --no-random-sleep > "$WORK/lego-renew.log" 2>&1
    result "lego renewal: $(grep -iE 'renew|days|ARI|skip' "$WORK/lego-renew.log" | tr '\n' ' ' | cut -c1-400)"
    log "lego: revoke"
    lego certificates revoke "${common[@]}" --email ops@lab.internal \
        --cert.name lego.lab.internal --keep > "$WORK/lego-revoke.log" 2>&1
    result "$(in_crl lego "/$leaf")"
}

run_acmesh() {
    acmesh() {
        docker run --rm --network "$NET" --network-alias acmesh.lab.internal \
            -v "$WORK/certs:/certs:ro" -v "$WORK/acmesh:/acme.sh" "$ACMESH_IMAGE" "$@"
    }
    log "acme.sh: register with EAB"
    acmesh --register-account --server "$DIRECTORY" --ca-bundle /certs/front.pem \
        --eab-kid "$KID" --eab-hmac-key "$HMAC" -m ops@lab.internal > "$WORK/acmesh-register.log" 2>&1
    log "acme.sh: issue for acmesh.lab.internal over http-01, standalone"
    # ACMESH_DAYS: acme.sh's --days, to measure a renewal rule other than its default.
    acmesh --issue --standalone -d acmesh.lab.internal --server "$DIRECTORY" \
        --ca-bundle /certs/front.pem ${ACMESH_DAYS:+--days "$ACMESH_DAYS"} > "$WORK/acmesh-issue.log" 2>&1
    local leaf
    leaf=$(cd "$WORK" && find acmesh -name 'acmesh.lab.internal.cer' | head -1)
    # acme.sh moves a revoked certificate's files aside: keep the leaf to look it up in the CRL.
    cp "$WORK/$leaf" "$WORK/acmesh-leaf.pem"
    leaf=acmesh-leaf.pem
    result "$(check_leaf acmesh "/$leaf")"
    acmesh --info -d acmesh.lab.internal > "$WORK/acmesh-info.log" 2>&1 || true
    result "acme.sh schedule: $(grep -E 'Le_NextRenewTimeStr|Le_RenewalDays|Le_CertCreateTimeStr' "$WORK/acmesh-info.log" | tr '\n' ' ')"
    log "acme.sh: the cron run, at once"
    acmesh --cron > "$WORK/acmesh-cron.log" 2>&1 || true
    result "acme.sh cron: $(grep -iE 'skip|renew|next' "$WORK/acmesh-cron.log" | tr '\n' ' ' | cut -c1-400)"
    log "acme.sh: revoke"
    acmesh --revoke -d acmesh.lab.internal --server "$DIRECTORY" --ca-bundle /certs/front.pem \
        > "$WORK/acmesh-revoke.log" 2>&1
    result "$(in_crl acmesh "/$leaf")"
}

for client in $CLIENTS; do
    "run_$client"
done
log "results in $WORK/results.txt, logs beside them"
