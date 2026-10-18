#!/usr/bin/env bash
# ACME interoperability run for CertMate's ACME server (#476).
#
# Builds CertMate from this checkout, puts nginx in front of it with a
# throwaway TLS certificate (RFC 8555 section 6.1 wants HTTPS; BEHIND_PROXY
# keeps the scheme), turns ACME on and issues an EAB key through the admin
# API, as an operator would. Then each client, in a container of its own on
# the same Docker network under its own name, registers with the EAB key,
# answers http-01 with its standalone server and gets a certificate. What
# docs/acme-server.md says of each client is checked here, and any check
# failing fails the run:
#
# - the leaf chains to /acme/root;
# - asked to renew at once, the client waits: lego until a third of the
#   lifetime is left, its own rule; acme.sh for a moment inside the renewal
#   window the server gave it, which is two thirds to five sixths of the
#   lifetime;
# - once CertMate's admin revokes the certificate, the client's next run
#   replaces it, and the CRL lists the revoked one;
# - the client revokes the new one itself, and the CRL lists it.
#
# The clients are pinned by digest, so a run measures this server against
# the same lego and acme.sh each time: moving a digest is how a new client
# release is measured. Each step also reports how many /acme/ requests it
# made, read from the front's access log: what the rate limit on /acme/ has
# to leave room for.
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

# As root: on Linux the image's own user cannot write $WORK, which belongs to
# whoever runs this, and lego and acme.sh write their files as root, in
# directories the host user may not read. Every file the containers wrote is
# found and read through this, not by the host shell.
py() { docker run --rm -i --user 0:0 -v "$WORK:/w" --entrypoint /opt/venv/bin/python certmate:interop - "$@"; }

found() {  # $1 directory inside $WORK, $2 file name: its path inside $WORK
    py "$1" "$2" <<'PY'
import pathlib, sys
matches = sorted(pathlib.Path('/w', sys.argv[1]).rglob(sys.argv[2]))
assert matches, f'no {sys.argv[2]} under {sys.argv[1]}'
print(matches[0].relative_to('/w'))
PY
}

log "a throwaway TLS certificate for the front"
py <<'PY'
import datetime
import os
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
os.chmod('/w/certs/front.key', 0o644)
PY

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
# ACME_VALIDITY_DAYS: the certificates' validity, to measure the clients' renewal against another one.
api PATCH /api/acme/server "{\"enabled\": true${ACME_VALIDITY_DAYS:+, \"validity_days\": $ACME_VALIDITY_DAYS}}" >/dev/null
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

# Every check goes through this. A check written as `result "$(check ...)"`
# could not fail the run: bash ignores the status of a command substitution
# inside another command's arguments, so a leaf that did not chain to the root
# or a revocation missing from the CRL printed an empty line and the run went
# on. The assignment is what carries the failure.
check() {  # the command prints one line for the results; its failure stops the run
    local line
    line=$("$@")
    result "$line"
}

tolerated() {  # a step whose own exit status says nothing; the checks after it do
    "$@" || true
}

check_leaf() {  # $1 client, $2 leaf inside $WORK
    py "$1" "$2" <<'PY'
import sys
from cryptography import x509
client, leaf_path = sys.argv[1], sys.argv[2].lstrip('/')
root = x509.load_pem_x509_certificate(open('/w/root.pem', 'rb').read())
leaf = x509.load_pem_x509_certificates(open('/w/' + leaf_path, 'rb').read())[0]
leaf.verify_directly_issued_by(root)
days = (leaf.not_valid_after_utc - leaf.not_valid_before_utc).total_seconds() / 86400
names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
print(f'{client} issued: chains to the ACME root, names={names}, lifetime={days:.3f} days, serial={leaf.serial_number:x}')
PY
}

in_crl() {  # $1 client, $2 leaf inside $WORK
    public /acme/crl > "$WORK/crl.der"
    py "$1" "$2" <<'PY'
import sys
from cryptography import x509
client, leaf_path = sys.argv[1], sys.argv[2].lstrip('/')
root = x509.load_pem_x509_certificate(open('/w/root.pem', 'rb').read())
crl = x509.load_der_x509_crl(open('/w/crl.der', 'rb').read())
leaf = x509.load_pem_x509_certificates(open('/w/' + leaf_path, 'rb').read())[0]
assert crl.is_signature_valid(root.public_key()), 'the CRL is not signed by the ACME root'
entry = crl.get_revoked_certificate_by_serial_number(leaf.serial_number)
assert entry is not None, f'{client}: {leaf.serial_number:x} is revoked and not in the signed CRL'
print(f'{client} revoked: {leaf.serial_number:x} in the signed CRL')
PY
}

keep() {  # $1 a file inside $WORK, $2 a name to keep a copy under: the clients overwrite or move theirs
    py "$1" "$2" <<'PY'
import shutil, sys
shutil.copy('/w/' + sys.argv[1].lstrip('/'), '/w/' + sys.argv[2])
PY
}

admin_revokes() {  # $1 a leaf inside $WORK: revoked through CertMate's API, as from the ACME view
    api GET /api/acme/certificates > "$WORK/certificates.json"
    local id
    id=$(py "$1" <<'PY'
import json, sys
from cryptography import x509
serial = format(x509.load_pem_x509_certificates(open('/w/' + sys.argv[1].lstrip('/'), 'rb').read())[0].serial_number, 'x')
print(next(c['id'] for c in json.load(open('/w/certificates.json'))['certificates'] if c['serial'] == serial))
PY
)
    api POST "/api/acme/certificates/$id/revoke" '{"reason": 4}' >/dev/null
}

renewal() {  # $1 client, $2 renewed|kept, $3 the leaf it had, $4 the leaf it has now
    py "$@" <<'PY'
import sys
from cryptography import x509
client, expected, before, after = sys.argv[1:]
load = lambda p: x509.load_pem_x509_certificates(open('/w/' + p.lstrip('/'), 'rb').read())[0].serial_number
old, new = load(before), load(after)
if expected == 'renewed':
    assert new != old, f'{client} kept {old:x}, which it was expected to replace'
    print(f'{client} replaced it: {old:x} -> {new:x}')
else:
    assert new == old, f'{client} replaced {old:x} with {new:x}, where it was expected to wait'
    print(f'{client} kept it: {old:x}')
PY
}

when_check() {  # $1 client, $2 the moment it chose (RFC 3339), $3 its leaf, [$4 the window it was given]
    # Without a window: the client's own rule, a third of the lifetime left.
    # With one: that window is the one documented (two thirds to five sixths
    # of the lifetime), and the moment is inside it.
    py "$@" <<'PY'
import sys
from datetime import datetime, timedelta
from cryptography import x509
client, chosen, leaf_path = sys.argv[1:4]
parse = lambda s: datetime.fromisoformat(s.replace('Z', '+00:00'))
leaf = x509.load_pem_x509_certificates(open('/w/' + leaf_path.lstrip('/'), 'rb').read())[0]
born = leaf.not_valid_before_utc
life = leaf.not_valid_after_utc - born
day = lambda moment: (moment - born).total_seconds() / 86400
at = parse(chosen)
if len(sys.argv) == 4:
    rule = born + life * 2 / 3
    assert abs(at - rule) < timedelta(minutes=2), f'{client} renews on day {day(at):.2f}, not with a third of the lifetime left'
    print(f'{client} renews on day {day(at):.1f} of {day(leaf.not_valid_after_utc):.1f}: a third of the lifetime left')
else:
    start, end = (parse(s) for s in sys.argv[4].split())
    for got, share in ((start, 2 / 3), (end, 5 / 6)):
        assert abs(got - (born + life * share)) < timedelta(minutes=1), f'the window given to {client} is days {day(start):.2f} to {day(end):.2f}'
    assert start <= at <= end, f'{client} renews on day {day(at):.2f}, outside the window it was given'
    print(f'{client} renews on day {day(at):.1f} of {day(leaf.not_valid_after_utc):.1f}, '
          f'inside the window it was given, days {day(start):.1f} to {day(end):.1f}')
PY
}

acmesh_window() {  # acme.sh's own log: the window the server gave it, "<start> <end>"
    py "$1" <<'PY'
import re, sys
m = re.search(r'ARI suggestedWindow: (\S+) to (\S+)', open('/w/' + sys.argv[1]).read())
assert m, 'acme.sh did not read a renewal window'
print(m.group(1), m.group(2))
PY
}

lego_chose() {  # lego's own log: the moment its skip message says it will renew
    py "$1" <<'PY'
import re, sys
from datetime import datetime, timedelta
log = open('/w/' + sys.argv[1]).read()
m = re.search(r'time=(\S+) .*Skip renewal: .*can be performed in ([0-9a-zµ.]+?)\.', log)
assert m, 'lego did not say it skipped the renewal: ' + log[-300:]
units = {'d': 86400, 'h': 3600, 'm': 60, 's': 1, 'ms': 1e-3, 'µs': 1e-6, 'us': 1e-6, 'ns': 1e-9}
wait = sum(float(n) * units[u] for n, u in re.findall(r'([0-9.]+)(ms|µs|us|ns|d|h|m|s)', m.group(2)))
at = datetime.fromisoformat(m.group(1).replace('Z', '+00:00')) + timedelta(seconds=wait)
print(at.strftime('%Y-%m-%dT%H:%M:%SZ'))
PY
}

acmesh_chose() {  # acme.sh --info: the renewal time it scheduled
    py "$1" <<'PY'
import re, sys
m = re.search(r'Le_NextRenewTimeStr=(\S+)', open('/w/' + sys.argv[1]).read())
assert m, 'acme.sh --info shows no Le_NextRenewTimeStr'
print(m.group(1))
PY
}

acme_requests() {  # /acme/ requests the front has served so far; the public helper goes around it
    docker logs acme-front 2>/dev/null | grep -c '"[A-Z]* /acme/' || true
}

counted() {  # $1 label, $2 log file, then the command; reports the /acme/ requests it made
    local label=$1 output=$2 before after
    shift 2
    before=$(acme_requests)
    "$@" > "$output" 2>&1
    after=$(acme_requests)
    result "$label: $((after - before)) ACME requests"
}

run_lego() {
    lego() {
        docker run --rm --network "$NET" --network-alias lego.lab.internal \
            -e LEGO_CA_CERTIFICATES=/certs/front.pem -v "$WORK/certs:/certs:ro" -v "$WORK/lego:/data" \
            "$LEGO_IMAGE" "$@"
    }
    local common=(--server "$DIRECTORY" --path /data --log.format text)
    local order=(--eab --eab.kid "$KID" --eab.hmac "$HMAC" --email ops@lab.internal --accept-tos
                 --domains lego.lab.internal --http --no-random-sleep)
    log "lego: register with EAB and issue for lego.lab.internal over http-01"
    counted "lego register and issue" "$WORK/lego-issue.log" lego run "${common[@]}" "${order[@]}"
    local leaf at
    leaf=$(found lego lego.lab.internal.crt)
    check check_leaf lego "$leaf"
    keep "$leaf" lego-first.pem
    log "lego: asked to renew at once"
    counted "lego renewal check" "$WORK/lego-renew.log" lego run "${common[@]}" "${order[@]}"
    check renewal lego kept lego-first.pem "$leaf"
    at=$(lego_chose lego-renew.log)
    check when_check lego "$at" lego-first.pem
    log "lego: CertMate's admin revokes it, then lego's next run"
    admin_revokes lego-first.pem
    counted "lego run after an admin revoked it" "$WORK/lego-after-revocation.log" \
        lego run "${common[@]}" "${order[@]}"
    check renewal lego renewed lego-first.pem "$leaf"
    check check_leaf lego "$leaf"
    check in_crl lego lego-first.pem
    log "lego: revoke"
    counted "lego revoke" "$WORK/lego-revoke.log" \
        lego certificates revoke "${common[@]}" --email ops@lab.internal --cert.name lego.lab.internal --keep
    check in_crl lego "$leaf"
}

run_acmesh() {
    acmesh() {
        docker run --rm --network "$NET" --network-alias acmesh.lab.internal \
            -v "$WORK/certs:/certs:ro" -v "$WORK/acmesh:/acme.sh" "$ACMESH_IMAGE" "$@"
    }
    log "acme.sh: register with EAB"
    counted "acme.sh register" "$WORK/acmesh-register.log" \
        acmesh --register-account --server "$DIRECTORY" --ca-bundle /certs/front.pem \
        --eab-kid "$KID" --eab-hmac-key "$HMAC" -m ops@lab.internal
    log "acme.sh: issue for acmesh.lab.internal over http-01, standalone"
    # ACMESH_DAYS: acme.sh's --days, to measure a rule other than the server's window. It
    # replaces the window, so the run stops after reporting the schedule it gives.
    counted "acme.sh issue" "$WORK/acmesh-issue.log" \
        acmesh --issue --standalone -d acmesh.lab.internal --server "$DIRECTORY" \
        --ca-bundle /certs/front.pem ${ACMESH_DAYS:+--days "$ACMESH_DAYS"}
    local leaf at window
    leaf=$(found acmesh acmesh.lab.internal.cer)
    check check_leaf acmesh "$leaf"
    # acme.sh moves a revoked certificate's files aside: keep each leaf to look it up later.
    keep "$leaf" acmesh-first.pem
    acmesh --info -d acmesh.lab.internal > "$WORK/acmesh-info.log" 2>&1 || true
    at=$(acmesh_chose acmesh-info.log)
    if [ -n "${ACMESH_DAYS:-}" ]; then
        result "acme.sh, given --days $ACMESH_DAYS, renews at $at"
        return
    fi
    window=$(acmesh_window acmesh-issue.log)
    check when_check acme.sh "$at" acmesh-first.pem "$window"
    log "acme.sh: the cron run, at once"
    counted "acme.sh cron, at once" "$WORK/acmesh-cron.log" tolerated acmesh --cron
    check renewal acme.sh kept acmesh-first.pem "$leaf"
    log "acme.sh: CertMate's admin revokes it, then acme.sh's next cron run"
    admin_revokes acmesh-first.pem
    counted "acme.sh cron after an admin revoked it" "$WORK/acmesh-cron-after-revocation.log" \
        tolerated acmesh --cron
    check renewal acme.sh renewed acmesh-first.pem "$leaf"
    check check_leaf acmesh "$leaf"
    check in_crl acmesh acmesh-first.pem
    keep "$leaf" acmesh-renewed.pem
    log "acme.sh: revoke"
    counted "acme.sh revoke" "$WORK/acmesh-revoke.log" \
        acmesh --revoke -d acmesh.lab.internal --server "$DIRECTORY" --ca-bundle /certs/front.pem
    check in_crl acmesh acmesh-renewed.pem
}

for client in $CLIENTS; do
    "run_$client"
done
log "results in $WORK/results.txt, logs beside them"
